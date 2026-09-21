#include "cache.h"
#include "dns_name.h"
#include "dns_packet.h"
#include "dns_wire.h"
#include "infra.h"

#include <pthread.h>
#include <strings.h>   /* strcasecmp */

/* Clamp every RR TTL to max_ttl, skipping OPT (its TTL holds EDNS flags). */
static void patch_response_ttls(unsigned char* buf, int len, uint32_t max_ttl)
{
    if (!buf || len < HEADER_LEN || max_ttl == 0) return;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, len); rr_next(&it, &rr); )
        if (rr.type != QTYPE_OPT && rr.ttl > max_ttl)
            wr32(buf + rr.rdata - 6, max_ttl);
}

/* Seconds on the monotonic clock.  Expiry is computed from this, not the wall
 * clock: an NTP step (a Pi has no RTC, so boot-time jumps are routine) would
 * otherwise expire or immortalize every entry at once. */
static time_t cache_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

/* FNV-1a over a name, optionally mixed with a type.  ASCII case is folded so
 * the two caches agree on a key: DNS names are case-insensitive (RFC 4343),
 * but names decoded straight off the wire (CNAME targets, NS names) keep the
 * spelling the remote server chose, while client queries arrive lowercased. */
static uint64_t hash_name(const char* s, uint16_t qtype)
{
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) {
        uint8_t c = (uint8_t)*s;
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        h ^= c; h *= 1099511628211ull;
    }
    h ^= qtype;        h *= 1099511628211ull;
    h ^= qtype >> 8;   h *= 1099511628211ull;
    return h;
}

/* =========================================================================
 * Generic intrusive LRU helpers (most-recently-used at head).  Callers hold
 * the owning cache/shard lock.
 * ========================================================================= */

#define LRU_UNLINK(c, e) do {                                           \
    if ((e)->lru_prev) (e)->lru_prev->lru_next = (e)->lru_next;         \
    else               (c)->lru_head           = (e)->lru_next;         \
    if ((e)->lru_next) (e)->lru_next->lru_prev = (e)->lru_prev;         \
    else               (c)->lru_tail           = (e)->lru_prev;         \
    (e)->lru_prev = (e)->lru_next = NULL;                               \
} while (0)

#define LRU_PUSH_FRONT(c, e) do {                                       \
    (e)->lru_prev = NULL;                                               \
    (e)->lru_next = (c)->lru_head;                                      \
    if ((c)->lru_head) (c)->lru_head->lru_prev = (e);                   \
    (c)->lru_head = (e);                                                \
    if (!(c)->lru_tail) (c)->lru_tail = (e);                            \
} while (0)

#define LRU_TOUCH(c, e) do {                                            \
    if ((c)->lru_head != (e)) { LRU_UNLINK(c, e); LRU_PUSH_FRONT(c, e); } \
} while (0)

/* ---- NS cache -------------------------------------------------------------- */

/* NS-cache keys are compared exactly, so fold case first: referral owners
 * come off the wire case-preserved while lookups use lowercased query names. */
static void lc_key(const char* in, char* out, size_t cap)
{
    size_t i = 0;
    for (; in[i] && i + 1 < cap; i++)
        out[i] = (in[i] >= 'A' && in[i] <= 'Z') ? (char)(in[i] + 32) : in[i];
    out[i] = '\0';
}

static void ns_entry_free(NSCacheEntry* e)
{
    free(e->domain);
    for (int i = 0; i < e->nips; i++) free(e->ips[i]);
    free(e);
}

static void ns_bucket_unlink(NSCache* c, NSCacheEntry* target)
{
    NSCacheEntry** pp = &c->buckets[hash_name(target->domain, 0) % c->size];
    while (*pp) {
        if (*pp == target) { *pp = target->next; return; }
        pp = &(*pp)->next;
    }
}

static void ns_cache_evict_lru(NSCache* c)
{
    NSCacheEntry* victim = c->lru_tail;
    if (!victim) return;
    LRU_UNLINK(c, victim);
    ns_bucket_unlink(c, victim);
    ns_entry_free(victim);
    if (c->count > 0) c->count--;
}

NSCache* ns_cache_create(size_t size)
{
    NSCache* cache = calloc(1, sizeof(NSCache));
    if (!cache) return NULL;
    cache->buckets = calloc(size, sizeof(NSCacheEntry*));
    if (!cache->buckets) { free(cache); return NULL; }
    cache->size = size;
    cache->max_entries = NS_CACHE_MAX_ENTRIES;
    pthread_mutex_init(&cache->lock, NULL);
    return cache;
}

void ns_cache_flush(NSCache* cache)
{
    if (!cache) return;
    pthread_mutex_lock(&cache->lock);
    for (size_t i = 0; i < cache->size; i++) {
        NSCacheEntry* e = cache->buckets[i];
        while (e) { NSCacheEntry* n = e->next; ns_entry_free(e); e = n; }
        cache->buckets[i] = NULL;
    }
    cache->count = 0;
    cache->lru_head = cache->lru_tail = NULL;
    pthread_mutex_unlock(&cache->lock);
}

void ns_cache_destroy(NSCache* cache)
{
    if (!cache) return;
    ns_cache_flush(cache);
    free(cache->buckets);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

int ns_cache_put_set(NSCache* cache, const char* zone_in,
                     char* const* ips, int nips, uint32_t ttl)
{
    if (!cache || !zone_in || !ips || nips <= 0) return -1;
    if (nips > NS_SET_MAX) nips = NS_SET_MAX;
    if (ttl < MIN_CACHE_TTL) ttl = MIN_CACHE_TTL;
    if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;

    char zone[DNAME_TEXT_MAX];
    lc_key(zone_in, zone, sizeof(zone));

    /* Build the replacement entry outside the lock. */
    NSCacheEntry* ne = calloc(1, sizeof(NSCacheEntry));
    if (!ne) return -1;
    ne->domain = strdup(zone);
    if (!ne->domain) { free(ne); return -1; }
    for (int i = 0; i < nips; i++) {
        if (!ips[i]) continue;
        bool dup = false;
        for (int j = 0; j < ne->nips && !dup; j++) dup = strcmp(ne->ips[j], ips[i]) == 0;
        if (dup) continue;
        ne->ips[ne->nips] = strdup(ips[i]);
        if (ne->ips[ne->nips]) ne->nips++;
    }
    if (ne->nips == 0) { ns_entry_free(ne); return -1; }
    ne->expiry = cache_now() + ttl;

    size_t idx = hash_name(zone, 0) % cache->size;
    pthread_mutex_lock(&cache->lock);
    for (NSCacheEntry* e = cache->buckets[idx]; e; e = e->next) {
        if (strcmp(e->domain, zone) == 0) {        /* replace in place */
            LRU_UNLINK(cache, e);
            ns_bucket_unlink(cache, e);
            ns_entry_free(e);
            cache->count--;
            break;
        }
    }
    ne->next = cache->buckets[idx];
    cache->buckets[idx] = ne;
    LRU_PUSH_FRONT(cache, ne);
    cache->count++;
    if (cache->max_entries && cache->count > cache->max_entries)
        ns_cache_evict_lru(cache);
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

int ns_cache_get_set(NSCache* cache, const char* zone_in, char* ips_out[NS_SET_MAX])
{
    if (!cache || !zone_in || !ips_out) return 0;
    char zone[DNAME_TEXT_MAX];
    lc_key(zone_in, zone, sizeof(zone));
    size_t idx = hash_name(zone, 0) % cache->size;
    time_t now = cache_now();

    int n = 0;
    pthread_mutex_lock(&cache->lock);
    for (NSCacheEntry* e = cache->buckets[idx]; e; e = e->next) {
        if (strcmp(e->domain, zone) != 0) continue;
        if (e->expiry > now) {
            LRU_TOUCH(cache, e);
            for (int i = 0; i < e->nips; i++)
                if ((ips_out[n] = strdup(e->ips[i])) != NULL) n++;
        }
        break;
    }
    pthread_mutex_unlock(&cache->lock);

    /* Best server first (fast and healthy), outside the lock. */
    int score[NS_SET_MAX];
    for (int i = 0; i < n; i++) score[i] = infra_score(ips_out[i]);
    for (int i = 1; i < n; i++) {
        int s = score[i]; char* ip = ips_out[i]; int j = i - 1;
        while (j >= 0 && score[j] > s) { score[j + 1] = score[j]; ips_out[j + 1] = ips_out[j]; j--; }
        score[j + 1] = s; ips_out[j + 1] = ip;
    }
    return n;
}

void ns_cache_cleanup_expired(NSCache* cache)
{
    if (!cache) return;
    time_t now = cache_now();
    pthread_mutex_lock(&cache->lock);
    for (size_t i = 0; i < cache->size; i++) {
        NSCacheEntry** pp = &cache->buckets[i];
        while (*pp) {
            NSCacheEntry* e = *pp;
            if (e->expiry <= now) {
                *pp = e->next;
                LRU_UNLINK(cache, e);
                if (cache->count > 0) cache->count--;
                ns_entry_free(e);
            } else {
                pp = &e->next;
            }
        }
    }
    pthread_mutex_unlock(&cache->lock);
}

/* ---- Answer cache (sharded) ------------------------------------------------ */

/* Shard from the high hash bits, bucket from the low bits, so the two choices
 * are independent. */
static AnswerShard* shard_for(AnswerCache* c, uint64_t h)
{
    return &c->shards[(h >> 40) % ANSWER_CACHE_SHARDS];
}

static void answer_entry_free(AnswerCacheEntry* e)
{
    free(e->domain);
    free(e->response_data);
    free(e);
}

static void answer_bucket_unlink(AnswerShard* s, AnswerCacheEntry* target)
{
    AnswerCacheEntry** pp = &s->buckets[hash_name(target->domain, target->qtype) % s->size];
    while (*pp) {
        if (*pp == target) { *pp = target->next; return; }
        pp = &(*pp)->next;
    }
}

static void answer_shard_evict_lru(AnswerShard* s)
{
    AnswerCacheEntry* victim = s->lru_tail;
    if (!victim) return;
    LRU_UNLINK(s, victim);
    answer_bucket_unlink(s, victim);
    s->bytes -= (size_t)victim->response_len;
    if (s->count > 0) s->count--;
    answer_entry_free(victim);
}

AnswerCache* answer_cache_create(size_t size)
{
    AnswerCache* cache = calloc(1, sizeof(AnswerCache));
    if (!cache) return NULL;
    size_t per = size / ANSWER_CACHE_SHARDS + 1;
    for (int i = 0; i < ANSWER_CACHE_SHARDS; i++) {
        AnswerShard* s = &cache->shards[i];
        s->buckets = calloc(per, sizeof(AnswerCacheEntry*));
        if (!s->buckets) {
            for (int j = 0; j < i; j++) free(cache->shards[j].buckets);
            free(cache);
            return NULL;
        }
        s->size        = per;
        s->max_entries = ANSWER_CACHE_MAX_ENTRIES / ANSWER_CACHE_SHARDS;
        s->max_bytes   = ANSWER_CACHE_MAX_BYTES / ANSWER_CACHE_SHARDS;
        pthread_mutex_init(&s->lock, NULL);
    }
    return cache;
}

void answer_cache_destroy(AnswerCache* cache)
{
    if (!cache) return;
    for (int i = 0; i < ANSWER_CACHE_SHARDS; i++) {
        AnswerShard* s = &cache->shards[i];
        pthread_mutex_lock(&s->lock);
        for (size_t b = 0; b < s->size; b++) {
            AnswerCacheEntry* e = s->buckets[b];
            while (e) { AnswerCacheEntry* n = e->next; answer_entry_free(e); e = n; }
        }
        free(s->buckets);
        pthread_mutex_unlock(&s->lock);
        pthread_mutex_destroy(&s->lock);
    }
    free(cache);
}

/* NXDOMAIN with an empty answer section: cached name-wide (RFC 8020).  An
 * NXDOMAIN that follows a CNAME chain is not — the alias itself exists. */
static bool is_name_wide_nxdomain(const char* resp, ssize_t len)
{
    if (len < HEADER_LEN) return false;
    const unsigned char* r = (const unsigned char*)resp;
    return (r[3] & 0x0F) == RCODE_NAME_ERROR && r[6] == 0 && r[7] == 0;
}

int answer_cache_put(AnswerCache* cache, const char* domain, uint16_t qtype,
                     const char* response_data, ssize_t response_len, uint32_t ttl)
{
    if (!cache || !domain || !response_data || response_len <= 0) return -1;

    // TTL 0 means "do not cache" (RFC 1035 §3.2.1); honour short TTLs as-is.
    if (ttl == 0) return 0;
    if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;
    if ((size_t)response_len > ANSWER_CACHE_MAX_ENTRY) return 0;   /* too big to keep */
    if (is_name_wide_nxdomain(response_data, response_len))
        qtype = ANSWER_QTYPE_ANY_NXDOMAIN;

    /* Copy outside the lock. */
    char* data = malloc((size_t)response_len);
    if (!data) return -1;
    memcpy(data, response_data, (size_t)response_len);

    uint64_t h = hash_name(domain, qtype);
    AnswerShard* s = shard_for(cache, h);
    size_t idx = h % s->size;
    time_t now = cache_now();

    pthread_mutex_lock(&s->lock);
    AnswerCacheEntry* e = s->buckets[idx];
    for (; e; e = e->next)
        if (e->qtype == qtype && strcasecmp(e->domain, domain) == 0) break;

    if (e) {                                         /* replace in place */
        s->bytes += (size_t)response_len - (size_t)e->response_len;
        free(e->response_data);
        e->response_data = data;
        e->response_len  = response_len;
        e->expiry        = now + ttl;
        LRU_TOUCH(s, e);
    } else {
        e = calloc(1, sizeof(AnswerCacheEntry));
        char* dom = e ? strdup(domain) : NULL;
        if (!e || !dom) {
            pthread_mutex_unlock(&s->lock);
            free(e); free(dom); free(data);
            return -1;
        }
        e->domain        = dom;
        e->qtype         = qtype;
        e->response_data = data;
        e->response_len  = response_len;
        e->expiry        = now + ttl;
        e->next = s->buckets[idx];
        s->buckets[idx] = e;
        LRU_PUSH_FRONT(s, e);
        s->count++;
        s->bytes += (size_t)response_len;
    }

    while (s->lru_tail && s->lru_tail != e &&
           ((s->max_entries && s->count > s->max_entries) ||
            (s->max_bytes && s->bytes > s->max_bytes)))
        answer_shard_evict_lru(s);
    pthread_mutex_unlock(&s->lock);
    return 0;
}

/* Look up exactly (domain, qtype); returns a malloc'd copy + remaining TTL. */
static char* shard_lookup(AnswerCache* cache, const char* domain, uint16_t qtype,
                          ssize_t* out_len, uint32_t* remaining)
{
    uint64_t h = hash_name(domain, qtype);
    AnswerShard* s = shard_for(cache, h);
    time_t now = cache_now();
    char* copy = NULL;

    pthread_mutex_lock(&s->lock);
    for (AnswerCacheEntry* e = s->buckets[h % s->size]; e; e = e->next) {
        if (e->qtype != qtype || strcasecmp(e->domain, domain) != 0) continue;
        if (e->expiry > now && (copy = malloc((size_t)e->response_len)) != NULL) {
            LRU_TOUCH(s, e);
            memcpy(copy, e->response_data, (size_t)e->response_len);
            *out_len   = e->response_len;
            *remaining = (uint32_t)(e->expiry - now);
        }
        break;
    }
    pthread_mutex_unlock(&s->lock);
    return copy;
}

/* Rewrite the QTYPE of the (single) question in place. */
static void set_question_qtype(unsigned char* buf, ssize_t len, uint16_t qtype)
{
    int pos = dns_name_end(buf, (int)len, HEADER_LEN);
    if (pos >= 0 && pos + 2 <= len) wr16(buf + pos, qtype);
}

/* Exact (domain, qtype) hit, else a name-wide NXDOMAIN (RFC 8020) with its
 * question rewritten to the asked type.  TTLs are aged (RFC 1034 §4.1.3). */
char* answer_cache_get_raw(AnswerCache* cache, const char* domain, uint16_t qtype,
                           ssize_t* out_len)
{
    if (out_len) *out_len = 0;
    if (!cache || !domain) return NULL;

    ssize_t len = 0;
    uint32_t remaining = 0;
    char* data = shard_lookup(cache, domain, qtype, &len, &remaining);
    if (!data && qtype != ANSWER_QTYPE_ANY_NXDOMAIN) {
        data = shard_lookup(cache, domain, ANSWER_QTYPE_ANY_NXDOMAIN, &len, &remaining);
        if (data) set_question_qtype((unsigned char*)data, len, qtype);
    }
    if (!data) return NULL;

    patch_response_ttls((unsigned char*)data, (int)len, remaining);
    if (out_len) *out_len = len;
    return data;
}

/* answer_cache_get_raw() parsed into a Packet. */
struct Packet* answer_cache_get(AnswerCache* cache, const char* domain, uint16_t qtype)
{
    ssize_t data_len = 0;
    char* data_copy = answer_cache_get_raw(cache, domain, qtype, &data_len);
    if (!data_copy) return NULL;
    struct Packet* pkt = parse_response(data_copy, data_len);
    free(data_copy);
    return pkt;
}

void answer_cache_cleanup_expired(AnswerCache* cache)
{
    if (!cache) return;
    time_t now = cache_now();
    for (int i = 0; i < ANSWER_CACHE_SHARDS; i++) {
        AnswerShard* s = &cache->shards[i];
        pthread_mutex_lock(&s->lock);
        for (size_t b = 0; b < s->size; b++) {
            AnswerCacheEntry** pp = &s->buckets[b];
            while (*pp) {
                AnswerCacheEntry* e = *pp;
                if (e->expiry <= now) {
                    *pp = e->next;
                    LRU_UNLINK(s, e);
                    if (s->count > 0) s->count--;
                    s->bytes -= (size_t)e->response_len;
                    answer_entry_free(e);
                } else {
                    pp = &e->next;
                }
            }
        }
        pthread_mutex_unlock(&s->lock);
    }
}

/* Any RRSIG present?  Tells "unsigned" (cacheable even without AD) apart
 * from "signed but unvalidated" (must not be cached or served as secure). */
bool wire_is_signed(const unsigned char* buf, int len)
{
    if (!buf || len < HEADER_LEN) return false;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, len); rr_next(&it, &rr); )
        if (rr.type == QTYPE_RRSIG) return true;
    return false;
}

bool response_is_signed(struct Packet* response)
{
    return response && response->request &&
           wire_is_signed((const unsigned char*)response->request, (int)response->recv_len);
}

/* SOA MINIMUM field of an SOA RR, or false if the RDATA is malformed. */
static bool soa_minimum(const uint8_t* m, int len, const DnsRR* rr, uint32_t* out)
{
    int p = dns_name_end(m, len, rr->rdata);            /* MNAME */
    if (p >= 0) p = dns_name_end(m, len, p);            /* RNAME */
    if (p < 0 || p + 20 > rr->rdata + rr->rdlen) return false;
    *out = rd32(m + p + 16);                            /* after serial..expire */
    return true;
}

/*
 * Cache lifetime of a response (0 = don't cache), capped at MAX_CACHE_TTL:
 *   positive answer : smallest answer TTL
 *   NXDOMAIN/NODATA : min(SOA TTL, SOA MINIMUM); no SOA -> 0 (RFC 2308 §5)
 * No floor: TTL 0 means "do not cache" (RFC 1035 §3.2.1).
 */
uint32_t extract_min_ttl_from_response(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) return 0;
    const uint8_t* m = (const uint8_t*)response->request;
    int len = (int)response->recv_len;

    bool found = false;
    uint32_t min_ttl = 0;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, m, len); rr_next(&it, &rr) && rr.section == SEC_ANSWER; ) {
        if (!found || rr.ttl < min_ttl) min_ttl = rr.ttl;
        found = true;
    }
    if (!found) {
        for (rr_iter_init(&it, m, len); rr_next(&it, &rr) && rr.section != SEC_ADDITIONAL; ) {
            uint32_t minimum;
            if (rr.section != SEC_AUTHORITY || rr.type != QTYPE_SOA) continue;
            if (soa_minimum(m, len, &rr, &minimum)) {
                min_ttl = rr.ttl < minimum ? rr.ttl : minimum;
                found = true;
            }
            break;
        }
    }
    if (!found) return 0;
    return min_ttl > MAX_CACHE_TTL ? MAX_CACHE_TTL : min_ttl;
}

/* RFC 2308 §3: a negative answer's SOA TTL is min(SOA TTL, MINIMUM); rewrite
 * it so the first response (not just cache hits) carries the right TTL. */
void clamp_negative_soa_ttl(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) return;
    uint8_t* m = (uint8_t*)response->request;
    int len = (int)response->recv_len;
    if (rd16(m + 6) != 0) return;                       /* has answers */

    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, m, len); rr_next(&it, &rr) && rr.section == SEC_AUTHORITY; ) {
        if (rr.type != QTYPE_SOA) continue;
        uint32_t minimum;
        if (soa_minimum(m, len, &rr, &minimum) && minimum < rr.ttl)
            wr32(m + rr.rdata - 6, minimum);
        return;
    }
}

/* TTL of the referral's first authority NS, clamped; DEFAULT_NS_TTL if none. */
uint32_t extract_referral_ns_ttl(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN)
        return DEFAULT_NS_TTL;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, response->request, (int)response->recv_len); rr_next(&it, &rr); ) {
        if (rr.section != SEC_AUTHORITY || rr.type != QTYPE_NS) continue;
        if (rr.ttl < MIN_CACHE_TTL) return MIN_CACHE_TTL;
        if (rr.ttl > MAX_CACHE_TTL) return MAX_CACHE_TTL;
        return rr.ttl;
    }
    return DEFAULT_NS_TTL;
}

void print_cache_stats(NSCache* ns_cache, AnswerCache* answer_cache)
{
    if (!ns_cache || !answer_cache) return;

    pthread_mutex_lock(&ns_cache->lock);
    size_t ns_count = ns_cache->count;
    pthread_mutex_unlock(&ns_cache->lock);

    size_t answer_count = 0, answer_bytes = 0;
    for (int i = 0; i < ANSWER_CACHE_SHARDS; i++) {
        AnswerShard* s = &answer_cache->shards[i];
        pthread_mutex_lock(&s->lock);
        answer_count += s->count;
        answer_bytes += s->bytes;
        pthread_mutex_unlock(&s->lock);
    }

    printf("Cache statistics:\n");
    printf("  NS cache:     %zu zones\n", ns_count);
    printf("  Answer cache: %zu entries, %zu KB (%d shards)\n",
           answer_count, answer_bytes / 1024, ANSWER_CACHE_SHARDS);
}
