#include "cache.h"
#include "request.h"
#include "dns_wire.h"
#include <string.h>
#include <stdlib.h>

/*
 * Walk all RRs in a wire-format DNS response and clamp every TTL to max_ttl.
 * OPT records (type 41) carry extended-RCODE/EDNS flags in their TTL field —
 * skip them so EDNS negotiation is not corrupted.
 */
static void patch_response_ttls(unsigned char* buf, int len, uint32_t max_ttl)
{
    if (!buf || len < HEADER_LEN || max_ttl == 0) return;

    uint16_t qdcount = rd16(buf + 4);
    uint16_t ancount = rd16(buf + 6);
    uint16_t nscount = rd16(buf + 8);
    uint16_t arcount = rd16(buf + 10);
    int pos = HEADER_LEN;

    /* Skip question section */
    for (int i = 0; i < qdcount && pos < len; i++) {
        skip_dns_name(buf, len, &pos);
        pos += 4; /* QTYPE + QCLASS */
    }

    int total_rrs = (int)ancount + nscount + arcount;
    for (int i = 0; i < total_rrs && pos < len; i++) {
        skip_dns_name(buf, len, &pos);
        if (pos + 10 > len) break;

        uint16_t rr_type = rd16(buf + pos);
        if (rr_type != 41) { /* skip OPT pseudo-RR */
            uint32_t rr_ttl = rd32(buf + pos + 4);
            if (rr_ttl > max_ttl) {
                uint32_t clamped = htonl(max_ttl);
                memcpy(buf + pos + 4, &clamped, 4);
            }
        }

        uint16_t rdlen = rd16(buf + pos + 8);
        pos += 10 + rdlen;
    }
}

// Simple hash function
static unsigned long hash_string(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static unsigned long hash_domain_type(const char* domain, uint16_t qtype) {
    unsigned long hash = 5381;
    int c;
    while ((c = *domain++))
        hash = ((hash << 5) + hash) + c;
    hash = ((hash << 5) + hash) + qtype;
    return hash;
}

/* =========================================================================
 * Intrusive LRU helpers (most-recently-used at head).  All callers MUST hold
 * the owning cache's lock.  These keep the answer/NS caches bounded so a flood
 * of unique names cannot grow memory without limit (eviction past max_entries).
 * ========================================================================= */

static void ns_lru_unlink(NSCache* c, NSCacheEntry* e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             c->lru_head           = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             c->lru_tail           = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void ns_lru_push_front(NSCache* c, NSCacheEntry* e) {
    e->lru_prev = NULL;
    e->lru_next = c->lru_head;
    if (c->lru_head) c->lru_head->lru_prev = e;
    c->lru_head = e;
    if (!c->lru_tail) c->lru_tail = e;
}

static void ns_lru_touch(NSCache* c, NSCacheEntry* e) {
    if (c->lru_head == e) return;
    ns_lru_unlink(c, e);
    ns_lru_push_front(c, e);
}

/* Remove an entry from its hash-collision chain (by identity). */
static void ns_bucket_unlink(NSCache* c, NSCacheEntry* target) {
    size_t idx = hash_string(target->domain) % c->size;
    NSCacheEntry** pp = &c->buckets[idx];
    while (*pp) {
        if (*pp == target) { *pp = target->next; return; }
        pp = &(*pp)->next;
    }
}

/* Evict the least-recently-used NS entry.  Caller holds the lock. */
static void ns_cache_evict_lru(NSCache* c) {
    NSCacheEntry* victim = c->lru_tail;
    if (!victim) return;
    ns_lru_unlink(c, victim);
    ns_bucket_unlink(c, victim);
    free(victim->domain);
    free(victim->ns_ip);
    free(victim);
    if (c->count > 0) c->count--;
}

static void answer_lru_unlink(AnswerCache* c, AnswerCacheEntry* e) {
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             c->lru_head           = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             c->lru_tail           = e->lru_prev;
    e->lru_prev = e->lru_next = NULL;
}

static void answer_lru_push_front(AnswerCache* c, AnswerCacheEntry* e) {
    e->lru_prev = NULL;
    e->lru_next = c->lru_head;
    if (c->lru_head) c->lru_head->lru_prev = e;
    c->lru_head = e;
    if (!c->lru_tail) c->lru_tail = e;
}

static void answer_lru_touch(AnswerCache* c, AnswerCacheEntry* e) {
    if (c->lru_head == e) return;
    answer_lru_unlink(c, e);
    answer_lru_push_front(c, e);
}

static void answer_bucket_unlink(AnswerCache* c, AnswerCacheEntry* target) {
    size_t idx = hash_domain_type(target->domain, target->qtype) % c->size;
    AnswerCacheEntry** pp = &c->buckets[idx];
    while (*pp) {
        if (*pp == target) { *pp = target->next; return; }
        pp = &(*pp)->next;
    }
}

/* Evict the least-recently-used answer entry.  Caller holds the lock. */
static void answer_cache_evict_lru(AnswerCache* c) {
    AnswerCacheEntry* victim = c->lru_tail;
    if (!victim) return;
    answer_lru_unlink(c, victim);
    answer_bucket_unlink(c, victim);
    free(victim->domain);
    free(victim->response_data);
    free(victim);
    if (c->count > 0) c->count--;
}

NSCache* ns_cache_create(size_t size) {
    NSCache* cache = malloc(sizeof(NSCache));
    if (!cache) return NULL;
    
    cache->buckets = calloc(size, sizeof(NSCacheEntry*));
    if (!cache->buckets) {
        free(cache);
        return NULL;
    }
     
    cache->size = size;
    cache->count = 0;
    cache->max_entries = NS_CACHE_MAX_ENTRIES;
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    pthread_mutex_init(&cache->lock, NULL);
    return cache;
}

void ns_cache_destroy(NSCache* cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        NSCacheEntry* entry = cache->buckets[i];
        while (entry) {
            NSCacheEntry* next = entry->next;
            free(entry->domain);
            free(entry->ns_ip);
            free(entry);
            entry = next;
        }
    }
    
    free(cache->buckets);
    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

int ns_cache_put(NSCache* cache, const char* domain, const char* ns_ip, uint32_t ttl) {
    if (!cache || !domain || !ns_ip) return -1;
    
    // TTL limits
    if (ttl < MIN_CACHE_TTL) ttl = MIN_CACHE_TTL;
    if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;
    
    unsigned long hash = hash_string(domain);
    size_t index = hash % cache->size;
    
    pthread_mutex_lock(&cache->lock);
    
    // Check if entry already exists and updates it
    NSCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0) {
            char* new_ip = strdup(ns_ip);
            if (!new_ip) {
                pthread_mutex_unlock(&cache->lock);
                return -1;
            }
            free(entry->ns_ip);
            entry->ns_ip = new_ip;
            entry->expiry = time(NULL) + ttl;
            ns_lru_touch(cache, entry);
            pthread_mutex_unlock(&cache->lock);
            return 0;
        }
        entry = entry->next;
    }

    // Create new entry
    NSCacheEntry* new_entry = malloc(sizeof(NSCacheEntry));
    if (!new_entry) {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    new_entry->domain = strdup(domain);
    new_entry->ns_ip  = strdup(ns_ip);
    if (!new_entry->domain || !new_entry->ns_ip) {
        free(new_entry->domain);
        free(new_entry->ns_ip);
        free(new_entry);
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }
    new_entry->expiry = time(NULL) + ttl;
    new_entry->next = cache->buckets[index];
    cache->buckets[index] = new_entry;
    ns_lru_push_front(cache, new_entry);
    cache->count++;
    if (cache->max_entries && cache->count > cache->max_entries)
        ns_cache_evict_lru(cache);

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

char* ns_cache_get(NSCache* cache, const char* domain) {
    if (!cache || !domain) return NULL;
    
    unsigned long hash = hash_string(domain);
    size_t index = hash % cache->size;
    time_t now = time(NULL);
    
    pthread_mutex_lock(&cache->lock);
    
    NSCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0) {
            if (entry->expiry > now) {
                ns_lru_touch(cache, entry);
                char* result = strdup(entry->ns_ip);
                pthread_mutex_unlock(&cache->lock);
                return result;
            } else {
                pthread_mutex_unlock(&cache->lock);
                return NULL;
            }
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&cache->lock);
    return NULL;
}

void ns_cache_cleanup_expired(NSCache* cache) {
    if (!cache) return;
    
    time_t now = time(NULL);
    int removed = 0;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        NSCacheEntry** entry_ptr = &cache->buckets[i];
        while (*entry_ptr) {
            NSCacheEntry* entry = *entry_ptr;
            if (entry->expiry <= now) {
                *entry_ptr = entry->next;
                ns_lru_unlink(cache, entry);
                if (cache->count > 0) cache->count--;
                free(entry->domain);
                free(entry->ns_ip);
                free(entry);
                removed++;
            } else {
                entry_ptr = &entry->next;
            }
        }
    }
    
    pthread_mutex_unlock(&cache->lock);
}

AnswerCache* answer_cache_create(size_t size) {
    AnswerCache* cache = malloc(sizeof(AnswerCache));
    if (!cache) return NULL;
    
    cache->buckets = calloc(size, sizeof(AnswerCacheEntry*));
    if (!cache->buckets) {
        free(cache);
        return NULL;
    }
    
    cache->size = size;
    cache->count = 0;
    cache->max_entries = ANSWER_CACHE_MAX_ENTRIES;
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    pthread_mutex_init(&cache->lock, NULL);
    return cache;
}

void answer_cache_destroy(AnswerCache* cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        AnswerCacheEntry* entry = cache->buckets[i];
        while (entry) {
            AnswerCacheEntry* next = entry->next;
            free(entry->domain);
            free(entry->response_data);
            free(entry);
            entry = next;
        }
    }
    
    free(cache->buckets);
    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

int answer_cache_put(AnswerCache* cache, const char* domain, uint16_t qtype,
                     const char* response_data, ssize_t response_len, uint32_t ttl) {
    if (!cache || !domain || !response_data || response_len <= 0) return -1;
    
    // TTL 0 means "do not cache" (RFC 1035 §3.2.1); honour short TTLs as-is.
    if (ttl == 0) return 0;
    if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;
    
    unsigned long hash = hash_domain_type(domain, qtype);
    size_t index = hash % cache->size;
    
    pthread_mutex_lock(&cache->lock);
    
    // Check if entry exists and updates it
    AnswerCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0 && entry->qtype == qtype) {
            char* new_data = malloc(response_len);
            if (!new_data) {
                pthread_mutex_unlock(&cache->lock);
                return -1;
            }
            free(entry->response_data);
            entry->response_data = new_data;
            memcpy(entry->response_data, response_data, response_len);
            entry->response_len = response_len;
            entry->stored_at = time(NULL);
            entry->expiry = entry->stored_at + ttl;
            answer_lru_touch(cache, entry);
            pthread_mutex_unlock(&cache->lock);
            return 0;
        }
        entry = entry->next;
    }

    // Create new entry
    AnswerCacheEntry* new_entry = malloc(sizeof(AnswerCacheEntry));
    if (!new_entry) {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }
    
    new_entry->domain = strdup(domain);
    new_entry->qtype = qtype;
    new_entry->response_data = malloc(response_len);
    if (!new_entry->response_data) {
        free(new_entry->domain);
        free(new_entry);
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }
    
    memcpy(new_entry->response_data, response_data, response_len);
    new_entry->response_len = response_len;
    new_entry->stored_at = time(NULL);
    new_entry->expiry = new_entry->stored_at + ttl;
    new_entry->next = cache->buckets[index];
    cache->buckets[index] = new_entry;
    answer_lru_push_front(cache, new_entry);
    cache->count++;
    if (cache->max_entries && cache->count > cache->max_entries)
        answer_cache_evict_lru(cache);

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

/*
 * Core cache lookup.  Returns a freshly malloc'd copy of the raw, TTL-patched
 * response bytes for (domain, qtype), or NULL on miss/expiry/OOM.  On success
 * *out_len is set to the byte length and the caller owns the buffer (free it).
 *
 * The hot path (cache hits served straight from the poll loop) calls this
 * directly: it copies the bytes once, patches TTLs, and sends them.  This
 * avoids building and immediately freeing a full struct Packet — a second
 * buffer copy plus full_domain/component strdup()s — on every cache hit.
 */
char* answer_cache_get_raw(AnswerCache* cache, const char* domain, uint16_t qtype,
                           ssize_t* out_len) {
    if (out_len) *out_len = 0;
    if (!cache || !domain) return NULL;

    unsigned long hash = hash_domain_type(domain, qtype);
    size_t index = hash % cache->size;
    time_t now = time(NULL);

    pthread_mutex_lock(&cache->lock);

    AnswerCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0 && entry->qtype == qtype) {
            if (entry->expiry > now) {
                answer_lru_touch(cache, entry);
                // Copy raw response data under the lock, then patch outside
                // the critical section to avoid holding mutex during allocation.
                ssize_t data_len = entry->response_len;
                char* data_copy = malloc(data_len);
                if (!data_copy) {
                    pthread_mutex_unlock(&cache->lock);
                    return NULL;
                }
                memcpy(data_copy, entry->response_data, data_len);
                /* Compute remaining TTL: how many seconds until expiry. */
                uint32_t remaining = (uint32_t)(entry->expiry - now);
                pthread_mutex_unlock(&cache->lock);

                /* RFC 1034 §4.1.3: decrement all RR TTLs by elapsed time
                 * before returning the cached response to the client. */
                patch_response_ttls((unsigned char*)data_copy, (int)data_len,
                                    remaining);

                if (out_len) *out_len = data_len;
                return data_copy;
            } else {
                pthread_mutex_unlock(&cache->lock);
                return NULL;
            }
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&cache->lock);
    return NULL;
}

/*
 * Convenience wrapper: look up a cached answer and parse it into a struct
 * Packet.  Used by the resolver worker path, which needs the parsed fields.
 */
struct Packet* answer_cache_get(AnswerCache* cache, const char* domain, uint16_t qtype) {
    ssize_t data_len = 0;
    char* data_copy = answer_cache_get_raw(cache, domain, qtype, &data_len);
    if (!data_copy) return NULL;

    struct Packet* pkt = parse_response(data_copy, data_len);
    free(data_copy);
    return pkt;
}

void answer_cache_cleanup_expired(AnswerCache* cache) {
    if (!cache) return;
    
    time_t now = time(NULL);
    int removed = 0;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        AnswerCacheEntry** entry_ptr = &cache->buckets[i];
        while (*entry_ptr) {
            AnswerCacheEntry* entry = *entry_ptr;
            if (entry->expiry <= now) {
                *entry_ptr = entry->next;
                answer_lru_unlink(cache, entry);
                if (cache->count > 0) cache->count--;
                free(entry->domain);
                free(entry->response_data);
                free(entry);
                removed++;
            } else {
                entry_ptr = &entry->next;
            }
        }
    }
    
    pthread_mutex_unlock(&cache->lock);
}

/*
 * Return true if the response carries at least one RRSIG — i.e. the answer is
 * DNSSEC-signed.  Used to tell "genuinely unsigned" (safe to cache even when a
 * validating query couldn't set AD) apart from "signed but unvalidated" (an
 * incomplete/transient validation that must NOT be cached, or it would serve a
 * stale non-AD answer until the TTL expires).
 */
bool wire_is_signed(const unsigned char* buf, int len) {
    if (!buf || len < HEADER_LEN) return false;

    uint16_t qdcount = rd16(buf + 4);
    uint16_t ancount = rd16(buf + 6);
    uint16_t nscount = rd16(buf + 8);
    uint16_t arcount = rd16(buf + 10);
    int pos = HEADER_LEN;

    for (int i = 0; i < qdcount && pos < len; i++) {
        skip_dns_name(buf, len, &pos);
        pos += 4; /* QTYPE + QCLASS */
    }

    int total_rrs = (int)ancount + nscount + arcount;
    for (int i = 0; i < total_rrs && pos < len; i++) {
        skip_dns_name(buf, len, &pos);
        if (pos + 10 > len) break;
        uint16_t type  = rd16(buf + pos);
        uint16_t rdlen = rd16(buf + pos + 8);
        if (type == QTYPE_RRSIG) return true;
        pos += 10 + rdlen;
    }
    return false;
}

bool response_is_signed(struct Packet* response) {
    if (!response || !response->request) return false;
    return wire_is_signed((const unsigned char*)response->request,
                          (int)response->recv_len);
}

/*
 * How long a response may be cached, in seconds (0 = do not cache).
 *
 *   positive answer : the smallest TTL in the answer section
 *   NXDOMAIN/NODATA : min(SOA TTL, SOA MINIMUM) from the authority section
 *                     (RFC 2308 §5); a negative answer without an SOA is not
 *                     cached at all (RFC 2308 §5, "SHOULD NOT be cached")
 *
 * The result is capped at MAX_CACHE_TTL.  There is deliberately no floor: a
 * record's owner chose its TTL, and TTL 0 means "do not cache" (RFC 1035 §3.2.1).
 */
uint32_t extract_min_ttl_from_response(struct Packet* response) {
    if (!response || !response->request || response->recv_len < HEADER_LEN)
        return 0;

    unsigned char* buffer = (unsigned char*)response->request;
    int buffer_len = (int)response->recv_len;
    int pos = HEADER_LEN;
    uint16_t qd = rd16(buffer + 4);
    uint16_t an = rd16(buffer + 6);
    uint16_t ns = rd16(buffer + 8);

    for (int i = 0; i < qd && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;  // QTYPE + QCLASS
    }

    bool found = false;
    uint32_t min_ttl = 0;
    for (int i = 0; i < an && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint32_t ttl = rd32(buffer + pos + 4);
        uint16_t rdlength = rd16(buffer + pos + 8);
        if (!found || ttl < min_ttl) { min_ttl = ttl; found = true; }
        pos += 10 + rdlength;
    }

    if (!found) {
        /* Negative answer: the SOA in the authority section sets the TTL. */
        for (int i = 0; i < ns && pos < buffer_len; i++) {
            skip_dns_name(buffer, buffer_len, &pos);
            if (pos + 10 > buffer_len) break;
            uint16_t type     = rd16(buffer + pos);
            uint32_t ttl      = rd32(buffer + pos + 4);
            uint16_t rdlength = rd16(buffer + pos + 8);
            if (type == QTYPE_SOA && pos + 10 + rdlength <= buffer_len) {
                int rdata_pos = pos + 10;
                skip_dns_name(buffer, buffer_len, &rdata_pos);   /* MNAME */
                skip_dns_name(buffer, buffer_len, &rdata_pos);   /* RNAME */
                rdata_pos += 16;                         /* serial..expire */
                if (rdata_pos + 4 <= pos + 10 + rdlength) {
                    uint32_t soa_minimum = rd32(buffer + rdata_pos);
                    min_ttl = (ttl < soa_minimum) ? ttl : soa_minimum;
                    found = true;
                }
                break;
            }
            pos += 10 + rdlength;
        }
    }

    if (!found) return 0;
    return (min_ttl > MAX_CACHE_TTL) ? MAX_CACHE_TTL : min_ttl;
}

/*
 * Return the TTL of the first NS record in the authority section of a referral
 * response (rcode=NOERROR, ancount=0, nscount>0), clamped to [MIN_CACHE_TTL,
 * MAX_CACHE_TTL].  Falls back to DEFAULT_NS_TTL if no NS record is found.
 */
uint32_t extract_referral_ns_ttl(struct Packet* response) {
    if (!response || !response->request || response->recv_len < HEADER_LEN)
        return DEFAULT_NS_TTL;

    unsigned char* buf = (unsigned char*)response->request;
    int blen = (int)response->recv_len;
    int pos = HEADER_LEN;

    /* Skip question section */
    for (int i = 0; i < (int)response->qdcount && pos < blen; i++) {
        skip_dns_name(buf, blen, &pos);
        pos += 4; /* QTYPE + QCLASS */
    }

    /* Skip answer section (should be empty for a referral) */
    for (int i = 0; i < (int)response->ancount && pos < blen; i++) {
        skip_dns_name(buf, blen, &pos);
        if (pos + 10 > blen) break;
        uint16_t rdlen = rd16(buf + pos + 8);
        pos += 10 + rdlen;
    }

    /* Read TTL of the first NS record in the authority section */
    for (int i = 0; i < (int)response->nscount && pos < blen; i++) {
        skip_dns_name(buf, blen, &pos);
        if (pos + 10 > blen) break;
        uint16_t type  = rd16(buf + pos);
        uint32_t ttl   = rd32(buf + pos + 4);
        uint16_t rdlen = rd16(buf + pos + 8);
        if (type == QTYPE_NS) {
            if (ttl < MIN_CACHE_TTL) ttl = MIN_CACHE_TTL;
            if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;
            return ttl;
        }
        pos += 10 + rdlen;
    }

    return DEFAULT_NS_TTL;
}

void print_cache_stats(NSCache* ns_cache, AnswerCache* answer_cache) {
    if (!ns_cache || !answer_cache) return;
    
    int ns_count = 0, answer_count = 0;
    time_t now = time(NULL);
    
    // Count NS cache entries
    pthread_mutex_lock(&ns_cache->lock);
    for (size_t i = 0; i < ns_cache->size; i++) {
        NSCacheEntry* entry = ns_cache->buckets[i];
        while (entry) {
            if (entry->expiry > now) ns_count++;
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&ns_cache->lock);
    
    // Count Answer cache entries
    pthread_mutex_lock(&answer_cache->lock);
    for (size_t i = 0; i < answer_cache->size; i++) {
        AnswerCacheEntry* entry = answer_cache->buckets[i];
        while (entry) {
            if (entry->expiry > now) answer_count++;
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&answer_cache->lock);
    
    printf("Cache statistics:\n");
    printf("  NS cache:     %d entries\n", ns_count);
    printf("  Answer cache: %d entries\n", answer_count);
}