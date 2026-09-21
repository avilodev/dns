#include "access_control.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

/* ---- CIDR allow-list ------------------------------------------------------- */

#define ACL_MAX 64

typedef struct {
    int     family;     /* AF_INET or AF_INET6 */
    uint8_t addr[16];   /* network address, big-endian; 4 bytes used for IPv4 */
    int     prefix;     /* prefix length in bits */
} Cidr;

static Cidr acl_list[ACL_MAX];
static int  acl_count = 0;   /* 0 = allow all (no list configured) */

/* Compare the first `bits` bits of two byte arrays. */
static bool prefix_match(const uint8_t *a, const uint8_t *b, int bits)
{
    int full = bits / 8;
    int rem  = bits % 8;
    if (full && memcmp(a, b, (size_t)full) != 0)
        return false;
    if (rem) {
        uint8_t mask = (uint8_t)(0xFF << (8 - rem));
        if ((a[full] & mask) != (b[full] & mask))
            return false;
    }
    return true;
}

/* Parse "addr" or "addr/prefix" into *out.  Returns 0 on success, -1 on error. */
static int parse_cidr(const char *tok, Cidr *out)
{
    char buf[128];
    while (*tok == ' ' || *tok == '\t') tok++;
    size_t n = strlen(tok);
    while (n > 0 && (tok[n - 1] == ' ' || tok[n - 1] == '\t')) n--;
    if (n == 0 || n >= sizeof(buf)) return -1;
    memcpy(buf, tok, n);
    buf[n] = '\0';

    int   prefix = -1;
    char *slash  = strchr(buf, '/');
    if (slash) {
        /* The prefix must be a non-empty run of digits: strtol() reads "" as 0
         * and accepts a leading sign, so "10.0.0.0/" would otherwise parse as
         * /0 and silently match every address. */
        const char *digits = slash + 1;
        if (*digits < '0' || *digits > '9') return -1;
        char *end;
        long  v = strtol(digits, &end, 10);
        if (*end != '\0' || v < 0) return -1;
        prefix = (int)v;
        *slash = '\0';
    }

    uint8_t a4[4], a6[16];
    if (inet_pton(AF_INET, buf, a4) == 1) {
        if (prefix < 0) prefix = 32;
        if (prefix > 32) return -1;
        out->family = AF_INET;
        memset(out->addr, 0, sizeof(out->addr));
        memcpy(out->addr, a4, 4);
        out->prefix = prefix;
        return 0;
    }
    if (inet_pton(AF_INET6, buf, a6) == 1) {
        if (prefix < 0) prefix = 128;
        if (prefix > 128) return -1;
        out->family = AF_INET6;
        memcpy(out->addr, a6, 16);
        out->prefix = prefix;
        return 0;
    }
    return -1;
}

void acl_init_defaults(void)
{
    static const char *defs[] = {
        "127.0.0.0/8",      /* IPv4 loopback        */
        "10.0.0.0/8",       /* RFC1918              */
        "172.16.0.0/12",    /* RFC1918              */
        "192.168.0.0/16",   /* RFC1918              */
        "169.254.0.0/16",   /* IPv4 link-local      */
        "::1/128",          /* IPv6 loopback        */
        "fc00::/7",         /* IPv6 unique-local    */
        "fe80::/10",        /* IPv6 link-local      */
    };
    acl_count = 0;
    for (size_t i = 0; i < sizeof(defs) / sizeof(defs[0]); i++) {
        if (acl_count >= ACL_MAX) break;
        if (parse_cidr(defs[i], &acl_list[acl_count]) == 0)
            acl_count++;
    }
}

int acl_set_list(const char *cidr_csv)
{
    if (!cidr_csv) return -1;
    char *dup = strdup(cidr_csv);
    if (!dup) return -1;

    Cidr tmp[ACL_MAX];
    int  n  = 0;
    int  rc = 0;
    for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
        if (n >= ACL_MAX) { rc = -1; break; }
        if (parse_cidr(tok, &tmp[n]) != 0) { rc = -1; break; }
        n++;
    }
    free(dup);
    if (rc != 0 || n == 0) return -1;

    memcpy(acl_list, tmp, sizeof(Cidr) * (size_t)n);
    acl_count = n;
    return 0;
}

/* Match a 4- or 16-byte client address (of family `fam`) against the list. */
static bool acl_match_family(int fam, const uint8_t *addr)
{
    for (int i = 0; i < acl_count; i++) {
        if (acl_list[i].family != fam) continue;
        if (prefix_match(addr, acl_list[i].addr, acl_list[i].prefix))
            return true;
    }
    return false;
}

bool acl_allows(const struct sockaddr_storage *src)
{
    if (acl_count == 0) return true;   /* no list = allow all */
    if (!src) return false;

    if (src->ss_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)src;
        return acl_match_family(AF_INET, (const uint8_t *)&s->sin_addr);
    }
    if (src->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)src;
        const uint8_t *a = (const uint8_t *)&s->sin6_addr;
        /* IPv4-mapped IPv6 (::ffff:a.b.c.d): evaluate against IPv4 rules too. */
        if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr) &&
            acl_match_family(AF_INET, a + 12))
            return true;
        return acl_match_family(AF_INET6, a);
    }
    return false;
}

/* ---- Per-source token-bucket rate limiter ---------------------------------- */

#define RL_SLOTS 4096
#define RL_WAYS  4                  /* set-associative: RL_SLOTS / RL_WAYS sets */

typedef struct {
    uint8_t         key[16];
    int             keylen;   /* 0 = empty slot, else 4 or 16 */
    double          tokens;
    struct timespec last;
    int             tcp_conns;   /* open TCP connections from this source */
} RlSlot;

static RlSlot          rl_table[RL_SLOTS];
static pthread_mutex_t rl_lock = PTHREAD_MUTEX_INITIALIZER;
static int             rl_qps   = 0;   /* 0 = disabled */
static int             rl_burst = 0;

void rl_configure(int qps, int burst)
{
    rl_qps = (qps > 0) ? qps : 0;
    if (burst <= 0)
        burst = (rl_qps > 0) ? rl_qps * 2 : 0;
    rl_burst = burst;
    pthread_mutex_lock(&rl_lock);
    memset(rl_table, 0, sizeof(rl_table));
    pthread_mutex_unlock(&rl_lock);
}

/* Per-source key: the IPv4 address, or the IPv6 /64 (one end site usually
 * owns a whole /64, so keying on the /128 is trivially evaded by rotating
 * addresses).  IPv4-mapped IPv6 keys as the IPv4 address.  Returns the key
 * length (4/16) or 0. */
static int rl_key(const struct sockaddr_storage *src, uint8_t key[16])
{
    memset(key, 0, 16);
    if (src->ss_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)src;
        memcpy(key, &s->sin_addr, 4);
        return 4;
    }
    if (src->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)src;
        if (IN6_IS_ADDR_V4MAPPED(&s->sin6_addr)) {
            memcpy(key, (const uint8_t *)&s->sin6_addr + 12, 4);
            return 4;
        }
        memcpy(key, &s->sin6_addr, 8);          /* /64 prefix */
        return 16;
    }
    return 0;
}

/* FNV-1a hash over the key bytes. */
static uint32_t rl_hash(const uint8_t *key, int len)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < len; i++) {
        h ^= key[i];
        h *= 16777619u;
    }
    return h;
}

static double ts_diff(const struct timespec *a, const struct timespec *b)
{
    return (double)(a->tv_sec - b->tv_sec) + (double)(a->tv_nsec - b->tv_nsec) / 1e9;
}

/* Find src's slot, or claim one in its set (an empty way, else the way idle
 * longest).  Two colliding sources therefore keep separate buckets instead of
 * resetting each other to a full burst.
 *
 * A way whose source still has TCP connections open is NEVER reclaimed: its
 * tcp_conns is the only record of those connections, and zeroing it both lost
 * the per-source cap for the evicted source (its release() then matched no
 * slot and decremented nothing) and handed the claiming source a fresh full
 * token bucket.  When every way is busy this returns NULL and the caller
 * decides; see rl_allow() and tcp_conn_acquire().
 *
 * Caller holds rl_lock. */
static RlSlot *rl_slot(const uint8_t key[16], int klen, const struct timespec *now,
                       bool *fresh)
{
    uint32_t set = (rl_hash(key, klen) % (RL_SLOTS / RL_WAYS)) * RL_WAYS;
    RlSlot *empty = NULL, *idle = NULL;
    for (int w = 0; w < RL_WAYS; w++) {
        RlSlot *s = &rl_table[set + w];
        if (s->keylen == klen && memcmp(s->key, key, 16) == 0) {
            *fresh = false;
            return s;
        }
        if (s->keylen == 0) { if (!empty) empty = s; continue; }
        if (s->tcp_conns == 0 && (!idle || ts_diff(&idle->last, &s->last) > 0))
            idle = s;                      /* oldest way with no open TCP */
    }
    RlSlot *victim = empty ? empty : idle;
    if (!victim) return NULL;              /* every way holds live connections */
    memset(victim, 0, sizeof(*victim));
    memcpy(victim->key, key, 16);
    victim->keylen = klen;
    victim->tokens = rl_burst;
    victim->last   = *now;
    *fresh = true;
    return victim;
}

bool rl_allow(const struct sockaddr_storage *src)
{
    if (rl_qps <= 0) return true;
    if (!src) return true;

    uint8_t key[16];
    int klen = rl_key(src, key);
    if (klen == 0) return true;   /* unknown family — do not block */

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    bool allowed, fresh;
    pthread_mutex_lock(&rl_lock);
    RlSlot *s = rl_slot(key, klen, &now, &fresh);
    if (!s) {
        /* No way in this set can be reclaimed without discarding another
         * source's open TCP connections.  Allow: reaching this needs RL_WAYS
         * distinct sources holding TCP connections that hash to one set, and
         * dropping an innocent new client's query is the worse failure. */
        pthread_mutex_unlock(&rl_lock);
        return true;
    }
    if (!fresh) {
        double elapsed = ts_diff(&now, &s->last);
        if (elapsed < 0) elapsed = 0;
        s->tokens += elapsed * rl_qps;
        if (s->tokens > rl_burst) s->tokens = rl_burst;
        s->last = now;
    }
    if (s->tokens >= 1.0) {
        s->tokens -= 1.0;
        allowed = true;
    } else {
        allowed = false;
    }
    pthread_mutex_unlock(&rl_lock);
    return allowed;
}

bool tcp_conn_acquire(const struct sockaddr_storage *src)
{
    if (!src) return true;
    uint8_t key[16];
    int klen = rl_key(src, key);
    if (klen == 0) return true;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    bool ok, fresh;   /* fresh unused: a new slot starts at 0 conns */
    pthread_mutex_lock(&rl_lock);
    RlSlot *s = rl_slot(key, klen, &now, &fresh);
    /* No slot means every way in this set is already at its connection cap:
     * refuse rather than accept a connection we cannot account for. */
    ok = s && s->tcp_conns < TCP_MAX_CONNS_PER_SOURCE;
    if (ok) s->tcp_conns++;
    pthread_mutex_unlock(&rl_lock);
    return ok;
}

void tcp_conn_release(const struct sockaddr_storage *src)
{
    if (!src) return;
    uint8_t key[16];
    int klen = rl_key(src, key);
    if (klen == 0) return;
    uint32_t set = (rl_hash(key, klen) % (RL_SLOTS / RL_WAYS)) * RL_WAYS;
    pthread_mutex_lock(&rl_lock);
    for (int w = 0; w < RL_WAYS; w++) {
        RlSlot *s = &rl_table[set + w];
        if (s->keylen == klen && memcmp(s->key, key, 16) == 0) {
            if (s->tcp_conns > 0) s->tcp_conns--;
            break;
        }
    }
    pthread_mutex_unlock(&rl_lock);
}
