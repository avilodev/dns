#include "access_control.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

/* ==========================================================================
 * CIDR allow-list
 * ========================================================================== */

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
        char *end;
        long  v = strtol(slash + 1, &end, 10);
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

/* ==========================================================================
 * Per-source token-bucket rate limiter
 * ========================================================================== */

#define RL_SLOTS 4096

typedef struct {
    uint8_t         key[16];
    int             keylen;   /* 0 = empty slot, else 4 or 16 */
    double          tokens;
    struct timespec last;
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

/* Copy the source address bytes into key[]; returns key length (4/16) or 0. */
static int rl_key(const struct sockaddr_storage *src, uint8_t key[16])
{
    if (src->ss_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)src;
        memset(key, 0, 16);
        memcpy(key, &s->sin_addr, 4);
        return 4;
    }
    if (src->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)src;
        memcpy(key, &s->sin6_addr, 16);
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

bool rl_allow(const struct sockaddr_storage *src)
{
    if (rl_qps <= 0) return true;
    if (!src) return true;

    uint8_t key[16];
    int klen = rl_key(src, key);
    if (klen == 0) return true;   /* unknown family — do not block */

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint32_t idx = rl_hash(key, klen) % RL_SLOTS;

    bool allowed;
    pthread_mutex_lock(&rl_lock);
    RlSlot *s = &rl_table[idx];
    if (s->keylen != klen || memcmp(s->key, key, (size_t)klen) != 0) {
        /* Fresh source, or a hash collision evicting a previous one. */
        memcpy(s->key, key, (size_t)klen);
        s->keylen = klen;
        s->tokens = rl_burst;
        s->last   = now;
    } else {
        double elapsed = (double)(now.tv_sec - s->last.tv_sec) +
                         (double)(now.tv_nsec - s->last.tv_nsec) / 1e9;
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
