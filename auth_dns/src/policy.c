#include "policy.h"
#include "types.h"      /* QTYPE_A / QTYPE_AAAA / RCODE_* */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    /* strcasecmp / strncasecmp */
#include <ctype.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <arpa/inet.h>

/* Hash-table size: the blocklist can hold large public lists (chained). */
#define POLICY_BLOCK_BUCKETS 16384
#define POLICY_SINK_TTL       60   /* seconds for sinkhole answers */
#define MAX_NAME             255

/* ==========================================================================
 * Helpers
 * ========================================================================== */

/* Lowercase-copy a name into out[cap]. */
static void lc_copy(const char* in, char* out, size_t cap)
{
    size_t i = 0;
    for (; in && in[i] && i + 1 < cap; i++)
        out[i] = (char)tolower((unsigned char)in[i]);
    out[i] = '\0';
}

/* FNV-1a over a (already lowercased) name. */
static uint32_t name_hash(const char* s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++) { h ^= (uint8_t)*s; h *= 16777619u; }
    return h;
}

/* ==========================================================================
 * Blocklist: hash set of names, subtree (suffix) match on lookup
 * ========================================================================== */

typedef struct BlockEntry { char* name; struct BlockEntry* next; } BlockEntry;
typedef struct { BlockEntry** buckets; size_t size; size_t count; } BlockSet;

static BlockSet* blockset_create(size_t size)
{
    BlockSet* s = calloc(1, sizeof(BlockSet));
    if (!s) return NULL;
    s->buckets = calloc(size, sizeof(BlockEntry*));
    if (!s->buckets) { free(s); return NULL; }
    s->size = size;
    return s;
}

static void blockset_free(BlockSet* s)
{
    if (!s) return;
    for (size_t i = 0; i < s->size; i++) {
        BlockEntry* e = s->buckets[i];
        while (e) { BlockEntry* n = e->next; free(e->name); free(e); e = n; }
    }
    free(s->buckets);
    free(s);
}

static int blockset_contains(const BlockSet* s, const char* lname)
{
    uint32_t idx = name_hash(lname) % s->size;
    for (BlockEntry* e = s->buckets[idx]; e; e = e->next)
        if (strcmp(e->name, lname) == 0) return 1;
    return 0;
}

static void blockset_add(BlockSet* s, const char* name)
{
    char lname[MAX_NAME + 1];
    lc_copy(name, lname, sizeof(lname));
    if (lname[0] == '\0') return;
    if (blockset_contains(s, lname)) return;   /* dedupe */

    BlockEntry* e = malloc(sizeof(BlockEntry));
    if (!e) return;
    e->name = strdup(lname);
    if (!e->name) { free(e); return; }
    uint32_t idx = name_hash(lname) % s->size;
    e->next = s->buckets[idx];
    s->buckets[idx] = e;
    s->count++;
}

/* True if `lname` (lowercased) or any of its parent suffixes is in the set. */
static int blockset_match_subtree(const BlockSet* s, const char* lname)
{
    const char* p = lname;
    while (p && *p) {
        if (blockset_contains(s, p)) return 1;
        const char* dot = strchr(p, '.');
        p = dot ? dot + 1 : NULL;
    }
    return 0;
}

/* ==========================================================================
 * Active state (rwlock-guarded; swapped on load) + block-mode config
 * ========================================================================== */

static BlockSet*        g_block = NULL;
static pthread_rwlock_t g_lock  = PTHREAD_RWLOCK_INITIALIZER;
static _Atomic uint64_t g_blocked = 0;

/* Block-mode config (read under the same rwlock as the table for simplicity). */
static int     g_block_rcode = RCODE_NAME_ERROR;  /* 3 = NXDOMAIN (default) */
static int     g_sink_v4_ok = 0; static uint8_t g_sink_v4[4];
static int     g_sink_v6_ok = 0; static uint8_t g_sink_v6[16];

void policy_set_block_mode(const char* mode)
{
    pthread_rwlock_wrlock(&g_lock);
    g_sink_v4_ok = g_sink_v6_ok = 0;
    if (!mode || strcasecmp(mode, "nxdomain") == 0) {
        g_block_rcode = RCODE_NAME_ERROR;
    } else if (strcasecmp(mode, "zero") == 0) {
        g_block_rcode = RCODE_NO_ERROR;
        memset(g_sink_v4, 0, 4); g_sink_v4_ok = 1;
        memset(g_sink_v6, 0, 16); g_sink_v6_ok = 1;
    } else if (inet_pton(AF_INET, mode, g_sink_v4) == 1) {
        g_block_rcode = RCODE_NO_ERROR; g_sink_v4_ok = 1;
    } else if (inet_pton(AF_INET6, mode, g_sink_v6) == 1) {
        g_block_rcode = RCODE_NO_ERROR; g_sink_v6_ok = 1;
    } else {
        fprintf(stderr, "policy: invalid -S block mode '%s'; using NXDOMAIN\n", mode);
        g_block_rcode = RCODE_NAME_ERROR;
    }
    pthread_rwlock_unlock(&g_lock);
}

int policy_block_mode_rcode(void)
{
    pthread_rwlock_rdlock(&g_lock);
    int r = g_block_rcode;
    pthread_rwlock_unlock(&g_lock);
    return r;
}

uint64_t policy_blocked_count(void) { return atomic_load(&g_blocked); }

/* ==========================================================================
 * File parsing — only the "[blocklist]" section of the shared config file
 * ========================================================================== */

static int looks_like_ip(const char* tok)
{
    unsigned char tmp[16];
    return inet_pton(AF_INET, tok, tmp) == 1 || inet_pton(AF_INET6, tok, tmp) == 1;
}

/* Strip a '#' comment in place. */
static void strip_comment(char* line)
{
    char* h = strchr(line, '#');
    if (h) *h = '\0';
}

static void parse_block_line(BlockSet* s, char* line)
{
    strip_comment(line);
    char* save = NULL;
    char* tok = strtok_r(line, " \t\r\n", &save);
    if (!tok) return;
    if (looks_like_ip(tok))                       /* hosts-format: skip the IP */
        tok = strtok_r(NULL, " \t\r\n", &save);
    for (; tok; tok = strtok_r(NULL, " \t\r\n", &save))
        blockset_add(s, tok);
}

/* ==========================================================================
 * Public load + lookup
 * ========================================================================== */

int policy_load(const char* config_path)
{
    BlockSet* nb = blockset_create(POLICY_BLOCK_BUCKETS);
    if (!nb) return -1;

    if (config_path) {
        FILE* f = fopen(config_path, "r");
        if (!f) {
            fprintf(stderr, "policy: cannot open '%s'\n", config_path);
        } else {
            char line[2048];
            int in_block = 0;   /* are we inside the [blocklist] section? */
            while (fgets(line, sizeof(line), f)) {
                const char* p = line;
                while (*p == ' ' || *p == '\t') p++;
                if (*p == '[') {                /* a section header */
                    in_block = (strncasecmp(p, "[blocklist]", 11) == 0);
                    continue;
                }
                if (in_block) parse_block_line(nb, line);
            }
            fclose(f);
        }
    }

    pthread_rwlock_wrlock(&g_lock);
    BlockSet* ob = g_block;
    g_block = nb;
    pthread_rwlock_unlock(&g_lock);

    blockset_free(ob);
    return (int)nb->count;
}

PolicyAction policy_lookup(const char* qname, uint16_t qtype, SynthAnswer* out)
{
    SynthAnswer tmp;
    if (!out) out = &tmp;
    memset(out, 0, sizeof(*out));
    if (!qname || !*qname) return POLICY_PASS;

    char lname[MAX_NAME + 1];
    lc_copy(qname, lname, sizeof(lname));

    pthread_rwlock_rdlock(&g_lock);

    if (g_block && blockset_match_subtree(g_block, lname)) {
        if (g_block_rcode == RCODE_NO_ERROR) {        /* sinkhole mode */
            if (qtype == QTYPE_A && g_sink_v4_ok) {
                out->qtype = QTYPE_A; out->addrlen = 4;
                memcpy(out->addr, g_sink_v4, 4); out->ttl = POLICY_SINK_TTL;
            } else if (qtype == QTYPE_AAAA && g_sink_v6_ok) {
                out->qtype = QTYPE_AAAA; out->addrlen = 16;
                memcpy(out->addr, g_sink_v6, 16); out->ttl = POLICY_SINK_TTL;
            }
            /* other qtypes (or missing sink family) -> NODATA: out left zeroed */
        }
        pthread_rwlock_unlock(&g_lock);
        atomic_fetch_add(&g_blocked, 1);
        return POLICY_BLOCK;
    }

    pthread_rwlock_unlock(&g_lock);
    return POLICY_PASS;
}
