#include "auth_lookup.h"
#include "auth_answer.h"   /* find_zsk_for_owner / find_ksk_for_zone decls */
#include "auth.h"          /* auth_domains[], auth_domain_count */
#include "dnssec.h"        /* ZoneKey, g_zone_keys */
#include "dns_name.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

extern ZoneKey *g_zone_keys;   /* defined in auth.c */

/* =========================================================================
 * Name index
 * ========================================================================= */

typedef struct {
    const char *name;      /* points into the table (owner or its suffix) */
    uint64_t    hash;
    int         start;     /* first record owned by name                  */
    int         count;     /* records owned by name (0 = ancestor only)   */
    bool        has_desc;  /* some strict descendant owns records         */
} NameSlot;

struct AuthIndex {
    NameSlot *slots;
    size_t    cap;         /* power of two, <= 50% load */
};

AuthIndex *g_auth_index = NULL;

static uint64_t name_hash(const char *s)
{
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) { h ^= (uint8_t)*s; h *= 1099511628211ull; }
    return h;
}

/* Find (or, with create, claim) the slot for name. */
static NameSlot *index_slot(AuthIndex *idx, const char *name, bool create)
{
    uint64_t h = name_hash(name);
    for (size_t i = h & (idx->cap - 1); ; i = (i + 1) & (idx->cap - 1)) {
        NameSlot *s = &idx->slots[i];
        if (!s->name) {
            if (!create) return NULL;
            s->name = name; s->hash = h; s->start = 0; s->count = 0; s->has_desc = false;
            return s;
        }
        if (s->hash == h && strcmp(s->name, name) == 0) return s;
    }
}

static const struct AuthDomain *g_sort_table;
static int by_owner_then_position(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    int c = strcmp(g_sort_table[x].domain, g_sort_table[y].domain);
    return c ? c : (x > y) - (x < y);
}

AuthIndex *auth_index_build(struct AuthDomain *table, int n)
{
    /* 1. Sort by owner, keeping file order within an owner (RRset order). */
    if (n > 1) {
        int *order = malloc((size_t)n * sizeof(int));
        struct AuthDomain *sorted = malloc((size_t)n * sizeof(*sorted));
        if (!order || !sorted) { free(order); free(sorted); return NULL; }
        for (int i = 0; i < n; i++) order[i] = i;
        g_sort_table = table;           /* single-threaded: called on load */
        qsort(order, (size_t)n, sizeof(int), by_owner_then_position);
        for (int i = 0; i < n; i++) sorted[i] = table[order[i]];
        memcpy(table, sorted, (size_t)n * sizeof(*sorted));
        free(sorted);
        free(order);
    }

    /* 2. Hash every owner and every ancestor of an owner.  Each owner adds at
     * most one slot per label, so 256 * n bounds the slot count; size for
     * <= 50% load. */
    AuthIndex *idx = calloc(1, sizeof(AuthIndex));
    if (!idx) return NULL;
    size_t want = 16;
    for (int i = 0; i < n; i++) want += (size_t)dname_label_count(table[i].domain) + 1;
    idx->cap = 64;
    while (idx->cap < want * 2) idx->cap <<= 1;
    idx->slots = calloc(idx->cap, sizeof(NameSlot));
    if (!idx->slots) { free(idx); return NULL; }

    for (int i = 0; i < n; ) {
        const char *name = table[i].domain;
        int j = i;
        while (j < n && strcmp(table[j].domain, name) == 0) j++;
        NameSlot *s = index_slot(idx, name, true);
        s->start = i;
        s->count = j - i;
        for (const char *p = dname_parent(name); p; p = dname_parent(p)) {
            NameSlot *a = index_slot(idx, p, true);
            if (a->has_desc) break;     /* this ancestor chain is already marked */
            a->has_desc = true;
        }
        i = j;
    }
    return idx;
}

void auth_index_free(AuthIndex *idx)
{
    if (!idx) return;
    free(idx->slots);
    free(idx);
}

int auth_records_for(const char *name, int *start)
{
    /* Always define *start: callers loop `for (i = *start; i < *start + cnt;)`,
     * which reads it even when cnt is 0. */
    if (start) *start = 0;
    if (!name || !g_auth_index) return 0;
    NameSlot *s = index_slot(g_auth_index, name, false);
    if (!s || s->count == 0) return 0;
    *start = s->start;
    return s->count;
}

bool rec_has_type(const struct AuthDomain *d, uint16_t type)
{
    switch (type) {
    case QTYPE_A:     return d->has_a;
    case QTYPE_AAAA:  return d->has_ipv6;
    case QTYPE_MX:    return d->has_mx;
    case QTYPE_NS:    return d->has_ns;
    case QTYPE_TXT:   return d->has_txt;
    case QTYPE_SRV:   return d->has_srv;
    case QTYPE_HTTPS: return d->has_https;
    case QTYPE_CNAME: return d->has_cname;
    case QTYPE_SOA:   return d->has_soa;
    default:          return false;
    }
}

/* True if `name` has a strict descendant that owns records. */
static bool has_descendant(const char *name)
{
    if (!name || !g_auth_index) return false;
    NameSlot *s = index_slot(g_auth_index, name, false);
    return s && s->has_desc;
}

/* =========================================================================
 * Utility helpers (all called while rdlock held)
 * ========================================================================= */

/* Count dot-separated labels: "a.b.c" → 3, "example.com" → 2 */
int count_labels(const char *name)
{
    return dname_label_count(name);   /* escape-aware */
}

/*
 * find_zone_soa — longest-suffix SOA match.
 * "www.avilo.com" → finds SOA entry for "avilo.com".
 * Returns pointer into auth_domains[], or NULL.
 */
const struct AuthDomain *find_zone_soa(const char *owner)
{
    if (!owner) return NULL;
    /* Deepest first: owner, then each ancestor — O(labels), not O(records). */
    for (const char *n = owner; n && *n; n = dname_parent(n)) {
        int st, cnt = auth_records_for(n, &st);
        for (int i = st; i < st + cnt; i++)
            if (auth_domains[i].has_soa) return &auth_domains[i];
    }
    return NULL;
}

/* True if any record (or wildcard) is owned by exactly `name`. */
static bool name_has_records(const char *name)
{
    int st;
    return auth_records_for(name, &st) > 0;
}

/*
 * find_wildcard — RFC 4592 wildcard lookup for a name with no records.
 *
 * Walk up from the parent of `owner` to find the closest encloser (the
 * nearest ancestor that exists — owns records or is an empty non-terminal).
 * Only "*.<closest encloser>" may synthesize an answer, so a wildcard covers
 * names any number of labels below it ("a.b.avilo.com" matches
 * "*.avilo.com"), but never across an existing node in between.
 */
const struct AuthDomain *find_wildcard(const char *owner)
{
    if (!owner) return NULL;
    for (const char *parent = dname_parent(owner); parent; parent = dname_parent(parent)) {
        char wc[DNAME_TEXT_MAX + 2];
        snprintf(wc, sizeof(wc), "*.%s", parent);
        int st;
        if (auth_records_for(wc, &st) > 0 && auth_domains[st].is_wildcard)
            return &auth_domains[st];
        /* `parent` exists: it is the closest encloser, and it has no wildcard. */
        if (name_has_records(parent) || is_empty_non_terminal(parent))
            return NULL;
    }
    return NULL;
}

/*
 * is_empty_non_terminal — true if `owner` is a strict ancestor of some loaded
 * record (e.g. "_tcp.avilo.com" when "_imaps._tcp.avilo.com" exists).  Such a
 * name owns no records itself but DOES exist in the tree, so a query for it is
 * NODATA (NOERROR), not NXDOMAIN (RFC 1034 §4.3.2, empty non-terminal).
 */
bool is_empty_non_terminal(const char *owner)
{
    if (!owner || !*owner) return false;
    return has_descendant(owner);              /* strict descendant exists */
}

/* True if `name` owns NS records and is not itself a zone apex (SOA). */
static bool is_delegation(const char *name)
{
    bool ns = false;
    int st, cnt = auth_records_for(name, &st);
    for (int i = st; i < st + cnt; i++) {
        if (auth_domains[i].has_soa) return false;
        if (auth_domains[i].has_ns)  ns = true;
    }
    return ns;
}

const char *find_zone_cut(const char *owner, const char *apex)
{
    if (!owner || !apex) return NULL;
    const char *cut = NULL;
    /* Walk owner -> apex; the last (highest) cut seen wins, since everything
     * below the first cut from the apex belongs to the child zone. */
    for (const char *n = owner; n && strcmp(n, apex) != 0; n = dname_parent(n)) {
        if (!dname_is_subdomain(n, apex)) return NULL;
        if (is_delegation(n)) cut = n;
    }
    return cut;
}

/* Find the ZSK whose zone is a suffix of owner. */
const ZoneKey *find_zsk_for_owner(const char *owner)
{
    if (!owner || !g_zone_keys) return NULL;
    const ZoneKey *best = NULL;
    size_t best_len = 0;
    for (const ZoneKey *k = g_zone_keys; k; k = k->next) {
        if (k->flags != 256) continue;   /* ZSK flag = 256 */
        size_t zlen = strlen(k->zone);
        if (dname_is_subdomain(owner, k->zone) && zlen > best_len) {
            best = k;
            best_len = zlen;
        }
    }
    return best;
}

/* Find the KSK for an exact zone apex. */
const ZoneKey *find_ksk_for_zone(const char *zone)
{
    if (!zone || !g_zone_keys) return NULL;
    for (const ZoneKey *k = g_zone_keys; k; k = k->next) {
        if (k->flags == 257 && strcmp(k->zone, zone) == 0)
            return k;
    }
    return NULL;
}
