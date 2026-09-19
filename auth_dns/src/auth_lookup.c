#include "auth_lookup.h"
#include "auth_answer.h"   /* find_zsk_for_owner / find_ksk_for_zone decls */
#include "auth.h"          /* auth_domains[], auth_domain_count */
#include "dnssec.h"        /* ZoneKey, g_zone_keys */
#include "dns_name.h"

#include <string.h>
#include <stdio.h>
#include <stdbool.h>

extern ZoneKey *g_zone_keys;   /* defined in auth.c */

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
    const struct AuthDomain *best = NULL;
    size_t best_len = 0;

    for (int i = 0; i < auth_domain_count; i++) {
        if (!auth_domains[i].has_soa) continue;
        const char *zone = auth_domains[i].domain;
        size_t zlen = strlen(zone);
        if (dname_is_subdomain(owner, zone) && zlen > best_len) {
            best = &auth_domains[i];
            best_len = zlen;
        }
    }
    return best;
}

/* True if any record (or wildcard) is owned by exactly `name`. */
static bool name_has_records(const char *name)
{
    for (int i = 0; i < auth_domain_count; i++)
        if (strcmp(auth_domains[i].domain, name) == 0) return true;
    return false;
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
        for (int i = 0; i < auth_domain_count; i++) {
            if (auth_domains[i].is_wildcard &&
                strcmp(auth_domains[i].domain, wc) == 0)
                return &auth_domains[i];
        }
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
    for (int i = 0; i < auth_domain_count; i++) {
        const char *d = auth_domains[i].domain;
        if (strcmp(d, owner) != 0 && dname_is_subdomain(d, owner))
            return true;                       /* strict descendant exists */
    }
    return false;
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
