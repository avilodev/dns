#include "auth_lookup.h"
#include "auth_answer.h"   /* find_zsk_for_owner / find_ksk_for_zone decls */
#include "auth.h"          /* auth_domains[], auth_domain_count */
#include "dnssec.h"        /* ZoneKey, g_zone_keys */

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
    if (!name || *name == '\0') return 0;
    int n = 1;
    for (const char *p = name; *p; p++)
        if (*p == '.') n++;
    return n;
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
        size_t olen = strlen(owner);
        bool match = (strcmp(owner, zone) == 0) ||
                     (olen > zlen &&
                      owner[olen - zlen - 1] == '.' &&
                      strcmp(owner + olen - zlen, zone) == 0);
        if (match && zlen > best_len) {
            best = &auth_domains[i];
            best_len = zlen;
        }
    }
    return best;
}

/*
 * find_wildcard — check if a wildcard record covers owner.
 * "www.avilo.com" → looks for "*.avilo.com" entry.
 */
const struct AuthDomain *find_wildcard(const char *owner)
{
    if (!owner) return NULL;
    const char *dot = strchr(owner, '.');
    if (!dot) return NULL;
    char wc[264];
    snprintf(wc, sizeof(wc), "*%s", dot);   /* "*.parent.zone" */
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].is_wildcard &&
            strcmp(auth_domains[i].domain, wc) == 0)
            return &auth_domains[i];
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
    size_t olen = strlen(owner);
    for (int i = 0; i < auth_domain_count; i++) {
        const char *d = auth_domains[i].domain;
        size_t dlen = strlen(d);
        if (dlen > olen + 1 &&
            d[dlen - olen - 1] == '.' &&
            strcmp(d + dlen - olen, owner) == 0)
            return true;
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
        size_t olen = strlen(owner);
        bool match = (strcmp(owner, k->zone) == 0) ||
                     (olen > zlen &&
                      owner[olen - zlen - 1] == '.' &&
                      strcmp(owner + olen - zlen, k->zone) == 0);
        if (match && zlen > best_len) {
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
