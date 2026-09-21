#ifndef AUTH_LOOKUP_H
#define AUTH_LOOKUP_H

#include <stdbool.h>
#include "auth.h"   /* struct AuthDomain */

/* Read-side lookups over the record store (callers hold g_auth_domains_lock). */

/* Name index over a sorted record table: owner name -> [start, start+count)
 * plus whether any strict descendant exists.  Built once per load and swapped
 * together with the table, so every lookup is O(1) regardless of zone size. */
typedef struct AuthIndex AuthIndex;

/* Sort `table` by owner name (records of one owner stay in file order) and
 * build its index.  NULL on allocation failure. */
AuthIndex *auth_index_build(struct AuthDomain *table, int n);
void       auth_index_free(AuthIndex *idx);

/* The index matching auth_domains[]; swapped with it under the wrlock. */
extern AuthIndex *g_auth_index;

/* Records owned by exactly `name`: sets *start, returns the count (0 = none). */
int auth_records_for(const char *name, int *start);

/* Does record `d` carry an RR of `type`?  The single definition of what each
 * has_* flag means — notably that a plain A record is the one with NO type
 * flag set and a real address in ip[].  Response building and the NSEC type
 * bitmap must agree on this, or the bitmap claims types the zone won't serve. */
bool rec_has_type(const struct AuthDomain *d, uint16_t type);

int count_labels(const char *name);

/* Longest-suffix SOA match; NULL if none. */
const struct AuthDomain *find_zone_soa(const char *owner);

/* Wildcard (*.parent) record covering owner; NULL if none. */
const struct AuthDomain *find_wildcard(const char *owner);

/* True if owner is a strict ancestor of a loaded name (empty non-terminal). */
bool is_empty_non_terminal(const char *owner);

/* Delegation point for owner inside the zone at `apex`: the highest name
 * strictly below the apex, at or above owner, that owns NS records (a zone
 * cut, RFC 1034 §4.2.1).  Returns a pointer into `owner`, or NULL. */
const char *find_zone_cut(const char *owner, const char *apex);

#endif /* AUTH_LOOKUP_H */
