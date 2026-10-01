#ifndef AUTH_LOOKUP_H
#define AUTH_LOOKUP_H

#include <stdbool.h>
#include "auth.h"   // struct AuthDomain

// Read-side lookups over the record store (callers hold g_auth_domains_lock).

// Name index over a sorted record table: owner name -> record range
typedef struct auth_index auth_index;

// Sort `table` by owner name and build its index.
auth_index *auth_index_build(struct auth_domain *table, int n);
void       auth_index_free(auth_index *idx);

// The index matching auth_domains[]; swapped with it under the wrlock.
extern auth_index *g_auth_index;

// Records owned by exactly `name`: sets *start, returns the count (0 = none).
int auth_records_for(const char *name, int *start);

// Does record `d` carry an RR of `type`?
bool rec_has_type(const struct auth_domain *d, uint16_t type);

int count_labels(const char *name);

// Longest-suffix SOA match; NULL if none.
const struct auth_domain *find_zone_soa(const char *owner);

// Wildcard (*.parent) record covering owner; NULL if none.
const struct auth_domain *find_wildcard(const char *owner);

// True if owner is a strict ancestor of a loaded name (empty non-terminal).
bool is_empty_non_terminal(const char *owner);

// Delegation point for owner inside the zone at `apex`
const char *find_zone_cut(const char *owner, const char *apex);

#endif /* AUTH_LOOKUP_H */
