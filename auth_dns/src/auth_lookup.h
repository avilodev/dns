#ifndef AUTH_LOOKUP_H
#define AUTH_LOOKUP_H

#include <stdbool.h>
#include "auth.h"   /* struct AuthDomain */

/* Read-side lookups over the record store (callers hold g_auth_domains_lock). */

int count_labels(const char *name);

/* Longest-suffix SOA match; NULL if none. */
const struct AuthDomain *find_zone_soa(const char *owner);

/* Wildcard (*.parent) record covering owner; NULL if none. */
const struct AuthDomain *find_wildcard(const char *owner);

/* True if owner is a strict ancestor of a loaded name (empty non-terminal). */
bool is_empty_non_terminal(const char *owner);

#endif /* AUTH_LOOKUP_H */
