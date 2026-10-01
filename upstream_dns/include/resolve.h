#ifndef RESOLVE_H
#define RESOLVE_H

#include "types.h"

#define MAX_ITERATIONS      20   // referral hops per resolution
#define MAX_SERVERS_VISITED 30

struct ns_resolution_context;

// Iteratively resolve `query`.
struct packet* send_resolver(struct packet* query);

// Same, for NS-name lookups nested inside another resolution.
struct packet* send_resolver_with_ns_context(struct packet* query,
											 struct ns_resolution_context* ns_context);

#endif /* RESOLVE_H */
