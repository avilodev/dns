#ifndef RESOLVE_H
#define RESOLVE_H

#include "types.h"

#define MAX_ITERATIONS      20   /* referral hops per resolution */
#define MAX_SERVERS_VISITED 30

struct NSResolutionContext;

/*
 * Iteratively resolve `query` (a build_query() packet whose do_bit/cd carry
 * the client's DNSSEC intent).  Returns the answer — AD set only when we
 * validated it — or NULL for SERVFAIL.
 */
struct Packet* send_resolver(struct Packet* query);

/* Same, for NS-name lookups nested inside another resolution. */
struct Packet* send_resolver_with_ns_context(struct Packet* query,
                                             struct NSResolutionContext* ns_context);

#endif /* RESOLVE_H */
