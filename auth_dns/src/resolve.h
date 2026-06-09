#ifndef RESOLVE_H
#define RESOLVE_H

#include "types.h"

#include "utils.h"

/* Forward pkt to the upstream resolver.  client_tcp != 0 means the client
 * reached us over TCP, so we query upstream over TCP too (returns the full,
 * untruncated answer). */
struct Packet* resolve_recursive(struct Packet* pkt, int client_tcp);

#endif /* RESOLVE_H */