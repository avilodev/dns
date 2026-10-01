#ifndef RESOLVE_H
#define RESOLVE_H

#include "types.h"

#include "utils.h"

// Forward pkt to the upstream resolver, over TCP if the client used TCP
struct packet* resolve_recursive(struct packet* pkt, int client_tcp);

#endif /* RESOLVE_H */