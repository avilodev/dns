#ifndef RESOLVE_H
#define RESOLVE_H

#include "types.h"
#include "cname_handler.h"
#include "cache.h"
#include "udp_client.h"
#include "response_handler.h"
#include "dns_packet.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ITERATIONS 20
#define MAX_SERVERS_VISITED 30

// Forward declaration only
struct NSResolutionContext;

/**
 * Server history for loop detection
 */
typedef struct {
    char* servers[MAX_SERVERS_VISITED];
    int count;
} ServerHistory;

struct Packet* send_resolver(struct Packet* query);
struct Packet* send_resolver_with_ns_context(struct Packet* query, 
                                             struct NSResolutionContext* ns_context);
struct Packet* send_resolver_internal(struct Packet* query, int cname_depth,
                                     CnameChain* chain,
                                     struct NSResolutionContext* ns_context);
bool already_queried(ServerHistory* history, const char* server);
void free_server_history(ServerHistory* history);

#endif // RESOLVE_H