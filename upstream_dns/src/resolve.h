#ifndef RESOLVE_H
#define RESOLVE_H

#include "types.h"
#include "shared_types.h"

#include "utils.h"
#include "request.h"
#include "cache.h"

#include "dns_wire.h"
#include "dns_packet.h"
#include "response_handler.h"
#include "cname_handler.h"
#include "ns_resolver.h"
#include "cname_handler.h"
#include "udp_client.h"

#include <stdlib.h>
#include <time.h>

#define MAX_ITERATIONS 16

typedef struct {
    char* servers[MAX_ITERATIONS];
    int count;
} ServerHistory;

struct Packet* send_resolver(struct Packet* query);
struct Packet* send_resolver_internal(struct Packet* query, int cname_depth,
                                             CnameChain* chain);

bool already_queried(ServerHistory* history, const char* server);
void free_server_history(ServerHistory* history);
 
#endif /* RESOLVE_H */ 