#ifndef CNAME_HANDLER_H
#define CNAME_HANDLER_H

#include "types.h"
#include "shared_types.h"
#include "resolve.h"
#include "dns_wire.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

bool check_cname_loop(CnameChain* chain, const char* domain);
struct Packet* reconstruct_cname_response(
    struct Packet* original_query,
    CnameChainData* chain_data,
    struct Packet* final_answer);

void free_cname_chain(CnameChain* chain);
void free_cname_chain_data(CnameChainData* chain_data);

#endif /* CNAME_HANDLER_H */