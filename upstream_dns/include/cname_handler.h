#ifndef CNAME_HANDLER_H
#define CNAME_HANDLER_H

#include "types.h"

#define MAX_CNAME_DEPTH 10

/* CNAME targets seen during one resolution (loop detection). */
typedef struct {
    char* domains[MAX_CNAME_DEPTH];
    int count;
} CnameChain;

bool check_cname_loop(const CnameChain* chain, const char* domain);
void cname_chain_add(CnameChain* chain, const char* domain);
void free_cname_chain(CnameChain* chain);

/*
 * Answer for `query` as "qname CNAME target" (TTL `ttl`) followed by the
 * answer RRs of final_answer — or its authority section when it has no
 * answers (NODATA/NXDOMAIN).  Consumes final_answer.  Returns NULL on error.
 */
struct Packet* reconstruct_cname_response(const struct Packet* query,
                                          const char* target, uint32_t ttl,
                                          struct Packet* final_answer);

#endif /* CNAME_HANDLER_H */
