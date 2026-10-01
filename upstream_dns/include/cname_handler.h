#ifndef CNAME_HANDLER_H
#define CNAME_HANDLER_H

#include "types.h"

#define MAX_CNAME_DEPTH 10

// CNAME targets seen during one resolution (loop detection).
typedef struct {
	char* domains[MAX_CNAME_DEPTH];
	int count;
} cname_chain;

bool check_cname_loop(const cname_chain* chain, const char* domain);
void cname_chain_add(cname_chain* chain, const char* domain);
void free_cname_chain(cname_chain* chain);

// Answer for `query` as "qname CNAME target"
struct packet* reconstruct_cname_response(const struct packet* query,
										  const char* target, uint32_t ttl,
										  struct packet* final_answer);

#endif /* CNAME_HANDLER_H */
