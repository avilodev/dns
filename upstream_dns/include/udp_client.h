#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include "types.h"

/* Send `query` to a nameserver and return the matching reply (QR=1, same ID
 * and question), or NULL on timeout/error.  Each hop is bounded by the
 * active resolution budget; outcomes feed infra.c's server scores. */
struct Packet* query_server(const char* server_ip, struct Packet* query);
struct Packet* query_server_tcp(const char* server_ip, struct Packet* query);

/*
 * Per-resolution time budget (thread-local: one worker owns a query from
 * start to finish).  Ref-counted, so nested CNAME / NS-name resolutions share
 * the outermost deadline.
 */
void resolver_deadline_begin(int budget_sec);
void resolver_deadline_end(void);
bool resolver_deadline_exceeded(void);

#endif /* UDP_CLIENT_H */
