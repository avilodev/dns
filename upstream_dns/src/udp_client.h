#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include "types.h"
#include "shared_types.h"

#include "utils.h"
#include "request.h"

struct Packet* query_server(const char* server_ip, struct Packet* query);
struct Packet* query_server_with_timeout(const char* server_ip, struct Packet* query, int timeout_sec);
struct Packet* query_server_tcp(const char* server_ip, struct Packet* query);

/*
 * Per-resolution time budget (thread-local; one worker thread owns a query for
 * its whole lifetime).  Begin/end are ref-counted so nested sub-resolutions
 * (CNAME follow, NS-name resolution) share the outermost budget instead of each
 * starting a fresh one.  query_server / query_server_tcp consult the remaining
 * budget to bound each hop; resolver_deadline_exceeded() lets the recursion
 * loop bail cleanly with SERVFAIL.
 */
void resolver_deadline_begin(int budget_sec);
void resolver_deadline_end(void);
bool resolver_deadline_exceeded(void);


#endif /* UDP_CLIENT_H */