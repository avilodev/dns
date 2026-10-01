#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include "types.h"

// Send `query` to a nameserver and return the matching reply
struct packet* query_server(const char* server_ip, struct packet* query);
struct packet* query_server_tcp(const char* server_ip, struct packet* query);

// Per-resolution time budget.
void resolver_deadline_begin(int budget_sec);
void resolver_deadline_end(void);
bool resolver_deadline_exceeded(void);

#endif /* UDP_CLIENT_H */
