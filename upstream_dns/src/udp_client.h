#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include "types.h"
#include "shared_types.h"

#include "utils.h"
#include "request.h"

struct Packet* query_server(const char* server_ip, struct Packet* query);
struct Packet* query_server_with_timeout(const char* server_ip, struct Packet* query, int timeout_sec);
struct Packet* query_server_tcp(const char* server_ip, struct Packet* query);


#endif /* UDP_CLIENT_H */