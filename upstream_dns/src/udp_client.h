#ifndef UDP_CLIENT_H
#define UDP_CLIENT_H

#include "types.h"
#include "shared_types.h"

#include "utils.h"
#include "request.h"

struct Packet* query_server(const char* server_ip, struct Packet* query);

#endif /* UDP_CLIENT_H */