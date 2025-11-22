#ifndef RESPONSE_H
#define RESPONSE_H

#include "types.h"
#include <arpa/inet.h>
#include <stdbool.h>

int send_response(int sock, struct Packet* response, struct sockaddr_in* client_addr);
struct Packet* build_nxdomain_response(struct Packet* request);
char* extract_ip_from_response(struct Packet* response);

#endif // RESPONSE_H