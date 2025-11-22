#ifndef REQUEST_H
#define REQUEST_H

#include "types.h"

#include "utils.h"
#include "dns_packet.h"
#include "dns_wire.h"
#include "cname_handler.h"

struct Packet* parse_request_headers(char* buffer, ssize_t recv_len);
void parse_domain_components(struct Packet* pkt, const char* domain);

#endif /* REQUEST_H */ 