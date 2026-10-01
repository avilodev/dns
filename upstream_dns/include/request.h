#ifndef REQUEST_H
#define REQUEST_H

#include "types.h"
#include "dns_packet.h"

// Parse an untrusted client query.
struct packet* parse_request_headers(char* buffer, ssize_t recv_len);

#endif /* REQUEST_H */
