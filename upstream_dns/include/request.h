#ifndef REQUEST_H
#define REQUEST_H

#include "types.h"
#include "dns_packet.h"

/*
 * Parse an untrusted client query.  Returns NULL for garbage or a response
 * (QR=1).  A well-formed query we won't serve comes back with pkt->rcode set
 * (NOTIMP / FORMERR).  Otherwise pkt->request is trimmed to header+question
 * and the client's EDNS fields are filled in.
 */
struct Packet* parse_request_headers(char* buffer, ssize_t recv_len);

#endif /* REQUEST_H */
