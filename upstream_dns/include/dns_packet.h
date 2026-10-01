#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include "types.h"

// Fill pkt's header fields (id, flags, counts) from a wire header.
void packet_read_header(struct packet* pkt, const uint8_t* msg);

// Copy a received message into a new Packet (header + question parsed).
struct packet* parse_response(const char* buffer, ssize_t recv_len);

// New outgoing iterative query: random ID, RD=0, OPT with DO=1.
struct packet* build_query(const char* name, uint16_t qtype, uint16_t qclass);

void free_packet(struct packet* pkt);

#endif /* DNS_PACKET_H */
