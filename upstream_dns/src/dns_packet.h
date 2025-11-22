#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include "types.h"
#include "resolve.h"

struct Packet* copy_packet(struct Packet* pkt);
int construct_dns_packet(struct Packet* pkt);
int free_packet(struct Packet* pkt);

struct Packet* format_resolver(struct Packet* pkt);
void set_packet_fields(struct Packet* pkt);

#endif /* DNS_PACKET_H */