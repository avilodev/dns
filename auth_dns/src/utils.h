#ifndef UTILS_H
#define UTILS_H

#include "types.h"

int load_config(int argc, char** argv);

char* extract_ip_from_response(struct Packet* response);

void print_packet_info(const char* label, struct Packet* pkt);
void print_hex_dump(const char* data, ssize_t len); 

int free_packet(struct Packet* pkt);

#endif /* UTILS_H */