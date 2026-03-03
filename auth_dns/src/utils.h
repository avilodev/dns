#ifndef UTILS_H
#define UTILS_H

#include "types.h"

int load_config(int argc, char** argv);

/**
 * Write a domain name in DNS wire-format label encoding.
 * e.g. "mail.example.com" -> \x04mail\x07example\x03com\x00
 * Appends a null-terminator label at the end.
 */
void write_dns_labels(const char* name, char* buf, int* pos);

char* extract_ip_from_response(struct Packet* response);

void print_packet_info(const char* label, struct Packet* pkt);
void print_hex_dump(const char* data, ssize_t len); 

int free_packet(struct Packet* pkt);

#endif /* UTILS_H */