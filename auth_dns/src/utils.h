#ifndef UTILS_H
#define UTILS_H

#include "types.h"

int load_config(int argc, char** argv);

/*
 * Write a domain name in DNS wire-format label encoding.
 * e.g. "mail.example.com" -> \x04mail\x07example\x03com\x00
 * Appends a null-terminator label at the end.
 * buf_size bounds the destination buffer; writing stops before overflow.
 */
void write_dns_labels(const char* name, char* buf, int* pos, int buf_size);

char* extract_ip_from_response(struct Packet* response);

int free_packet(struct Packet* pkt);

#endif /* UTILS_H */