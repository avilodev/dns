#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include "types.h"

#define MAX_NAME_JUMPS 10

void skip_dns_name(unsigned char* buffer, int buffer_len, int* pos);
char* parse_dns_name_from_wire(unsigned char* buffer, int buffer_len, int pos);
int write_dns_name(const char* name, unsigned char* buffer, size_t buffer_size, size_t pos);
int encode_dns_name(const char* domain, unsigned char* buffer, size_t buf_size);

#endif /* DNS_WIRE_H */