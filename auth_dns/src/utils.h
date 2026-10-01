#ifndef UTILS_H
#define UTILS_H

#include "types.h"

int load_config(int argc, char** argv);

// Write a domain name in DNS wire-format label encoding
void write_dns_labels(const char* name, char* buf, int* pos, int buf_size);

char* extract_ip_from_response(const struct packet* response);

int free_packet(struct packet* pkt);

// Privilege-drop-safe file access via a pinned parent directory fd
void  path_pin(const char* path);
int   path_open(const char* path, int flags, int mode);
FILE* path_fopen(const char* path);   // read-only

// Rename between two pinned names in the SAME pinned directory
int   path_rename(const char* from, const char* to);

#endif /* UTILS_H */