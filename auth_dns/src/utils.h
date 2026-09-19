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

char* extract_ip_from_response(const struct Packet* response);

int free_packet(struct Packet* pkt);

/*
 * Privilege-drop-safe file access.  path_pin() opens the file's parent
 * directory while still root and keeps the fd; path_open()/path_fopen() then
 * reach the file with openat() relative to it, so a SIGHUP reload after the
 * drop needs permission only on that directory and the file — not on every
 * ancestor (e.g. a 0700 /home/<user> the drop user cannot traverse).
 * Unpinned paths fall back to plain open().
 */
void  path_pin(const char* path);
int   path_open(const char* path, int flags, int mode);
FILE* path_fopen(const char* path);   /* read-only */

#endif /* UTILS_H */