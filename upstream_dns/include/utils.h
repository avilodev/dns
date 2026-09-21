#ifndef UTILS_H
#define UTILS_H

#include "types.h"

int get_random_id(void);

/* Uniform random integer in [0, n), n <= 256. */
int random_index(int n);

/* Mnemonic for a QTYPE, or NULL if unknown (callers print "TYPE%u"). */
const char* qtype_to_string(uint16_t qtype);

/*
 * Privilege-drop-safe file access: path_pin() opens the file's parent dir
 * while still root; path_open() later reaches the file via openat(), so it
 * only needs permission on that dir (not on a 0700 ancestor).  Unpinned
 * paths fall back to open().
 */
void path_pin(const char* path);
int  path_open(const char* path, int flags, int mode);

/* ---- Sockets --------------------------------------------------------- */

/* Send one DNS-over-TCP message (2-byte length prefix + body). */
bool tcp_send_msg(int fd, const void* msg, size_t len);

/* "a.b.c.d" / IPv6 text -> sockaddr.  Returns its length, or 0 if invalid. */
socklen_t sockaddr_from_ip(const char* ip, uint16_t port, struct sockaddr_storage* out);

/* sockaddr -> IP text (INET6_ADDRSTRLEN) and host-order port. */
void sockaddr_to_ip(const struct sockaddr_storage* ss, char* ip, uint16_t* port);

#endif /* UTILS_H */
