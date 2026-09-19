#ifndef UDP_HELPERS_H
#define UDP_HELPERS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>   /* ssize_t */

/* Stateless wire-format helpers shared by the UDP worker path (process_query)
 * and the zero-alloc cache fast path: minimal error replies, a lightweight
 * no-alloc query parser, EDNS-aware truncation, and forwarded-flag fixup. */

void send_servfail(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                   const unsigned char* req_buf, ssize_t req_len);

void send_refused(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                  const unsigned char* req_buf, ssize_t req_len);

int  build_error_reply(const unsigned char* req, ssize_t req_len, int rcode,
                       unsigned char* out, int out_cap);
void send_error_rcode(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                      const unsigned char* req_buf, ssize_t req_len, int rcode);
void send_error_tcp(int fd, const unsigned char* req_buf, ssize_t req_len, int rcode);
int quick_parse_query(const char* buf, ssize_t len,
                      char* domain_out, int domain_max,
                      uint16_t* qtype_out, bool* do_out,
                      uint16_t* edns_size_out);

void finalize_udp_truncation(char** buf, ssize_t* len, uint16_t edns_udp_size);

void ensure_edns_opt(char** buf, ssize_t* len, bool do_bit);
void normalize_forwarded_flags(unsigned char* resp, ssize_t len, int client_rd);

#endif /* UDP_HELPERS_H */
