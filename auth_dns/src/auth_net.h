#ifndef AUTH_NET_H
#define AUTH_NET_H

#include <stdint.h>
#include <sys/types.h>     /* ssize_t */
#include <sys/socket.h>    /* struct sockaddr, socklen_t */

/* auth_dns network I/O: listener socket creation (SO_REUSEPORT UDP + TCP,
 * v4/v6, honoring the -b bind address) and minimal UDP/TCP error replies. */

int create_reuseport_udp_socket(int family, int port);
int create_tcp_socket_v4(int port);
int create_tcp_socket_v6(int port);

void send_servfail_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                       const char* buf, ssize_t buf_len);
void send_refused_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                      const char* buf, ssize_t buf_len);
void send_refused_tcp(int fd, const char* buf, ssize_t buf_len);
void tcp_write_msg(int fd, const unsigned char* msg, uint16_t len);

#endif /* AUTH_NET_H */
