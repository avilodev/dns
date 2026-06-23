#include "auth_net.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "types.h"   /* PORT, RCODE_*, Config */

extern Config g_config;   /* read for the -b bind address */

/*
 * Resolve the configured -b bind address for a given address family.
 *   Returns  1 if a bind address was applied (written to *out4 / *out6),
 *            0 if no -b was given (wildcard address written),
 *           -1 if -b was given but is of a different family (skip this socket).
 */
static int auth_resolve_bind(int family, struct in_addr *out4,
                             struct in6_addr *out6) {
    if (!g_config.bind_addr) {
        if (family == AF_INET)  out4->s_addr = INADDR_ANY;
        if (family == AF_INET6) *out6 = in6addr_any;
        return 0;
    }
    if (family == AF_INET)
        return (inet_pton(AF_INET, g_config.bind_addr, out4) == 1) ? 1 : -1;
    return (inet_pton(AF_INET6, g_config.bind_addr, out6) == 1) ? 1 : -1;
}

/*
 * Create one SO_REUSEPORT UDP socket bound to `port` for `family`, applying the
 * -b bind address and a 1-second recv timeout.  Returns the fd, or -1 (family
 * unavailable, -b is a different family, or bind failed).
 *
 * Called from main() while still root so every port-53 bind happens BEFORE
 * privileges are dropped; the fd is then handed to a worker thread.  The kernel
 * still load-balances datagrams across the N per-worker SO_REUSEPORT sockets.
 */
int create_reuseport_udp_socket(int family, int port) {
    int sock = socket(family, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        perror("Warning: SO_REUSEPORT unavailable");

    if (family == AF_INET6) {
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(port);
        if (auth_resolve_bind(AF_INET6, NULL, &addr.sin6_addr) < 0) {
            close(sock); return -1;
        }
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock); return -1;
        }
    } else {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        if (auth_resolve_bind(AF_INET, &addr.sin_addr, NULL) < 0) {
            close(sock); return -1;
        }
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock); return -1;
        }
    }

    /* 1-second recv timeout so each worker re-checks g_running every second. */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return sock;
}

int create_tcp_socket_v4(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("Error: socket() IPv4 TCP"); return -1; }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    if (auth_resolve_bind(AF_INET, &addr.sin_addr, NULL) < 0) {
        close(sock); return -1;   /* -b is IPv6: no IPv4 TCP socket */
    }
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Error: bind() IPv4 TCP"); close(sock); return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) {
        perror("Error: listen() IPv4 TCP"); close(sock); return -1;
    }
    return sock;
}

int create_tcp_socket_v6(int port) {
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Warning: socket() IPv6 TCP; no IPv6 TCP support");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET,   SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,  &opt, sizeof(opt));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    if (auth_resolve_bind(AF_INET6, NULL, &addr.sin6_addr) < 0) {
        close(sock); return -1;   /* -b is IPv4: no IPv6 TCP socket */
    }
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Warning: bind() IPv6 TCP"); close(sock); return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) {
        perror("Warning: listen() IPv6 TCP"); close(sock); return -1;
    }
    return sock;
}

/* --- Shared query resolution logic --------------------------------------- */

/* Send a raw SERVFAIL back over UDP without parsing the request. */
void send_servfail_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                               const char* buf, ssize_t buf_len) {
    if (!addr || !buf || buf_len < 2) return;
    unsigned char resp[12] = {0};
    resp[0] = (unsigned char)buf[0];  // TX ID high byte
    resp[1] = (unsigned char)buf[1];  // TX ID low byte
    resp[2] = 0x80;                   // QR=1
    resp[3] = 0x80 | RCODE_SERVER_FAILURE;
    sendto(sock, resp, sizeof(resp), 0, addr, addr_len);
}

/*
 * Send a minimal REFUSED reply (RFC 1035 RCODE 5) — used to reject recursion
 * from sources outside the allow-list (known_issues 4.3).
 */
void send_refused_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                             const char* buf, ssize_t buf_len) {
    if (!addr || !buf || buf_len < 3) return;
    unsigned char resp[12] = {0};
    resp[0] = (unsigned char)buf[0];
    resp[1] = (unsigned char)buf[1];
    resp[2] = 0x80 | ((unsigned char)buf[2] & 0x79);  // QR=1, echo OPCODE+RD
    resp[3] = 0x80 | RCODE_REFUSED;                   // RA=1, RCODE=REFUSED
    sendto(sock, resp, sizeof(resp), 0, addr, addr_len);
}

/* Send a length-prefixed REFUSED reply over a TCP connection. */
void send_refused_tcp(int fd, const char* buf, ssize_t buf_len) {
    if (buf_len < 3) return;
    uint16_t len_net = htons(12);
    unsigned char resp[12] = {0};
    resp[0] = (unsigned char)buf[0];
    resp[1] = (unsigned char)buf[1];
    resp[2] = 0x80 | ((unsigned char)buf[2] & 0x79);
    resp[3] = 0x80 | RCODE_REFUSED;
    if (write(fd, &len_net, 2) != 2) return;
    if (write(fd, resp, 12)   != 12) return;
}

/* Best-effort length-prefixed write of a small fixed DNS message over TCP.
 * Return values are checked so the build stays clean under _FORTIFY_SOURCE. */
void tcp_write_msg(int fd, const unsigned char* msg, uint16_t len) {
    uint16_t len_net = htons(len);
    if (write(fd, &len_net, 2) != 2) return;
    if (write(fd, msg, len) != (ssize_t)len) return;
}
