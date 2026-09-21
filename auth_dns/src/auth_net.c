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

/* --- Error replies ------------------------------------------------------- */

/* Does the raw request carry an OPT RR?  Returns 1 with *do_bit set, else 0. */
static int request_opt(const unsigned char* req, ssize_t req_len, bool* do_bit)
{
    if (req_len < HEADER_LEN) return 0;
    int total = ((req[6] << 8) | req[7]) + ((req[8] << 8) | req[9]) +
                ((req[10] << 8) | req[11]);
    int qd = (req[4] << 8) | req[5];
    ssize_t p = HEADER_LEN;
    for (int i = 0; i < qd + total; i++) {
        while (p < req_len) {                          /* skip owner / QNAME */
            uint8_t l = req[p];
            if (l == 0)             { p += 1; break; }
            if ((l & 0xC0) == 0xC0) { p += 2; break; }
            p += 1 + l;
        }
        if (i < qd) { p += 4; continue; }
        if (p + 10 > req_len) return 0;
        if (req[p] == 0 && req[p + 1] == 41) {
            *do_bit = (req[p + 6] & 0x80) != 0;
            return 1;
        }
        p += 10 + ((req[p + 8] << 8) | req[p + 9]);
    }
    return 0;
}

/*
 * Build an error reply (header + echoed question) for a raw query.
 *
 * The question is echoed whenever the query carries exactly one well-formed
 * question: stub resolvers such as glibc discard replies whose question does
 * not match what they asked (only FORMERR is exempt) and then wait out their
 * full timeout.  Opcode and RD are echoed, RA is set.  Returns the reply length
 * (12 when no question could be echoed), or 0 on bad input.
 */
static int build_error_reply_ex(const unsigned char* req, ssize_t req_len, int rcode,
                                unsigned char* out, int out_cap, bool add_opt)
{
    if (!req || req_len < 2 || !out || out_cap < HEADER_LEN) return 0;
    memset(out, 0, HEADER_LEN);
    out[0] = req[0];
    out[1] = req[1];
    out[2] = (unsigned char)(0x80 | (req_len > 2 ? (req[2] & 0x79) : 0)); /* QR, opcode, RD */
    out[3] = (unsigned char)(0x80 | (req_len > 3 ? (req[3] & 0x10) : 0) |
                             (rcode & 0x0F));                /* RA, CD, RCODE */

    if (req_len < HEADER_LEN + 5 || req[4] != 0 || req[5] != 1) return HEADER_LEN;
    int q = HEADER_LEN;
    while (q < req_len) {
        uint8_t l = req[q];
        if (l == 0) { q++; break; }
        if (l > 63) return HEADER_LEN;            /* compression / bad label */
        q += 1 + l;
    }
    if (q > req_len || q + 4 > req_len || req[q - 1] != 0) return HEADER_LEN;
    int qlen = q + 4 - HEADER_LEN;
    if (HEADER_LEN + qlen > out_cap) return HEADER_LEN;
    memcpy(out + HEADER_LEN, req + HEADER_LEN, (size_t)qlen);
    out[5] = 1;                                   /* QDCOUNT = 1 */
    int n = HEADER_LEN + qlen;

    /* EDNS client: the reply carries an OPT too (RFC 6891 §7).  Not for
     * FORMERR, where the client's OPT itself may be what was malformed. */
    bool do_bit = false;
    if (add_opt && n + 11 <= out_cap && request_opt(req, req_len, &do_bit)) {
        unsigned char* o = out + n;
        o[0] = 0;                                  /* root owner */
        o[1] = 0; o[2] = 41;                       /* TYPE = OPT */
        o[3] = 1232 >> 8; o[4] = 1232 & 0xFF;      /* our UDP payload size */
        o[5] = 0; o[6] = 0;                        /* ext-RCODE, version */
        o[7] = do_bit ? 0x80 : 0; o[8] = 0;        /* flags (DO mirrored) */
        o[9] = 0; o[10] = 0;                       /* RDLEN */
        out[11] = 1;                               /* ARCOUNT = 1 */
        n += 11;
    }
    return n;
}

int build_error_reply(const unsigned char* req, ssize_t req_len, int rcode,
                      unsigned char* out, int out_cap)
{
    return build_error_reply_ex(req, req_len, rcode, out, out_cap,
                                rcode != RCODE_FORMAT_ERROR);
}

void send_error_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                    const char* buf, ssize_t buf_len, int rcode)
{
    if (!addr || !buf) return;
    unsigned char resp[HEADER_LEN + 260 + 11] = {0};
    int n = build_error_reply((const unsigned char*)buf, buf_len, rcode, resp, sizeof(resp));
    if (n > 0) sendto(sock, resp, (size_t)n, 0, addr, addr_len);
}

void send_error_tcp(int fd, const char* buf, ssize_t buf_len, int rcode)
{
    unsigned char resp[HEADER_LEN + 260 + 11] = {0};
    int n = build_error_reply((const unsigned char*)buf, buf_len, rcode, resp, sizeof(resp));
    if (n > 0) tcp_write_msg(fd, resp, (uint16_t)n);
}

/* Send a SERVFAIL back over UDP. */
void send_servfail_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                               const char* buf, ssize_t buf_len) {
    send_error_udp(sock, addr, addr_len, buf, buf_len, RCODE_SERVER_FAILURE);
}

/*
 * Send a REFUSED reply (RFC 1035 RCODE 5) — used to reject recursion from
 * sources outside the allow-list (known_issues 4.3).  No larger than the
 * query, so it cannot be used for amplification.
 */
void send_refused_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                             const char* buf, ssize_t buf_len) {
    send_error_udp(sock, addr, addr_len, buf, buf_len, RCODE_REFUSED);
}

/* Send a length-prefixed REFUSED reply over a TCP connection. */
void send_refused_tcp(int fd, const char* buf, ssize_t buf_len) {
    send_error_tcp(fd, buf, buf_len, RCODE_REFUSED);
}

/* Best-effort length-prefixed write of a small fixed DNS message over TCP.
 * Return values are checked so the build stays clean under _FORTIFY_SOURCE. */
void tcp_write_msg(int fd, const unsigned char* msg, uint16_t len) {
    unsigned char out[2 + HEADER_LEN + 260 + 11];
    if (len > sizeof(out) - 2) return;
    out[0] = (unsigned char)(len >> 8);
    out[1] = (unsigned char)(len & 0xFF);
    memcpy(out + 2, msg, len);
    size_t off = 0, total = (size_t)len + 2;
    while (off < total) {
        ssize_t w = write(fd, out + off, total - off);
        if (w <= 0) return;
        off += (size_t)w;
    }
}
