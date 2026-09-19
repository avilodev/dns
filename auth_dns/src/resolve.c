#include "resolve.h"
#include <sys/random.h>
#include <ctype.h>
#include <string.h>

extern Config g_config;

/*
 * Compare the question section of a forwarded query against the upstream reply
 * (RFC 5452 §6): QNAME case-insensitively, QTYPE/QCLASS exactly.  Question-
 * section QNAMEs are never compressed, so a lockstep label walk is safe.
 * Returns 1 on match, 0 otherwise.
 */
static int question_matches(const char* qbuf, ssize_t qlen,
                            const char* rbuf, ssize_t rlen) {
    if (qlen < HEADER_LEN + 5 || rlen < HEADER_LEN + 5) return 0;
    int qp = HEADER_LEN, rp = HEADER_LEN;
    while (1) {
        if (qp >= qlen || rp >= rlen) return 0;
        unsigned char ql = (unsigned char)qbuf[qp];
        unsigned char rl = (unsigned char)rbuf[rp];
        if (ql != rl) return 0;          /* differing label length */
        if (ql & 0xC0) return 0;         /* compression not expected here */
        qp++; rp++;
        if (ql == 0) break;              /* both reached the root label */
        if (qp + ql > qlen || rp + ql > rlen) return 0;
        for (int i = 0; i < ql; i++)
            if (tolower((unsigned char)qbuf[qp + i]) !=
                tolower((unsigned char)rbuf[rp + i]))
                return 0;
        qp += ql; rp += ql;
    }
    if (qp + 4 > qlen || rp + 4 > rlen) return 0;
    return memcmp(qbuf + qp, rbuf + rp, 4) == 0;  /* QTYPE + QCLASS */
}

/*
 * Fill *ss with the configured upstream address (IPv4 or IPv6 literal, as
 * accepted by -u).  Returns the sockaddr length, or 0 if the address is invalid.
 */
static socklen_t upstream_sockaddr(struct sockaddr_storage* ss) {
    memset(ss, 0, sizeof(*ss));
    struct sockaddr_in*  s4 = (struct sockaddr_in*)ss;
    struct sockaddr_in6* s6 = (struct sockaddr_in6*)ss;
    if (inet_pton(AF_INET, g_config.upstream_dns, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port   = htons(g_config.upstream_port);
        return sizeof(*s4);
    }
    if (inet_pton(AF_INET6, g_config.upstream_dns, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port   = htons(g_config.upstream_port);
        return sizeof(*s6);
    }
    fprintf(stderr, "Error: Invalid upstream DNS address\n");
    return 0;
}

/* Write exactly len bytes to fd, looping over short writes.
 * Returns 0 on success, -1 on error. */
static int write_all(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    while (len > 0) {
        ssize_t nw = write(fd, p, len);
        if (nw <= 0) return -1;
        p += nw;
        len -= (size_t)nw;
    }
    return 0;
}

/*
 * Forward pkt to the configured upstream over TCP (RFC 1035 §4.2.2, RFC 7766)
 * and return the response, or NULL on error.  Used when the client itself used
 * TCP — i.e. the answer may exceed a UDP buffer (full DNSSEC RRSIG sets, fat
 * TXT/DKIM records), so we must fetch it over TCP to return it in full.
 * Mirrors the UDP path's RFC 5452 discipline: random TX ID, TX-ID + question
 * validation, then remap the TX ID back to the client's.
 */
static struct Packet* query_upstream_tcp(struct Packet* pkt) {
    struct sockaddr_storage upstream_server;
    socklen_t upstream_len = upstream_sockaddr(&upstream_server);
    if (!upstream_len) return NULL;

    int sock = socket(upstream_server.ss_family, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Error: TCP socket creation failed for upstream query");
        return NULL;
    }

    struct timeval timeout = { .tv_sec = SOCKET_TIMEOUT, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr*)&upstream_server, upstream_len) < 0) {
        perror("Error: TCP connect() to upstream failed");
        close(sock);
        return NULL;
    }

    // Randomize TX ID before forwarding (RFC 5452 anti-spoofing)
    uint16_t client_txid = rd16(pkt->request);
    uint16_t random_txid;
    if (getrandom(&random_txid, sizeof(random_txid), 0) != (ssize_t)sizeof(random_txid)) {
        random_txid = (uint16_t)(rand() & 0xFFFF);
    }
    ((uint8_t*)pkt->request)[0] = (random_txid >> 8) & 0xFF;
    ((uint8_t*)pkt->request)[1] =  random_txid       & 0xFF;

    /* DNS-over-TCP framing: 2-byte big-endian length prefix, then the message. */
    uint16_t qlen_net = htons((uint16_t)pkt->recv_len);
    int sent_ok = (write_all(sock, &qlen_net, 2) == 0) &&
                  (write_all(sock, pkt->request, (size_t)pkt->recv_len) == 0);

    // Restore client's TX ID in the request buffer (caller still owns pkt)
    ((uint8_t*)pkt->request)[0] = (client_txid >> 8) & 0xFF;
    ((uint8_t*)pkt->request)[1] =  client_txid       & 0xFF;

    if (!sent_ok) {
        perror("Error: Failed to send TCP query to upstream");
        close(sock);
        return NULL;
    }

    /* Read the 2-byte response length prefix. */
    uint16_t rlen_net = 0;
    if (recv(sock, &rlen_net, 2, MSG_WAITALL) != 2) {
        fprintf(stderr, "Error: Failed to read TCP length prefix from upstream\n");
        close(sock);
        return NULL;
    }
    uint16_t rlen = ntohs(rlen_net);
    if (rlen < HEADER_LEN) {
        fprintf(stderr, "Error: TCP response from upstream too short (%u bytes)\n", rlen);
        close(sock);
        return NULL;
    }

    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        close(sock);
        return NULL;
    }
    /* TCP answers can be up to 65535 bytes — size the buffer to the prefix,
     * but never below MAXLINE: callers (append_edns_opt) append to a response
     * in place and assume the MAXLINE capacity every other response buffer
     * has.  An exact-size buffer here was overrun by the EDNS OPT append. */
    response->request = malloc(rlen > MAXLINE ? rlen : MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        close(sock);
        return NULL;
    }

    ssize_t got = recv(sock, response->request, rlen, MSG_WAITALL);
    close(sock);
    if (got != (ssize_t)rlen) {
        fprintf(stderr, "Error: Short TCP read from upstream (%zd/%u bytes)\n", got, rlen);
        free_packet(response);
        return NULL;
    }
    response->recv_len = rlen;

    /* Validate TX ID (RFC 5452). */
    if (rd16(response->request) != random_txid) {
        fprintf(stderr, "Warning: TX ID mismatch from upstream (TCP) — dropping\n");
        free_packet(response);
        return NULL;
    }

    /* Validate the question matches what we asked (RFC 5452 §6). */
    if (!question_matches(pkt->request, pkt->recv_len,
                          response->request, response->recv_len)) {
        fprintf(stderr, "Warning: Question mismatch from upstream (TCP) — dropping\n");
        free_packet(response);
        return NULL;
    }

    // Remap TX ID in response back to the client's original ID
    ((uint8_t*)response->request)[0] = (client_txid >> 8) & 0xFF;
    ((uint8_t*)response->request)[1] =  client_txid       & 0xFF;


    return response;
}

/* Forward pkt to the configured upstream over UDP and return the response, or NULL on error. */
static struct Packet* query_upstream_udp(struct Packet* pkt) {
    struct sockaddr_storage upstream_server;
    socklen_t upstream_len = upstream_sockaddr(&upstream_server);
    if (!upstream_len) return NULL;

    // Create UDP socket for upstream query
    int sock = socket(upstream_server.ss_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Error: Socket creation failed for upstream query");
        return NULL;
    }

    // Set socket timeout to prevent hanging
    struct timeval timeout = {
        .tv_sec = SOCKET_TIMEOUT,
        .tv_usec = 0
    };
    
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Warning: Failed to set socket timeout");
    }

    /* connect() the UDP socket so the kernel only delivers datagrams from the
     * exact upstream IP *and port* — closes the "accepts any source port" gap
     * (RFC 5452); the source-port entropy of an off-path spoofer now matters. */
    if (connect(sock, (struct sockaddr*)&upstream_server, upstream_len) < 0) {
        perror("Error: connect() to upstream failed");
        close(sock);
        return NULL;
    }

    // Randomize TX ID before forwarding (RFC 5452 anti-spoofing)
    uint16_t client_txid = rd16(pkt->request);
    uint16_t random_txid;
    if (getrandom(&random_txid, sizeof(random_txid), 0) != (ssize_t)sizeof(random_txid)) {
        // getrandom() should never fail on Linux, but fall back gracefully
        random_txid = (uint16_t)(rand() & 0xFFFF);
    }
    ((uint8_t*)pkt->request)[0] = (random_txid >> 8) & 0xFF;
    ((uint8_t*)pkt->request)[1] =  random_txid       & 0xFF;

    // Forward query to upstream DNS server with randomized TX ID
    // (socket is connect()ed, so send() targets the upstream).
    ssize_t sent = send(sock, pkt->request, pkt->recv_len, 0);

    // Restore client's TX ID in the request buffer (caller still owns pkt)
    ((uint8_t*)pkt->request)[0] = (client_txid >> 8) & 0xFF;
    ((uint8_t*)pkt->request)[1] =  client_txid       & 0xFF;

    if (sent < 0) {
        perror("Error: Failed to forward query to upstream");
        close(sock);
        return NULL;
    }

    if (sent != pkt->recv_len) {
        fprintf(stderr, "Warning: Partial send to upstream (%zd/%zd bytes)\n",
                sent, pkt->recv_len);
    }

    // Allocate response packet
    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        close(sock);
        return NULL;
    }

    response->request = malloc(MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        close(sock);
        return NULL;
    }

    // Receive response — retry on stray packets (wrong TX ID or question).
    // The connect()ed socket already restricts the source to the upstream's
    // IP and port.  The socket timeout covers each wait; we keep receiving
    // until we get a valid response or the timeout fires.
    uint16_t recv_id;

    for (;;) {
        response->recv_len = recv(sock, response->request, MAXLINE, 0);

        if (response->recv_len < 0) {
            if (errno_is_timeout(errno)) {
                fprintf(stderr, "Error: Upstream DNS query timed out\n");
            } else {
                perror("Error: Failed to receive upstream response");
            }
            close(sock);
            free_packet(response);
            return NULL;
        }

        if (response->recv_len < HEADER_LEN) {
            /* Too short to be a DNS response — ignore and keep waiting. */
            continue;
        }

        /* Validate TX ID. */
        recv_id = rd16(response->request);
        if (random_txid != recv_id) {
            fprintf(stderr, "Warning: TX ID mismatch from upstream "
                    "(sent %u, got %u) — ignoring stray packet\n",
                    random_txid, recv_id);
            continue;
        }

        /* A TX-ID-matching error reply with no question section (some servers
         * send SERVFAIL/REFUSED that way): treat it as a failure now instead of
         * discarding it and sitting out the whole timeout. */
        if (response->request[4] == 0 && response->request[5] == 0 &&
            (response->request[3] & 0x0F) != 0) {
            fprintf(stderr, "Upstream returned rcode %d without a question\n",
                    response->request[3] & 0x0F);
            close(sock);
            free_packet(response);
            return NULL;
        }

        /* Validate the question matches what we asked (RFC 5452 §6). */
        if (!question_matches(pkt->request, pkt->recv_len,
                              response->request, response->recv_len)) {
            fprintf(stderr, "Warning: Question mismatch from upstream "
                    "— ignoring stray packet\n");
            continue;
        }

        break;  /* valid response */
    }

    close(sock);

    // Remap TX ID in response back to the client's original ID
    ((uint8_t*)response->request)[0] = (client_txid >> 8) & 0xFF;
    ((uint8_t*)response->request)[1] =  client_txid       & 0xFF;


    return response;
}

/*
 * Forward pkt to the configured upstream and return the response (NULL on error).
 *
 * Transport choice (fixes the "no TCP fallback on auth → upstream hop" bug):
 *   - client_tcp == 0 (client used UDP): query upstream over UDP and forward the
 *     answer as-is.  If upstream truncated it (TC=1), that bit is preserved so the
 *     client retries over TCP — handled by the branch below.  We never upgrade a
 *     UDP client to a TCP-sized answer here: it could not fit the client's UDP
 *     buffer anyway.
 *   - client_tcp == 1 (client used TCP): query upstream over TCP so a large answer
 *     (full DNSSEC RRSIG sets, fat TXT/DKIM) is returned in full.  If upstream's
 *     TCP path is unavailable, fall back to UDP best-effort rather than failing.
 */
struct Packet* resolve_recursive(struct Packet* pkt, int client_tcp) {
    if (!pkt || !pkt->request) {
        fprintf(stderr, "Error: Invalid packet for recursive resolution\n");
        return NULL;
    }

    if (client_tcp) {
        struct Packet* tcp_resp = query_upstream_tcp(pkt);
        if (tcp_resp) return tcp_resp;
        /* Upstream TCP unavailable — fall back to a best-effort UDP query. */
    }

    return query_upstream_udp(pkt);
}
