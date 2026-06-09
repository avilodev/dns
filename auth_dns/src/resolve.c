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
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Error: TCP socket creation failed for upstream query");
        return NULL;
    }

    struct timeval timeout = { .tv_sec = SOCKET_TIMEOUT, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in upstream_server;
    memset(&upstream_server, 0, sizeof(upstream_server));
    upstream_server.sin_family = AF_INET;
    upstream_server.sin_port = htons(g_config.upstream_port);
    if (inet_pton(AF_INET, g_config.upstream_dns, &upstream_server.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid upstream DNS address\n");
        close(sock);
        return NULL;
    }

    if (connect(sock, (struct sockaddr*)&upstream_server,
                sizeof(upstream_server)) < 0) {
        perror("Error: TCP connect() to upstream failed");
        close(sock);
        return NULL;
    }

    // Randomize TX ID before forwarding (RFC 5452 anti-spoofing)
    uint16_t client_txid = ntohs(*(uint16_t*)pkt->request);
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
     * not MAXLINE (which only bounds the UDP path). */
    response->request = malloc(rlen);
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
    if (ntohs(*(uint16_t*)response->request) != random_txid) {
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

    // Copy domain information for logging
    if (pkt->domain) {
        response->domain = strdup(pkt->domain);
    }
    if (pkt->top_level_domain) {
        response->top_level_domain = strdup(pkt->top_level_domain);
    }

    return response;
}

/* Forward pkt to the configured upstream over UDP and return the response, or NULL on error. */
static struct Packet* query_upstream_udp(struct Packet* pkt) {
    // Create UDP socket for upstream query
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
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

    // Configure upstream server address
    struct sockaddr_in upstream_server;
    memset(&upstream_server, 0, sizeof(upstream_server));
    upstream_server.sin_family = AF_INET;
    upstream_server.sin_port = htons(g_config.upstream_port);
    
    if (inet_pton(AF_INET, g_config.upstream_dns, &upstream_server.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid upstream DNS address\n");
        close(sock);
        return NULL;
    }

    /* connect() the UDP socket so the kernel only delivers datagrams from the
     * exact upstream IP *and port* — closes the "accepts any source port" gap
     * (RFC 5452); the source-port entropy of an off-path spoofer now matters. */
    if (connect(sock, (struct sockaddr*)&upstream_server,
                sizeof(upstream_server)) < 0) {
        perror("Error: connect() to upstream failed");
        close(sock);
        return NULL;
    }

    // Randomize TX ID before forwarding (RFC 5452 anti-spoofing)
    uint16_t client_txid = ntohs(*(uint16_t*)pkt->request);
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

    // Save expected source IP before recvfrom overwrites the address struct
    char expected_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &upstream_server.sin_addr, expected_ip, sizeof(expected_ip));

    // Receive response — retry on stray packets (wrong source IP or TX ID).
    // The socket timeout covers the total wait; we keep recvfrom-ing until we
    // get a valid response or the timeout fires.
    struct sockaddr_in recv_addr;
    socklen_t server_len;
    char recv_ip[INET_ADDRSTRLEN];
    uint16_t recv_id;

    for (;;) {
        server_len = sizeof(recv_addr);
        response->recv_len = recvfrom(sock, response->request, MAXLINE, 0,
                                      (struct sockaddr*)&recv_addr, &server_len);

        if (response->recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
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

        /* Validate source IP. */
        inet_ntop(AF_INET, &recv_addr.sin_addr, recv_ip, sizeof(recv_ip));
        if (strcmp(recv_ip, expected_ip) != 0) {
            fprintf(stderr, "Warning: Source IP mismatch from upstream "
                    "(expected %s, got %s) — ignoring stray packet\n",
                    expected_ip, recv_ip);
            continue;
        }

        /* Validate TX ID. */
        recv_id = ntohs(*(uint16_t*)response->request);
        if (random_txid != recv_id) {
            fprintf(stderr, "Warning: TX ID mismatch from upstream "
                    "(sent %u, got %u) — ignoring stray packet\n",
                    random_txid, recv_id);
            continue;
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

    // Copy domain information for logging
    if (pkt->domain) {
        response->domain = strdup(pkt->domain);
    }
    if (pkt->top_level_domain) {
        response->top_level_domain = strdup(pkt->top_level_domain);
    }

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
