#include "udp_client.h"
#include <sys/random.h>
#include <strings.h>   /* strcasecmp */
#include <time.h>      /* clock_gettime, CLOCK_MONOTONIC */
#include <limits.h>    /* LONG_MAX */

/* ==========================================================================
 * Per-resolution time budget (thread-local)
 *
 * One worker thread handles a query from start to finish, so a thread-local
 * deadline transparently covers the whole call tree — the main delegation
 * walk plus every CNAME and NS-name sub-resolution — without threading a
 * parameter through a dozen signatures.  begin/end are ref-counted: only the
 * outermost call arms the deadline, so nested sub-resolutions share it.
 * ========================================================================== */

static __thread int             tls_depth = 0;   /* 0 = no active budget */
static __thread struct timespec tls_deadline;

void resolver_deadline_begin(int budget_sec)
{
    if (tls_depth == 0) {
        clock_gettime(CLOCK_MONOTONIC, &tls_deadline);
        tls_deadline.tv_sec += budget_sec;
    }
    tls_depth++;
}

void resolver_deadline_end(void)
{
    if (tls_depth > 0) tls_depth--;
}

/* Milliseconds left on the active budget; LONG_MAX when no budget is armed.
 * May go <= 0 once the deadline has passed. */
static long deadline_remaining_ms(void)
{
    if (tls_depth == 0) return LONG_MAX;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (tls_deadline.tv_sec - now.tv_sec) * 1000L +
           (tls_deadline.tv_nsec - now.tv_nsec) / 1000000L;
}

bool resolver_deadline_exceeded(void)
{
    return tls_depth != 0 && deadline_remaining_ms() <= 0;
}

/*
 * Per-hop receive timeout (seconds) bounded by both the remaining total budget
 * and PER_HOP_TIMEOUT_SEC.  Returns 0 when fewer than one whole second of
 * budget remains, signalling the caller to abort rather than start a hop that
 * could overshoot the deadline.  With no budget armed, falls back to
 * SOCKET_TIMEOUT so out-of-band callers behave as before.
 */
static int per_hop_timeout_sec(void)
{
    if (tls_depth == 0) return SOCKET_TIMEOUT;
    long rem_ms = deadline_remaining_ms();
    if (rem_ms <= 0) return 0;
    long rem_sec = rem_ms / 1000;        /* floor: a hop never outlives the budget */
    if (rem_sec <= 0) return 0;
    return (rem_sec < PER_HOP_TIMEOUT_SEC) ? (int)rem_sec : PER_HOP_TIMEOUT_SEC;
}

/*
 * Bind sockfd to a random source port in [1024, 65535] (RFC 5452 §3.3).
 * Retries on EADDRINUSE; falls back to port 0 (OS-chosen) if all fail.
 */
static void bind_random_port(int sockfd, int addr_family)
{
    for (int attempt = 0; attempt < 8; attempt++) {
        uint16_t rport;
        if (getrandom(&rport, sizeof(rport), 0) != (ssize_t)sizeof(rport))
            rport = (uint16_t)(time(NULL) & 0xFFFF);
        if (rport < 1024)
            rport = (uint16_t)(rport | 0x0400); /* ensure >= 1024 */

        if (addr_family == AF_INET6) {
            struct sockaddr_in6 loc = {0};
            loc.sin6_family = AF_INET6;
            loc.sin6_addr   = in6addr_any;
            loc.sin6_port   = htons(rport);
            if (bind(sockfd, (struct sockaddr*)&loc, sizeof(loc)) == 0) return;
        } else {
            struct sockaddr_in loc = {0};
            loc.sin_family      = AF_INET;
            loc.sin_addr.s_addr = INADDR_ANY;
            loc.sin_port        = htons(rport);
            if (bind(sockfd, (struct sockaddr*)&loc, sizeof(loc)) == 0) return;
        }
    }
    /* Fallback: let the OS pick an ephemeral port. */
    if (addr_family == AF_INET6) {
        struct sockaddr_in6 loc = {0};
        loc.sin6_family = AF_INET6;
        loc.sin6_addr   = in6addr_any;
        bind(sockfd, (struct sockaddr*)&loc, sizeof(loc));
    } else {
        struct sockaddr_in loc = {0};
        loc.sin_family      = AF_INET;
        loc.sin_addr.s_addr = INADDR_ANY;
        bind(sockfd, (struct sockaddr*)&loc, sizeof(loc));
    }
}

/*
 * Query server, retrying recvfrom on source-IP or transaction-ID mismatch
 * until the deadline expires.  Prevents spoofed packets from causing the
 * real response to be silently dropped.
 */
struct Packet* query_server_with_timeout(const char* server_ip, struct Packet* query, int timeout_sec)
{
    if (!server_ip || !query || !query->request) {
        return NULL;
    }

    bool is_ipv6 = strchr(server_ip, ':') != NULL;
    int addr_family = is_ipv6 ? AF_INET6 : AF_INET;

    int sockfd = socket(addr_family, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("  Socket creation failed");
        return NULL;
    }

    // Set initial timeout; will be updated per iteration in the receive loop.
    struct timeval timeout = {
        .tv_sec = timeout_sec,
        .tv_usec = 0
    };
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("  setsockopt failed");
        close(sockfd);
        return NULL;
    }

    /* Bind to a random source port (RFC 5452 §3.3 source-port randomization). */
    bind_random_port(sockfd, addr_family);

    ssize_t sent;
    socklen_t addr_len;

    if (is_ipv6) {
        struct sockaddr_in6 server_addr = {0};
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(DNS_PORT);

        if (inet_pton(AF_INET6, server_ip, &server_addr.sin6_addr) <= 0) {
            fprintf(stderr, "  Invalid IPv6 address: %s\n", server_ip);
            close(sockfd);
            return NULL;
        }

        sent = sendto(sockfd, query->request, query->recv_len, 0,
                      (struct sockaddr*)&server_addr, sizeof(server_addr));
        addr_len = sizeof(server_addr);
    } else {
        struct sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(DNS_PORT);

        if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
            fprintf(stderr, "  Invalid IP address: %s\n", server_ip);
            close(sockfd);
            return NULL;
        }

        sent = sendto(sockfd, query->request, query->recv_len, 0,
                      (struct sockaddr*)&server_addr, sizeof(server_addr));
        addr_len = sizeof(server_addr);
    }

    if (sent < 0) {
        perror("  sendto failed");
        close(sockfd);
        return NULL;
    }

    char* recv_buffer = malloc(MAXLINE);
    if (!recv_buffer) {
        perror("  malloc failed");
        close(sockfd);
        return NULL;
    }

    union {
        struct sockaddr_in  v4;
        struct sockaddr_in6 v6;
    } recv_addr;

    // Record deadline so we can update SO_RCVTIMEO on each retry iteration.
    struct timeval deadline;
    gettimeofday(&deadline, NULL);
    deadline.tv_sec += timeout_sec;

    // Retry loop: keep receiving until we get a matching response or time out.
    // This prevents spoofed packets (wrong source IP or TX ID) from causing
    // the real response to be silently discarded.
    while (1) {
        // Compute remaining time for this iteration.
        struct timeval now;
        gettimeofday(&now, NULL);
        long remaining_usec = (deadline.tv_sec - now.tv_sec) * 1000000L +
                              (deadline.tv_usec - now.tv_usec);
        if (remaining_usec <= 0) {
            break;  // Overall timeout expired
        }

        struct timeval remaining_tv = {
            .tv_sec  = remaining_usec / 1000000L,
            .tv_usec = remaining_usec % 1000000L
        };
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &remaining_tv, sizeof(remaining_tv));

        socklen_t recv_addr_len = addr_len;
        ssize_t received = recvfrom(sockfd, recv_buffer, MAXLINE, 0,
                                    (struct sockaddr*)&recv_addr, &recv_addr_len);

        if (received < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("  recvfrom failed");
            }
            break;  // Timeout or hard error
        }

        // Validate source IP matches the server we queried.
        char recv_ip[INET6_ADDRSTRLEN];
        if (is_ipv6) {
            inet_ntop(AF_INET6, &recv_addr.v6.sin6_addr, recv_ip, sizeof(recv_ip));
        } else {
            inet_ntop(AF_INET, &recv_addr.v4.sin_addr, recv_ip, sizeof(recv_ip));
        }
        if (strcmp(recv_ip, server_ip) != 0) {
            fprintf(stderr, "  Source IP mismatch: expected %s, got %s — retrying\n",
                    server_ip, recv_ip);
            continue;
        }

        struct Packet* response = parse_response(recv_buffer, received);
        if (!response) {
            fprintf(stderr, "  Failed to parse DNS response\n");
            continue;
        }

        /* Structural validation — catch malformed or spoofed responses. */
        if (response->qr != 1) {
            fprintf(stderr, "  Response QR=0 (query flag set); dropping\n");
            free_packet(response);
            continue;
        }
        if (response->opcode != 0) {
            fprintf(stderr, "  Response has unexpected opcode %u; dropping\n",
                    (unsigned)response->opcode);
            free_packet(response);
            continue;
        }
        /* Each RR occupies at minimum 11 bytes (1-byte null owner + type 2 +
         * class 2 + TTL 4 + rdlength 2).  If the claimed section counts would
         * require more bytes than the packet contains, the packet is invalid. */
        {
            uint32_t total_rr = (uint32_t)response->ancount +
                                (uint32_t)response->nscount +
                                (uint32_t)response->arcount;
            if (total_rr > 0 && (ssize_t)(total_rr * 11U) > received - HEADER_LEN) {
                fprintf(stderr,
                        "  Response claims %u RRs but packet is only %zd bytes; dropping\n",
                        (unsigned)total_rr, received);
                free_packet(response);
                continue;
            }
        }

        if (response->id != query->id) {
            fprintf(stderr, "  Transaction ID mismatch: sent %u, got %u — retrying\n",
                    query->id, response->id);
            free_packet(response);
            continue;
        }

        /* RFC 5452 §6: the response's question section MUST match the query's.
         * Anti-spoofing defense-in-depth on top of source IP + TXID + random
         * source port, and it prevents a reply to question B being accepted
         * (and cached) for query A.  Names are compared case-insensitively
         * (RFC 1035 §3.1). */
        if (!response->full_domain || !query->full_domain ||
            strcasecmp(response->full_domain, query->full_domain) != 0 ||
            response->q_type  != query->q_type ||
            response->q_class != query->q_class) {
            fprintf(stderr,
                    "  Question mismatch: got %s/%u/%u, expected %s/%u/%u — retrying\n",
                    response->full_domain ? response->full_domain : "(none)",
                    (unsigned)response->q_type, (unsigned)response->q_class,
                    query->full_domain ? query->full_domain : "(none)",
                    (unsigned)query->q_type, (unsigned)query->q_class);
            free_packet(response);
            continue;
        }

        // Valid response received.
        close(sockfd);
        free(recv_buffer);
        return response;
    }

    close(sockfd);
    free(recv_buffer);
    return NULL;
}

/*
 * Default query_server: one hop, bounded by the active recursion budget.
 * Returns NULL immediately if the budget is already spent so the caller fails
 * fast instead of starting another timed wait.
 */
struct Packet* query_server(const char* server_ip, struct Packet* query)
{
    int timeout_sec = per_hop_timeout_sec();
    if (timeout_sec == 0) return NULL;   /* budget exhausted */
    return query_server_with_timeout(server_ip, query, timeout_sec);
}

/*
 * Send a DNS query over TCP (RFC 1035 §4.2.2) and return the response.
 * Used as a fallback when a UDP response arrives with TC=1 (truncated).
 * Returns NULL on timeout or error.
 */
struct Packet* query_server_tcp(const char* server_ip, struct Packet* query)
{
    if (!server_ip || !query || !query->request || query->recv_len <= 0) return NULL;

    /* Honour the recursion budget: a TCP fallback is one more hop and must not
     * outlive the deadline either.  Bail if the budget is already spent. */
    int tcp_timeout = per_hop_timeout_sec();
    if (tcp_timeout == 0) return NULL;

    bool is_ipv6 = strchr(server_ip, ':') != NULL;
    int addr_family = is_ipv6 ? AF_INET6 : AF_INET;

    int sockfd = socket(addr_family, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("  TCP socket creation failed");
        return NULL;
    }

    struct timeval tv = { .tv_sec = tcp_timeout, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int connected = -1;
    if (is_ipv6) {
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(DNS_PORT);
        if (inet_pton(AF_INET6, server_ip, &addr.sin6_addr) > 0)
            connected = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    } else {
        struct sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(DNS_PORT);
        if (inet_pton(AF_INET, server_ip, &addr.sin_addr) > 0)
            connected = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    }

    if (connected < 0) {
        perror("  TCP connect failed");
        close(sockfd);
        return NULL;
    }

    /* DNS-over-TCP: 2-byte big-endian message length prefix, then query. */
    uint16_t qlen_net = htons((uint16_t)query->recv_len);
    const uint8_t* p = (const uint8_t*)&qlen_net;
    size_t rem = 2;
    while (rem > 0) {
        ssize_t nw = write(sockfd, p, rem);
        if (nw <= 0) { close(sockfd); return NULL; }
        p += nw; rem -= (size_t)nw;
    }
    p = (const uint8_t*)query->request;
    rem = (size_t)query->recv_len;
    while (rem > 0) {
        ssize_t nw = write(sockfd, p, rem);
        if (nw <= 0) { close(sockfd); return NULL; }
        p += nw; rem -= (size_t)nw;
    }

    /* Read 2-byte response length prefix. */
    uint16_t rlen_net = 0;
    ssize_t n = recv(sockfd, &rlen_net, 2, MSG_WAITALL);
    if (n != 2) { close(sockfd); return NULL; }
    uint16_t rlen = ntohs(rlen_net);
    if (rlen < HEADER_LEN || rlen > MAXLINE) { close(sockfd); return NULL; }

    char* rbuf = malloc(rlen);
    if (!rbuf) { close(sockfd); return NULL; }

    n = recv(sockfd, rbuf, rlen, MSG_WAITALL);
    close(sockfd);

    if (n != rlen) { free(rbuf); return NULL; }

    struct Packet* response = parse_response(rbuf, rlen);
    free(rbuf);
    return response;
}
