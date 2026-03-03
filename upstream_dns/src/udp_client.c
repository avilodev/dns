#include "udp_client.h"
#include <sys/random.h>

/**
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

/**
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
                perror("  ✗ recvfrom failed");
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

        // Valid response received.
        close(sockfd);
        free(recv_buffer);
        return response;
    }

    close(sockfd);
    free(recv_buffer);
    return NULL;
}

/**
 * Default query_server with standard timeout
 */
struct Packet* query_server(const char* server_ip, struct Packet* query)
{
    return query_server_with_timeout(server_ip, query, SOCKET_TIMEOUT);
}
