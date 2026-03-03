#include "resolve.h"
#include <sys/random.h>

extern Config g_config;

/**
 * Resolve DNS query recursively using upstream DNS server 
 * @param pkt Parsed DNS request
 * @return Response packet from upstream server or NULL on error
 */
struct Packet* resolve_recursive(struct Packet* pkt) {
    if (!pkt || !pkt->request) {
        fprintf(stderr, "Error: Invalid packet for recursive resolution\n");
        return NULL;
    }

    //printf("→ Forwarding query to upstream DNS (%s) for %s\n", 
           //g_config.upstream_dns, pkt->full_domain ? pkt->full_domain : "unknown");

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
    ssize_t sent = sendto(sock, pkt->request, pkt->recv_len, 0,
                          (struct sockaddr*)&upstream_server, sizeof(upstream_server));

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

    // Receive response — use a separate struct so we can validate source IP
    struct sockaddr_in recv_addr;
    socklen_t server_len = sizeof(recv_addr);
    response->recv_len = recvfrom(sock, response->request, MAXLINE, 0,
                                   (struct sockaddr*)&recv_addr, &server_len);

    close(sock);

    if (response->recv_len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "Error: Upstream DNS query timed out\n");
        } else {
            perror("Error: Failed to receive upstream response");
        }
        free_packet(response);
        return NULL;
    }

    if (response->recv_len < HEADER_LEN) {
        fprintf(stderr, "Error: Invalid DNS response from upstream (%zd bytes)\n",
                response->recv_len);
        free_packet(response);
        return NULL;
    }

    // Validate source IP matches the server we queried
    char recv_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &recv_addr.sin_addr, recv_ip, sizeof(recv_ip));
    if (strcmp(recv_ip, expected_ip) != 0) {
        fprintf(stderr, "Warning: Source IP mismatch from upstream (expected %s, got %s) — dropping\n",
                expected_ip, recv_ip);
        free_packet(response);
        return NULL;
    }

    // Validate transaction ID matches what we sent (the randomized ID)
    uint16_t recv_id = ntohs(*(uint16_t*)response->request);
    if (random_txid != recv_id) {
        fprintf(stderr, "Warning: TX ID mismatch from upstream (sent %u, got %u) — dropping\n",
                random_txid, recv_id);
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

    //printf("← Received %zd bytes from upstream DNS\n", response->recv_len);

    return response;
}
