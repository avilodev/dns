#include "resolve.h"

extern Config g_config;

/**
 * Resolve DNS query recursively using upstream DNS server (1.1.1.1)
 * @param pkt Parsed DNS request
 * @return Response packet from upstream server or NULL on error
 */
struct Packet* resolve_recursive(struct Packet* pkt) {
    if (!pkt || !pkt->request) {
        fprintf(stderr, "Error: Invalid packet for recursive resolution\n");
        return NULL;
    }

    printf("→ Forwarding query to upstream DNS (%s) for %s\n", 
           g_config.upstream_dns, pkt->full_domain ? pkt->full_domain : "unknown");

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

    // Forward original query to upstream DNS server
    ssize_t sent = sendto(sock, pkt->request, pkt->recv_len, 0, 
                          (struct sockaddr*)&upstream_server, sizeof(upstream_server));
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

    // Receive response from upstream server
    socklen_t server_len = sizeof(upstream_server);
    response->recv_len = recvfrom(sock, response->request, MAXLINE, 0, 
                                   (struct sockaddr*)&upstream_server, &server_len);

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

    // Copy domain information for logging
    if (pkt->domain) {
        response->domain = strdup(pkt->domain);
    }
    if (pkt->top_level_domain) {
        response->top_level_domain = strdup(pkt->top_level_domain);
    }

    printf("← Received %zd bytes from upstream DNS\n", response->recv_len);

    return response;
}