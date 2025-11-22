#include "udp_client.h"


/**
 * Query a specific DNS server via UDP
 * Includes timeout and transaction ID validation
 */
struct Packet* query_server(const char* server_ip, struct Packet* query)
{
    if (!server_ip || !query || !query->request) {
        return NULL;
    }

    // Detect if this is IPv4 or IPv6
    bool is_ipv6 = strchr(server_ip, ':') != NULL;
    int addr_family = is_ipv6 ? AF_INET6 : AF_INET;

    // Create UDP socket
    int sockfd = socket(addr_family, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("  Socket creation failed");
        return NULL;
    }

    // Set receive timeout
    struct timeval timeout = {
        .tv_sec = SOCKET_TIMEOUT,
        .tv_usec = 0
    };
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("  setsockopt failed");
        close(sockfd);
        return NULL;
    }

    ssize_t sent;
    socklen_t addr_len;
    
    if (is_ipv6) {
        // IPv6
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
        // IPv4
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

    printf("  → Sent %zd bytes to %s:53\n", sent, server_ip);

    // Allocate buffer for response
    char* recv_buffer = malloc(MAXLINE);
    if (!recv_buffer) {
        perror("  malloc failed");
        close(sockfd);
        return NULL;
    }
    memset(recv_buffer, 0, MAXLINE);

    // Receive DNS response
    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } recv_addr;
    
    ssize_t received = recvfrom(sockfd, recv_buffer, MAXLINE, 0,
                                (struct sockaddr*)&recv_addr, &addr_len);
    
    close(sockfd);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "  ✗ Timeout waiting for response from %s\n", server_ip);
        } else {
            perror("  ✗ recvfrom failed");
        }
        free(recv_buffer);
        return NULL;
    }

    printf("  ← Received %zd bytes from %s:53\n", received, server_ip);

    // Parse the response
    struct Packet* response = parse_request_headers(recv_buffer, received);
    free(recv_buffer);
    
    if (!response) {
        fprintf(stderr, "  ✗ Failed to parse DNS response\n");
        return NULL;
    }

    // Validate transaction ID
    if (response->id != query->id) {
        fprintf(stderr, "  ✗ Transaction ID mismatch: sent %u, got %u\n", 
                query->id, response->id);
        free_packet(response);
        return NULL;
    }

    return response;
}
