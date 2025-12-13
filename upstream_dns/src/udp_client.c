#include "udp_client.h"


/**
 * Query server
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

    struct timeval timeout = {
        .tv_sec = timeout_sec,
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
    memset(recv_buffer, 0, MAXLINE);

    union {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
    } recv_addr;
    
    struct timeval start, end;
    gettimeofday(&start, NULL);
    
    ssize_t received = recvfrom(sockfd, recv_buffer, MAXLINE, 0,
                                (struct sockaddr*)&recv_addr, &addr_len);
    
    gettimeofday(&end, NULL);
    long elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 + 
                     (end.tv_usec - start.tv_usec) / 1000;
    
    close(sockfd);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Timeout, just return NULL
        } else {
            perror("  ✗ recvfrom failed");
        }
        free(recv_buffer);
        return NULL;
    }

    printf("  ← Received %zd bytes from %s in %ldms\n", received, server_ip, elapsed_ms);

    struct Packet* response = parse_response(recv_buffer, received);
    free(recv_buffer);
    
    if (!response) {
        fprintf(stderr, "  ✗ Failed to parse DNS response\n");
        return NULL;
    }

    if (response->id != query->id) {
        fprintf(stderr, "  ✗ Transaction ID mismatch: sent %u, got %u\n", 
                query->id, response->id);
        free_packet(response);
        return NULL;
    }

    return response;
}

/**
 * Default query_server with standard timeout
 */
struct Packet* query_server(const char* server_ip, struct Packet* query)
{
    return query_server_with_timeout(server_ip, query, SOCKET_TIMEOUT);
}

