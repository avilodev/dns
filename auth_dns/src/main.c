#include "auth.h"
#include "logger.h"
#include "request.h"
#include "response.h"
#include "resolve.h"
#include "types.h"
#include "utils.h"
#include "thread_pool.h"

Config g_config;

// Structure to hold query processing context
struct QueryContext {
    int dns_sock;
    struct sockaddr_in client_addr; 
    char* buffer;
    ssize_t recv_len;
    unsigned long query_num;
};

/**
 * Process a single query
 */
void* process_query(void* arg) {
    struct QueryContext* ctx = (struct QueryContext*)arg;
    
    char* client_ip = inet_ntoa(ctx->client_addr.sin_addr);
    uint16_t client_port = ntohs(ctx->client_addr.sin_port);

    printf("\n[Query #%lu] From %s:%u (%zd bytes)\n", 
           ctx->query_num, client_ip, client_port, ctx->recv_len);

    // Parse DNS request
    struct Packet* pkt = parse_request_headers(ctx->buffer, ctx->recv_len);
    if (!pkt) {
        fprintf(stderr, "✗ Failed to parse packet header\n");
        log_entry(client_ip, client_port, "PARSE_ERROR", NULL);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    print_packet_info("QUESTION", pkt);

    struct Packet* answer = NULL;
    char* resolved_ip = NULL;

    // Check if this is an authoritative query
    answer = check_internal(pkt);
    
    if (answer) {
        // Handle authoritative response
        printf("✓ Responding authoritatively\n");
        
        // Parse the answer packet to print its info
        struct Packet* parsed_answer = parse_request_headers((char*)answer->request, answer->recv_len);
        if (parsed_answer) {
            print_packet_info("ANSWER", parsed_answer);
            free_packet(parsed_answer);
        }
        
        // Extract IP for logging
        resolved_ip = extract_ip_from_response(answer);
        if (resolved_ip) {
            printf("✓ Resolved IPs: %s\n", resolved_ip);
        } else {
            printf("⚠ No A/AAAA records found\n");
        }
        log_entry(client_ip, client_port, pkt->full_domain, resolved_ip);
        free(resolved_ip);
        
        if (send_response(ctx->dns_sock, answer, &ctx->client_addr) < 0) {
            fprintf(stderr, "✗ Failed to send authoritative response\n");
        } else {
            printf("✓ Sent authoritative response (%zd bytes)\n", answer->recv_len);
        }

	print_hex_dump(answer->request, answer->recv_len);
        
        free_packet(answer);
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    // Resolve recursively using upstream DNS 
    answer = resolve_recursive(pkt);
    
    if (!answer) {
        fprintf(stderr, "✗ Recursive resolution failed\n");
        log_entry(client_ip, client_port, pkt->full_domain, "FAILED");
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    // Parse the upstream response to print its info correctly
    struct Packet* parsed_answer = parse_request_headers((char*)answer->request, answer->recv_len);
    if (parsed_answer) {
        print_packet_info("ANSWER", parsed_answer);
        free_packet(parsed_answer);
    }

    // Extract IP for logging
    resolved_ip = extract_ip_from_response(answer);
    if (resolved_ip) {
        printf("✓ Resolved IPs: %s\n", resolved_ip);
    } else {
        printf("⚠ No A/AAAA records found\n");
    }
    log_entry(client_ip, client_port, pkt->full_domain, resolved_ip);
    free(resolved_ip);

    // Send response to client
    if (send_response(ctx->dns_sock, answer, &ctx->client_addr) < 0) {
        fprintf(stderr, "✗ Failed to send recursive response\n");
    } else {
        printf("✓ Sent recursive response (%zd bytes)\n", answer->recv_len);
    }

    //print_hex_dump(answer->request, answer->recv_len);

    free_packet(pkt);
    free_packet(answer);
    free(ctx->buffer);
    free(ctx);
    return NULL;
}

int main(int argc, char** argv) {

    if(load_config(argc, argv) < 0)
    {
        printf("Uasge: ./auth_dns/bin/dns <-p Upstream DNS port> <-t thread_count> <-u upstream_dns> <-q queue_size>\n");
        exit(1);
    }

    printf("=================================\n");
    printf("  DNS Server %s\n", VERSION);
    printf("=================================\n\n");

    // Load authoritative domains from file
    printf("Loading authoritative domains...\n");
    char auth_domains_path[256];
    sprintf(auth_domains_path, "%s%s", SERVER_PATH, AUTH_FILE_PATH);
    int auth_domain_count = load_auth_domains(auth_domains_path);

    if (auth_domain_count > 0) {
        fprintf(stderr, "Warning: Running with no authoritative domains\n\n");
    }

    int dns_sock;
    struct sockaddr_in dns_addr;

    // Create UDP socket for DNS
    dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_sock < 0) {
        perror("Error: Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Set socket options for address reuse
    int opt = 1;
    if (setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Error: SO_REUSEADDR failed");
        close(dns_sock);
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_addr.s_addr = INADDR_ANY;
    dns_addr.sin_port = htons(PORT);

    // Bind socket to port
    if (bind(dns_sock, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        perror("Error: Bind failed");
        printf("Note: Port %d requires root privileges. Try 'sudo' or use port >= 1024\n", PORT);
        close(dns_sock);
        exit(EXIT_FAILURE);
    }
    
    // Create thread pool
    struct ThreadPoolConfig pool_config = {
        .num_threads = g_config.thread_count,    
        .max_queue_size = g_config.thread_count
    };
    struct ThreadPool* thread_pool = threadpool_create(pool_config);
    if (!thread_pool) {
        fprintf(stderr, "Error: Failed to create thread pool\n");
        close(dns_sock);
        exit(EXIT_FAILURE);
    }
    
    printf("✓ DNS Server listening on 0.0.0.0:%d\n", PORT);
    printf("✓ Upstream DNS: %s\n", g_config.upstream_dns);
    printf("✓ Loaded %d authoritative domain(s)\n", auth_domain_count);
    printf("\nWaiting for queries...\n\n");

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned long query_count = 0;

    // Main loop
    while (1) {
        memset(&client_addr, 0, sizeof(client_addr));

        // Allocate buffer
        char* buffer = malloc(MAXLINE);
        if (!buffer) {
            perror("Error: Failed to allocate buffer");
            continue;
        }
        memset(buffer, 0, MAXLINE);

        // Receive DNS query
        ssize_t recv_len = recvfrom(dns_sock, buffer, MAXLINE, 0,
                                    (struct sockaddr*)&client_addr, &client_len);
        
        if (recv_len < 0) {
            perror("Error: recvfrom failed");
            free(buffer);
            continue;
        }

        query_count++;

        // Create context for worker thread
        struct QueryContext* ctx = malloc(sizeof(struct QueryContext));
        if (!ctx) {
            perror("Error: Failed to allocate context");
            free(buffer);
            continue;
        }

        ctx->dns_sock = dns_sock;
        ctx->client_addr = client_addr;
        ctx->buffer = buffer;
        ctx->recv_len = recv_len;
        ctx->query_num = query_count;

        // Add work to thread pool
        if (threadpool_add_work(thread_pool, process_query, ctx) < 0) {
            fprintf(stderr, "✗ Failed to queue work (pool might be full)\n");
            free(buffer);
            free(ctx);
        }
    }

    if(g_config.upstream_dns)
        free(g_config.upstream_dns);

    // Cleanup
    threadpool_wait(thread_pool);
    threadpool_destroy(thread_pool);
    close(dns_sock);
    return 0;
}
