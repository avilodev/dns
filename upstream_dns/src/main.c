#include "config.h"
#include "types.h"
#include "shared_types.h"
#include "thread_pool.h"
#include "utils.h"
#include "request.h"
#include "resolve.h"
#include "cache.h"

#include <pthread.h>
#include <stdbool.h>

Config g_config;
Hints* g_hints[13];
NSCache* g_ns_cache = NULL;
AnswerCache* g_answer_cache = NULL;

static volatile sig_atomic_t g_shutdown = 1;

// Structure to hold query processing context
struct QueryContext {
    int dns_sock;
    struct sockaddr_in client_addr; 
    char* buffer;
    ssize_t recv_len;
    unsigned long query_num;
};

/**
 * Signal handler for managing server and cache operations.
 * 
 * Handles system signals to control server shutdown and cache refresh.
 * This function is async-signal-safe and only modifies sig_atomic_t variables.
 * 
 * @param signum The signal number that triggered this handler
 * 
 * @note SIGINT/SIGTERM/SIGQUIT trigger graceful shutdown
 * @note SIGUSR1 triggers cache tree refresh
 * @warning This function runs in signal context - keep it minimal
 */
void signal_handler(int signum) {
    switch (signum) {
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
            printf("\nReceived shutdown signal (%d)\n", signum);
            g_shutdown = 0;
            break;
        case SIGUSR1: 
            printf("\n");
            print_cache_stats(g_ns_cache, g_answer_cache);
            break;
        default:
            break;
    }
}

/**
 * Setup signal handlers for server management.
 * 
 * Configures handlers for shutdown signals (SIGINT/SIGTERM/SIGQUIT),
 * cache refresh signal (SIGUSR1), and ignores SIGPIPE.
 * 
 * @note SIGPIPE is ignored to prevent crashes on broken connections
 * @note All other signals invoke signal_handler()
 */
void setup_signals(void) {
    signal(SIGPIPE, SIG_IGN);  // Ignore broken pipe
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
}

/**
 * Extract IP addresses from answer section for logging
 */
const char* extract_answer_ips(struct Packet* pkt, char* buffer, size_t buffer_size)
{
    if (!pkt || !pkt->request || !buffer || buffer_size == 0) {
        return "SUCCESS";
    }
    
    buffer[0] = '\0';
    size_t offset = 0;
    
    unsigned char* buf = (unsigned char*)pkt->request;
    int pos = HEADER_LEN;
    
    // Skip question section
    for (int i = 0; i < pkt->qdcount && pos < pkt->recv_len; i++) {
        skip_dns_name(buf, pkt->recv_len, &pos);
        if (pos + 4 <= pkt->recv_len) {
            pos += 4;
        }
    }
    
    // Extract IPs from answer section
    int ip_count = 0;
    int max_ips = 4;  // Limit to 4 IPs to prevent buffer overflow
    
    for (int i = 0; i < pkt->ancount && pos < pkt->recv_len && ip_count < max_ips; i++) {
        skip_dns_name(buf, pkt->recv_len, &pos);
        
        if (pos + 10 > pkt->recv_len) break;
        
        uint16_t rr_type = ntohs(*(uint16_t*)(buf + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buf + pos + 8));
        
        if (pos + 10 + rdlength > pkt->recv_len) break;
        
        if (rr_type == QTYPE_A && rdlength == 4) {
            struct in_addr addr;
            memcpy(&addr, buf + pos + 10, 4);
            char ip_str[INET_ADDRSTRLEN];
            
            if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str))) {
                size_t needed = strlen(ip_str) + (ip_count > 0 ? 2 : 0);
                if (offset + needed + 10 >= buffer_size) break;
                
                if (ip_count > 0) {
                    offset += snprintf(buffer + offset, buffer_size - offset, ", ");
                }
                offset += snprintf(buffer + offset, buffer_size - offset, "%s", ip_str);
                ip_count++;
            }
        } else if (rr_type == QTYPE_AAAA && rdlength == 16) {
            char ipv6_str[INET6_ADDRSTRLEN];
            
            if (inet_ntop(AF_INET6, buf + pos + 10, ipv6_str, sizeof(ipv6_str))) {
                size_t needed = strlen(ipv6_str) + (ip_count > 0 ? 2 : 0);
                if (offset + needed + 10 >= buffer_size) break;
                
                if (ip_count > 0) {
                    offset += snprintf(buffer + offset, buffer_size - offset, ", ");
                }
                offset += snprintf(buffer + offset, buffer_size - offset, "%s", ipv6_str);
                ip_count++;
            }
        }
        
        pos += 10 + rdlength;
    }
    
    // Add ... if there are more IPs
    if (ip_count >= max_ips && ip_count < pkt->ancount) {
        if (offset + 10 < buffer_size) {
            snprintf(buffer + offset, buffer_size - offset, " (+%d more)", 
                     pkt->ancount - ip_count);
        }
    }
    
    if (buffer[0] == '\0') {
        return "SUCCESS";
    }
    
    return buffer;
}

void* process_query(void* arg) {
    struct QueryContext* ctx = (struct QueryContext*)arg;
    
    if (!ctx) return NULL;
    
    char* client_ip = inet_ntoa(ctx->client_addr.sin_addr);
    uint16_t client_port = ntohs(ctx->client_addr.sin_port);

    struct Packet* pkt = parse_request_headers(ctx->buffer, ctx->recv_len);
    if (!pkt) {
        fprintf(stderr, "✗ Failed to parse request from %s:%u\n", client_ip, client_port);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    // Validate parsed packet
    if (!pkt->full_domain) {
        fprintf(stderr, "✗ No domain in request from %s:%u\n", client_ip, client_port);
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    //const char* qtype_str = qtype_to_string(pkt->q_type);

    struct Packet* answer = format_resolver(pkt);
    if (!answer) {
        fprintf(stderr, "✗ Failed to format resolver for %s\n", pkt->full_domain);
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    struct Packet* ret = send_resolver(answer);
    if (!ret) {
        fprintf(stderr, "✗ Failed to resolve %s\n", pkt->full_domain);
        free_packet(pkt);
        free_packet(answer);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    // Update transaction ID to match client's
    ret->id = pkt->id;
    if (ret->request && ret->recv_len >= 2) {
        ((unsigned char*)ret->request)[0] = (ret->id >> 8) & 0xFF;
        ((unsigned char*)ret->request)[1] = ret->id & 0xFF;
    }

    // Set TC bit if response is too large for UDP
    if (ret->recv_len > 512 && ret->request && ret->recv_len >= 3) {
        ((unsigned char*)ret->request)[2] |= 0x02;  // Set TC bit
    }

    // Send response
    ssize_t sent = -1;
    if (ret->request && ret->recv_len > 0) {
        sent = sendto(ctx->dns_sock, ret->request, ret->recv_len, 0,
                     (struct sockaddr*)&ctx->client_addr, 
                     sizeof(ctx->client_addr));
    }
    
    // Determine result type for logging
    const char* result;
    char* result_buffer = malloc(2048);
    if (!result_buffer) {
        result = "MEMORY_ERROR";
    } else {
        result_buffer[0] = '\0';
        
        if (sent < 0) {
            result = "SEND_FAILED";
        } else if (ret->rcode == RCODE_NAME_ERROR) {
            result = "NXDOMAIN";
        } else if (ret->rcode != RCODE_NO_ERROR) {
            snprintf(result_buffer, 2048, "ERROR_RCODE_%u", ret->rcode);
            result = result_buffer;
        } else if (ret->ancount > 0) {
            // Extract IPs for display
            result = extract_answer_ips(ret, result_buffer, 2048);
        } else if (ret->aa && ret->ancount == 0) {
            result = "NODATA";
        } else {
            result = "NO_ANSWER";
        }
    }
    
    // Log with timestamp
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("[%s] %s:%u - %s -> %s\n", 
           timestamp, client_ip, client_port,
           pkt->full_domain, result);

    if (result_buffer) {
        free(result_buffer);
    }

    free_packet(ret);
    free_packet(answer);
    free_packet(pkt);
    free(ctx->buffer);
    free(ctx);
    return NULL;
}


int main(int argc, char** argv)
{
    int ret = load_config(argc, argv);
    if(ret < 0)
    {
        printf("Uasge: ./upstream_dns/bin/dns <-p Upstream DNS port> <-t thread_count> <-q queue_size>\n");
        exit(1);
    }

    // Setup signal handlers
    setup_signals();

    // Initialize caches BEFORE creating threads
    printf("\n=== Initializing DNS Caches ===\n");
    g_ns_cache = ns_cache_create(NS_CACHE_SIZE);
    g_answer_cache = answer_cache_create(ANSWER_CACHE_SIZE);
    
    if (!g_ns_cache || !g_answer_cache) {
        fprintf(stderr, "Error: Failed to create caches\n");
        exit(EXIT_FAILURE);
    }
    printf("=================================\n\n");

    char hints_file[256];
    sprintf(hints_file, "%s%s", SERVER_PATH, HINTS_FILE);
    ret = load_hints(hints_file);
    if(ret < 0)
    {
        printf("Hints file failed\n");
        exit(1);
    }
    printf("%d Root Servers Loaded\n", ret);

    //For random root DNS
    SEED_RANDOM();

    int dns_sock = create_server_socket(PORT);
    
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
    
    printf("\nWaiting for queries...\n\n");

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned long query_count = 0;

    // Main server loop
    while (g_shutdown) {
        memset(&client_addr, 0, sizeof(client_addr));

        // Allocate buffer for this query
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

    //Free hints file
    free_hints();

    // Cleanup (unreachable in this implementation, but good practice)
    threadpool_wait(thread_pool);
    threadpool_destroy(thread_pool);
    close(dns_sock);
    return 0;
}
