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

//d
void* process_query(void* arg) {
    struct QueryContext* ctx = (struct QueryContext*)arg;
    
    char* client_ip = inet_ntoa(ctx->client_addr.sin_addr);
    uint16_t client_port = ntohs(ctx->client_addr.sin_port);

    struct Packet* pkt = parse_request_headers(ctx->buffer, ctx->recv_len);
    if (!pkt) {
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    const char* qtype_str = 
        (pkt->q_type == QTYPE_A) ? "A" : 
        (pkt->q_type == QTYPE_AAAA) ? "AAAA" : 
        (pkt->q_type == QTYPE_CNAME) ? "CNAME" :
        (pkt->q_type == QTYPE_MX) ? "MX" :
        (pkt->q_type == QTYPE_NS) ? "NS" :
        (pkt->q_type == QTYPE_TXT) ? "TXT" : "OTHER";

    struct Packet* answer = format_resolver(pkt);
    if (!answer) {
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    struct Packet* ret = send_resolver(answer);
    if (!ret) {
        free_packet(pkt);
        free_packet(answer);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    // Update transaction ID to match client's
    ret->id = pkt->id;
    if (ret->request && ret->recv_len >= 2) {
        ret->request[0] = (ret->id >> 8) & 0xFF;
        ret->request[1] = ret->id & 0xFF;
    }

    // Send response
    ssize_t sent = sendto(ctx->dns_sock, ret->request, ret->recv_len, 0,
                          (struct sockaddr*)&ctx->client_addr, 
                          sizeof(ctx->client_addr));
    
    // Determine result type for logging
    const char* result;
    if (sent < 0) {
        result = "SEND_FAILED";
    } else if (ret->rcode == RCODE_NAME_ERROR) {
        result = "NXDOMAIN";  // Domain doesn't exist
    } else if (ret->rcode != RCODE_NO_ERROR) {
        result = "ERROR";
    } else if (ret->ancount > 0) {
        result = "SUCCESS";   // Got answers
    } else if (ret->aa && ret->ancount == 0) {
        result = "NODATA";    // Domain exists, no records of this type
    } else {
        result = "NO_ANSWER"; // Unexpected
    }
    
    printf("[%lu] %s:%u %s/%s -> %s\n", 
           ctx->query_num, client_ip, client_port,
           pkt->full_domain ? pkt->full_domain : "?",
           qtype_str, result);

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

    // Main server loop - just receives and dispatches to thread pool
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
