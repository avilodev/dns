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
#include <poll.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>

Config g_config;
Hints* g_hints[13];
NSCache* g_ns_cache = NULL;
AnswerCache* g_answer_cache = NULL;
TrustAnchor* g_trust_anchors = NULL;

/* Protects g_ns_cache pointer across SIGHUP swaps and concurrent readers.
 * Workers and the cleanup thread hold rdlock while using the pointer.
 * SIGHUP swap holds wrlock for the duration of the pointer swap (not destruction). */
pthread_rwlock_t g_ns_cache_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload_hints = 0;

/* Per-QTYPE query counters (atomic, safe for concurrent worker threads). */
static _Atomic uint64_t g_qtype_counters[256];
static _Atomic uint64_t g_total_queries;

/* qtype_to_string() is exported from utils.c — declared in utils.h */

static void print_qtype_stats(void) {
    uint64_t total = atomic_load(&g_total_queries);
    printf("\n╔════════════════════════════════════════════╗\n");
    printf("║           QUERY STATISTICS                 ║\n");
    printf("╠════════════════════════════════════════════╣\n");
    printf("║ Total queries: %8" PRIu64 "               ║\n", total);
    printf("╠════════════════════════════════════════════╣\n");
    for (int i = 1; i <= 255; i++) {
        uint64_t c = atomic_load(&g_qtype_counters[i]);
        if (c == 0) continue;
        const char* name = qtype_to_string((uint16_t)i);
        if (name)
            printf("║  %-10s %8" PRIu64 "               ║\n", name, c);
        else
            printf("║  TYPE%-5d %8" PRIu64 "               ║\n", i, c);
    }
    /* index 0 = "other" (qtype >= 256, should not occur in practice) */
    uint64_t other = atomic_load(&g_qtype_counters[0]);
    if (other)
        printf("║  %-10s %8" PRIu64 "               ║\n", "OTHER", other);
    printf("╚════════════════════════════════════════════╝\n\n");
}

/* --------------------------------------------------------------------------
 * Simple query logger — persistent fd, localtime_r, mutex-protected.
 * Format: [timestamp] client_ip:port QTYPE domain RCODE [-> info]
 * -------------------------------------------------------------------------- */
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_log_fd = -1;

static const char* rcode_name_up(uint8_t rcode) {
    switch (rcode) {
        case 0:  return "NOERROR";
        case 1:  return "FORMERR";
        case 2:  return "SERVFAIL";
        case 3:  return "NXDOMAIN";
        case 4:  return "NOTIMP";
        case 5:  return "REFUSED";
        case 9:  return "NOTAUTH";
        case 16: return "BADVERS";
        default: return "ERR";
    }
}

static void log_query(const char* client_ip, uint16_t port,
                      uint16_t qtype_val, const char* domain,
                      uint8_t rcode, const char* info) {
    pthread_mutex_lock(&g_log_mutex);

    if (g_log_fd < 0) {
        g_log_fd = open(LOG_FILE_PATH, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (g_log_fd < 0) {
            perror("Warning: Failed to open upstream log file");
            pthread_mutex_unlock(&g_log_mutex);
            return;
        }
    }

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char ts[26];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    const char* qt = qtype_to_string(qtype_val);
    char qt_buf[12];
    if (!qt) { snprintf(qt_buf, sizeof(qt_buf), "TYPE%u", qtype_val); qt = qt_buf; }

    char line[512];
    int len;
    if (info)
        len = snprintf(line, sizeof(line), "[%s] %s:%u %s %s %s -> %s\n",
                       ts, client_ip ? client_ip : "-", port,
                       qt, domain ? domain : "-", rcode_name_up(rcode), info);
    else
        len = snprintf(line, sizeof(line), "[%s] %s:%u %s %s %s\n",
                       ts, client_ip ? client_ip : "-", port,
                       qt, domain ? domain : "-", rcode_name_up(rcode));

    if (len > 0 && write(g_log_fd, line, len) < 0)
        perror("Warning: Upstream log write failed");

    pthread_mutex_unlock(&g_log_mutex);
}

static void log_close_upstream(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_fd >= 0) { close(g_log_fd); g_log_fd = -1; }
    pthread_mutex_unlock(&g_log_mutex);
}

// Structure to hold UDP query processing context (IPv4 or IPv6)
struct QueryContext {
    int dns_sock;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    char* buffer;
    ssize_t recv_len;
    unsigned long query_num;
};

// Structure to hold TCP query processing context
struct TCPQueryContext {
    int client_fd;
    char client_ip[INET6_ADDRSTRLEN];
    uint16_t client_port;
};

// Self-pipe for safe SIGUSR1 handling: signal handler writes to [1],
// main loop reads from [0] and calls print_cache_stats() from normal context.
static int stats_pipe[2] = {-1, -1};

/**
 * Signal handler — async-signal-safe only.
 * Sets g_shutdown flag for SIGINT/SIGTERM/SIGQUIT.
 * Writes one byte to stats_pipe for SIGUSR1 so the main loop
 * can safely call print_cache_stats() outside signal context.
 */
void signal_handler(int signum) {
    switch (signum) {
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
            g_running = 0;
            break;
        case SIGHUP:
            g_reload_hints = 1;
            break;
        case SIGUSR1:
        case SIGUSR2:
            if (stats_pipe[1] >= 0) {
                char b = 's';
                // write() is async-signal-safe; O_NONBLOCK prevents blocking
                write(stats_pipe[1], &b, 1);
            }
            break;
        default:
            break;
    }
}

/**
 * Setup signal handlers for server management.
 */
void setup_signals(void) {
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
}

static pthread_mutex_t g_cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cleanup_cond  = PTHREAD_COND_INITIALIZER;

/**
 * Background thread: sweep expired entries from both caches every 60 seconds.
 * Uses a condition variable so shutdown wakes it immediately instead of
 * waiting up to 60 seconds for the sleep() to expire.
 */
static void* cache_cleanup_thread(void* arg) {
    (void)arg;
    pthread_mutex_lock(&g_cleanup_mutex);
    while (g_running) {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 60;
        pthread_cond_timedwait(&g_cleanup_cond, &g_cleanup_mutex, &deadline);
        pthread_rwlock_rdlock(&g_ns_cache_rwlock);
        if (g_ns_cache)     ns_cache_cleanup_expired(g_ns_cache);
        pthread_rwlock_unlock(&g_ns_cache_rwlock);
        if (g_answer_cache) answer_cache_cleanup_expired(g_answer_cache);
    }
    pthread_mutex_unlock(&g_cleanup_mutex);
    return NULL;
}

/**
 * Send a minimal SERVFAIL response to the client.
 * Used when resolution fails so the client fails fast instead of timing out.
 */
static void send_servfail(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                          const unsigned char* req_buf, ssize_t req_len) {
    if (!client_addr || !req_buf || req_len < 2) return;

    unsigned char resp[12] = {0};
    resp[0] = req_buf[0];  // Transaction ID high byte
    resp[1] = req_buf[1];  // Transaction ID low byte
    // QR=1, copy OPCODE and RD from query, clear AA and TC
    resp[2] = 0x80 | (req_buf[2] & 0x79);
    // RA=1, RCODE=SERVFAIL(2)
    resp[3] = 0x80 | RCODE_SERVER_FAILURE;
    // qdcount, ancount, nscount, arcount all 0

    sendto(sock, resp, sizeof(resp), 0, client_addr, addr_len);
}

void* process_query(void* arg) {
    struct QueryContext* ctx = (struct QueryContext*)arg;

    if (!ctx) return NULL;

    char client_ip_buf[INET6_ADDRSTRLEN];
    uint16_t client_port_val;
    if (ctx->client_addr.ss_family == AF_INET6) {
        inet_ntop(AF_INET6,
                  &((struct sockaddr_in6*)&ctx->client_addr)->sin6_addr,
                  client_ip_buf, sizeof(client_ip_buf));
        client_port_val = ntohs(((struct sockaddr_in6*)&ctx->client_addr)->sin6_port);
    } else {
        inet_ntop(AF_INET,
                  &((struct sockaddr_in*)&ctx->client_addr)->sin_addr,
                  client_ip_buf, sizeof(client_ip_buf));
        client_port_val = ntohs(((struct sockaddr_in*)&ctx->client_addr)->sin_port);
    }

    const struct sockaddr* caddr = (const struct sockaddr*)&ctx->client_addr;

    struct Packet* pkt = parse_request_headers(ctx->buffer, ctx->recv_len);
    if (!pkt) {
        fprintf(stderr, "Failed to parse request from %s\n", client_ip_buf);
        send_servfail(ctx->dns_sock, caddr, ctx->client_addr_len,
                      (unsigned char*)ctx->buffer, ctx->recv_len);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    // Non-standard opcode: send NOTIMP and drop
    if (pkt->rcode == RCODE_NOTIMP) {
        unsigned char notimp[12] = {0};
        notimp[0] = (unsigned char)ctx->buffer[0];
        notimp[1] = (unsigned char)ctx->buffer[1];
        notimp[2] = 0x80;                   // QR=1
        notimp[3] = 0x80 | RCODE_NOTIMP;   // RA=1, RCODE=4
        sendto(ctx->dns_sock, notimp, sizeof(notimp), 0, caddr, ctx->client_addr_len);
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    // Pre-set parser errors (e.g. FORMERR for invalid QCLASS, RFC 1035)
    if (pkt->rcode != 0) {
        unsigned char err[12] = {0};
        err[0] = (unsigned char)ctx->buffer[0];
        err[1] = (unsigned char)ctx->buffer[1];
        err[2] = 0x80;                          // QR=1
        err[3] = 0x80 | (pkt->rcode & 0xF);    // RA=1, RCODE
        sendto(ctx->dns_sock, err, sizeof(err), 0, caddr, ctx->client_addr_len);
        free_packet(pkt); free(ctx->buffer); free(ctx);
        return NULL;
    }

    // Unsupported EDNS version: send BADVERS (RFC 6891 §6.1.3)
    if (pkt->edns_present && pkt->edns_version > 0) {
        // BADVERS = 16 (0x10): upper 8 bits go in OPT TTL extended-RCODE field (= 1),
        // lower 4 bits in header RCODE = 0
        unsigned char bv[23] = {0};
        bv[0] = (unsigned char)ctx->buffer[0];
        bv[1] = (unsigned char)ctx->buffer[1];
        bv[2] = 0x80;                   // QR=1
        bv[3] = 0x00;                   // header RCODE = 0 (extended portion in OPT)
        bv[11] = 1;                     // ARCOUNT = 1
        bv[12] = 0x00;                  // OPT owner = root
        bv[13] = 0x00; bv[14] = 0x29;  // TYPE = OPT (41)
        bv[15] = 0x02; bv[16] = 0x00;  // CLASS = 512 (UDP payload size)
        bv[17] = 0x01;                  // Extended RCODE upper 8 bits = 1 → BADVERS=16
        bv[18] = 0x00;                  // EDNS Version = 0
        bv[19] = 0x00; bv[20] = 0x00;  // Flags = 0
        bv[21] = 0x00; bv[22] = 0x00;  // RDLEN = 0
        sendto(ctx->dns_sock, bv, sizeof(bv), 0, caddr, ctx->client_addr_len);
        free_packet(pkt); free(ctx->buffer); free(ctx);
        return NULL;
    }

    if (!pkt->full_domain) {
        fprintf(stderr, "No domain in request from %s\n", client_ip_buf);
        send_servfail(ctx->dns_sock, caddr, ctx->client_addr_len,
                      (unsigned char*)ctx->buffer, ctx->recv_len);
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    /* Count this query. */
    atomic_fetch_add(&g_total_queries, 1);
    {
        uint8_t idx = (pkt->q_type < 256) ? (uint8_t)pkt->q_type : 0;
        atomic_fetch_add(&g_qtype_counters[idx], 1);
    }

    struct Packet* answer = format_resolver(pkt);
    if (!answer) {
        fprintf(stderr, "Failed to format resolver for %s\n", pkt->full_domain);
        send_servfail(ctx->dns_sock, caddr, ctx->client_addr_len,
                      (unsigned char*)ctx->buffer, ctx->recv_len);
        free_packet(pkt);
        free(ctx->buffer);
        free(ctx);
        return NULL;
    }

    struct Packet* ret = send_resolver(answer);
    if (!ret) {
        fprintf(stderr, "Failed to resolve %s\n", pkt->full_domain);
        log_query(client_ip_buf, client_port_val, pkt->q_type, pkt->full_domain,
                  RCODE_SERVER_FAILURE, NULL);
        send_servfail(ctx->dns_sock, caddr, ctx->client_addr_len,
                      (unsigned char*)ctx->buffer, ctx->recv_len);
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

    // EDNS-aware TC truncation + OPT echo (RFC 6891 §7)
    {
        uint16_t udp_limit = (pkt->edns_present && pkt->edns_udp_size >= 512)
                             ? pkt->edns_udp_size : 512;
        unsigned char* r = (ret->request && ret->recv_len >= HEADER_LEN)
                           ? (unsigned char*)ret->request : NULL;
        if (r && ret->recv_len > (ssize_t)udp_limit) {
            // Find end of question section in the response
            int qend = HEADER_LEN;
            while (qend < ret->recv_len) {
                uint8_t ll = r[qend];
                if (ll == 0)          { qend++; break; }
                if ((ll & 0xC0) == 0xC0) { qend += 2; break; }
                qend += 1 + ll;
            }
            if (qend + 4 <= ret->recv_len) qend += 4;  // skip QTYPE + QCLASS
            // Set TC=1, clear answer/authority sections
            r[2] |= 0x02;
            r[6] = 0; r[7] = 0;  // ANCOUNT = 0
            r[8] = 0; r[9] = 0;  // NSCOUNT = 0
            if (pkt->edns_present && qend + 11 <= MAXLINE) {
                // Append OPT RR: RFC 6891 §7 MUST include OPT in TC=1 response
                unsigned char* np = realloc(ret->request, qend + 11);
                if (np) {
                    ret->request = (char*)np; ret->recv_len = qend + 11; r = np;
                    r[10] = 0; r[11] = 1;  // ARCOUNT = 1
                    r[qend +  0] = 0x00;
                    r[qend +  1] = 0x00; r[qend + 2] = 0x29;  // OPT
                    r[qend +  3] = (uint8_t)(udp_limit >> 8);
                    r[qend +  4] = (uint8_t)(udp_limit & 0xFF);
                    r[qend +  5] = 0x00; r[qend + 6] = 0x00;  // ext RCODE + version
                    r[qend +  7] = 0x00; r[qend + 8] = 0x00;  // flags
                    r[qend +  9] = 0x00; r[qend +10] = 0x00;  // RDLEN
                } else {
                    ret->recv_len = qend;
                    r[10] = 0; r[11] = 0;  // ARCOUNT = 0
                }
            } else {
                ret->recv_len = qend;
                r[10] = 0; r[11] = 0;
            }
        } else if (r && pkt->edns_present) {
            // Response fits. Ensure at least one OPT is present (RFC 6891 §7 MUST).
            uint16_t arcount = ntohs(*(uint16_t*)(r + 10));
            if (arcount == 0 && ret->recv_len + 11 <= MAXLINE) {
                unsigned char* np = realloc(ret->request, ret->recv_len + 11);
                if (np) {
                    int base = (int)ret->recv_len;
                    ret->request = (char*)np; ret->recv_len += 11; r = np;
                    np[10] = 0; np[11] = 1;
                    np[base +  0] = 0x00;
                    np[base +  1] = 0x00; np[base + 2] = 0x29;
                    np[base +  3] = (uint8_t)(udp_limit >> 8);
                    np[base +  4] = (uint8_t)(udp_limit & 0xFF);
                    np[base +  5] = 0x00; np[base + 6] = 0x00;
                    np[base +  7] = 0x00; np[base + 8] = 0x00;
                    np[base +  9] = 0x00; np[base +10] = 0x00;
                }
            }
        }
    }

    // Log and send response
    {
        uint8_t ans_rcode = (ret->recv_len >= HEADER_LEN && ret->request)
            ? (uint8_t)(ntohs(*(uint16_t*)(ret->request + 2)) & 0xF) : 0;
        log_query(client_ip_buf, client_port_val, pkt->q_type,
                  pkt->full_domain, ans_rcode, NULL);
    }

    if (ret->request && ret->recv_len > 0) {
        sendto(ctx->dns_sock, ret->request, ret->recv_len, 0,
               caddr, ctx->client_addr_len);
    }

    free_packet(ret);
    free_packet(answer);
    free_packet(pkt);
    free(ctx->buffer);
    free(ctx);
    return NULL;
}

/**
 * Worker function for TCP queries.
 * Reads DNS-over-TCP messages (2-byte length prefix + payload) and resolves
 * them iteratively. Supports connection reuse / pipelining (RFC 7766).
 */
void* process_tcp_query(void* arg) {
    struct TCPQueryContext* ctx = (struct TCPQueryContext*)arg;
    int fd = ctx->client_fd;

    // Guard against slow clients
    struct timeval tv = { .tv_sec = SOCKET_TIMEOUT, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // SO_KEEPALIVE: detect dead half-open connections (RFC 7766 §6.2.3)
    int ka = 1;
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE,  &ka,  sizeof(ka));
    int ka_idle = 60, ka_intvl = 10, ka_cnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &ka_idle,  sizeof(ka_idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &ka_intvl, sizeof(ka_intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &ka_cnt,   sizeof(ka_cnt));

    /* RFC 7766: process multiple queries on one TCP connection (pipelining).
     * Loop until EOF, timeout (RCVTIMEO fires), or a hard error. */
    while (1) {
        // DNS-over-TCP: read 2-byte length prefix
        uint16_t msg_len_net;
        ssize_t n = recv(fd, &msg_len_net, 2, MSG_WAITALL);
        if (n != 2) break;  // EOF or timeout → close connection

        uint16_t msg_len = ntohs(msg_len_net);
        if (msg_len < HEADER_LEN || msg_len > MAXLINE) break;

        char* buffer = malloc(msg_len);
        if (!buffer) break;

        n = recv(fd, buffer, msg_len, MSG_WAITALL);
        if (n != msg_len) { free(buffer); break; }

        struct Packet* pkt = parse_request_headers(buffer, msg_len);
        if (!pkt) {
            // Cannot parse: send SERVFAIL using raw TX ID from buffer, keep connection
            uint16_t sf_len_net = htons(12);
            unsigned char sf[12] = {0};
            sf[0] = (unsigned char)buffer[0];
            sf[1] = (unsigned char)buffer[1];
            sf[2] = 0x80;
            sf[3] = 0x80 | RCODE_SERVER_FAILURE;
            write(fd, &sf_len_net, 2);
            write(fd, sf, 12);
            free(buffer); continue;
        }

        // Non-standard opcode: send NOTIMP, then continue pipelining
        if (pkt->rcode == RCODE_NOTIMP) {
            uint16_t notimp_len_net = htons(12);
            unsigned char notimp[12] = {0};
            notimp[0] = (unsigned char)buffer[0];
            notimp[1] = (unsigned char)buffer[1];
            notimp[2] = 0x80;                   // QR=1
            notimp[3] = 0x80 | RCODE_NOTIMP;   // RA=1, RCODE=4
            write(fd, &notimp_len_net, 2);
            write(fd, notimp, 12);
            free_packet(pkt); free(buffer);
            continue;
        }

        // Pre-set parser errors (e.g. FORMERR for invalid QCLASS)
        if (pkt->rcode != 0) {
            uint16_t err_len_net = htons(12);
            unsigned char err[12] = {0};
            err[0] = (unsigned char)buffer[0];
            err[1] = (unsigned char)buffer[1];
            err[2] = 0x80;
            err[3] = 0x80 | (pkt->rcode & 0xF);
            write(fd, &err_len_net, 2);
            write(fd, err, 12);
            free_packet(pkt); free(buffer); continue;
        }

        if (!pkt->full_domain) {
            uint16_t sf_len_net = htons(12);
            unsigned char sf[12] = {0};
            sf[0] = (unsigned char)buffer[0];
            sf[1] = (unsigned char)buffer[1];
            sf[2] = 0x80;
            sf[3] = 0x80 | RCODE_SERVER_FAILURE;
            write(fd, &sf_len_net, 2);
            write(fd, sf, 12);
            free_packet(pkt); free(buffer); continue;
        }

        struct Packet* answer = format_resolver(pkt);
        if (!answer) {
            uint16_t sf_len_net = htons(12);
            unsigned char sf[12] = {0};
            sf[0] = (pkt->id >> 8) & 0xFF;
            sf[1] = pkt->id & 0xFF;
            sf[2] = 0x80;
            sf[3] = 0x80 | RCODE_SERVER_FAILURE;
            write(fd, &sf_len_net, 2);
            write(fd, sf, 12);
            free_packet(pkt); free(buffer); continue;
        }

        struct Packet* ret = send_resolver(answer);
        if (!ret) {
            log_query(ctx->client_ip, ctx->client_port, pkt->q_type,
                      pkt->full_domain, RCODE_SERVER_FAILURE, NULL);
            // Send SERVFAIL to client so it gets an answer rather than timing out
            uint16_t sf_len_net = htons(12);
            unsigned char sf[12] = {0};
            sf[0] = (pkt->id >> 8) & 0xFF;
            sf[1] = pkt->id & 0xFF;
            sf[2] = 0x80;
            sf[3] = 0x80 | RCODE_SERVER_FAILURE;
            write(fd, &sf_len_net, 2);
            write(fd, sf, 12);
            free_packet(pkt); free_packet(answer); free(buffer);
            continue;
        }

        // Update transaction ID to match client's
        ret->id = pkt->id;
        if (ret->request && ret->recv_len >= 2) {
            ((unsigned char*)ret->request)[0] = (ret->id >> 8) & 0xFF;
            ((unsigned char*)ret->request)[1] = ret->id & 0xFF;
        }
        // Note: do NOT set TC bit for TCP responses — TCP has no 512-byte limit

        {
            uint8_t ans_rcode = (ret->recv_len >= HEADER_LEN && ret->request)
                ? (uint8_t)(ntohs(*(uint16_t*)(ret->request + 2)) & 0xF) : 0;
            log_query(ctx->client_ip, ctx->client_port, pkt->q_type,
                      pkt->full_domain, ans_rcode, NULL);
        }

        // Send TCP response: 2-byte length prefix + payload
        if (ret->request && ret->recv_len > 0) {
            uint16_t resp_len = htons((uint16_t)ret->recv_len);
            const uint8_t* p = (const uint8_t*)&resp_len;
            size_t rem = 2;
            bool send_ok = true;
            while (rem > 0) {
                ssize_t nw = write(fd, p, rem);
                if (nw <= 0) { send_ok = false; break; }
                p += nw; rem -= (size_t)nw;
            }
            if (send_ok) {
                p = (const uint8_t*)ret->request;
                rem = (size_t)ret->recv_len;
                while (rem > 0) {
                    ssize_t nw = write(fd, p, rem);
                    if (nw <= 0) break;
                    p += nw; rem -= (size_t)nw;
                }
            }
        }

        free_packet(ret);
        free_packet(answer);
        free_packet(pkt);
        free(buffer);
    }

    close(fd);
    free(ctx);
    return NULL;
}


int main(int argc, char** argv)
{
    int ret = load_config(argc, argv);
    if (ret < 0) {
        printf("Usage: ./upstream_dns/bin/dns <-p Upstream DNS port> <-t thread_count> <-q queue_size>\n");
        exit(1);
    }

    // Create self-pipe before setting up signals so the handler can use it.
    // Write end is O_NONBLOCK so writes in signal context never block.
    if (pipe(stats_pipe) < 0) {
        perror("Warning: Failed to create stats pipe; SIGUSR1 stats disabled");
        stats_pipe[0] = stats_pipe[1] = -1;
    } else {
        int flags = fcntl(stats_pipe[1], F_GETFL, 0);
        if (flags >= 0) fcntl(stats_pipe[1], F_SETFL, flags | O_NONBLOCK);
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

    // Start background cache cleanup thread.
    // Not detached — we join it during shutdown to avoid a race where
    // the thread accesses caches after they are destroyed.
    pthread_t cleanup_tid = 0;
    bool cleanup_thread_started = false;
    if (pthread_create(&cleanup_tid, NULL, cache_cleanup_thread, NULL) == 0) {
        cleanup_thread_started = true;
    } else {
        perror("Warning: Failed to create cache cleanup thread; expired entries won't be pruned");
    }

    char hints_file[256];
    snprintf(hints_file, sizeof(hints_file), "%s%s", SERVER_PATH, HINTS_FILE);
    ret = load_hints(hints_file);
    if (ret < 0) {
        fprintf(stderr, "Warning: Cannot read hints file %s; using built-in root hints\n", hints_file);
        ret = load_hints_builtin();
    }
    if (ret < 0) {
        fprintf(stderr, "Error: No root hints available — cannot start\n");
        exit(1);
    }
    printf("%d Root Servers Loaded\n", ret);

    // Load DNSSEC trust anchors (non-fatal if missing — DNSSEC validation skipped)
    char trust_anchor_file[256];
    snprintf(trust_anchor_file, sizeof(trust_anchor_file),
             "%s/config/root-trust-anchor.key", SERVER_PATH);
    g_trust_anchors = load_trust_anchors(trust_anchor_file);
    if (!g_trust_anchors) {
        fprintf(stderr, "Warning: No trust anchors loaded — DNSSEC validation disabled\n");
    }

    // Create all listeners
    int udp4_sock = create_server_socket(PORT);
    int udp6_sock = create_server_socket_v6(PORT);  // may be -1
    int tcp4_sock = create_tcp_socket_v4(PORT);     // may be -1
    int tcp6_sock = create_tcp_socket_v6(PORT);     // may be -1

    // Create thread pool — use g_config.queue_size for the work queue
    struct ThreadPoolConfig pool_config = {
        .num_threads    = g_config.thread_count,
        .max_queue_size = g_config.queue_size
    };
    struct ThreadPool* thread_pool = threadpool_create(pool_config);
    if (!thread_pool) {
        fprintf(stderr, "Error: Failed to create thread pool\n");
        close(udp4_sock);
        if (udp6_sock >= 0) close(udp6_sock);
        if (tcp4_sock >= 0) close(tcp4_sock);
        if (tcp6_sock >= 0) close(tcp6_sock);
        exit(EXIT_FAILURE);
    }

    unsigned long query_count = 0;

    // Build poll() fd set — up to 5 fds: UDP4, stats pipe, UDP6, TCP4, TCP6
    struct pollfd pfds[5];
    int nfds = 0;
    int udp4_idx, stats_idx, udp6_idx = -1, tcp4_idx = -1, tcp6_idx = -1;

    pfds[nfds].fd = udp4_sock; pfds[nfds].events = POLLIN; udp4_idx = nfds++;
    pfds[nfds].fd = stats_pipe[0];
    pfds[nfds].events = (stats_pipe[0] >= 0) ? POLLIN : 0;
    stats_idx = nfds++;
    if (udp6_sock >= 0) { pfds[nfds].fd = udp6_sock; pfds[nfds].events = POLLIN; udp6_idx = nfds++; }
    if (tcp4_sock >= 0) { pfds[nfds].fd = tcp4_sock; pfds[nfds].events = POLLIN; tcp4_idx = nfds++; }
    if (tcp6_sock >= 0) { pfds[nfds].fd = tcp6_sock; pfds[nfds].events = POLLIN; tcp6_idx = nfds++; }

    // Main server loop — uses poll() to multiplex all sockets and the stats pipe.
    while (g_running) {
        // Handle SIGHUP: reload root hints from disk and flush the NS cache
        // so stale entries pointing to old IPs don't survive the reload.
        if (g_reload_hints) {
            g_reload_hints = 0;
            printf("SIGHUP received — reloading root hints from %s\n", hints_file);
            free_hints();
            int n = load_hints(hints_file);
            if (n > 0)
                printf("Root hints reloaded: %d server(s)\n", n);
            else
                fprintf(stderr, "Warning: Hints reload failed; root hints may be empty\n");

            // Flush NS cache: root hint IPs may have changed and cached zone
            // apex → IP entries could now point to unreachable servers.
            // wrlock ensures no worker is mid-read of the old pointer when we swap.
            NSCache* new_ns = ns_cache_create(NS_CACHE_SIZE);
            NSCache* old_ns = NULL;
            pthread_rwlock_wrlock(&g_ns_cache_rwlock);
            if (new_ns) {
                old_ns   = g_ns_cache;
                g_ns_cache = new_ns;
            }
            pthread_rwlock_unlock(&g_ns_cache_rwlock);
            // Destroy the old cache outside the lock (no reader can reference it now)
            if (new_ns)
                printf("NS cache flushed.\n");
            else
                fprintf(stderr, "Warning: Failed to create new NS cache; keeping old one\n");
            if (old_ns) ns_cache_destroy(old_ns);
        }

        // 1-second timeout so we re-check g_shutdown promptly after a signal
        int nready = poll(pfds, nfds, 1000);
        if (nready < 0) {
            if (errno == EINTR) continue;
            perror("Error: poll failed");
            break;
        }

        if (nready == 0) continue;  // timeout — loop to check g_shutdown

        // Handle SIGUSR1 stats request from self-pipe
        if (stats_pipe[0] >= 0 && (pfds[stats_idx].revents & POLLIN)) {
            char buf[16];
            // Drain all pending bytes (multiple signals may have queued)
            while (read(stats_pipe[0], buf, sizeof(buf)) > 0) {}
            print_cache_stats(g_ns_cache, g_answer_cache);
            print_qtype_stats();
        }

        // --- UDP IPv4 — drain all pending datagrams before returning to poll() ---
        if (pfds[udp4_idx].revents & POLLIN) {
            while (1) {
                char* buffer = malloc(MAXLINE);
                if (!buffer) { perror("Error: malloc"); break; }

                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                memset(&client_addr, 0, sizeof(client_addr));

                ssize_t recv_len = recvfrom(udp4_sock, buffer, MAXLINE, MSG_DONTWAIT,
                                            (struct sockaddr*)&client_addr, &client_len);
                if (recv_len < 0) {
                    free(buffer);
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        perror("Error: recvfrom UDP4");
                    break;  // kernel buffer drained
                }

                query_count++;

                struct QueryContext* ctx = malloc(sizeof(struct QueryContext));
                if (!ctx) {
                    send_servfail(udp4_sock, (const struct sockaddr*)&client_addr,
                                  client_len, (unsigned char*)buffer, recv_len);
                    free(buffer); break;
                }

                ctx->dns_sock = udp4_sock;
                memset(&ctx->client_addr, 0, sizeof(ctx->client_addr));
                memcpy(&ctx->client_addr, &client_addr, client_len);
                ctx->client_addr_len = client_len;
                ctx->buffer      = buffer;
                ctx->recv_len    = recv_len;
                ctx->query_num   = query_count;

                if (threadpool_add_work(thread_pool, process_query, ctx) < 0) {
                    fprintf(stderr, "Error: Failed to queue work (pool might be full)\n");
                    send_servfail(udp4_sock, (const struct sockaddr*)&client_addr,
                                  client_len, (unsigned char*)buffer, recv_len);
                    free(buffer); free(ctx);
                }
            }
        }

        // --- UDP IPv6 — drain all pending datagrams before returning to poll() ---
        if (udp6_idx >= 0 && (pfds[udp6_idx].revents & POLLIN)) {
            while (1) {
                char* buffer = malloc(MAXLINE);
                if (!buffer) { perror("Error: malloc"); break; }

                struct sockaddr_in6 client_addr6;
                socklen_t client_len = sizeof(client_addr6);
                memset(&client_addr6, 0, sizeof(client_addr6));

                ssize_t recv_len = recvfrom(udp6_sock, buffer, MAXLINE, MSG_DONTWAIT,
                                            (struct sockaddr*)&client_addr6, &client_len);
                if (recv_len < 0) {
                    free(buffer);
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        perror("Error: recvfrom UDP6");
                    break;  // kernel buffer drained
                }

                query_count++;

                struct QueryContext* ctx = malloc(sizeof(struct QueryContext));
                if (!ctx) {
                    send_servfail(udp6_sock, (const struct sockaddr*)&client_addr6,
                                  client_len, (unsigned char*)buffer, recv_len);
                    free(buffer); break;
                }

                ctx->dns_sock = udp6_sock;
                memset(&ctx->client_addr, 0, sizeof(ctx->client_addr));
                memcpy(&ctx->client_addr, &client_addr6, client_len);
                ctx->client_addr_len = client_len;
                ctx->buffer      = buffer;
                ctx->recv_len    = recv_len;
                ctx->query_num   = query_count;

                if (threadpool_add_work(thread_pool, process_query, ctx) < 0) {
                    fprintf(stderr, "Error: Failed to queue work (pool might be full)\n");
                    send_servfail(udp6_sock, (const struct sockaddr*)&client_addr6,
                                  client_len, (unsigned char*)buffer, recv_len);
                    free(buffer); free(ctx);
                }
            }
        }

        // --- TCP IPv4 accept ---
        if (tcp4_idx >= 0 && (pfds[tcp4_idx].revents & POLLIN)) {
            struct sockaddr_in caddr;
            socklen_t clen = sizeof(caddr);
            int cfd = accept(tcp4_sock, (struct sockaddr*)&caddr, &clen);
            if (cfd >= 0) {
                struct TCPQueryContext* ctx = malloc(sizeof(*ctx));
                if (ctx) {
                    ctx->client_fd = cfd;
                    inet_ntop(AF_INET, &caddr.sin_addr, ctx->client_ip, sizeof(ctx->client_ip));
                    ctx->client_port = ntohs(caddr.sin_port);
                    if (threadpool_add_work(thread_pool, process_tcp_query, ctx) < 0) {
                        close(cfd); free(ctx);
                    }
                } else { close(cfd); }
            }
        }

        // --- TCP IPv6 accept ---
        if (tcp6_idx >= 0 && (pfds[tcp6_idx].revents & POLLIN)) {
            struct sockaddr_in6 caddr6;
            socklen_t clen = sizeof(caddr6);
            int cfd = accept(tcp6_sock, (struct sockaddr*)&caddr6, &clen);
            if (cfd >= 0) {
                struct TCPQueryContext* ctx = malloc(sizeof(*ctx));
                if (ctx) {
                    ctx->client_fd = cfd;
                    inet_ntop(AF_INET6, &caddr6.sin6_addr, ctx->client_ip, sizeof(ctx->client_ip));
                    ctx->client_port = ntohs(caddr6.sin6_port);
                    if (threadpool_add_work(thread_pool, process_tcp_query, ctx) < 0) {
                        close(cfd); free(ctx);
                    }
                } else { close(cfd); }
            }
        }
    }

    // Wake cleanup thread so it sees g_shutdown == 0 and exits promptly.
    pthread_mutex_lock(&g_cleanup_mutex);
    pthread_cond_signal(&g_cleanup_cond);
    pthread_mutex_unlock(&g_cleanup_mutex);

    // Join the cleanup thread before destroying the caches it accesses.
    if (cleanup_thread_started)
        pthread_join(cleanup_tid, NULL);

    // Cleanup
    if (stats_pipe[0] >= 0) close(stats_pipe[0]);
    if (stats_pipe[1] >= 0) close(stats_pipe[1]);

    free_hints();
    free_trust_anchors(g_trust_anchors);
    g_trust_anchors = NULL;

    threadpool_wait(thread_pool);
    threadpool_destroy(thread_pool);

    pthread_rwlock_destroy(&g_ns_cache_rwlock);
    ns_cache_destroy(g_ns_cache);
    g_ns_cache = NULL;
    answer_cache_destroy(g_answer_cache);
    g_answer_cache = NULL;

    close(udp4_sock);
    if (udp6_sock >= 0) close(udp6_sock);
    if (tcp4_sock >= 0) close(tcp4_sock);
    if (tcp6_sock >= 0) close(tcp6_sock);

    log_close_upstream();

    return 0;
}
