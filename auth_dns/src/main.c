#include "auth.h"
#include "logger.h"
#include "request.h"
#include "response.h"
#include "resolve.h"
#include "types.h"
#include "utils.h"
#include "thread_pool.h"
#include "dnssec.h"

#include <poll.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <inttypes.h>

Config g_config;

/* Defined in auth.c; NULL when DNSSEC signing is not configured. */
extern ZoneKey *g_zone_keys;

/* Write PID to PID_FILE_PATH; best-effort, non-fatal. */
static void write_pid_file(void) {
    FILE *f = fopen(PID_FILE_PATH, "w");
    if (!f) { perror("Warning: Cannot write PID file " PID_FILE_PATH); return; }
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
}
static void remove_pid_file(void) { unlink(PID_FILE_PATH); }

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;

static char g_auth_domains_path[256];

/* Per-QTYPE query counters (atomic, safe for concurrent worker threads). */
static _Atomic uint64_t g_qtype_counters[256];
static _Atomic uint64_t g_total_queries;

/* Self-pipe for async-signal-safe SIGUSR2 stats dump. */
static int stats_pipe[2] = {-1, -1};

/* qtype_name() is exported from logger.c — declared in logger.h */

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
        const char* name = qtype_name((uint16_t)i);
        if (name)
            printf("║  %-10s %8" PRIu64 "               ║\n", name, c);
        else
            printf("║  TYPE%-5d %8" PRIu64 "               ║\n", i, c);
    }
    uint64_t other = atomic_load(&g_qtype_counters[0]);
    if (other)
        printf("║  %-10s %8" PRIu64 "               ║\n", "OTHER", other);
    printf("╚════════════════════════════════════════════╝\n\n");
}

/* --- TCP query context --------------------------------------------------- */
struct TCPQueryContext {
    int client_fd;
    char client_ip[INET6_ADDRSTRLEN];
    uint16_t client_port;
};

/* --- Signal handler ------------------------------------------------------- */
static void signal_handler(int signum) {
    switch (signum) {
        case SIGINT:
        case SIGTERM:
        case SIGQUIT:
            g_running = 0;
            break;
        case SIGHUP:
            g_reload = 1;
            break;
        case SIGUSR1:
        case SIGUSR2:
            if (stats_pipe[1] >= 0) {
                char b = 's';
                write(stats_pipe[1], &b, 1);
            }
            break;
        default:
            break;
    }
}

static void setup_signals(void) {
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

/* --- Socket helpers ------------------------------------------------------- */

/* Returns -1 if the kernel has no IPv6 support; doesn't exit. */
static int create_udp_socket_v6(int port) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Warning: socket() IPv6 UDP; no IPv6 support");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET,   SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,  &opt, sizeof(opt));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr   = in6addr_any;
    addr.sin6_port   = htons(port);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Warning: bind() IPv6 UDP");
        close(sock);
        return -1;
    }
    return sock;
}

static int create_tcp_socket_v4(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("Error: socket() IPv4 TCP"); return -1; }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Error: bind() IPv4 TCP"); close(sock); return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) {
        perror("Error: listen() IPv4 TCP"); close(sock); return -1;
    }
    return sock;
}

static int create_tcp_socket_v6(int port) {
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Warning: socket() IPv6 TCP; no IPv6 TCP support");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET,   SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,  &opt, sizeof(opt));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr   = in6addr_any;
    addr.sin6_port   = htons(port);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Warning: bind() IPv6 TCP"); close(sock); return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) {
        perror("Warning: listen() IPv6 TCP"); close(sock); return -1;
    }
    return sock;
}

/* --- Shared query resolution logic --------------------------------------- */

/* Send a raw SERVFAIL back over UDP without parsing the request. */
static void send_servfail_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                               const char* buf, ssize_t buf_len) {
    if (!addr || !buf || buf_len < 2) return;
    unsigned char resp[12] = {0};
    resp[0] = (unsigned char)buf[0];  // TX ID high byte
    resp[1] = (unsigned char)buf[1];  // TX ID low byte
    resp[2] = 0x80;                   // QR=1
    resp[3] = 0x80 | RCODE_SERVER_FAILURE;
    sendto(sock, resp, sizeof(resp), 0, addr, addr_len);
}

/*
 * Normalize the header flags of a forwarded (recursively-resolved) answer.
 * resolve_recursive() returns the raw authoritative-server response, whose
 * flags describe THAT server, not us.  For a recursive/forwarding answer we
 * MUST fix three bits (RFC 1035 §4.1.1):
 *   - clear AA — we are not authoritative for forwarded names
 *   - set   RA — this server provides recursion
 *   - echo  RD — mirror the client's query
 * QR, opcode, TC, AD, CD and RCODE are left exactly as the upstream set them.
 */
static void normalize_forwarded_flags(struct Packet* ans, const struct Packet* req) {
    if (!ans || !ans->request || ans->recv_len < 4 || !req) return;
    uint16_t flags = ntohs(*(uint16_t*)(ans->request + 2));
    flags &= ~(1u << 10);              /* AA = 0 */
    flags |=  (1u << 7);               /* RA = 1 */
    if (req->rd) flags |=  (1u << 8);  /* RD echo */
    else         flags &= ~(1u << 8);
    *(uint16_t*)(ans->request + 2) = htons(flags);
}

/* Core resolution: authoritative first, then recursive upstream. */
static struct Packet* resolve_query(struct Packet* pkt) {
    struct Packet* answer = check_internal(pkt);
    if (answer) return answer;
    answer = resolve_recursive(pkt);
    if (answer) normalize_forwarded_flags(answer, pkt);
    return answer;
}

/* --- UDP packet handler — called inline by each SO_REUSEPORT worker ------- */

/*
 * handle_udp_packet — core UDP query processing.
 * buf is a caller-owned stack buffer; no heap allocation needed for this path.
 */
static void handle_udp_packet(int sock,
                               const struct sockaddr_storage *caddr,
                               socklen_t clen,
                               char *buf, ssize_t n)
{
    char client_ip[INET6_ADDRSTRLEN] = "?";
    uint16_t client_port = 0;
    if (caddr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6*)caddr;
        inet_ntop(AF_INET6, &s6->sin6_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(s6->sin6_port);
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in*)caddr;
        inet_ntop(AF_INET, &s4->sin_addr, client_ip, sizeof(client_ip));
        client_port = ntohs(s4->sin_port);
    }

    struct Packet *pkt = parse_request_headers(buf, n);
    if (!pkt) {
        log_entry(client_ip, client_port, 0, "PARSE_ERROR", RCODE_SERVER_FAILURE, NULL);
        send_servfail_udp(sock, (const struct sockaddr*)caddr, clen, buf, n);
        return;
    }

    // Non-standard opcode: special-case NOTIFY (opcode 4, RFC 1996)
    if (pkt->rcode == RCODE_NOTIMP) {
        unsigned char reply[12] = {0};
        reply[0] = (unsigned char)buf[0];
        reply[1] = (unsigned char)buf[1];
        if (pkt->opcode == 4) {
            reply[2] = 0x80 | (4 << 3);
            reply[3] = 0x00;
        } else {
            reply[2] = 0x80;
            reply[3] = 0x80 | RCODE_NOTIMP;
        }
        sendto(sock, reply, sizeof(reply), 0, (const struct sockaddr*)caddr, clen);
        free_packet(pkt);
        return;
    }

    // Pre-set parser errors (e.g. FORMERR for invalid QCLASS, RFC 1035)
    if (pkt->rcode != 0) {
        unsigned char err[12] = {0};
        err[0] = (unsigned char)buf[0];
        err[1] = (unsigned char)buf[1];
        err[2] = 0x80;
        err[3] = 0x80 | (pkt->rcode & 0xF);
        sendto(sock, err, sizeof(err), 0, (const struct sockaddr*)caddr, clen);
        free_packet(pkt);
        return;
    }

    // Unsupported EDNS version: send BADVERS (RFC 6891 §6.1.3)
    if (pkt->edns_present && pkt->edns_version > 0) {
        struct Packet *bv = build_badvers_response(pkt);
        if (bv) {
            send_response(sock, bv, (const struct sockaddr*)caddr, clen);
            free_packet(bv);
        }
        free_packet(pkt);
        return;
    }

    atomic_fetch_add(&g_total_queries, 1);
    {
        uint8_t idx = (pkt->q_type < 256) ? (uint8_t)pkt->q_type : 0;
        atomic_fetch_add(&g_qtype_counters[idx], 1);
    }

    struct Packet *answer = resolve_query(pkt);

    if (!answer) {
        log_entry(client_ip, client_port, pkt->q_type, pkt->full_domain, RCODE_SERVER_FAILURE, NULL);
        struct Packet *sf = build_servfail_response(pkt);
        if (sf) {
            send_response(sock, sf, (const struct sockaddr*)caddr, clen);
            free_packet(sf);
        }
        free_packet(pkt);
        return;
    }

    char *resolved_ip = extract_ip_from_response(answer);
    {
        uint8_t ans_rcode = (answer->recv_len >= HEADER_LEN && answer->request)
            ? (uint8_t)(ntohs(*(uint16_t*)(answer->request + 2)) & 0xF) : 0;
        log_entry(client_ip, client_port, pkt->q_type, pkt->full_domain, ans_rcode, resolved_ip);
    }
    free(resolved_ip);

    finalize_udp_response(answer, pkt);
    send_response(sock, answer, (const struct sockaddr*)caddr, clen);

    free_packet(answer);
    free_packet(pkt);
}

/* --- SO_REUSEPORT UDP worker thread --------------------------------------- */

/*
 * Each UDP worker thread owns its own socket bound with SO_REUSEPORT.
 * The kernel distributes incoming datagrams across all sockets on the same
 * port, so N worker threads give N-fold parallel receive throughput with no
 * userspace lock on the hot path.  The receive buffer is stack-allocated;
 * no malloc/free is needed per query.
 */
struct UDPWorkerArg {
    int port;
    int family;   /* AF_INET or AF_INET6 */
};

static void* udp_worker_thread(void *arg)
{
    struct UDPWorkerArg *wa = arg;

    int sock = socket(wa->family, SOCK_DGRAM, 0);
    if (sock < 0) { perror("worker: socket"); free(wa); return NULL; }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        perror("Warning: SO_REUSEPORT unavailable");

    if (wa->family == AF_INET6) {
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
        struct sockaddr_in6 addr = {0};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr   = in6addr_any;
        addr.sin6_port   = htons(wa->port);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("worker: bind IPv6"); close(sock); free(wa); return NULL;
        }
    } else {
        struct sockaddr_in addr = {0};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port        = htons(wa->port);
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("worker: bind IPv4"); close(sock); free(wa); return NULL;
        }
    }

    /* 1-second recv timeout so we check g_running once per second. */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[MAXLINE];   /* stack-allocated: no malloc per query */

    while (g_running) {
        struct sockaddr_storage caddr;
        socklen_t clen = sizeof(caddr);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr*)&caddr, &clen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;   /* timeout — re-check g_running */
            perror("worker: recvfrom");
            break;
        }
        if (n < HEADER_LEN) continue;   /* too short to be DNS */
        handle_udp_packet(sock, &caddr, clen, buf, n);
    }

    close(sock);
    free(wa);
    return NULL;
}

/* --- Worker: TCP query --------------------------------------------------- */

void* process_tcp_query(void* arg) {
    struct TCPQueryContext* ctx = (struct TCPQueryContext*)arg;
    int fd = ctx->client_fd;

    // Guard against slow clients
    struct timeval tv = { .tv_sec = SOCKET_TIMEOUT, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // SO_KEEPALIVE: detect dead half-open connections (RFC 7766 §6.2.3)
    int ka = 1;
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE,   &ka,  sizeof(ka));
    int ka_idle = 60, ka_intvl = 10, ka_cnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,   &ka_idle,  sizeof(ka_idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,  &ka_intvl, sizeof(ka_intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,    &ka_cnt,   sizeof(ka_cnt));

    /* RFC 7766: process multiple queries on one TCP connection (pipelining).
     * Loop until EOF, timeout (RCVTIMEO fires), or a hard error. */
    while (1) {
        // DNS-over-TCP: 2-byte length prefix
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
            // Cannot parse: send SERVFAIL using raw TX ID, keep connection alive (RFC 7766)
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

        // Non-standard opcode: special-case NOTIFY (opcode 4, RFC 1996)
        if (pkt->rcode == RCODE_NOTIMP) {
            uint16_t reply_len_net = htons(12);
            unsigned char reply[12] = {0};
            reply[0] = (unsigned char)buffer[0];
            reply[1] = (unsigned char)buffer[1];
            if (pkt->opcode == 4) {
                /* NOTIFY: respond NOERROR QR=1 OPCODE=4 (RFC 1996 §4) */
                reply[2] = 0x80 | (4 << 3); // QR=1, OPCODE=4
                reply[3] = 0x00;             // RCODE=NOERROR
            } else {
                reply[2] = 0x80;                   // QR=1
                reply[3] = 0x80 | RCODE_NOTIMP;   // RA=1, RCODE=4
            }
            write(fd, &reply_len_net, 2);
            write(fd, reply, 12);
            free_packet(pkt);
            free(buffer);
            continue;
        }

        // Pre-set parser errors (e.g. FORMERR for invalid QCLASS, RFC 1035)
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

        // Unsupported EDNS version: send BADVERS (RFC 6891 §6.1.3)
        if (pkt->edns_present && pkt->edns_version > 0) {
            struct Packet* bv = build_badvers_response(pkt);
            if (bv) { send_tcp_response(fd, bv); free_packet(bv); }
            free_packet(pkt);
            free(buffer);
            continue;
        }

        /* Count this query. */
        atomic_fetch_add(&g_total_queries, 1);
        {
            uint8_t idx = (pkt->q_type < 256) ? (uint8_t)pkt->q_type : 0;
            atomic_fetch_add(&g_qtype_counters[idx], 1);
        }

        struct Packet* answer = resolve_query(pkt);

        if (!answer) {
            log_entry(ctx->client_ip, ctx->client_port, pkt->q_type, pkt->full_domain, RCODE_SERVER_FAILURE, NULL);
            struct Packet* sf = build_servfail_response(pkt);
            if (sf) { send_tcp_response(fd, sf); free_packet(sf); }
            free_packet(pkt);
            free(buffer);
            continue;
        }

        char* resolved_ip = extract_ip_from_response(answer);
        {
            uint8_t ans_rcode = (answer->recv_len >= HEADER_LEN && answer->request)
                ? (uint8_t)(ntohs(*(uint16_t*)(answer->request + 2)) & 0xF) : 0;
            log_entry(ctx->client_ip, ctx->client_port, pkt->q_type, pkt->full_domain, ans_rcode, resolved_ip);
        }
        free(resolved_ip);

        send_tcp_response(fd, answer);

        free_packet(answer);
        free_packet(pkt);
        free(buffer);
    }

    close(fd);
    free(ctx);
    return NULL;
}

/* --- Main ---------------------------------------------------------------- */

int main(int argc, char** argv) {
    if (load_config(argc, argv) < 0) {
        printf("Usage: ./auth_dns/bin/dns <-p Upstream DNS port> <-t thread_count> <-u upstream_dns> <-q queue_size>\n");
        exit(1);
    }

    printf("=================================\n");
    printf("  DNS Server %s\n", VERSION);
    printf("=================================\n\n");

    // Create self-pipe before setting up signals so the handler can use it.
    // Write end is O_NONBLOCK so writes in signal context never block.
    if (pipe(stats_pipe) < 0) {
        perror("Warning: Failed to create stats pipe; SIGUSR2 stats disabled");
        stats_pipe[0] = stats_pipe[1] = -1;
    } else {
        int flags = fcntl(stats_pipe[1], F_GETFL, 0);
        if (flags >= 0) fcntl(stats_pipe[1], F_SETFL, flags | O_NONBLOCK);
    }

    setup_signals();
    write_pid_file();

    // Load authoritative domains
    printf("Loading authoritative domains...\n");
    snprintf(g_auth_domains_path, sizeof(g_auth_domains_path),
             "%s%s", SERVER_PATH, AUTH_FILE_PATH);
    int loaded_count = load_auth_domains(g_auth_domains_path);
    if (loaded_count == 0) {
        fprintf(stderr, "Warning: Running with no authoritative domains\n\n");
    }

    // Load DNSSEC signing keys (non-fatal — signing stays disabled if absent)
    printf("Loading DNSSEC signing keys...\n");
    g_zone_keys = load_zone_keys(SERVER_PATH "/config");
    if (g_zone_keys)
        printf("DNSSEC online signing enabled.\n\n");
    else
        printf("DNSSEC online signing disabled (no keys configured).\n\n");

    // Create TCP sockets
    int tcp4_sock = create_tcp_socket_v4(PORT);  // may be -1
    int tcp6_sock = create_tcp_socket_v6(PORT);  // may be -1

    printf("DNS Server listening on port %d (UDP IPv4 SO_REUSEPORT", PORT);
    if (create_udp_socket_v6(PORT) >= 0) printf(", UDP IPv6 SO_REUSEPORT");
    if (tcp4_sock >= 0) printf(", TCP IPv4");
    if (tcp6_sock >= 0) printf(", TCP IPv6");
    printf(")\n");
    printf("Upstream DNS: %s:%d\n", g_config.upstream_dns, g_config.upstream_port);
    printf("Loaded %d authoritative domain(s)\n\n", loaded_count);

    /*
     * UDP: spawn N SO_REUSEPORT worker threads per address family.
     * The kernel distributes incoming datagrams across all sockets on the
     * same port, so every worker runs independently — no shared lock on the
     * UDP hot path and no per-query malloc for a receive buffer or context.
     */
    int n_udp = g_config.thread_count;
    pthread_t *udp4_threads = calloc(n_udp, sizeof(pthread_t));
    pthread_t *udp6_threads = calloc(n_udp, sizeof(pthread_t));
    int n_udp6 = 0;

    if (!udp4_threads || !udp6_threads) {
        fprintf(stderr, "Error: Failed to allocate UDP worker thread arrays\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < n_udp; i++) {
        struct UDPWorkerArg *wa = malloc(sizeof(*wa));
        if (!wa) { fprintf(stderr, "Error: malloc UDPWorkerArg\n"); exit(EXIT_FAILURE); }
        wa->port   = PORT;
        wa->family = AF_INET;
        if (pthread_create(&udp4_threads[i], NULL, udp_worker_thread, wa) != 0) {
            perror("Error: pthread_create UDP4 worker");
            exit(EXIT_FAILURE);
        }
    }

    /* Probe for IPv6 support before spawning IPv6 workers. */
    {
        int probe = socket(AF_INET6, SOCK_DGRAM, 0);
        if (probe >= 0) { close(probe); n_udp6 = n_udp; }
    }
    for (int i = 0; i < n_udp6; i++) {
        struct UDPWorkerArg *wa = malloc(sizeof(*wa));
        if (!wa) { fprintf(stderr, "Error: malloc UDPWorkerArg\n"); exit(EXIT_FAILURE); }
        wa->port   = PORT;
        wa->family = AF_INET6;
        if (pthread_create(&udp6_threads[i], NULL, udp_worker_thread, wa) != 0) {
            perror("Warning: pthread_create UDP6 worker");
            n_udp6 = i;   /* only join the threads we actually started */
            break;
        }
    }

    /*
     * TCP: dedicated thread pool sized at min(4, thread_count) so that
     * slow or idle TCP connections don't starve UDP workers.
     */
    int tcp_threads = g_config.thread_count < 4 ? g_config.thread_count : 4;
    struct ThreadPoolConfig pool_config = {
        .num_threads    = tcp_threads,
        .max_queue_size = g_config.queue_size
    };
    struct ThreadPool *thread_pool = threadpool_create(pool_config);
    if (!thread_pool) {
        fprintf(stderr, "Error: Failed to create TCP thread pool\n");
        exit(EXIT_FAILURE);
    }

    // Build poll() fd set (up to 4: TCP4, TCP6, stats_pipe, unused)
    struct pollfd pfds[4];
    int nfds = 0;
    int tcp4_idx = -1, tcp6_idx = -1, stats_idx = -1;

    if (tcp4_sock >= 0) { pfds[nfds].fd = tcp4_sock; pfds[nfds].events = POLLIN; tcp4_idx = nfds++; }
    if (tcp6_sock >= 0) { pfds[nfds].fd = tcp6_sock; pfds[nfds].events = POLLIN; tcp6_idx = nfds++; }
    pfds[nfds].fd = stats_pipe[0]; pfds[nfds].events = (stats_pipe[0] >= 0) ? POLLIN : 0; stats_idx = nfds++;

    printf("Waiting for queries...\n\n");

    while (g_running) {
        // Handle SIGHUP reload before polling
        if (g_reload) {
            g_reload = 0;
            printf("SIGHUP received — reloading auth domains from %s\n", g_auth_domains_path);
            reload_auth_domains(g_auth_domains_path);

            /* Reload DNSSEC zone keys so key rotation takes effect without restart. */
            if (g_zone_keys) { free_zone_keys(g_zone_keys); g_zone_keys = NULL; }
            g_zone_keys = load_zone_keys(SERVER_PATH "/config");
            printf("DNSSEC signing keys reloaded: %s\n",
                   g_zone_keys ? "enabled" : "disabled (no keys configured)");

            /* Reopen log file so logrotate can move the old one. */
            log_reopen();
        }

        int nready = poll(pfds, nfds, 1000);
        if (nready < 0) {
            if (errno == EINTR) continue;
            perror("Error: poll failed");
            break;
        }
        if (nready == 0) continue;

        // Handle SIGUSR1/SIGUSR2 stats request from self-pipe
        if (stats_pipe[0] >= 0 && (pfds[stats_idx].revents & POLLIN)) {
            char buf[16];
            while (read(stats_pipe[0], buf, sizeof(buf)) > 0) {}
            print_qtype_stats();
        }

        // --- TCP IPv4 accept ---
        if (tcp4_idx >= 0 && (pfds[tcp4_idx].revents & POLLIN)) {
            struct sockaddr_storage caddr;
            socklen_t clen = sizeof(caddr);
            int cfd = accept(tcp4_sock, (struct sockaddr*)&caddr, &clen);
            if (cfd >= 0) {
                struct TCPQueryContext *ctx = malloc(sizeof(*ctx));
                if (ctx) {
                    ctx->client_fd = cfd;
                    struct sockaddr_in *s4 = (struct sockaddr_in*)&caddr;
                    inet_ntop(AF_INET, &s4->sin_addr, ctx->client_ip, sizeof(ctx->client_ip));
                    ctx->client_port = ntohs(s4->sin_port);
                    if (threadpool_add_work(thread_pool, process_tcp_query, ctx) < 0) {
                        close(cfd); free(ctx);
                    }
                } else { close(cfd); }
            }
        }

        // --- TCP IPv6 accept ---
        if (tcp6_idx >= 0 && (pfds[tcp6_idx].revents & POLLIN)) {
            struct sockaddr_storage caddr;
            socklen_t clen = sizeof(caddr);
            int cfd = accept(tcp6_sock, (struct sockaddr*)&caddr, &clen);
            if (cfd >= 0) {
                struct TCPQueryContext *ctx = malloc(sizeof(*ctx));
                if (ctx) {
                    ctx->client_fd = cfd;
                    struct sockaddr_in6 *s6 = (struct sockaddr_in6*)&caddr;
                    inet_ntop(AF_INET6, &s6->sin6_addr, ctx->client_ip, sizeof(ctx->client_ip));
                    ctx->client_port = ntohs(s6->sin6_port);
                    if (threadpool_add_work(thread_pool, process_tcp_query, ctx) < 0) {
                        close(cfd); free(ctx);
                    }
                } else { close(cfd); }
            }
        }
    }

    printf("Shutting down DNS server...\n");

    /* g_running=0 causes each UDP worker to exit after its 1-second timeout. */
    for (int i = 0; i < n_udp;  i++) pthread_join(udp4_threads[i], NULL);
    for (int i = 0; i < n_udp6; i++) pthread_join(udp6_threads[i], NULL);
    free(udp4_threads);
    free(udp6_threads);

    threadpool_wait(thread_pool);
    threadpool_destroy(thread_pool);

    if (tcp4_sock >= 0) close(tcp4_sock);
    if (tcp6_sock >= 0) close(tcp6_sock);

    if (stats_pipe[0] >= 0) { close(stats_pipe[0]); stats_pipe[0] = -1; }
    if (stats_pipe[1] >= 0) { close(stats_pipe[1]); stats_pipe[1] = -1; }

    if (g_config.upstream_dns) free(g_config.upstream_dns);
    if (g_zone_keys) { free_zone_keys(g_zone_keys); g_zone_keys = NULL; }

    log_close();
    remove_pid_file();

    return 0;
}
