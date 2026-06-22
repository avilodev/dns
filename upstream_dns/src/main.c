#include "config.h"
#include "types.h"
#include "shared_types.h"
#include "thread_pool.h"
#include "utils.h"
#include "request.h"
#include "resolve.h"
#include "cache.h"
#include "access_control.h"
#include "query_log.h"

#include <pthread.h>
#include <stdbool.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>

Config g_config;
Hints* g_hints[13];
NSCache* g_ns_cache = NULL;
AnswerCache* g_answer_cache = NULL;
TrustAnchor* g_trust_anchors = NULL;

/* Write PID to PID_FILE_PATH; best-effort, non-fatal. */
static void write_pid_file(void) {
    FILE *f = fopen(PID_FILE_PATH, "w");
    if (!f) { perror("Warning: Cannot write PID file " PID_FILE_PATH); return; }
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
}
static void remove_pid_file(void)
{
    unlink(PID_FILE_PATH);
}

/*
 * Drop from root to an unprivileged user[:group] after the listeners are bound.
 * The upstream resolver's default port (5335) does not need root, but if it is
 * started as root (e.g. a systemd unit without User=) we still drop so the
 * network-facing parser/validator does not run privileged.  No-op when not
 * root; fatal on any failure.  `spec` is "user" or "user:group".
 */
static void drop_privileges(const char *spec) {
    if (geteuid() != 0) return;                 /* not root — nothing to drop */
    if (!spec || !*spec) {
        fprintf(stderr, "Warning: running as root with no -U user; "
                        "NOT dropping privileges (set -U or a systemd User=)\n");
        return;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *colon = strchr(buf, ':');
    const char *gname = NULL;
    if (colon) { *colon = '\0'; gname = colon + 1; }

    struct passwd *pw = getpwnam(buf);
    if (!pw) { fprintf(stderr, "Error: -U unknown user '%s'\n", buf); exit(EXIT_FAILURE); }
    uid_t uid = pw->pw_uid;
    gid_t gid = pw->pw_gid;
    if (gname && *gname) {
        struct group *gr = getgrnam(gname);
        if (!gr) { fprintf(stderr, "Error: -U unknown group '%s'\n", gname); exit(EXIT_FAILURE); }
        gid = gr->gr_gid;
    }
    if (uid == 0) { fprintf(stderr, "Error: -U user '%s' is root\n", buf); exit(EXIT_FAILURE); }

    if (setgroups(1, &gid) != 0) { perror("Error: setgroups"); exit(EXIT_FAILURE); }
    if (setgid(gid)        != 0) { perror("Error: setgid");    exit(EXIT_FAILURE); }
    if (setuid(uid)        != 0) { perror("Error: setuid");    exit(EXIT_FAILURE); }
    if (setuid(0) == 0) {
        fprintf(stderr, "Error: privilege drop failed — still able to regain root\n");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Dropped privileges to %s (uid=%d gid=%d)\n",
            buf, (int)uid, (int)gid);
}

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
    printf("Query statistics:\n");
    printf("  Total queries: %" PRIu64 "\n", atomic_load(&g_total_queries));
    for (int i = 1; i <= 255; i++) {
        uint64_t c = atomic_load(&g_qtype_counters[i]);
        if (c == 0) continue;
        const char* name = qtype_to_string((uint16_t)i);
        if (name) printf("  %-10s %" PRIu64 "\n", name, c);
        else      printf("  TYPE%-6d %" PRIu64 "\n", i, c);
    }
    /* index 0 = "other" (qtype >= 256, should not occur in practice) */
    uint64_t other = atomic_load(&g_qtype_counters[0]);
    if (other) printf("  %-10s %" PRIu64 "\n", "OTHER", other);
}

// Structure to hold UDP query processing context (IPv4 or IPv6).
// buffer is embedded directly (no separate malloc/free per query).
struct QueryContext {
    int dns_sock;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    char buffer[MAXLINE];
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

/*
 * Signal handler — async-signal-safe only.
 * Clears g_running for SIGINT/SIGTERM/SIGQUIT (triggers graceful shutdown).
 * Writes one byte to stats_pipe for SIGUSR1/SIGUSR2 so the main loop
 * can safely call print_qtype_stats() outside signal context.
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
                if (write(stats_pipe[1], &b, 1) < 0) { /* best-effort */ }
            }
            break;
        default:
            break;
    }
}

/*
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

/*
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

/*
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

/*
 * Send a minimal REFUSED reply (RFC 1035 RCODE 5) — used to reject queries
 * from sources outside the configured allow-list (known_issues 4.3).  A small
 * header-only reply keeps the refusal from being usable for amplification.
 */
static void send_refused(int sock, const struct sockaddr* client_addr,
                         socklen_t addr_len,
                         const unsigned char* req_buf, ssize_t req_len) {
    if (!client_addr || !req_buf || req_len < 2) return;

    unsigned char resp[12] = {0};
    resp[0] = req_buf[0];  // Transaction ID high byte
    resp[1] = req_buf[1];  // Transaction ID low byte
    // QR=1, copy OPCODE and RD from query, clear AA and TC
    resp[2] = 0x80 | (req_buf[2] & 0x79);
    // RA=1, RCODE=REFUSED(5)
    resp[3] = 0x80 | RCODE_REFUSED;
    // qdcount, ancount, nscount, arcount all 0

    sendto(sock, resp, sizeof(resp), 0, client_addr, addr_len);
}

/*
 * Lightweight inline parser: extract the QNAME (dotted string) and QTYPE
 * from a raw DNS query packet without allocating any memory.
 * Returns 1 on success, 0 if the packet is malformed or not a standard query.
 */
static int quick_parse_query(const char* buf, ssize_t len,
                              char* domain_out, int domain_max,
                              uint16_t* qtype_out, bool* do_out,
                              uint16_t* edns_size_out)
{
    if (do_out) *do_out = false;
    if (edns_size_out) *edns_size_out = 0;   /* 0 = client sent no EDNS OPT */
    if (len < 17) return 0;                          // header(12) + min QNAME(1) + null(1) + QTYPE(2) + QCLASS(2)
    if (buf[2] & 0x80) return 0;                     // QR=1 means response, not a query
    if ((uint8_t)buf[4] != 0 || (uint8_t)buf[5] != 1) return 0;  // QDCOUNT must be 1

    int pos = 12;
    int out_pos = 0;
    while (pos < len) {
        uint8_t ll = (uint8_t)buf[pos++];
        if (ll == 0) break;
        if ((ll & 0xC0) == 0xC0) return 0;           // compression in question section = malformed
        if (ll > 63 || pos + ll > len) return 0;
        if (out_pos > 0) {
            if (out_pos + 1 >= domain_max) return 0;
            domain_out[out_pos++] = '.';
        }
        if (out_pos + (int)ll >= domain_max) return 0;
        for (int i = 0; i < (int)ll; i++)
            domain_out[out_pos++] = (char)tolower((unsigned char)buf[pos++]);
    }
    domain_out[out_pos] = '\0';

    if (pos + 4 > len) return 0;
    *qtype_out = (uint16_t)(((uint8_t)buf[pos] << 8) | (uint8_t)buf[pos + 1]);

    /* Scan the additional section for the EDNS OPT record to learn (a) whether
     * the client set the DO (DNSSEC OK) bit — needed so the fast path never
     * serves a signed-but-unvalidated cached answer to a validating client —
     * and (b) the client's advertised UDP payload size, needed so the fast
     * path can apply EDNS-aware TC truncation just like the worker path. */
    if (do_out || edns_size_out) {
        int p = pos + 4;  /* past QTYPE(2) + QCLASS(2) */
        int an = ((uint8_t)buf[6]  << 8) | (uint8_t)buf[7];
        int ns = ((uint8_t)buf[8]  << 8) | (uint8_t)buf[9];
        int ar = ((uint8_t)buf[10] << 8) | (uint8_t)buf[11];
        int total = an + ns + ar;
        for (int i = 0; i < total && p < len; i++) {
            while (p < len) {                        /* skip owner name */
                uint8_t l = (uint8_t)buf[p];
                if (l == 0)              { p += 1; break; }
                if ((l & 0xC0) == 0xC0)  { p += 2; break; }
                p += 1 + l;
            }
            if (p + 10 > len) break;
            uint16_t rtype  = ((uint8_t)buf[p] << 8) | (uint8_t)buf[p + 1];
            uint16_t rclass = ((uint8_t)buf[p + 2] << 8) | (uint8_t)buf[p + 3];
            uint32_t rttl  = ((uint32_t)(uint8_t)buf[p + 4] << 24) |
                             ((uint32_t)(uint8_t)buf[p + 5] << 16) |
                             ((uint32_t)(uint8_t)buf[p + 6] <<  8) |
                              (uint32_t)(uint8_t)buf[p + 7];
            uint16_t rdlen = ((uint8_t)buf[p + 8] << 8) | (uint8_t)buf[p + 9];
            if (rtype == 41) {                       /* OPT: CLASS = UDP size */
                if (do_out)        *do_out = (rttl & 0x00008000u) != 0;
                if (edns_size_out) *edns_size_out = rclass ? rclass : 512;
                break;
            }
            p += 10 + rdlen;
        }
    }
    return 1;
}

/*
 * Apply EDNS-aware UDP truncation to a finished response buffer, in place.
 * Shared by the worker path (process_query) and the zero-alloc cache fast
 * path so the two can never drift (the fast path previously skipped this and
 * could send a >512-byte UDP answer to a non-EDNS client — RFC 1035 §4.2.1).
 *
 *   *buf / *len    : malloc'd response bytes; updated (may be realloc'd).
 *   edns_udp_size  : client's advertised EDNS UDP payload size, or 0 when the
 *                    client sent no OPT (→ 512-byte limit).
 *
 * Over the limit → set TC=1, drop the answer/authority sections, and (for EDNS
 * clients) append a bare OPT RR (RFC 6891 §7).  Truncation only shrinks the
 * buffer, so that OPT always fits without a realloc.  Within the limit, a bare
 * OPT is appended for EDNS clients that lack one (best-effort).
 */
static void finalize_udp_truncation(char** buf, ssize_t* len, uint16_t edns_udp_size)
{
    if (!buf || !*buf || !len || *len < HEADER_LEN) return;

    bool     edns      = (edns_udp_size != 0);
    uint16_t udp_limit = (edns && edns_udp_size >= 512) ? edns_udp_size : 512;
    unsigned char* r   = (unsigned char*)*buf;

    if (*len > (ssize_t)udp_limit) {
        /* Find end of the question section. */
        int qend = HEADER_LEN;
        while (qend < *len) {
            uint8_t ll = r[qend];
            if (ll == 0)             { qend++; break; }
            if ((ll & 0xC0) == 0xC0) { qend += 2; break; }
            qend += 1 + ll;
        }
        if (qend + 4 <= *len) qend += 4;       /* QTYPE + QCLASS */

        r[2] |= 0x02;                           /* TC = 1                  */
        r[6] = 0; r[7] = 0;                     /* ANCOUNT = 0             */
        r[8] = 0; r[9] = 0;                     /* NSCOUNT = 0             */

        if (edns && qend + 11 <= *len) {        /* room guaranteed (shrank) */
            r[10] = 0; r[11] = 1;               /* ARCOUNT = 1             */
            r[qend + 0] = 0x00;                 /* root owner              */
            r[qend + 1] = 0x00; r[qend + 2] = 0x29;            /* TYPE = OPT */
            r[qend + 3] = (uint8_t)(udp_limit >> 8);
            r[qend + 4] = (uint8_t)(udp_limit & 0xFF);         /* UDP size  */
            r[qend + 5] = 0x00; r[qend + 6] = 0x00;            /* xRCODE/ver */
            r[qend + 7] = 0x00; r[qend + 8] = 0x00;            /* flags     */
            r[qend + 9] = 0x00; r[qend +10] = 0x00;            /* RDLEN = 0 */
            *len = qend + 11;
        } else {
            r[10] = 0; r[11] = 0;               /* ARCOUNT = 0             */
            *len = qend;
        }
        return;
    }

    /* Within the limit: ensure an OPT is present for EDNS clients (RFC 6891 §7). */
    if (edns) {
        uint16_t arcount = (uint16_t)((r[10] << 8) | r[11]);
        if (arcount == 0 && *len + 11 <= MAXLINE) {
            unsigned char* np = realloc(*buf, (size_t)*len + 11);
            if (np) {
                int base = (int)*len;
                *buf = (char*)np;
                np[10] = 0; np[11] = 1;
                np[base + 0] = 0x00;
                np[base + 1] = 0x00; np[base + 2] = 0x29;
                np[base + 3] = (uint8_t)(udp_limit >> 8);
                np[base + 4] = (uint8_t)(udp_limit & 0xFF);
                np[base + 5] = 0x00; np[base + 6] = 0x00;
                np[base + 7] = 0x00; np[base + 8] = 0x00;
                np[base + 9] = 0x00; np[base +10] = 0x00;
                *len += 11;
            }
        }
    }
}

/*
 * Normalize the header flags of a forwarded (recursively-resolved) answer in
 * place.  send_resolver() returns the raw authoritative-server response, whose
 * flags describe THAT server, not us.  This resolver has no zones of its own, so
 * every answer it returns is recursive and MUST fix three bits (RFC 1035 §4.1.1):
 *   - clear AA — we are not authoritative for forwarded names
 *   - set   RA — this server provides recursion
 *   - echo  RD — mirror the client's query
 * QR, opcode, TC, AD, CD and RCODE are left exactly as the upstream set them.
 * (auth_dns carries the identical fix in its own normalize_forwarded_flags.)
 */
static void normalize_forwarded_flags(unsigned char* resp, ssize_t len, int client_rd)
{
    if (!resp || len < 4) return;
    uint16_t flags = ntohs(*(uint16_t*)(resp + 2));
    flags &= ~(1u << 10);                /* AA = 0 */
    flags |=  (1u << 7);                 /* RA = 1 */
    if (client_rd) flags |=  (1u << 8);  /* RD echo */
    else           flags &= ~(1u << 8);
    *(uint16_t*)(resp + 2) = htons(flags);
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
        free_packet(pkt); free(ctx);
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
        free_packet(pkt); free(ctx);
        return NULL;
    }

    if (!pkt->full_domain) {
        fprintf(stderr, "No domain in request from %s\n", client_ip_buf);
        send_servfail(ctx->dns_sock, caddr, ctx->client_addr_len,
                      (unsigned char*)ctx->buffer, ctx->recv_len);
        free_packet(pkt);
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
        free(ctx);
        return NULL;
    }

    /* Carry the client's DNSSEC intent (DO/CD) onto the resolver query so
     * validation runs only when the client asked for it (RFC 4035 §3.2.2).
     * format_resolver()/set_packet_fields() zero these on the outgoing wire
     * query, so we copy them from the parsed client request here. */
    answer->do_bit = pkt->do_bit;
    answer->cd     = pkt->cd;

    struct Packet* ret = send_resolver(answer);
    if (!ret) {
        fprintf(stderr, "Failed to resolve %s\n", pkt->full_domain);
        log_query(client_ip_buf, client_port_val, pkt->q_type, pkt->full_domain,
                  RCODE_SERVER_FAILURE, NULL);
        send_servfail(ctx->dns_sock, caddr, ctx->client_addr_len,
                      (unsigned char*)ctx->buffer, ctx->recv_len);
        free_packet(pkt);
        free_packet(answer);
        free(ctx);
        return NULL;
    }

    // Update transaction ID to match client's
    ret->id = pkt->id;
    if (ret->request && ret->recv_len >= 2) {
        ((unsigned char*)ret->request)[0] = (ret->id >> 8) & 0xFF;
        ((unsigned char*)ret->request)[1] = ret->id & 0xFF;
    }

    // Present our own recursive-resolver flags, not the upstream authority's
    // (clear AA, set RA, echo client RD) — RFC 1035 §4.1.1.
    normalize_forwarded_flags((unsigned char*)ret->request, ret->recv_len, pkt->rd);

    // A client that did not set DO must not receive DNSSEC records / AD / DO
    // (RFC 4035 §3.2.1) — we validated upstream with DO=1, now strip on the way
    // out so the answer matches a plain resolver (e.g. 1.1.1.1).
    if (!pkt->do_bit)
        strip_dnssec_for_non_do(&ret->request, &ret->recv_len, pkt->q_type);

    // EDNS-aware TC truncation + OPT echo (RFC 6891 §7), shared with the
    // cache fast path.  Pass the client's UDP size (0 = no EDNS → 512 limit).
    finalize_udp_truncation(&ret->request, &ret->recv_len,
                            pkt->edns_present
                                ? (pkt->edns_udp_size ? pkt->edns_udp_size : 512)
                                : 0);

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
    free(ctx);
    return NULL;
}

/*
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
            if (write(fd, &sf_len_net, 2) == 2 && write(fd, sf, 12) == 12) {}
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
            if (write(fd, &notimp_len_net, 2) == 2 && write(fd, notimp, 12) == 12) {}
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
            if (write(fd, &err_len_net, 2) == 2 && write(fd, err, 12) == 12) {}
            free_packet(pkt); free(buffer); continue;
        }

        if (!pkt->full_domain) {
            uint16_t sf_len_net = htons(12);
            unsigned char sf[12] = {0};
            sf[0] = (unsigned char)buffer[0];
            sf[1] = (unsigned char)buffer[1];
            sf[2] = 0x80;
            sf[3] = 0x80 | RCODE_SERVER_FAILURE;
            if (write(fd, &sf_len_net, 2) == 2 && write(fd, sf, 12) == 12) {}
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
            if (write(fd, &sf_len_net, 2) == 2 && write(fd, sf, 12) == 12) {}
            free_packet(pkt); free(buffer); continue;
        }

        /* Carry the client's DNSSEC intent (DO/CD) onto the resolver query
         * (see process_query() for rationale). */
        answer->do_bit = pkt->do_bit;
        answer->cd     = pkt->cd;

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
            if (write(fd, &sf_len_net, 2) == 2 && write(fd, sf, 12) == 12) {}
            free_packet(pkt); free_packet(answer); free(buffer);
            continue;
        }

        // Update transaction ID to match client's
        ret->id = pkt->id;
        if (ret->request && ret->recv_len >= 2) {
            ((unsigned char*)ret->request)[0] = (ret->id >> 8) & 0xFF;
            ((unsigned char*)ret->request)[1] = ret->id & 0xFF;
        }
        // Present our own recursive-resolver flags, not the upstream authority's
        // (clear AA, set RA, echo client RD) — RFC 1035 §4.1.1.
        normalize_forwarded_flags((unsigned char*)ret->request, ret->recv_len, pkt->rd);
        // Strip DNSSEC machinery for a non-DO client (RFC 4035 §3.2.1).
        if (!pkt->do_bit)
            strip_dnssec_for_non_do(&ret->request, &ret->recv_len, pkt->q_type);
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
    /* Line-buffer stdout so startup/status lines stream to `docker logs`
     * instead of sitting in libc's block buffer when stdout isn't a TTY. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    int ret = load_config(argc, argv);
    if (ret < 0) {
        printf("Usage: ./bin/upstream_dns <-p port> <-t thread_count> "
               "<-q queue_size> <-b bind_addr> <-a allow_cidrs> "
               "<-r per_source_qps>\n");
        exit(1);
    }

    /* Client access control (known_issues 4.3): install the default allow-list
     * (loopback + RFC1918 + link-local), then apply any -a override.  An open
     * resolver reachable from the internet is a DNS-amplification vector. */
    acl_init_defaults();
    if (g_config.acl_csv && acl_set_list(g_config.acl_csv) != 0) {
        fprintf(stderr, "Error: invalid -a allow-list: %s\n", g_config.acl_csv);
        exit(1);
    }
    rl_configure(g_config.rate_limit_qps, 0);
    if (g_config.rate_limit_qps > 0)
        printf("Rate limiting: %d queries/sec per source IP\n",
               g_config.rate_limit_qps);
    printf("Client allow-list active%s\n",
           g_config.acl_csv ? " (custom)" : " (defaults: loopback + RFC1918)");

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
    write_pid_file();

    // Initialize caches BEFORE creating threads
    g_ns_cache = ns_cache_create(NS_CACHE_SIZE);
    g_answer_cache = answer_cache_create(ANSWER_CACHE_SIZE);

    if (!g_ns_cache || !g_answer_cache) {
        fprintf(stderr, "Error: Failed to create caches\n");
        exit(EXIT_FAILURE);
    }

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
             "%s" TRUST_ANCHOR_FILE, SERVER_PATH);
    g_trust_anchors = load_trust_anchors(trust_anchor_file);
    if (!g_trust_anchors) {
        fprintf(stderr, "Warning: No trust anchors loaded — DNSSEC validation disabled\n");
    }

    // Create all listeners
    // Bind the port the user actually requested via -p (defaults to PORT).
    int listen_port = g_config.port;
    int udp4_sock = create_server_socket(listen_port);     // -1 if -b is IPv6
    int udp6_sock = create_server_socket_v6(listen_port);  // may be -1
    int tcp4_sock = create_tcp_socket_v4(listen_port);     // may be -1
    int tcp6_sock = create_tcp_socket_v6(listen_port);     // may be -1

    // At least one UDP listener must be up (both -1 only if -b is unusable).
    if (udp4_sock < 0 && udp6_sock < 0) {
        fprintf(stderr, "Error: no UDP listener could be bound"
                        " (check -b %s)\n",
                g_config.bind_addr ? g_config.bind_addr : "");
        exit(EXIT_FAILURE);
    }

    /* Open the query log while still privileged so its fd survives the drop
     * (writes use the fd, not the path).  Otherwise the lazy open in the worker
     * threads would run as the dropped user and fail on a root-owned log dir. */
    if (g_config.drop_user) log_reopen_upstream();

    /* Listeners are bound — drop root before serving any query (glibc setuid()
     * applies to every thread, incl. the cache-cleanup thread already running). */
    drop_privileges(g_config.drop_user);

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
    int udp4_idx = -1, stats_idx, udp6_idx = -1, tcp4_idx = -1, tcp6_idx = -1;

    if (udp4_sock >= 0) { pfds[nfds].fd = udp4_sock; pfds[nfds].events = POLLIN; udp4_idx = nfds++; }
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

            /* Reopen log file so logrotate can move the old one. */
            log_reopen_upstream();
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
        if (udp4_idx >= 0 && (pfds[udp4_idx].revents & POLLIN)) {
            while (1) {
                // Receive into a stack buffer first.
                // Cache hits are served here with zero heap allocation.
                // Only cache misses pay for malloc(QueryContext).
                char recv_buf[MAXLINE];
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                memset(&client_addr, 0, sizeof(client_addr));

                ssize_t recv_len = recvfrom(udp4_sock, recv_buf, MAXLINE, MSG_DONTWAIT,
                                            (struct sockaddr*)&client_addr, &client_len);
                if (recv_len < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        perror("Error: recvfrom UDP4");
                    break;  // kernel buffer drained
                }

                query_count++;

                // Access control (4.3): reject out-of-allow-list sources with
                // REFUSED and drop rate-limited sources, BEFORE the cache path
                // (cached DNSSEC answers are prime amplification payloads).
                {
                    struct sockaddr_storage ss;
                    memset(&ss, 0, sizeof(ss));
                    memcpy(&ss, &client_addr, client_len);
                    if (!acl_allows(&ss)) {
                        send_refused(udp4_sock, (const struct sockaddr*)&client_addr,
                                     client_len, (unsigned char*)recv_buf, recv_len);
                        continue;
                    }
                    if (!rl_allow(&ss))
                        continue;   // over rate — drop silently
                }

                // Cache hit: respond entirely from the poll loop — no thread wakeup.
                if (g_answer_cache) {
                    char domain_fast[256];
                    uint16_t qtype_fast;
                    bool do_fast = false;
                    uint16_t edns_size_fast = 0;
                    if (quick_parse_query(recv_buf, recv_len,
                                          domain_fast, sizeof(domain_fast),
                                          &qtype_fast, &do_fast, &edns_size_fast)) {
                        ssize_t cached_len = 0;
                        char* cached_raw = answer_cache_get_raw(g_answer_cache,
                                                                domain_fast, qtype_fast,
                                                                &cached_len);
                        if (cached_raw) {
                            // A validating client (DO=1) must not be served a
                            // signed-but-unvalidated cached answer from the fast
                            // path — route it to the worker to (re)validate.
                            // Validated (AD) and unsigned answers serve directly.
                            bool ad = cached_len > 3 &&
                                      (((unsigned char)cached_raw[3] >> 5) & 1);
                            if (do_fast && !ad &&
                                wire_is_signed((const unsigned char*)cached_raw,
                                               (int)cached_len)) {
                                free(cached_raw);  // fall through to worker
                            } else {
                                if (cached_len >= 2) {
                                    ((unsigned char*)cached_raw)[0] = (unsigned char)recv_buf[0];
                                    ((unsigned char*)cached_raw)[1] = (unsigned char)recv_buf[1];
                                }
                                /* Forwarded answer: our recursive-resolver flags,
                                 * not the cached upstream authority's (RFC 1035
                                 * §4.1.1).  RD echoes the query's RD bit. */
                                normalize_forwarded_flags((unsigned char*)cached_raw,
                                                          cached_len,
                                                          (unsigned char)recv_buf[2] & 0x01);
                                /* Non-DO client: strip DNSSEC RRs/AD/DO from the
                                 * cached (signed) answer (RFC 4035 §3.2.1). */
                                if (!do_fast)
                                    strip_dnssec_for_non_do(&cached_raw, &cached_len,
                                                            qtype_fast);
                                /* Same EDNS-aware truncation the worker applies. */
                                finalize_udp_truncation(&cached_raw, &cached_len,
                                                        edns_size_fast);
                                sendto(udp4_sock, cached_raw, cached_len, 0,
                                       (const struct sockaddr*)&client_addr, client_len);
                                free(cached_raw);
                                continue;  // zero parse/Packet alloc for cache hits
                            }
                        }
                    }
                }

                // Cache miss: allocate ctx, copy the already-received bytes into it.
                // DNS queries are small (<200 bytes typically), so the memcpy is cheap.
                struct QueryContext* ctx = malloc(sizeof(struct QueryContext));
                if (!ctx) {
                    send_servfail(udp4_sock, (const struct sockaddr*)&client_addr,
                                  client_len, (unsigned char*)recv_buf, recv_len);
                    break;
                }

                memcpy(ctx->buffer, recv_buf, recv_len);
                ctx->dns_sock = udp4_sock;
                memset(&ctx->client_addr, 0, sizeof(ctx->client_addr));
                memcpy(&ctx->client_addr, &client_addr, client_len);
                ctx->client_addr_len = client_len;
                ctx->recv_len    = recv_len;
                ctx->query_num   = query_count;

                if (threadpool_add_work(thread_pool, process_query, ctx) < 0) {
                    fprintf(stderr, "Error: Failed to queue work (pool might be full)\n");
                    send_servfail(udp4_sock, (const struct sockaddr*)&client_addr,
                                  client_len, (unsigned char*)recv_buf, recv_len);
                    free(ctx);
                }
            }
        }

        // --- UDP IPv6 — drain all pending datagrams before returning to poll() ---
        if (udp6_idx >= 0 && (pfds[udp6_idx].revents & POLLIN)) {
            while (1) {
                char recv_buf[MAXLINE];
                struct sockaddr_in6 client_addr6;
                socklen_t client_len = sizeof(client_addr6);
                memset(&client_addr6, 0, sizeof(client_addr6));

                ssize_t recv_len = recvfrom(udp6_sock, recv_buf, MAXLINE, MSG_DONTWAIT,
                                            (struct sockaddr*)&client_addr6, &client_len);
                if (recv_len < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        perror("Error: recvfrom UDP6");
                    break;  // kernel buffer drained
                }

                query_count++;

                // Access control (4.3) — same gate as the IPv4 path above.
                {
                    struct sockaddr_storage ss;
                    memset(&ss, 0, sizeof(ss));
                    memcpy(&ss, &client_addr6, client_len);
                    if (!acl_allows(&ss)) {
                        send_refused(udp6_sock, (const struct sockaddr*)&client_addr6,
                                     client_len, (unsigned char*)recv_buf, recv_len);
                        continue;
                    }
                    if (!rl_allow(&ss))
                        continue;   // over rate — drop silently
                }

                if (g_answer_cache) {
                    char domain_fast[256];
                    uint16_t qtype_fast;
                    bool do_fast = false;
                    uint16_t edns_size_fast = 0;
                    if (quick_parse_query(recv_buf, recv_len,
                                          domain_fast, sizeof(domain_fast),
                                          &qtype_fast, &do_fast, &edns_size_fast)) {
                        ssize_t cached_len = 0;
                        char* cached_raw = answer_cache_get_raw(g_answer_cache,
                                                                domain_fast, qtype_fast,
                                                                &cached_len);
                        if (cached_raw) {
                            bool ad = cached_len > 3 &&
                                      (((unsigned char)cached_raw[3] >> 5) & 1);
                            if (do_fast && !ad &&
                                wire_is_signed((const unsigned char*)cached_raw,
                                               (int)cached_len)) {
                                free(cached_raw);  // fall through to worker
                            } else {
                                if (cached_len >= 2) {
                                    ((unsigned char*)cached_raw)[0] = (unsigned char)recv_buf[0];
                                    ((unsigned char*)cached_raw)[1] = (unsigned char)recv_buf[1];
                                }
                                /* Forwarded answer: our recursive-resolver flags,
                                 * not the cached upstream authority's (RFC 1035
                                 * §4.1.1).  RD echoes the query's RD bit. */
                                normalize_forwarded_flags((unsigned char*)cached_raw,
                                                          cached_len,
                                                          (unsigned char)recv_buf[2] & 0x01);
                                /* Non-DO client: strip DNSSEC RRs/AD/DO from the
                                 * cached (signed) answer (RFC 4035 §3.2.1). */
                                if (!do_fast)
                                    strip_dnssec_for_non_do(&cached_raw, &cached_len,
                                                            qtype_fast);
                                /* Same EDNS-aware truncation the worker applies. */
                                finalize_udp_truncation(&cached_raw, &cached_len,
                                                        edns_size_fast);
                                sendto(udp6_sock, cached_raw, cached_len, 0,
                                       (const struct sockaddr*)&client_addr6, client_len);
                                free(cached_raw);
                                continue;
                            }
                        }
                    }
                }

                struct QueryContext* ctx = malloc(sizeof(struct QueryContext));
                if (!ctx) {
                    send_servfail(udp6_sock, (const struct sockaddr*)&client_addr6,
                                  client_len, (unsigned char*)recv_buf, recv_len);
                    break;
                }

                memcpy(ctx->buffer, recv_buf, recv_len);
                ctx->dns_sock = udp6_sock;
                memset(&ctx->client_addr, 0, sizeof(ctx->client_addr));
                memcpy(&ctx->client_addr, &client_addr6, client_len);
                ctx->client_addr_len = client_len;
                ctx->recv_len    = recv_len;
                ctx->query_num   = query_count;

                if (threadpool_add_work(thread_pool, process_query, ctx) < 0) {
                    fprintf(stderr, "Error: Failed to queue work (pool might be full)\n");
                    send_servfail(udp6_sock, (const struct sockaddr*)&client_addr6,
                                  client_len, (unsigned char*)recv_buf, recv_len);
                    free(ctx);
                }
            }
        }

        // --- TCP IPv4 accept ---
        if (tcp4_idx >= 0 && (pfds[tcp4_idx].revents & POLLIN)) {
            struct sockaddr_in caddr;
            socklen_t clen = sizeof(caddr);
            int cfd = accept(tcp4_sock, (struct sockaddr*)&caddr, &clen);
            if (cfd >= 0) {
                // Access control (4.3): drop connections from non-allowed
                // sources before spending a worker on them.
                struct sockaddr_storage ss;
                memset(&ss, 0, sizeof(ss));
                memcpy(&ss, &caddr, clen);
                if (!acl_allows(&ss)) {
                    close(cfd);
                } else {
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
        }

        // --- TCP IPv6 accept ---
        if (tcp6_idx >= 0 && (pfds[tcp6_idx].revents & POLLIN)) {
            struct sockaddr_in6 caddr6;
            socklen_t clen = sizeof(caddr6);
            int cfd = accept(tcp6_sock, (struct sockaddr*)&caddr6, &clen);
            if (cfd >= 0) {
                // Access control (4.3) — same gate as the IPv4 TCP path above.
                struct sockaddr_storage ss;
                memset(&ss, 0, sizeof(ss));
                memcpy(&ss, &caddr6, clen);
                if (!acl_allows(&ss)) {
                    close(cfd);
                } else {
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
    remove_pid_file();

    return 0;
}
