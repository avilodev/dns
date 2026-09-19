#include "auth.h"
#include "logger.h"
#include "request.h"
#include "response.h"
#include "resolve.h"
#include "types.h"
#include "utils.h"
#include "thread_pool.h"
#include "dnssec.h"
#include "access_control.h"
#include "policy.h"
#include "dns_synth.h"
#include "auth_net.h"
#include "auth_process.h"
#include "auth_chase.h"
#include "dns_name.h"

#include <poll.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <pwd.h>
#include <grp.h>

Config g_config;

/* Defined in auth.c; NULL when DNSSEC signing is not configured. */
extern ZoneKey *g_zone_keys;

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload  = 0;

static char g_config_path[256];   /* SERVER_PATH + CONFIG_FILE_PATH (config.txt) */

/* Per-QTYPE query counters (atomic, safe for concurrent worker threads). */
static _Atomic uint64_t g_qtype_counters[256];
static _Atomic uint64_t g_total_queries;

/* Self-pipe for async-signal-safe SIGUSR2 stats dump. */
static int stats_pipe[2] = {-1, -1};

/* qtype_name() is exported from logger.c — declared in logger.h */

static void print_qtype_stats(void) {
    printf("Query statistics:\n");
    printf("  Total queries: %" PRIu64 "\n", atomic_load(&g_total_queries));
    printf("  Blocked:       %" PRIu64 "\n", policy_blocked_count());
    for (int i = 1; i <= 255; i++) {
        uint64_t c = atomic_load(&g_qtype_counters[i]);
        if (c == 0) continue;
        const char* name = qtype_name((uint16_t)i);
        if (name) printf("  %-10s %" PRIu64 "\n", name, c);
        else      printf("  TYPE%-6d %" PRIu64 "\n", i, c);
    }
    uint64_t other = atomic_load(&g_qtype_counters[0]);
    if (other) printf("  %-10s %" PRIu64 "\n", "OTHER", other);
}

/* --- TCP query context --------------------------------------------------- */
struct TCPQueryContext {
    int client_fd;
    char client_ip[INET6_ADDRSTRLEN];
    uint16_t client_port;
    struct sockaddr_storage client_ss;   /* source addr for the recursion ACL */
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
                if (write(stats_pipe[1], &b, 1) < 0) { /* best-effort */ }
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
    uint16_t flags = rd16(ans->request + 2);
    flags &= ~(1u << 10);              /* AA = 0 */
    flags |=  (1u << 7);               /* RA = 1 */
    if (req->rd) flags |=  (1u << 8);  /* RD echo */
    else         flags &= ~(1u << 8);
    wr16(ans->request + 2, flags);
}

/*
 * Outcome of the recursion access-control gate (known_issues 4.3).
 *   QGATE_OK      — proceed (answer may still be NULL → SERVFAIL)
 *   QGATE_REFUSED — source not in the recursion allow-list → send REFUSED
 *   QGATE_DROP    — source over its rate limit → drop (UDP) / REFUSED (TCP)
 */
typedef enum { QGATE_OK = 0, QGATE_REFUSED, QGATE_DROP } QueryGate;

/* What the local stage left for the remote (forwarding) stage to do. */
typedef enum {
    LOCAL_DONE = 0,   /* answer is complete                                   */
    LOCAL_FORWARD,    /* nothing local: forward the whole query upstream      */
    LOCAL_CHASE       /* local CNAME chain ends outside our data: resolve the */
                      /* target upstream and append it                        */
} LocalResult;

#define MAX_CNAME_CHASE 8

/*
 * Local query policy: build a synthesized response for a blocklist hit
 * (NXDOMAIN by default, or a sinkhole answer under -S), or return NULL to let
 * the query proceed.  Served like the auth zones, before forwarding upstream.
 */
static struct Packet* policy_answer(const struct Packet* pkt) {
    if (!pkt || !pkt->full_domain || !pkt->request) return NULL;

    SynthAnswer ans;
    if (policy_lookup(pkt->full_domain, pkt->q_type, &ans) == POLICY_PASS)
        return NULL;

    struct Packet* r = calloc(1, sizeof(struct Packet));
    if (!r) return NULL;
    r->request = calloc(1, MAXLINE);
    if (!r->request) { free(r); return NULL; }

    int rcode = policy_block_mode_rcode();    /* 3 = NXDOMAIN, 0 = sinkhole */
    int has   = (ans.addrlen > 0);            /* sinkhole answer present? */
    ssize_t n = dns_synth_response((const unsigned char*)pkt->request, pkt->recv_len,
                                   rcode, has ? &ans : NULL, has ? 1 : 0,
                                   (unsigned char*)r->request, MAXLINE);
    if (n <= 0) { free(r->request); free(r); return NULL; }
    r->recv_len = n;
    r->id = pkt->id;
    return r;
}

/*
 * Locally served reverse zones for private address space (RFC 6303): PTR
 * lookups for RFC 1918, loopback, link-local and ULA addresses never leave the
 * network.  Names we hold records for are answered by check_internal() first;
 * everything else under these zones is NXDOMAIN (NODATA at the zone apex),
 * with the RFC 6303 SOA so clients can cache the answer.
 */
static const char* const k_private_reverse[] = {
    "10.in-addr.arpa",   "127.in-addr.arpa",  "254.169.in-addr.arpa",
    "168.192.in-addr.arpa",
    "16.172.in-addr.arpa", "17.172.in-addr.arpa", "18.172.in-addr.arpa",
    "19.172.in-addr.arpa", "20.172.in-addr.arpa", "21.172.in-addr.arpa",
    "22.172.in-addr.arpa", "23.172.in-addr.arpa", "24.172.in-addr.arpa",
    "25.172.in-addr.arpa", "26.172.in-addr.arpa", "27.172.in-addr.arpa",
    "28.172.in-addr.arpa", "29.172.in-addr.arpa", "30.172.in-addr.arpa",
    "31.172.in-addr.arpa",
    "d.f.ip6.arpa", "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
};

static struct Packet* private_reverse_answer(struct Packet* pkt) {
    if (!pkt || !pkt->full_domain) return NULL;
    const char* name = pkt->full_domain;
    for (size_t i = 0; i < sizeof(k_private_reverse) / sizeof(k_private_reverse[0]); i++) {
        const char* zone = k_private_reverse[i];
        if (!dname_is_subdomain(name, zone)) continue;
        bool apex = (strcmp(name, zone) == 0);

        /* RFC 6303 §3: "@ 10800 IN SOA @ nobody.invalid. 1 3600 1200 604800 10800" */
        static __thread struct AuthDomain soa;
        memset(&soa, 0, sizeof(soa));
        snprintf(soa.domain, sizeof(soa.domain), "%s", zone);
        snprintf(soa.soa_mname, sizeof(soa.soa_mname), "%s", zone);
        snprintf(soa.soa_rname, sizeof(soa.soa_rname), "nobody.invalid");
        soa.has_soa = true;
        soa.soa_serial = 1; soa.soa_refresh = 3600; soa.soa_retry = 1200;
        soa.soa_expire = 604800; soa.soa_minimum = 10800; soa.soa_ttl = 10800;
        return apex ? build_nodata_response(pkt, &soa)
                    : build_nxdomain_response(pkt, &soa);
    }
    return NULL;
}

/* Local answer for `q` from zones, blocklist and private reverse zones. */
static struct Packet* local_lookup(struct Packet* q) {
    struct Packet* a = check_internal(q);
    if (!a) a = policy_answer(q);
    if (!a) a = private_reverse_answer(q);
    return a;
}

/*
 * Local stage — everything answerable without the network: our zones, the
 * blocklist, private reverse zones, and CNAME chains whose targets are also
 * local.  Never blocks on I/O, so it is safe on the UDP receive threads.
 *
 * Authoritative answers (our own zones) and local policy are served to ANY
 * source — the auth server is, by design, publicly answerable for its zones.
 * Only the remote stage is access-controlled.
 */
static struct Packet* resolve_local(struct Packet* pkt, LocalResult* how) {
    *how = LOCAL_DONE;
    struct Packet* answer = local_lookup(pkt);
    if (!answer) { *how = LOCAL_FORWARD; return NULL; }

    /* RFC 1034 §4.3.2: an alias answer must carry its target's records too;
     * stub resolvers do not chase a bare CNAME themselves. */
    char target[DNAME_TEXT_MAX];
    for (int depth = 0; depth < MAX_CNAME_CHASE &&
                        cname_needs_chase(answer, pkt->q_type, target); depth++) {
        struct Packet* sub = make_chase_query(pkt, target);
        if (!sub) break;
        struct Packet* sub_ans = local_lookup(sub);
        free_packet(sub);
        if (!sub_ans) { *how = LOCAL_CHASE; break; }   /* target is not ours */
        int rc = merge_chased_answer(answer, sub_ans);
        free_packet(sub_ans);
        if (rc != 0) break;
    }
    return answer;
}

/*
 * Remote stage — may block for up to the upstream timeout.  Applies the
 * recursion gate (the DNS-amplification vector), then forwards the query or,
 * for LOCAL_CHASE, resolves the CNAME target and appends it to `partial`.
 * Returns the final answer (NULL → SERVFAIL).  Takes ownership of `partial`.
 */
static struct Packet* resolve_remote(struct Packet* pkt, struct Packet* partial,
                                     LocalResult how,
                                     const struct sockaddr_storage* src,
                                     QueryGate* gate, int client_tcp) {
    *gate = QGATE_OK;
    if (how == LOCAL_DONE) return partial;

    QueryGate g = QGATE_OK;
    if (src && !acl_allows(src))    g = QGATE_REFUSED;
    else if (src && !rl_allow(src)) g = QGATE_DROP;

    if (how == LOCAL_CHASE) {
        /* Our own alias is always served; only its external target needs the
         * recursion permission.  Without it, return the CNAME alone. */
        if (g != QGATE_OK) return partial;
        char target[DNAME_TEXT_MAX];
        if (!cname_needs_chase(partial, pkt->q_type, target)) return partial;
        struct Packet* sub = make_chase_query(pkt, target);
        struct Packet* sub_ans = sub ? resolve_recursive(sub, client_tcp) : NULL;
        if (sub_ans) merge_chased_answer(partial, sub_ans);
        free_packet(sub_ans);
        free_packet(sub);
        return partial;
    }

    /* LOCAL_FORWARD */
    free_packet(partial);
    if (g != QGATE_OK) { *gate = g; return NULL; }
    /* Forward upstream over the same transport the client used: a TCP client
     * needs a TCP upstream query to receive answers too large for UDP. */
    struct Packet* answer = resolve_recursive(pkt, client_tcp);
    if (answer) normalize_forwarded_flags(answer, pkt);
    return answer;
}

/* Parse-level handling shared by UDP and TCP.  Returns the parsed packet, or
 * NULL after having dealt with the message (dropped it or sent an error). */
typedef void (*ErrorSender)(void* ctx, const char* buf, ssize_t n, int rcode);
typedef void (*PacketSender)(void* ctx, struct Packet* resp);

static struct Packet* accept_query(char* buf, ssize_t n, void* ctx,
                                   ErrorSender send_err, PacketSender send_pkt,
                                   const char* client_ip, uint16_t client_port) {
    /* A QR=1 message is a response, not a query: never answer it (answering
     * responses invites reflection loops between two servers). */
    if (n >= 3 && ((unsigned char)buf[2] & 0x80)) return NULL;

    struct Packet* pkt = parse_request_headers(buf, n);
    if (!pkt) {
        log_entry(client_ip, client_port, 0, "PARSE_ERROR", RCODE_FORMAT_ERROR, NULL);
        send_err(ctx, buf, n, RCODE_FORMAT_ERROR);   /* malformed → FORMERR */
        return NULL;
    }

    // Non-standard opcode: NOTIFY (opcode 4, RFC 1996) is acknowledged.
    if (pkt->rcode == RCODE_NOTIMP && pkt->opcode == 4) {
        unsigned char reply[HEADER_LEN + 260];
        int len = build_error_reply((const unsigned char*)buf, n, 0, reply, sizeof(reply));
        if (len > 0) {
            reply[3] &= 0x7F;                         /* RA=0 on a NOTIFY ack */
            struct Packet ack = { .request = (char*)reply, .recv_len = len };
            send_pkt(ctx, &ack);
        }
        free_packet(pkt);
        return NULL;
    }

    // NOTIMP and parser errors (e.g. FORMERR for an invalid QCLASS, RFC 1035)
    if (pkt->rcode != 0) {
        send_err(ctx, buf, n, pkt->rcode);
        free_packet(pkt);
        return NULL;
    }

    // Unsupported EDNS version: send BADVERS (RFC 6891 §6.1.3)
    if (pkt->edns_present && pkt->edns_version > 0) {
        struct Packet *bv = build_badvers_response(pkt);
        if (bv) { send_pkt(ctx, bv); free_packet(bv); }
        free_packet(pkt);
        return NULL;
    }

    atomic_fetch_add(&g_total_queries, 1);
    {
        uint8_t idx = (pkt->q_type < 256) ? (uint8_t)pkt->q_type : 0;
        atomic_fetch_add(&g_qtype_counters[idx], 1);
    }
    return pkt;
}

/* Log the outcome of a query. */
static void log_answer(const char* ip, uint16_t port, const struct Packet* pkt,
                       const struct Packet* answer) {
    if (!answer) {
        log_entry(ip, port, pkt->q_type, pkt->full_domain, RCODE_SERVER_FAILURE, NULL);
        return;
    }
    char *resolved_ip = extract_ip_from_response(answer);
    uint8_t ans_rcode = (answer->recv_len >= HEADER_LEN && answer->request)
        ? (uint8_t)(rd16(answer->request + 2) & 0xF) : 0;
    log_entry(ip, port, pkt->q_type, pkt->full_domain, ans_rcode, resolved_ip);
    free(resolved_ip);
}

/* --- UDP ------------------------------------------------------------------ */

struct UdpClient {
    int sock;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    char ip[INET6_ADDRSTRLEN];
    uint16_t port;
};

static void udp_send_err(void* ctx, const char* buf, ssize_t n, int rcode) {
    struct UdpClient* c = ctx;
    send_error_udp(c->sock, (const struct sockaddr*)&c->addr, c->addr_len, buf, n, rcode);
}

static void udp_send_pkt(void* ctx, struct Packet* resp) {
    struct UdpClient* c = ctx;
    send_response(c->sock, resp, (const struct sockaddr*)&c->addr, c->addr_len);
}

/* Log, finalize and send a UDP answer (SERVFAIL when NULL); frees `answer`. */
static void udp_finish(struct UdpClient* c, struct Packet* pkt, struct Packet* answer) {
    log_answer(c->ip, c->port, pkt, answer);
    if (!answer) {
        answer = build_servfail_response(pkt);
        if (!answer) return;
    }
    finalize_udp_response(answer, pkt);
    udp_send_pkt(c, answer);
    free_packet(answer);
}

/* A query handed from a UDP receive thread to the forwarder pool. */
struct ForwardJob {
    struct UdpClient client;
    struct Packet* pkt;
    struct Packet* partial;
    LocalResult how;
};

static struct ThreadPool* g_forward_pool = NULL;

static void* forward_job(void* arg) {
    struct ForwardJob* job = arg;
    QueryGate gate;
    struct Packet* answer = resolve_remote(job->pkt, job->partial, job->how,
                                           &job->client.addr, &gate, 0 /* UDP */);
    if (gate == QGATE_REFUSED) {
        log_entry(job->client.ip, job->client.port, job->pkt->q_type,
                  job->pkt->full_domain, RCODE_REFUSED, NULL);
        send_error_udp(job->client.sock, (const struct sockaddr*)&job->client.addr,
                       job->client.addr_len, job->pkt->request, job->pkt->recv_len,
                       RCODE_REFUSED);
    } else if (gate == QGATE_OK) {
        udp_finish(&job->client, job->pkt, answer);
    }
    /* QGATE_DROP: over rate — drop silently; responding would still amplify. */
    free_packet(job->pkt);
    free(job);
    return NULL;
}

/*
 * handle_udp_packet — core UDP query processing on a receive thread.
 * Local answers are sent inline; anything that needs the upstream resolver is
 * handed to the forwarder pool, so a slow recursion never delays the answers
 * behind it on this socket (head-of-line blocking).
 */
static void handle_udp_packet(int sock,
                               const struct sockaddr_storage *caddr,
                               socklen_t clen,
                               char *buf, ssize_t n)
{
    struct UdpClient c = { .sock = sock, .addr_len = clen, .ip = "?" };
    memcpy(&c.addr, caddr, clen);
    if (caddr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6*)caddr;
        inet_ntop(AF_INET6, &s6->sin6_addr, c.ip, sizeof(c.ip));
        c.port = ntohs(s6->sin6_port);
    } else {
        const struct sockaddr_in *s4 = (const struct sockaddr_in*)caddr;
        inet_ntop(AF_INET, &s4->sin_addr, c.ip, sizeof(c.ip));
        c.port = ntohs(s4->sin_port);
    }

    struct Packet *pkt = accept_query(buf, n, &c, udp_send_err, udp_send_pkt, c.ip, c.port);
    if (!pkt) return;

    LocalResult how;
    struct Packet *answer = resolve_local(pkt, &how);
    if (how == LOCAL_DONE) {
        udp_finish(&c, pkt, answer);
        free_packet(pkt);
        return;
    }

    struct ForwardJob *job = malloc(sizeof(*job));
    if (job) {
        job->client = c;
        job->pkt = pkt;
        job->partial = answer;
        job->how = how;
        if (threadpool_add_work(g_forward_pool, forward_job, job) == 0) return;
        free(job);
    }
    /* Forwarder pool saturated: serve what we have (our CNAME) or SERVFAIL. */
    udp_finish(&c, pkt, how == LOCAL_CHASE ? answer : (free_packet(answer), NULL));
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
    int sock;   /* pre-bound SO_REUSEPORT socket (bound in main while root) */
};

static void* udp_worker_thread(void *arg)
{
    struct UDPWorkerArg *wa = arg;
    int sock = wa->sock;
    free(wa);

    char buf[MAXLINE];   /* stack-allocated: no malloc per query */

    while (g_running) {
        struct sockaddr_storage caddr;
        socklen_t clen = sizeof(caddr);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr*)&caddr, &clen);
        if (n < 0) {
            if (errno_is_timeout(errno) || errno == EINTR)
                continue;   /* timeout — re-check g_running */
            perror("worker: recvfrom");
            break;
        }
        if (n < HEADER_LEN) continue;   /* too short to be DNS */
        handle_udp_packet(sock, &caddr, clen, buf, n);
    }

    close(sock);
    return NULL;
}

/* --- Worker: TCP query --------------------------------------------------- */

/* Idle time allowed before (and between pipelined) queries on one TCP
 * connection.  Each connection holds a TCP worker, so idle connections are
 * closed promptly (RFC 7766 §6.2.3) rather than starving new clients. */
#define TCP_IDLE_TIMEOUT 2

static void tcp_send_err(void* ctx, const char* buf, ssize_t n, int rcode) {
    send_error_tcp(*(int*)ctx, buf, n, rcode);
}

static void tcp_send_pkt(void* ctx, struct Packet* resp) {
    send_tcp_response(*(int*)ctx, resp);
}

static void* process_tcp_query(void* arg) {
    struct TCPQueryContext* ctx = (struct TCPQueryContext*)arg;
    int fd = ctx->client_fd;

    /* Guard against slow and idle clients.  Real clients send their query
     * immediately after connecting, so the short idle limit applies from the
     * start — a connection that sits silent is closed within
     * TCP_IDLE_TIMEOUT and frees its worker. */
    struct timeval rtv = { .tv_sec = TCP_IDLE_TIMEOUT, .tv_usec = 0 };
    struct timeval wtv = { .tv_sec = SOCKET_TIMEOUT,   .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &wtv, sizeof(wtv));

    // SO_KEEPALIVE: detect dead half-open connections (RFC 7766 §6.2.3)
    int ka = 1;
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE,   &ka,  sizeof(ka));
    int ka_idle = 60, ka_intvl = 10, ka_cnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,   &ka_idle,  sizeof(ka_idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,  &ka_intvl, sizeof(ka_intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,    &ka_cnt,   sizeof(ka_cnt));

    /* RFC 7766: process multiple queries on one TCP connection (pipelining).
     * Loop until EOF, timeout (RCVTIMEO fires), or a hard error. */
    for (;;) {
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

        struct Packet* pkt = accept_query(buffer, msg_len, &fd, tcp_send_err, tcp_send_pkt,
                                          ctx->client_ip, ctx->client_port);
        if (!pkt) { free(buffer); continue; }

        LocalResult how;
        struct Packet* answer = resolve_local(pkt, &how);
        QueryGate gate;
        answer = resolve_remote(pkt, answer, how, &ctx->client_ss, &gate, 1 /* TCP */);

        if (gate == QGATE_REFUSED || gate == QGATE_DROP) {
            /* TCP isn't an amplification vector (3-way handshake), so a
             * rate-limited connection still gets an explicit REFUSED. */
            log_entry(ctx->client_ip, ctx->client_port, pkt->q_type, pkt->full_domain, RCODE_REFUSED, NULL);
            send_refused_tcp(fd, buffer, msg_len);
            free_packet(pkt);
            free(buffer);
            continue;
        }

        log_answer(ctx->client_ip, ctx->client_port, pkt, answer);
        if (!answer) answer = build_servfail_response(pkt);
        if (answer) {
            /* RFC 6891 §6.1.1: echo an OPT RR to EDNS clients over TCP too (4.7).
             * No truncation on TCP, so only the OPT-echo half is needed. */
            append_edns_opt(answer, pkt);
            send_tcp_response(fd, answer);
            free_packet(answer);
        }

        free_packet(pkt);
        free(buffer);
    }

    close(fd);
    free(ctx);
    return NULL;
}

/* --- Main ---------------------------------------------------------------- */

int main(int argc, char** argv) {
    /* Line-buffer stdout so startup/status lines stream to `docker logs`
     * instead of sitting in libc's block buffer when stdout isn't a TTY. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (load_config(argc, argv) < 0) {
        printf("Usage: ./bin/auth_dns <-p upstream_port> <-t thread_count> "
               "<-u upstream_dns> <-q queue_size> <-b bind_addr> "
               "<-a recursion_allow_cidrs> <-r per_source_qps> "
               "<-U user[:group]> <-S block_mode> <-c config_file>\n");
        exit(1);
    }

    /* Recursion access control (known_issues 4.3): the default allow-list
     * (loopback + RFC1918 + link-local) gates only the forwarding path; our
     * own authoritative zones remain answerable to any source. */
    acl_init_defaults();
    if (g_config.acl_csv && acl_set_list(g_config.acl_csv) != 0) {
        fprintf(stderr, "Error: invalid -a allow-list: %s\n", g_config.acl_csv);
        exit(1);
    }
    rl_configure(g_config.rate_limit_qps, 0);

    /* All local knowledge (authoritative zones + blocklist) lives in one file;
     * auth owns it and upstream stays a clean recursor.  Resolve the path once
     * (-c overrides the built-in default) and use it for both loads here and on
     * SIGHUP. */
    if (g_config.config_path)
        snprintf(g_config_path, sizeof(g_config_path), "%s", g_config.config_path);
    else
        snprintf(g_config_path, sizeof(g_config_path),
                 "%s%s", SERVER_PATH, CONFIG_FILE_PATH);

    /* Pin the config file and query log while still root, so SIGHUP reloads
     * after the privilege drop can reach them even when an ancestor directory
     * (e.g. a 0700 home) is not traversable by the drop user. */
    path_pin(g_config_path);
    path_pin(LOG_FILE_PATH);

    /* Blocklist (the [blocklist] section of config.txt). */
    policy_set_block_mode(g_config.block_mode);
    {
        int pn = policy_load(g_config_path);
        if (pn >= 0)
            printf("Blocklist loaded: %d entries (block mode: %s)\n", pn,
                   g_config.block_mode ? g_config.block_mode : "nxdomain");
        else
            fprintf(stderr, "Warning: policy_load failed; filtering disabled\n");
    }

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

    // Load authoritative domains (the [domain] sections of config.txt)
    printf("Loading authoritative domains...\n");
    int loaded_count = load_auth_domains(g_config_path);
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

    // Create TCP sockets (bound while still privileged; port 53 needs root).
    int tcp4_sock = create_tcp_socket_v4(PORT);  // may be -1
    int tcp6_sock = create_tcp_socket_v6(PORT);  // may be -1

    /*
     * UDP: one SO_REUSEPORT socket per worker, all bound here in main() while
     * we still have privileges.  The kernel load-balances datagrams across all
     * of them, so each worker runs independently — no shared lock on the UDP
     * hot path and no per-query malloc.  Binding here rather than inside each
     * thread is what lets us drop privileges before any worker starts.
     */
    int n_udp = g_config.thread_count;
    pthread_t *udp4_threads = calloc(n_udp, sizeof(pthread_t));
    pthread_t *udp6_threads = calloc(n_udp, sizeof(pthread_t));
    int *udp4_fds = malloc((size_t)n_udp * sizeof(int));
    int *udp6_fds = malloc((size_t)n_udp * sizeof(int));
    int n_udp6 = 0;

    if (!udp4_threads || !udp6_threads || !udp4_fds || !udp6_fds) {
        fprintf(stderr, "Error: Failed to allocate UDP worker arrays\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < n_udp; i++) {
        udp4_fds[i] = create_reuseport_udp_socket(AF_INET, PORT);
        if (udp4_fds[i] < 0) {
            fprintf(stderr, "Error: bind UDP IPv4 on port %d: %s\n",
                    PORT, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
    /* IPv6 is best-effort: stop at the first failure (no kernel v6, or -b is v4). */
    for (int i = 0; i < n_udp; i++) {
        int s = create_reuseport_udp_socket(AF_INET6, PORT);
        if (s < 0) break;
        udp6_fds[i] = s;
        n_udp6 = i + 1;
    }

    printf("DNS Server listening on port %d (UDP IPv4 SO_REUSEPORT", PORT);
    if (n_udp6 > 0)     printf(", UDP IPv6 SO_REUSEPORT");
    if (tcp4_sock >= 0) printf(", TCP IPv4");
    if (tcp6_sock >= 0) printf(", TCP IPv6");
    printf(")\n");
    printf("Upstream DNS: %s:%d\n", g_config.upstream_dns, g_config.upstream_port);
    printf("Loaded %d authoritative domain(s)\n\n", loaded_count);

    /* Open the query log now, while still privileged, so its fd survives the
     * drop (writes go through the fd; permission is checked only at open).
     * Without this the lazy open in the worker threads would run as the dropped
     * user and fail if the log dir is root-owned. */
    if (g_config.drop_user) log_reopen();

    /* All listening sockets are bound — drop root before serving any query. */
    drop_privileges(g_config.drop_user);

    /*
     * Forwarder pool: UDP queries that need the upstream resolver run here, so
     * the receive threads only ever do local, non-blocking work.
     */
    struct ThreadPoolConfig fwd_config = {
        .num_threads    = g_config.thread_count,
        .max_queue_size = g_config.queue_size
    };
    g_forward_pool = threadpool_create(fwd_config);
    if (!g_forward_pool) {
        fprintf(stderr, "Error: Failed to create forwarder thread pool\n");
        exit(EXIT_FAILURE);
    }


    for (int i = 0; i < n_udp; i++) {
        struct UDPWorkerArg *wa = malloc(sizeof(*wa));
        if (!wa) { fprintf(stderr, "Error: malloc UDPWorkerArg\n"); exit(EXIT_FAILURE); }
        wa->sock = udp4_fds[i];
        if (pthread_create(&udp4_threads[i], NULL, udp_worker_thread, wa) != 0) {
            perror("Error: pthread_create UDP4 worker");
            exit(EXIT_FAILURE);
        }
    }
    for (int i = 0; i < n_udp6; i++) {
        struct UDPWorkerArg *wa = malloc(sizeof(*wa));
        if (!wa) { fprintf(stderr, "Error: malloc UDPWorkerArg\n"); exit(EXIT_FAILURE); }
        wa->sock = udp6_fds[i];
        if (pthread_create(&udp6_threads[i], NULL, udp_worker_thread, wa) != 0) {
            perror("Warning: pthread_create UDP6 worker");
            close(udp6_fds[i]);
            n_udp6 = i;   /* only join the threads we actually started */
            break;
        }
    }

    free(udp4_fds);
    free(udp6_fds);

    /*
     * TCP: a dedicated pool (each connection holds a worker until it closes or
     * idles out), sized like the UDP side so a few idle connections cannot
     * lock out every other TCP client.
     */
    int tcp_threads = g_config.thread_count < 4 ? 4 : g_config.thread_count;
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
            printf("SIGHUP received — reloading config from %s\n", g_config_path);
            reload_auth_domains(g_config_path);

            /* Reload DNSSEC zone keys so key rotation takes effect without restart. */
            if (g_zone_keys) { free_zone_keys(g_zone_keys); g_zone_keys = NULL; }
            g_zone_keys = load_zone_keys(SERVER_PATH "/config");
            printf("DNSSEC signing keys reloaded: %s\n",
                   g_zone_keys ? "enabled" : "disabled (no keys configured)");

            /* Reopen log file so logrotate can move the old one. */
            log_reopen();

            /* Reload the blocklist; policy_load swaps the table atomically
             * behind its own lock. */
            {
                int pn = policy_load(g_config_path);
                if (pn >= 0) printf("Blocklist reloaded: %d entries\n", pn);
            }
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
                    memset(&ctx->client_ss, 0, sizeof(ctx->client_ss));
                    memcpy(&ctx->client_ss, &caddr, clen);
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
                    memset(&ctx->client_ss, 0, sizeof(ctx->client_ss));
                    memcpy(&ctx->client_ss, &caddr, clen);
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
    threadpool_wait(g_forward_pool);
    threadpool_destroy(g_forward_pool);

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
