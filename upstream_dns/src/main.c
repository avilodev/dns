#include "access_control.h"
#include "cache.h"
#include "client_reply.h"
#include "config.h"
#include "dns_name.h"
#include "query_log.h"
#include "response_handler.h"
#include "thread_pool.h"
#include "utils.h"
#include "workers.h"

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>

Config       g_config;
NSCache*     g_ns_cache      = NULL;
AnswerCache* g_answer_cache  = NULL;
TrustAnchor* g_trust_anchors = NULL;

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload_hints = 0;
static int stats_pipe[2] = {-1, -1};   /* SIGUSR1/2 -> main loop (self-pipe) */

/* ---- Process setup ----------------------------------------------------- */

/* Kept open: after the privilege drop we can't unlink it from /run, but we
 * can still truncate it so no stale PID is left for the cron job. */
static int g_pid_fd = -1;

static void write_pid_file(void)
{
    g_pid_fd = open(PID_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (g_pid_fd < 0) { perror("Warning: Cannot write PID file " PID_FILE_PATH); return; }
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    if (write(g_pid_fd, buf, (size_t)n) != n)
        perror("Warning: Short write to PID file " PID_FILE_PATH);
}

static void remove_pid_file(void)
{
    if (unlink(PID_FILE_PATH) != 0 && g_pid_fd >= 0 && ftruncate(g_pid_fd, 0) != 0)
        perror("Warning: Cannot clear PID file " PID_FILE_PATH);
    if (g_pid_fd >= 0) { close(g_pid_fd); g_pid_fd = -1; }
}

static void die(const char* msg, const char* arg)
{
    fprintf(stderr, "Error: %s%s\n", msg, arg ? arg : "");
    exit(EXIT_FAILURE);
}

/* After binding, drop root to -U "user[:group]" so the network-facing parser
 * never runs privileged.  No-op when not root; fatal on any failure. */
static void drop_privileges(const char* spec)
{
    if (geteuid() != 0) return;
    if (!spec || !*spec) {
        fprintf(stderr, "Warning: running as root with no -U user; "
                        "NOT dropping privileges (set -U or a systemd User=)\n");
        return;
    }

    char user[128];
    if (snprintf(user, sizeof(user), "%s", spec) >= (int)sizeof(user)) die("-U value too long", NULL);
    char* group = strchr(user, ':');
    if (group) *group++ = '\0';

    struct passwd* pw = getpwnam(user);
    if (!pw) die("-U unknown user ", user);
    if (pw->pw_uid == 0) die("-U user is root: ", user);
    gid_t gid = pw->pw_gid;
    if (group && *group) {
        struct group* gr = getgrnam(group);
        if (!gr) die("-U unknown group ", group);
        gid = gr->gr_gid;
    }

    if (setgroups(1, &gid) != 0 || setgid(gid) != 0 || setuid(pw->pw_uid) != 0) {
        perror("Error: privilege drop");
        exit(EXIT_FAILURE);
    }
    if (setuid(0) == 0) die("privilege drop failed — still able to regain root", NULL);
    fprintf(stderr, "Dropped privileges to %s (uid=%d gid=%d)\n", user, (int)pw->pw_uid, (int)gid);
}

/* Async-signal-safe: set flags, or poke the self-pipe for stats. */
static void signal_handler(int signum)
{
    switch (signum) {
    case SIGINT: case SIGTERM: case SIGQUIT:
        g_running = 0;
        break;
    case SIGHUP:
        g_reload_hints = 1;
        break;
    case SIGUSR1: case SIGUSR2:
        if (stats_pipe[1] >= 0 && write(stats_pipe[1], "s", 1) < 0) { /* best-effort */ }
        break;
    }
}

static void setup_signals(void)
{
    /* Both ends non-blocking: the handler must never block, and the main
     * loop drains until EAGAIN. */
    if (pipe(stats_pipe) < 0) {
        perror("Warning: Failed to create stats pipe; SIGUSR1 stats disabled");
        stats_pipe[0] = stats_pipe[1] = -1;
    } else {
        for (int e = 0; e < 2; e++) {
            int fl = fcntl(stats_pipe[e], F_GETFL, 0);
            if (fl >= 0) fcntl(stats_pipe[e], F_SETFL, fl | O_NONBLOCK);
        }
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa = { .sa_handler = signal_handler };
    sigemptyset(&sa.sa_mask);
    int sigs[] = { SIGINT, SIGTERM, SIGQUIT, SIGHUP, SIGUSR1, SIGUSR2 };
    for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
        sigaction(sigs[i], &sa, NULL);
}

/* ---- Cache sweeper ------------------------------------------------------- */

static pthread_mutex_t g_cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cleanup_cond  = PTHREAD_COND_INITIALIZER;

/* Sweep expired entries every 60 s; the condvar lets shutdown wake it. */
static void* cache_cleanup_thread(void* arg)
{
    (void)arg;
    pthread_mutex_lock(&g_cleanup_mutex);
    while (g_running) {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 60;
        pthread_cond_timedwait(&g_cleanup_cond, &g_cleanup_mutex, &deadline);
        ns_cache_cleanup_expired(g_ns_cache);
        answer_cache_cleanup_expired(g_answer_cache);
    }
    pthread_mutex_unlock(&g_cleanup_mutex);
    return NULL;
}

/* ---- Serving --------------------------------------------------------------- */

/*
 * Answer a datagram straight from the answer cache on the poll thread (no
 * worker wakeup, no Packet allocation).  Returns false on a miss — or for a
 * DO client when the entry is signed but unvalidated (the worker revalidates).
 */
static bool serve_from_cache(int sock, const char* req, ssize_t req_len,
                             const struct sockaddr_storage* ss, socklen_t ss_len)
{
    char domain[DNAME_TEXT_MAX];
    uint16_t qtype, edns_size;
    bool do_bit;
    if (!quick_parse_query(req, req_len, domain, sizeof(domain), &qtype, &do_bit, &edns_size))
        return false;

    ssize_t len = 0;
    char* resp = answer_cache_get_raw(g_answer_cache, domain, qtype, &len);
    if (!resp) return false;
    bool ad = (resp[3] & 0x20) != 0;
    if (do_bit && !ad && wire_is_signed((const unsigned char*)resp, (int)len)) {
        free(resp);
        return false;
    }

    /* Same reply shaping as the worker path (workers.c). */
    memcpy(resp, req, 2);                                           /* ID */
    normalize_forwarded_flags((unsigned char*)resp, len, req[2] & 0x01, req[3] & 0x10);
    restore_question_case((unsigned char*)resp, len, (const unsigned char*)req, req_len);
    if (!do_bit) strip_dnssec_for_non_do(&resp, &len, qtype);
    finalize_udp_truncation(&resp, &len, edns_size, do_bit);
    sendto(sock, resp, (size_t)len, 0, (const struct sockaddr*)ss, ss_len);

    char ip[INET6_ADDRSTRLEN];
    uint16_t port;
    sockaddr_to_ip(ss, ip, &port);
    log_query(ip, port, qtype, domain, (uint8_t)(resp[3] & 0x0F), "cache");
    count_query(qtype);
    free(resp);
    return true;
}

/* One datagram: filter, try the cache, else queue for a worker.  Returns
 * false to stop draining the socket (out of memory). */
static bool handle_udp_datagram(int sock, struct ThreadPool* pool, const char* buf, ssize_t len,
                                const struct sockaddr_storage* ss, socklen_t ss_len)
{
    const struct sockaddr* sa = (const struct sockaddr*)ss;

    /* Never answer a response (QR=1): that invites reflection loops. */
    if (len < HEADER_LEN || (buf[2] & 0x80)) return true;

    /* ACL and rate limit before the cache: cached DNSSEC answers are prime
     * amplification payloads.  The limiter runs FIRST and charges every source,
     * in or out of the allow-list — answering a refused source unconditionally
     * made it an unmetered reflector for anyone spoofing its address.  Sources
     * over their rate are dropped silently; a refusal is still sent to sources
     * within it, so a genuinely misconfigured client learns why. */
    if (!rl_allow(ss)) return true;
    if (!acl_allows(ss)) {
        send_error_udp(sock, sa, ss_len, (const unsigned char*)buf, len, RCODE_REFUSED);
        return true;
    }
    if (serve_from_cache(sock, buf, len, ss, ss_len)) return true;

    struct QueryContext* ctx = malloc(sizeof(*ctx));
    if (!ctx) {
        send_error_udp(sock, sa, ss_len, (const unsigned char*)buf, len, RCODE_SERVER_FAILURE);
        return false;
    }
    memcpy(ctx->buffer, buf, (size_t)len);
    ctx->recv_len        = len;
    ctx->dns_sock        = sock;
    ctx->client_addr     = *ss;
    ctx->client_addr_len = ss_len;
    if (threadpool_add_work(pool, process_query, ctx) < 0) {
        fprintf(stderr, "Error: Failed to queue work (pool might be full)\n");
        send_error_udp(sock, sa, ss_len, (const unsigned char*)buf, len, RCODE_SERVER_FAILURE);
        free(ctx);
    }
    return true;
}

static void drain_udp_socket(int sock, struct ThreadPool* pool)
{
    for (;;) {
        char buf[MAXLINE];
        struct sockaddr_storage ss = {0};
        socklen_t ss_len = sizeof(ss);
        ssize_t len = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*)&ss, &ss_len);
        if (len < 0) {
            if (!errno_is_timeout(errno)) perror("Error: recvfrom UDP");
            return;
        }
        if (!handle_udp_datagram(sock, pool, buf, len, &ss, ss_len)) return;
    }
}

/* Accept one connection; ACL, rate limit and the per-source connection cap
 * apply before it may hold a TCP worker. */
static void accept_tcp(int listener, struct ThreadPool* pool)
{
    struct sockaddr_storage ss = {0};
    socklen_t len = sizeof(ss);
    int fd = accept(listener, (struct sockaddr*)&ss, &len);
    if (fd < 0) return;
    if (!acl_allows(&ss) || !rl_allow(&ss) || !tcp_conn_acquire(&ss)) {
        close(fd);
        return;
    }
    struct TCPQueryContext* ctx = malloc(sizeof(*ctx));
    if (ctx) {
        ctx->client_fd = fd;
        ctx->client_ss = ss;
        if (threadpool_add_work(pool, process_tcp_query, ctx) == 0) return;
    }
    close(fd);
    free(ctx);
    tcp_conn_release(&ss);
}

/* SIGHUP: reload root hints (the old table stays if the file is unusable),
 * flush the NS cache (root IPs may have moved), and reopen the log. */
static void reload(const char* hints_file)
{
    printf("SIGHUP received — reloading root hints from %s\n", hints_file);
    int n = load_hints(hints_file);
    if (n > 0) printf("Root hints reloaded: %d server(s)\n", n);
    else       fprintf(stderr, "Warning: Hints reload failed; keeping current root hints\n");
    ns_cache_flush(g_ns_cache);
    printf("NS cache flushed.\n");
    log_reopen_upstream();
}

static void close_fd(int fd)
{
    if (fd >= 0) close(fd);
}

int main(int argc, char** argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);   /* stream status lines to `docker logs` */

    /* Seed the rand() fallbacks (used only if getrandom() fails). */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srand((unsigned)ts.tv_nsec ^ (unsigned)getpid() ^ (unsigned)time(NULL));

    if (load_config(argc, argv) < 0) {
        printf("Usage: ./bin/upstream_dns [-p port] [-t threads] [-q queue_size] [-b bind_addr]"
               " [-a allow_cidrs] [-r per_source_qps] [-U user[:group]]\n");
        exit(1);
    }

    /* Default allow-list (loopback + private ranges) unless -a replaces it:
     * an open resolver is an amplification vector. */
    acl_init_defaults();
    if (g_config.acl_csv && acl_set_list(g_config.acl_csv) != 0)
        die("invalid -a allow-list: ", g_config.acl_csv);
    rl_configure(g_config.rate_limit_qps, 0);
    if (g_config.rate_limit_qps > 0)
        printf("Rate limiting: %d queries/sec per source IP\n", g_config.rate_limit_qps);
    printf("Client allow-list active%s\n",
           g_config.acl_csv ? " (custom)" : " (defaults: loopback + RFC1918)");

    setup_signals();
    write_pid_file();

    g_ns_cache = ns_cache_create(NS_CACHE_SIZE);
    g_answer_cache = answer_cache_create(ANSWER_CACHE_SIZE);
    if (!g_ns_cache || !g_answer_cache) die("Failed to create caches", NULL);

    /* Joined on shutdown, before the caches are destroyed. */
    pthread_t cleanup_tid;
    bool cleanup_started = pthread_create(&cleanup_tid, NULL, cache_cleanup_thread, NULL) == 0;
    if (!cleanup_started)
        perror("Warning: Failed to create cache cleanup thread; expired entries won't be pruned");

    /* Pin the hints file and log while root, so reopens after the drop work
     * even under a non-traversable (0700) ancestor. */
    char hints_file[256];
    snprintf(hints_file, sizeof(hints_file), "%s%s", SERVER_PATH, HINTS_FILE);
    path_pin(hints_file);
    path_pin(LOG_FILE_PATH);
    path_pin(SERVER_PATH TRUST_ANCHOR_FILE);
    int nroots = load_hints(hints_file);
    if (nroots < 0) {
        fprintf(stderr, "Warning: Cannot read hints file %s; using built-in root hints\n", hints_file);
        nroots = load_hints_builtin();
    }
    printf("%d Root Servers Loaded\n", nroots);

    g_trust_anchors = load_trust_anchors(SERVER_PATH TRUST_ANCHOR_FILE);
    if (!g_trust_anchors)
        fprintf(stderr, "Warning: No trust anchors loaded — DNSSEC validation disabled\n");

    int port = g_config.port;
    int udp4 = create_listener(AF_INET,  SOCK_DGRAM,  port, true);   /* -1 only if -b is IPv6 */
    int udp6 = create_listener(AF_INET6, SOCK_DGRAM,  port, false);
    int tcp4 = create_listener(AF_INET,  SOCK_STREAM, port, false);
    int tcp6 = create_listener(AF_INET6, SOCK_STREAM, port, false);
    if (udp4 < 0 && udp6 < 0)
        die("no UDP listener could be bound; check -b ", g_config.bind_addr);

    /* Open the log while root so its fd survives the drop. */
    if (g_config.drop_user) log_reopen_upstream();
    drop_privileges(g_config.drop_user);

    /* TCP gets its own pool: a connection holds its worker until it closes,
     * so a few idle clients must not starve uncached UDP. */
    struct ThreadPool* udp_pool = threadpool_create((struct ThreadPoolConfig){
        .num_threads = g_config.thread_count, .max_queue_size = g_config.queue_size });
    struct ThreadPool* tcp_pool = threadpool_create((struct ThreadPoolConfig){
        .num_threads = g_config.thread_count < 4 ? 4 : g_config.thread_count,
        .max_queue_size = g_config.queue_size });
    if (!udp_pool || !tcp_pool) die("Failed to create thread pool", NULL);

    enum { P_STATS, P_UDP4, P_UDP6, P_TCP4, P_TCP6, P_COUNT };
    struct pollfd pfds[P_COUNT] = {
        [P_STATS] = { stats_pipe[0], POLLIN, 0 },
        [P_UDP4]  = { udp4, POLLIN, 0 },
        [P_UDP6]  = { udp6, POLLIN, 0 },
        [P_TCP4]  = { tcp4, POLLIN, 0 },
        [P_TCP6]  = { tcp6, POLLIN, 0 },
    };                                   /* poll() ignores negative fds */

    while (g_running) {
        if (g_reload_hints) {
            g_reload_hints = 0;
            reload(hints_file);
        }
        /* 1 s timeout so signals are noticed promptly. */
        int nready = poll(pfds, P_COUNT, 1000);
        if (nready < 0 && errno != EINTR) { perror("Error: poll failed"); break; }
        if (nready <= 0) continue;

        if (pfds[P_STATS].revents & POLLIN) {
            char buf[16];
            while (read(stats_pipe[0], buf, sizeof(buf)) > 0) {}
            print_cache_stats(g_ns_cache, g_answer_cache);
            print_query_stats();
        }
        if (pfds[P_UDP4].revents & POLLIN) drain_udp_socket(udp4, udp_pool);
        if (pfds[P_UDP6].revents & POLLIN) drain_udp_socket(udp6, udp_pool);
        if (pfds[P_TCP4].revents & POLLIN) accept_tcp(tcp4, tcp_pool);
        if (pfds[P_TCP6].revents & POLLIN) accept_tcp(tcp6, tcp_pool);
    }

    pthread_mutex_lock(&g_cleanup_mutex);
    pthread_cond_signal(&g_cleanup_cond);
    pthread_mutex_unlock(&g_cleanup_mutex);
    if (cleanup_started) pthread_join(cleanup_tid, NULL);

    /* Stop the workers before freeing anything they read. */
    threadpool_wait(udp_pool);
    threadpool_destroy(udp_pool);
    threadpool_wait(tcp_pool);
    threadpool_destroy(tcp_pool);

    free_trust_anchors(g_trust_anchors);
    ns_cache_destroy(g_ns_cache);
    answer_cache_destroy(g_answer_cache);
    close_fd(stats_pipe[0]);
    close_fd(stats_pipe[1]);
    close_fd(udp4);
    close_fd(udp6);
    close_fd(tcp4);
    close_fd(tcp6);
    log_close_upstream();
    remove_pid_file();
    return 0;
}
