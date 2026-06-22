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
#include "udp_helpers.h"
#include "workers.h"

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

/* Per-QTYPE query counters (atomic, safe for concurrent worker threads).
 * Non-static: incremented by the workers in workers.c, read here by
 * print_qtype_stats(). */
_Atomic uint64_t g_qtype_counters[256];
_Atomic uint64_t g_total_queries;

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
