#include "udp_client.h"
#include "dns_packet.h"
#include "infra.h"
#include "utils.h"

#include <limits.h>
#include <strings.h>
#include <time.h>
#include <sys/random.h>
#include <sys/time.h>

/* ---- Resolution time budget ------------------------------------------- */

static __thread int             tls_depth = 0;   /* 0 = no budget armed */
static __thread struct timespec tls_deadline;

void resolver_deadline_begin(int budget_sec)
{
    if (tls_depth++ == 0) {
        clock_gettime(CLOCK_MONOTONIC, &tls_deadline);
        tls_deadline.tv_sec += budget_sec;
    }
}

void resolver_deadline_end(void)
{
    if (tls_depth > 0) tls_depth--;
}

static long ms_between(const struct timespec* a, const struct timespec* b)
{
    return (b->tv_sec - a->tv_sec) * 1000L + (b->tv_nsec - a->tv_nsec) / 1000000L;
}

static long elapsed_ms(const struct timespec* t0)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return ms_between(t0, &now);
}

/* Milliseconds left on the budget (LONG_MAX when none is armed). */
static long deadline_remaining_ms(void)
{
    return tls_depth == 0 ? LONG_MAX : -elapsed_ms(&tls_deadline);
}

bool resolver_deadline_exceeded(void)
{
    return deadline_remaining_ms() <= 0;
}

/* Whole seconds a hop may wait: min(budget left, PER_HOP_TIMEOUT_SEC).
 * 0 means "don't start another hop".  No budget -> SOCKET_TIMEOUT. */
static int per_hop_timeout_sec(void)
{
    if (tls_depth == 0) return SOCKET_TIMEOUT;
    long rem_ms = deadline_remaining_ms();
    if (rem_ms <= 0) return 0;
    /* Round up, so the last fraction of a second is still spent on a hop
     * instead of being discarded by integer division. */
    long rem_sec = (rem_ms + 999) / 1000;
    return rem_sec < PER_HOP_TIMEOUT_SEC ? (int)rem_sec : PER_HOP_TIMEOUT_SEC;
}

/* ---- Queries ----------------------------------------------------------- */

/* Random source port >= 1024 (RFC 5452 §3.3); the OS picks if all tries fail. */
static void bind_random_port(int fd, int family)
{
    const char* any = family == AF_INET6 ? "::" : "0.0.0.0";
    struct sockaddr_storage ss;
    for (int attempt = 0; attempt < 8; attempt++) {
        uint16_t port;
        if (getrandom(&port, sizeof(port), 0) != sizeof(port))
            port = (uint16_t)time(NULL);
        if (port < 1024) port |= 0x0400;
        socklen_t len = sockaddr_from_ip(any, port, &ss);
        if (bind(fd, (struct sockaddr*)&ss, len) == 0) return;
    }
    socklen_t len = sockaddr_from_ip(any, 0, &ss);
    bind(fd, (struct sockaddr*)&ss, len);
}

/* A reply to exactly this query (RFC 5452 §6: ID and question must match). */
static bool reply_matches(const struct Packet* r, const struct Packet* q)
{
    return r->qr == 1 && r->opcode == 0 && r->id == q->id &&
           r->full_domain && q->full_domain &&
           strcasecmp(r->full_domain, q->full_domain) == 0 &&
           r->q_type == q->q_type && r->q_class == q->q_class;
}

/* Every RR needs >= 11 bytes; reject counts the datagram can't hold. */
static bool counts_plausible(const struct Packet* r, ssize_t len)
{
    uint32_t total = (uint32_t)r->ancount + r->nscount + r->arcount;
    return (ssize_t)(total * 11U) <= len - HEADER_LEN;
}

static struct Packet* query_udp(const char* server_ip, struct Packet* query, int timeout_sec)
{
    struct sockaddr_storage srv;
    socklen_t slen = sockaddr_from_ip(server_ip, DNS_PORT, &srv);
    if (slen == 0) {
        fprintf(stderr, "  Invalid IP address: %s\n", server_ip);
        return NULL;
    }
    int fd = socket(srv.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("  Socket creation failed");
        return NULL;
    }
    bind_random_port(fd, srv.ss_family);

    /* connect(): only the server's datagrams are delivered, and ICMP
     * unreachable fails recv() at once instead of running out the timeout. */
    if (connect(fd, (struct sockaddr*)&srv, slen) < 0 ||
        send(fd, query->request, (size_t)query->recv_len, 0) < 0) {
        infra_report_failure(server_ip);
        close(fd);
        return NULL;
    }
    struct timespec t_sent;
    clock_gettime(CLOCK_MONOTONIC, &t_sent);

    /* Keep reading until a matching reply or the deadline, so a spoofed or
     * stray datagram can't make us drop the real answer. */
    char buf[MAXLINE];
    struct Packet* resp = NULL;
    for (;;) {
        long left = timeout_sec * 1000L - elapsed_ms(&t_sent);
        if (left <= 0) break;
        struct timeval tv = { .tv_sec = left / 1000, .tv_usec = (left % 1000) * 1000 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (!errno_is_timeout(errno)) perror("  recv failed");
            break;
        }
        resp = parse_response(buf, n);
        if (resp && reply_matches(resp, query) && counts_plausible(resp, n)) break;
        fprintf(stderr, "  Reply from %s does not match the query; ignoring\n", server_ip);
        free_packet(resp);
        resp = NULL;
    }
    close(fd);

    if (resp) infra_report_rtt(server_ip, (int)elapsed_ms(&t_sent));
    else      infra_report_failure(server_ip);   /* timeout, unreachable, or junk */
    return resp;
}

struct Packet* query_server(const char* server_ip, struct Packet* query)
{
    if (!server_ip || !query || !query->request) return NULL;
    int timeout_sec = per_hop_timeout_sec();
    if (timeout_sec == 0) return NULL;           /* budget spent: fail fast */
    return query_udp(server_ip, query, timeout_sec);
}

/* TCP fallback for TC=1 answers (RFC 1035 §4.2.2). */
struct Packet* query_server_tcp(const char* server_ip, struct Packet* query)
{
    if (!server_ip || !query || !query->request || query->recv_len <= 0) return NULL;
    int timeout_sec = per_hop_timeout_sec();
    if (timeout_sec == 0) return NULL;

    struct sockaddr_storage srv;
    socklen_t slen = sockaddr_from_ip(server_ip, DNS_PORT, &srv);
    int fd = slen ? socket(srv.ss_family, SOCK_STREAM, 0) : -1;
    if (fd < 0) return NULL;

    struct timeval tv = { .tv_sec = timeout_sec };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&srv, slen) < 0) {
        perror("  TCP connect failed");
        infra_report_failure(server_ip);
        close(fd);
        return NULL;
    }
    struct timespec t_conn;
    clock_gettime(CLOCK_MONOTONIC, &t_conn);

    /* Length-prefixed exchange; a TCP answer may use the full 64 KB. */
    uint8_t prefix[2];
    char* buf = NULL;
    uint16_t rlen = 0;
    bool ok = tcp_send_msg(fd, query->request, (size_t)query->recv_len) &&
              recv(fd, prefix, 2, MSG_WAITALL) == 2 &&
              (rlen = rd16(prefix)) >= HEADER_LEN && (buf = malloc(rlen)) &&
              recv(fd, buf, rlen, MSG_WAITALL) == rlen;
    close(fd);
    if (!ok) { free(buf); return NULL; }

    struct Packet* resp = parse_response(buf, rlen);
    free(buf);
    if (resp && !counts_plausible(resp, rlen)) {
        fprintf(stderr, "  TCP response from %s has impossible RR counts; dropping\n", server_ip);
        infra_report_failure(server_ip);
        free_packet(resp);
        return NULL;
    }
    if (resp && !reply_matches(resp, query)) {
        fprintf(stderr, "  TCP response from %s does not match the query; dropping\n", server_ip);
        infra_report_failure(server_ip);
        free_packet(resp);
        return NULL;
    }
    if (resp) infra_report_rtt(server_ip, (int)elapsed_ms(&t_conn));
    return resp;
}
