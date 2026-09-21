#include "workers.h"
#include "access_control.h"
#include "cache.h"
#include "client_reply.h"
#include "query_log.h"
#include "request.h"
#include "resolve.h"
#include "response_handler.h"
#include "utils.h"

#include <netinet/tcp.h>
#include <sys/time.h>

/* malloc'd error reply for a raw query. */
static char* error_reply(const char* req, ssize_t req_len, int rcode, ssize_t* out_len)
{
    unsigned char tmp[ERROR_REPLY_MAX];
    int n = build_error_reply((const unsigned char*)req, req_len, rcode, tmp, sizeof(tmp));
    char* out = n > 0 ? malloc((size_t)n) : NULL;
    if (out) memcpy(out, tmp, (size_t)n);
    *out_len = out ? n : 0;
    return out;
}

/* RD=0 (RFC 1034 §4.3.1): answer only from what we already hold. */
static struct Packet* cache_only_answer(const struct Packet* pkt)
{
    if (!g_answer_cache || pkt->q_class != CLASS_IN) return NULL;
    return answer_cache_get(g_answer_cache, pkt->full_domain, pkt->q_type);
}

/*
 * Resolve one client query and return the malloc'd reply (NULL = send
 * nothing).  UDP replies are trimmed to the client's size; TCP replies are
 * sent whole.
 */
static char* answer_query(char* buf, ssize_t len, const char* ip, uint16_t port,
                          bool tcp, ssize_t* out_len)
{
    *out_len = 0;
    /* QR=1 is a response: answering it invites reflection loops. */
    if (len >= 3 && (buf[2] & 0x80)) return NULL;

    struct Packet* pkt = parse_request_headers(buf, len);
    if (!pkt) {
        fprintf(stderr, "Failed to parse request from %s\n", ip);
        return error_reply(buf, len, RCODE_FORMAT_ERROR, out_len);
    }

    char* reply = NULL;
    struct Packet* query = NULL;
    struct Packet* ret = NULL;

    if (pkt->rcode != 0) {                        /* NOTIMP / FORMERR from the parser */
        reply = error_reply(buf, len, pkt->rcode, out_len);
        goto done;
    }
    if (pkt->edns_present && pkt->edns_version > 0) {
        unsigned char bv[ERROR_REPLY_MAX];
        int n = build_badvers_reply((unsigned char*)buf, len, pkt->do_bit, bv, sizeof(bv));
        if (n > 0 && (reply = malloc((size_t)n))) {
            memcpy(reply, bv, (size_t)n);
            *out_len = n;
        }
        goto done;
    }
    count_query(pkt->q_type);

    /* The client's DO/CD decide whether we validate (RFC 4035 §3.2.2); the
     * wire query itself always asks for DNSSEC data. */
    query = build_query(pkt->full_domain, pkt->q_type, pkt->q_class);
    if (query) {
        query->do_bit = pkt->do_bit;
        query->cd     = pkt->cd;
        ret = pkt->rd ? send_resolver(query) : cache_only_answer(pkt);
    }
    if (!ret || !ret->request || ret->recv_len < HEADER_LEN) {
        /* SERVFAIL either way.  An RD=0 miss is "I could not answer this one",
         * which is what 1.1.1.1 and 8.8.8.8 return; REFUSED would mean "I will
         * not serve you" and can make a stub drop the server entirely. */
        int rc = RCODE_SERVER_FAILURE;
        if (pkt->rd) fprintf(stderr, "Failed to resolve %s\n", pkt->full_domain);
        log_query(ip, port, pkt->q_type, pkt->full_domain, (uint8_t)rc, NULL);
        reply = error_reply(buf, len, rc, out_len);
        goto done;
    }

    wr16(ret->request, pkt->id);
    normalize_forwarded_flags((unsigned char*)ret->request, ret->recv_len, pkt->rd, pkt->cd);
    restore_question_case((unsigned char*)ret->request, ret->recv_len,
                          (const unsigned char*)buf, len);
    /* We fetched with DO=1; a non-DO client gets a plain answer (RFC 4035 §3.2.1). */
    if (!pkt->do_bit)
        strip_dnssec_for_non_do(&ret->request, &ret->recv_len, pkt->q_type);
    if (!tcp)
        finalize_udp_truncation(&ret->request, &ret->recv_len,
                                pkt->edns_present ? (pkt->edns_udp_size ? pkt->edns_udp_size : 512) : 0,
                                pkt->do_bit);
    else if (pkt->edns_present)
        ensure_edns_opt(&ret->request, &ret->recv_len, pkt->do_bit);

    log_query(ip, port, pkt->q_type, pkt->full_domain, (uint8_t)(ret->request[3] & 0x0F), NULL);
    reply = ret->request;
    *out_len = ret->recv_len;
    ret->request = NULL;

done:
    free_packet(ret);
    free_packet(query);
    free_packet(pkt);
    return reply;
}

void* process_query(void* arg)
{
    struct QueryContext* ctx = arg;
    char ip[INET6_ADDRSTRLEN];
    uint16_t port;
    sockaddr_to_ip(&ctx->client_addr, ip, &port);

    ssize_t n;
    char* reply = answer_query(ctx->buffer, ctx->recv_len, ip, port, false, &n);
    if (reply)
        sendto(ctx->dns_sock, reply, (size_t)n, 0,
               (const struct sockaddr*)&ctx->client_addr, ctx->client_addr_len);
    free(reply);
    free(ctx);
    return NULL;
}

/* Idle clients are cut off after TCP_IDLE_TIMEOUT (each holds a worker);
 * keepalive reaps dead half-open peers (RFC 7766 §6.2.3). */
static void tune_client_socket(int fd)
{
    struct timeval rtv = { .tv_sec = TCP_IDLE_TIMEOUT };
    struct timeval wtv = { .tv_sec = SOCKET_TIMEOUT };
    int on = 1, idle = 60, intvl = 10, cnt = 3;
    setsockopt(fd, SOL_SOCKET,  SO_RCVTIMEO,   &rtv,   sizeof(rtv));
    setsockopt(fd, SOL_SOCKET,  SO_SNDTIMEO,   &wtv,   sizeof(wtv));
    setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE,  &on,    sizeof(on));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &idle,  sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
}

/* Pipelined DNS-over-TCP (RFC 7766): serve messages until EOF or timeout. */
void* process_tcp_query(void* arg)
{
    struct TCPQueryContext* ctx = arg;
    int fd = ctx->client_fd;
    char ip[INET6_ADDRSTRLEN];
    uint16_t port;
    sockaddr_to_ip(&ctx->client_ss, ip, &port);
    tune_client_socket(fd);

    for (;;) {
        uint8_t prefix[2];
        if (recv(fd, prefix, 2, MSG_WAITALL) != 2) break;
        uint16_t len = rd16(prefix);
        if (len < HEADER_LEN) break;

        /* RFC 7766: a TCP message may be up to 65535 bytes, far above the UDP
         * receive buffer.  Size the read to the length prefix rather than
         * capping at MAXLINE, which dropped a large query AND tore down the
         * connection instead of answering it. */
        char* buf = malloc(len);
        if (!buf) break;
        if (recv(fd, buf, len, MSG_WAITALL) != len) { free(buf); break; }

        ssize_t n;
        char* reply = answer_query(buf, len, ip, port, true, &n);
        free(buf);
        if (reply) tcp_send_msg(fd, reply, (size_t)n);
        free(reply);
    }

    close(fd);
    tcp_conn_release(&ctx->client_ss);
    free(ctx);
    return NULL;
}
