#include "workers.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

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

/* Per-QTYPE query counters — defined in main.c, also read by print_qtype_stats(). */
extern _Atomic uint64_t g_qtype_counters[256];
extern _Atomic uint64_t g_total_queries;

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
