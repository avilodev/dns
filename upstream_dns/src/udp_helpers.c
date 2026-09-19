#include "udp_helpers.h"

#include <arpa/inet.h>   /* ntohs, htons */
#include <stdlib.h>      /* realloc */
#include <string.h>
#include <unistd.h>

#include "types.h"       /* RCODE_*, HEADER_LEN, MAXLINE */
#include "dns_name.h"    /* dname_from_wire */

/*
 * Build an error reply (header + echoed question) for a raw query.
 *
 * The question is echoed whenever the query carries exactly one well-formed
 * question: stub resolvers such as glibc discard replies whose question does
 * not match what they asked (only FORMERR is exempt) and then sit out their
 * full timeout — the same reason auth_dns ignores a question-less SERVFAIL
 * from us and waits 5 s.  Opcode and RD are echoed, RA is set.  Returns the
 * reply length (12 when no question could be echoed), or 0 on bad input.
 */
int build_error_reply(const unsigned char* req, ssize_t req_len, int rcode,
                      unsigned char* out, int out_cap)
{
    if (!req || req_len < 2 || !out || out_cap < HEADER_LEN) return 0;
    memset(out, 0, HEADER_LEN);
    out[0] = req[0];
    out[1] = req[1];
    out[2] = (unsigned char)(0x80 | (req_len > 2 ? (req[2] & 0x79) : 0)); /* QR, opcode, RD */
    out[3] = (unsigned char)(0x80 | (rcode & 0x0F));                      /* RA, RCODE    */

    if (req_len < HEADER_LEN + 5 || req[4] != 0 || req[5] != 1) return HEADER_LEN;
    int q = HEADER_LEN;
    while (q < req_len) {
        uint8_t l = req[q];
        if (l == 0) { q++; break; }
        if (l > 63) return HEADER_LEN;            /* compression / bad label */
        q += 1 + l;
    }
    if (q > req_len || q + 4 > req_len || req[q - 1] != 0) return HEADER_LEN;
    int qlen = q + 4 - HEADER_LEN;
    if (HEADER_LEN + qlen > out_cap) return HEADER_LEN;
    memcpy(out + HEADER_LEN, req + HEADER_LEN, (size_t)qlen);
    out[5] = 1;                                   /* QDCOUNT = 1 */
    return HEADER_LEN + qlen;
}

static void send_error_udp(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                           const unsigned char* req_buf, ssize_t req_len, int rcode)
{
    if (!client_addr) return;
    unsigned char resp[HEADER_LEN + 260] = {0};
    int n = build_error_reply(req_buf, req_len, rcode, resp, sizeof(resp));
    if (n > 0) sendto(sock, resp, (size_t)n, 0, client_addr, addr_len);
}

/* SERVFAIL — resolution failed; lets the client fail fast instead of timing out. */
void send_servfail(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                   const unsigned char* req_buf, ssize_t req_len) {
    send_error_udp(sock, client_addr, addr_len, req_buf, req_len, RCODE_SERVER_FAILURE);
}

/* REFUSED — source outside the allow-list (known_issues 4.3).  The reply is no
 * larger than the query, so it cannot be used for amplification. */
void send_refused(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                  const unsigned char* req_buf, ssize_t req_len) {
    send_error_udp(sock, client_addr, addr_len, req_buf, req_len, RCODE_REFUSED);
}

void send_error_rcode(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
                      const unsigned char* req_buf, ssize_t req_len, int rcode) {
    send_error_udp(sock, client_addr, addr_len, req_buf, req_len, rcode);
}

/* Same error reply over TCP (2-byte length prefix).  Best effort. */
void send_error_tcp(int fd, const unsigned char* req_buf, ssize_t req_len, int rcode)
{
    unsigned char resp[2 + HEADER_LEN + 260] = {0};
    int n = build_error_reply(req_buf, req_len, rcode, resp + 2, sizeof(resp) - 2);
    if (n <= 0) return;
    resp[0] = (unsigned char)(n >> 8);
    resp[1] = (unsigned char)(n & 0xFF);
    size_t off = 0, total = (size_t)n + 2;
    while (off < total) {
        ssize_t w = write(fd, resp + off, total - off);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static bool wire_has_opt(const unsigned char* m, ssize_t len);

/*
 * Lightweight inline parser: extract the QNAME (dotted string) and QTYPE
 * from a raw DNS query packet without allocating any memory.
 * Returns 1 on success, 0 if the packet is malformed or not a standard query.
 */
int quick_parse_query(const char* buf, ssize_t len,
                              char* domain_out, int domain_max,
                              uint16_t* qtype_out, bool* do_out,
                              uint16_t* edns_size_out)
{
    if (do_out) *do_out = false;
    if (edns_size_out) *edns_size_out = 0;   /* 0 = client sent no EDNS OPT */
    if (len < 17) return 0;                          // header(12) + min QNAME(1) + null(1) + QTYPE(2) + QCLASS(2)
    if (buf[2] & 0x80) return 0;                     // QR=1 means response, not a query
    if ((buf[2] >> 3) & 0x0F) return 0;              // opcode != QUERY: let the worker answer NOTIMP
    if ((uint8_t)buf[4] != 0 || (uint8_t)buf[5] != 1) return 0;  // QDCOUNT must be 1

    /* Literal labels only (compression in a question is malformed), decoded
     * by the same codec as parse_request_headers() so both paths produce the
     * identical escaped, lowercased cache key. */
    for (int p = 12; ; ) {
        if (p >= len) return 0;
        uint8_t ll = (uint8_t)buf[p];
        if (ll == 0) break;
        if (ll & 0xC0) return 0;
        p += 1 + ll;
    }
    int pos = dname_from_wire((const uint8_t*)buf, (int)len, 12, true,
                              domain_out, (size_t)domain_max);
    if (pos < 0) return 0;

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
void finalize_udp_truncation(char** buf, ssize_t* len, uint16_t edns_udp_size)
{
    if (!buf || !*buf || !len || *len < HEADER_LEN) return;

    bool     edns      = (edns_udp_size != 0);
    uint16_t udp_limit = (edns && edns_udp_size >= 512) ? edns_udp_size : 512;
    /* Never send a UDP answer larger than we advertise ourselves: it avoids IP
     * fragmentation, and auth_dns reads forwarded answers into a MAXLINE
     * buffer, so an oversize datagram would arrive silently cut short. */
    if (udp_limit > EDNS_UDP_PAYLOAD) udp_limit = EDNS_UDP_PAYLOAD;
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
        if (!wire_has_opt(r, *len) && *len + 11 <= MAXLINE) {
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

/* Walk a response and report whether it already holds an OPT RR. */
static bool wire_has_opt(const unsigned char* m, ssize_t len)
{
    if (len < HEADER_LEN) return false;
    int qd = (m[4] << 8) | m[5];
    int total = ((m[6] << 8) | m[7]) + ((m[8] << 8) | m[9]) + ((m[10] << 8) | m[11]);
    ssize_t p = HEADER_LEN;
    for (int i = 0; i < qd + total; i++) {
        while (p < len) {                           /* skip owner name */
            uint8_t l = m[p];
            if (l == 0)             { p += 1; break; }
            if ((l & 0xC0) == 0xC0) { p += 2; break; }
            p += 1 + l;
        }
        if (i < qd) { p += 4; continue; }
        if (p + 10 > len) return false;
        if (m[p] == 0 && m[p + 1] == 41) return true;
        p += 10 + ((m[p + 8] << 8) | m[p + 9]);
    }
    return false;
}

/*
 * Append a bare OPT RR (1232-byte payload, DO mirrored) to a response for an
 * EDNS client when it lacks one (RFC 6891 §7).  Used on the TCP path, where
 * finalize_udp_truncation() does not run.  Best effort: leaves the buffer
 * untouched on allocation failure.
 */
void ensure_edns_opt(char** buf, ssize_t* len, bool do_bit)
{
    if (!buf || !*buf || !len || *len < HEADER_LEN) return;
    if (wire_has_opt((const unsigned char*)*buf, *len)) return;
    unsigned char* np = realloc(*buf, (size_t)*len + 11);
    if (!np) return;
    *buf = (char*)np;
    unsigned char* o = np + *len;
    o[0] = 0x00;                                   /* root owner */
    o[1] = 0x00; o[2] = 41;                        /* TYPE = OPT */
    o[3] = (uint8_t)(EDNS_UDP_PAYLOAD >> 8);
    o[4] = (uint8_t)(EDNS_UDP_PAYLOAD & 0xFF);     /* UDP payload size */
    o[5] = 0; o[6] = 0;                            /* ext-RCODE, version */
    o[7] = do_bit ? 0x80 : 0x00; o[8] = 0;         /* flags (DO) */
    o[9] = 0; o[10] = 0;                           /* RDLEN = 0 */
    uint16_t ar = (uint16_t)((np[10] << 8) | np[11]) + 1;
    np[10] = (uint8_t)(ar >> 8); np[11] = (uint8_t)(ar & 0xFF);
    *len += 11;
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
void normalize_forwarded_flags(unsigned char* resp, ssize_t len, int client_rd)
{
    if (!resp || len < 4) return;
    uint16_t flags = rd16(resp + 2);
    flags &= ~(1u << 10);                /* AA = 0 */
    flags |=  (1u << 7);                 /* RA = 1 */
    if (client_rd) flags |=  (1u << 8);  /* RD echo */
    else           flags &= ~(1u << 8);
    wr16(resp + 2, flags);
}
