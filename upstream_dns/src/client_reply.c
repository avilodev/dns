#include "client_reply.h"
#include "dns_name.h"
#include "utils.h"

/* Error reply; add_opt echoes an OPT when the query had one. */
static int error_reply(const unsigned char* req, ssize_t req_len, int rcode,
                       unsigned char* out, int out_cap, bool add_opt)
{
    if (!req || req_len < 2 || !out || out_cap < HEADER_LEN) return 0;
    memset(out, 0, HEADER_LEN);
    memcpy(out, req, 2);                                           /* ID */
    out[2] = (unsigned char)(0x80 | (req_len > 2 ? (req[2] & 0x79) : 0));    /* QR, opcode, RD */
    out[3] = (unsigned char)(0x80 | (req_len > 3 ? (req[3] & 0x10) : 0) |    /* RA, CD, RCODE */
                             (rcode & 0x0F));

    /* Echo exactly one literal question, if the query has one. */
    if (req_len < HEADER_LEN + 5 || rd16(req + 4) != 1) return HEADER_LEN;
    int q = HEADER_LEN;
    while (q < req_len && req[q] != 0) {
        if (req[q] > 63) return HEADER_LEN;                        /* pointer / bad label */
        q += 1 + req[q];
    }
    int qlen = q + 1 + 4 - HEADER_LEN;
    if (q >= req_len || HEADER_LEN + qlen > req_len || HEADER_LEN + qlen > out_cap)
        return HEADER_LEN;
    memcpy(out + HEADER_LEN, req + HEADER_LEN, (size_t)qlen);
    out[5] = 1;
    int n = HEADER_LEN + qlen;

    bool do_bit = false;
    if (add_opt && n + OPT_RR_LEN <= out_cap && find_opt_rr(req, (int)req_len, &do_bit)) {
        write_opt_rr(out + n, do_bit, 0);
        out[11] = 1;
        n += OPT_RR_LEN;
    }
    return n;
}

int build_error_reply(const unsigned char* req, ssize_t req_len, int rcode,
                      unsigned char* out, int out_cap)
{
    /* No OPT on FORMERR: the client's OPT may be what was malformed. */
    return error_reply(req, req_len, rcode, out, out_cap, rcode != RCODE_FORMAT_ERROR);
}

/* BADVERS = 16: low 4 bits in the header (0), upper bits in the OPT. */
int build_badvers_reply(const unsigned char* req, ssize_t req_len, bool do_bit,
                        unsigned char* out, int out_cap)
{
    int n = error_reply(req, req_len, RCODE_BADVERS & 0x0F, out, out_cap, false);
    if (n <= 0 || n + OPT_RR_LEN > out_cap) return 0;
    write_opt_rr(out + n, do_bit, RCODE_BADVERS >> 4);
    wr16(out + 10, 1);
    return n + OPT_RR_LEN;
}

void send_error_udp(int sock, const struct sockaddr* addr, socklen_t addr_len,
                    const unsigned char* req, ssize_t req_len, int rcode)
{
    unsigned char resp[ERROR_REPLY_MAX];
    int n = addr ? build_error_reply(req, req_len, rcode, resp, sizeof(resp)) : 0;
    if (n > 0) sendto(sock, resp, (size_t)n, 0, addr, addr_len);
}

int quick_parse_query(const char* buf, ssize_t len, char* domain_out, int domain_max,
                      uint16_t* qtype_out, bool* do_out, uint16_t* edns_size_out)
{
    const uint8_t* m = (const uint8_t*)buf;
    *do_out = false;
    *edns_size_out = 0;
    if (len < 17) return 0;                     /* header + root + QTYPE + QCLASS */
    if (m[2] & 0x80) return 0;                  /* a response */
    if ((m[2] >> 3) & 0x0F) return 0;           /* opcode != QUERY: worker answers NOTIMP */
    if (rd16(m + 4) != 1) return 0;

    /* Literal labels only, decoded like parse_request_headers() so both
     * paths produce the same cache key. */
    for (int p = HEADER_LEN; ; p += 1 + m[p]) {
        if (p >= len || (m[p] & 0xC0)) return 0;
        if (m[p] == 0) break;
    }
    int pos = dname_from_wire(m, (int)len, HEADER_LEN, true, domain_out, (size_t)domain_max);
    if (pos < 0 || pos + 4 > len) return 0;
    *qtype_out = rd16(m + pos);
    if (rd16(m + pos + 2) != CLASS_IN) return 0;   /* the cache holds class IN only */

    /* Meta and pseudo types get FORMERR/NOTIMP from parse_request_headers();
     * hand them to the worker so both paths answer a query the same way. */
    if (*qtype_out == QTYPE_OPT || (*qtype_out >= 249 && *qtype_out <= 254)) return 0;

    /* DO bit (never serve signed-but-unvalidated to a validator) and UDP
     * size (same truncation as the worker path).  An OPT that is repeated,
     * misplaced or not root-owned is FORMERR (RFC 6891 §6.1.1) — also the
     * worker's job, so don't answer those from the cache either. */
    int opt_count = 0;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, m, (int)len); rr_next(&it, &rr); ) {
        if (rr.type != QTYPE_OPT) continue;
        if (++opt_count > 1 || m[rr.owner] != 0 || rr.section != SEC_ADDITIONAL) return 0;
        if ((rr.ttl >> 16) & 0xFF) return 0;    /* EDNS version > 0: worker sends BADVERS */
        *do_out = (rr.ttl & 0x8000) != 0;
        *edns_size_out = rr.rclass ? rr.rclass : 512;
    }
    return 1;
}

void ensure_edns_opt(char** buf, ssize_t* len, bool do_bit)
{
    if (!buf || !*buf || !len || *len < HEADER_LEN) return;
    if (find_opt_rr((const uint8_t*)*buf, (int)*len, NULL)) return;
    unsigned char* np = realloc(*buf, (size_t)*len + OPT_RR_LEN);
    if (!np) return;
    *buf = (char*)np;
    write_opt_rr(np + *len, do_bit, 0);
    wr16(np + 10, (uint16_t)(rd16(np + 10) + 1));
    *len += OPT_RR_LEN;
}

void finalize_udp_truncation(char** buf, ssize_t* len, uint16_t edns_udp_size, bool do_bit)
{
    if (!buf || !*buf || !len || *len < HEADER_LEN) return;
    bool edns = edns_udp_size != 0;
    int limit = edns && edns_udp_size >= 512 ? edns_udp_size : 512;
    /* Never above what we advertise: avoids fragmentation, and auth_dns
     * reads forwarded answers into a fixed buffer. */
    if (limit > EDNS_UDP_PAYLOAD) limit = EDNS_UDP_PAYLOAD;

    /* Add our OPT BEFORE measuring: it is part of the datagram the limit
     * applies to.  Appending afterwards pushed an answer of limit-10..limit
     * bytes out at up to limit+OPT_RR_LEN — over what the client advertised,
     * and over the fragmentation margin EDNS_UDP_PAYLOAD exists to keep. */
    if (edns) ensure_edns_opt(buf, len, do_bit);
    if (*len <= limit) return;

    /* Too big: TC=1, keep only the question (+ a fresh OPT). */
    unsigned char* r = (unsigned char*)*buf;
    int qend = dns_question_end(r, (int)*len);
    if (qend < 0) qend = HEADER_LEN;
    wr16(r + 2, rd16(r + 2) | FLAG_TC);
    memset(r + 6, 0, 6);
    if (edns && qend + OPT_RR_LEN <= *len) {    /* fits: the message only shrank */
        write_opt_rr(r + qend, do_bit, 0);
        r[11] = 1;
        *len = qend + OPT_RR_LEN;
    } else {
        *len = qend;
    }
}

void normalize_forwarded_flags(unsigned char* resp, ssize_t len, int client_rd, int client_cd)
{
    if (!resp || len < 4) return;
    uint16_t flags = (rd16(resp + 2) & ~(FLAG_AA | FLAG_RD | FLAG_CD)) | FLAG_RA;
    if (client_rd) flags |= FLAG_RD;
    if (client_cd) flags |= FLAG_CD;
    wr16(resp + 2, flags);
}

static unsigned char ascii_lower(unsigned char c)
{
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 32) : c;
}

/* Only when both names are literal and equal ignoring case, so the
 * question itself can never change (RFC 1035 §7.3, RFC 4343 §4.1). */
void restore_question_case(unsigned char* resp, ssize_t resp_len,
                           const unsigned char* query, ssize_t query_len)
{
    if (!resp || !query || resp_len < HEADER_LEN + 1 || query_len < HEADER_LEN + 1) return;
    if (rd16(resp + 4) != 1) return;
    ssize_t p = HEADER_LEN;
    for (;;) {
        if (p >= resp_len || p >= query_len) return;
        uint8_t l = resp[p];
        if (l != query[p] || (l & 0xC0)) return;
        if (l == 0) break;
        if (p + 1 + l > resp_len || p + 1 + l > query_len) return;
        for (int k = 1; k <= l; k++)          /* bytes, not strings: labels may hold NULs */
            if (ascii_lower(resp[p + k]) != ascii_lower(query[p + k])) return;
        p += 1 + l;
    }
    memcpy(resp + HEADER_LEN, query + HEADER_LEN, (size_t)(p - HEADER_LEN));
}
