#include "udp_helpers.h"

#include <arpa/inet.h>   /* ntohs, htons */
#include <ctype.h>       /* tolower */
#include <stdlib.h>      /* realloc */
#include <string.h>

#include "types.h"       /* RCODE_*, HEADER_LEN, MAXLINE */

/*
 * Send a minimal SERVFAIL response to the client.
 * Used when resolution fails so the client fails fast instead of timing out.
 */
void send_servfail(int sock, const struct sockaddr* client_addr, socklen_t addr_len,
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
void send_refused(int sock, const struct sockaddr* client_addr,
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
int quick_parse_query(const char* buf, ssize_t len,
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
void finalize_udp_truncation(char** buf, ssize_t* len, uint16_t edns_udp_size)
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
void normalize_forwarded_flags(unsigned char* resp, ssize_t len, int client_rd)
{
    if (!resp || len < 4) return;
    uint16_t flags = ntohs(*(uint16_t*)(resp + 2));
    flags &= ~(1u << 10);                /* AA = 0 */
    flags |=  (1u << 7);                 /* RA = 1 */
    if (client_rd) flags |=  (1u << 8);  /* RD echo */
    else           flags &= ~(1u << 8);
    *(uint16_t*)(resp + 2) = htons(flags);
}
