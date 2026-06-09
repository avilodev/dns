#include "dns_synth.h"

#include <string.h>

/* Protocol constants — kept local so this module depends on nothing else. */
#define DNS_HEADER_LEN 12
#define DNS_TYPE_CNAME  5

/*
 * Encode a presentation-form name ("mail.example.com") into DNS wire labels.
 * Returns the number of bytes written (including the terminating zero), or -1.
 * Self-contained so dns_synth has no cross-module dependency.
 */
static int synth_encode_name(const char* name, unsigned char* out, size_t cap)
{
    if (!name || !out) return -1;
    size_t w = 0;

    /* Root / empty name. */
    if (name[0] == '\0' || (name[0] == '.' && name[1] == '\0')) {
        if (cap < 1) return -1;
        out[w++] = 0;
        return (int)w;
    }

    const char* p = name;
    while (*p) {
        if (*p == '.') { p++; continue; }          /* skip dots / empty labels */
        const char* end = p;
        while (*end && *end != '.') end++;
        size_t len = (size_t)(end - p);
        if (len > 63) return -1;
        if (w + 1 + len + 1 > cap) return -1;       /* len byte + label + terminator */
        out[w++] = (unsigned char)len;
        memcpy(out + w, p, len);
        w += len;
        p = end;
    }
    if (w + 1 > cap) return -1;
    out[w++] = 0;
    return (int)w;
}

/*
 * Build a synthesized response (NXDOMAIN refusal or local-zone answer) from a
 * client query.  See dns_synth.h for the header/flag contract.  Pure: the only
 * output is the caller-provided `out` buffer; no allocation, no sockets.
 */
ssize_t dns_synth_response(const unsigned char* query, ssize_t qlen,
                           int rcode,
                           const SynthAnswer* answers, int nanswers,
                           unsigned char* out, size_t out_max)
{
    if (!query || !out) return -1;
    if (qlen < 17) return -1;                 /* hdr(12) + min qname(1) + type(2) + class(2) */
    if (nanswers < 0 || (nanswers > 0 && !answers)) return -1;

    /* Walk the question's QNAME (starts at offset 12) to find its end.  A query's
     * question section must use literal labels — reject compression pointers. */
    ssize_t pos = DNS_HEADER_LEN;
    while (pos < qlen) {
        uint8_t ll = query[pos];
        if (ll == 0) { pos++; break; }
        if ((ll & 0xC0) == 0xC0) return -1;   /* compression in question = malformed */
        if (ll > 63) return -1;
        pos += 1 + ll;
        if (pos >= qlen) return -1;           /* label ran off the end, no terminator */
    }
    if (pos + 4 > qlen) return -1;            /* need QTYPE + QCLASS */
    ssize_t qend = pos + 4;                   /* end of the question section */

    if ((size_t)qend > out_max) return -1;    /* header + question must fit */
    memcpy(out, query, (size_t)qend);

    /* Header flags (RFC 1035 §4.1.1):
     *   byte 2: QR=1, opcode + RD preserved, AA=0, TC=0  -> 0x80 | (q[2] & 0x79)
     *   byte 3: RA=1, Z/AD/CD=0, RCODE=rcode             -> 0x80 | (rcode & 0x0F) */
    out[2] = (unsigned char)(0x80 | (query[2] & 0x79));
    out[3] = (unsigned char)(0x80 | (rcode & 0x0F));

    /* QDCOUNT=1, ANCOUNT=nanswers, NSCOUNT=0, ARCOUNT=0 (drop any query OPT). */
    out[4] = 0x00; out[5] = 0x01;
    out[6] = (unsigned char)((nanswers >> 8) & 0xFF);
    out[7] = (unsigned char)(nanswers & 0xFF);
    out[8] = 0x00; out[9] = 0x00;
    out[10] = 0x00; out[11] = 0x00;

    /* Append answer RRs; every owner is a compression pointer to the QNAME. */
    ssize_t w = qend;
    for (int i = 0; i < nanswers; i++) {
        const SynthAnswer* a = &answers[i];

        unsigned char rdata[256];
        uint16_t rdlen;
        if (a->qtype == DNS_TYPE_CNAME) {
            int n = synth_encode_name(a->cname, rdata, sizeof(rdata));
            if (n < 0) return -1;
            rdlen = (uint16_t)n;
        } else {
            if (a->addrlen != 4 && a->addrlen != 16) return -1;
            memcpy(rdata, a->addr, (size_t)a->addrlen);
            rdlen = (uint16_t)a->addrlen;
        }

        /* 2 (owner ptr) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rdlen) + rdlen */
        if ((size_t)w + 12u + rdlen > out_max) return -1;

        out[w++] = 0xC0; out[w++] = 0x0C;                  /* owner -> offset 12 */
        out[w++] = (unsigned char)(a->qtype >> 8);
        out[w++] = (unsigned char)(a->qtype & 0xFF);
        out[w++] = 0x00; out[w++] = 0x01;                  /* CLASS = IN */
        out[w++] = (unsigned char)((a->ttl >> 24) & 0xFF);
        out[w++] = (unsigned char)((a->ttl >> 16) & 0xFF);
        out[w++] = (unsigned char)((a->ttl >> 8) & 0xFF);
        out[w++] = (unsigned char)(a->ttl & 0xFF);
        out[w++] = (unsigned char)(rdlen >> 8);
        out[w++] = (unsigned char)(rdlen & 0xFF);
        memcpy(out + w, rdata, rdlen);
        w += rdlen;
    }

    return w;
}
