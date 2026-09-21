#include "auth_chase.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define T_CNAME 5
#define T_NS    2
#define T_SOA   6
#define T_PTR   12
#define T_MX    15
#define T_RRSIG 46
#define T_OPT   41

/* Offset just past the (possibly compressed) name at off, or -1. */
static int name_end(const unsigned char* m, int len, int off)
{
    while (off >= 0 && off < len) {
        uint8_t l = m[off];
        if (l == 0) return off + 1;
        if ((l & 0xC0) == 0xC0) return (off + 2 <= len) ? off + 2 : -1;
        if (l > 63) return -1;
        off += 1 + l;
    }
    return -1;
}

/* Copy the name at in[off] to out[*op] uncompressed.  Returns the offset in
 * `in` just past the name as stored, or -1 on malformed input / no room. */
static int copy_name(const unsigned char* in, int len, int off,
                     unsigned char* out, int cap, int* op)
{
    int ret = -1, cur = off, hops = 0, total = 0;
    while (cur >= 0 && cur < len) {
        uint8_t l = in[cur];
        if (l == 0) {
            if (ret < 0) ret = cur + 1;
            if (*op + 1 > cap) return -1;
            out[(*op)++] = 0;
            return ret;
        }
        if ((l & 0xC0) == 0xC0) {
            if (cur + 2 > len || ++hops > 64) return -1;
            if (ret < 0) ret = cur + 2;
            cur = ((l & 0x3F) << 8) | in[cur + 1];
            continue;
        }
        if (l > 63 || cur + 1 + l > len) return -1;
        total += 1 + l;
        if (total > 255 || *op + 1 + l > cap) return -1;
        memcpy(out + *op, in + cur, (size_t)l + 1);
        *op += 1 + l;
        cur += 1 + l;
    }
    return -1;
}

/* Name at off as escaped lowercase text (dns_name.h). */
static bool name_to_str(const unsigned char* m, int len, int off, char out[DNAME_TEXT_MAX])
{
    return dname_from_wire(m, len, off, true, out, DNAME_TEXT_MAX) >= 0;
}

static int skip_question(const unsigned char* m, int len)
{
    int qd = (m[4] << 8) | m[5];
    int p = 12;
    for (int i = 0; i < qd; i++) {
        p = name_end(m, len, p);
        if (p < 0 || p + 4 > len) return -1;
        p += 4;
    }
    return p;
}

bool cname_needs_chase(const struct Packet* resp, uint16_t qtype,
                       char target[DNAME_TEXT_MAX])
{
    if (!resp || !resp->request || resp->recv_len < 12) return false;
    if (qtype == T_CNAME || qtype == 255 /* ANY */ || qtype == T_RRSIG) return false;
    const unsigned char* m = (const unsigned char*)resp->request;
    int len = (int)resp->recv_len;
    if ((m[3] & 0x0F) != 0) return false;             /* only NOERROR answers */
    int an = (m[6] << 8) | m[7];
    if (an == 0) return false;

    int p = skip_question(m, len);
    if (p < 0) return false;
    bool have = false;
    for (int i = 0; i < an; i++) {
        int ne = name_end(m, len, p);
        if (ne < 0 || ne + 10 > len) return false;
        uint16_t type  = (uint16_t)((m[ne] << 8) | m[ne + 1]);
        uint16_t rdlen = (uint16_t)((m[ne + 8] << 8) | m[ne + 9]);
        if (ne + 10 + rdlen > len) return false;
        if (type == T_CNAME) {
            if (!name_to_str(m, len, ne + 10, target)) return false;
            have = true;
        } else if (type != T_RRSIG) {
            return false;                              /* already has data */
        }
        p = ne + 10 + rdlen;
    }
    return have && target[0] != '\0';
}

struct Packet* make_chase_query(const struct Packet* orig, const char* name)
{
    if (!orig || !orig->request || orig->recv_len < 4 || !name || !*name) return NULL;

    struct Packet* q = calloc(1, sizeof(struct Packet));
    if (!q) return NULL;
    q->request = calloc(1, MAXLINE);
    q->full_domain = strdup(name);
    if (!q->request || !q->full_domain) goto fail;

    unsigned char* w = (unsigned char*)q->request;
    memcpy(w, orig->request, 4);                        /* TX ID + flags */
    w[5] = 1;                                           /* QDCOUNT = 1   */
    int pos = 12;
    int nlen = dname_to_wire(name, w + pos, MAXLINE - pos - 4 - 11);
    if (nlen < 0) goto fail;
    pos += nlen;
    w[pos++] = (unsigned char)(orig->q_type >> 8);
    w[pos++] = (unsigned char)(orig->q_type & 0xFF);
    w[pos++] = (unsigned char)(orig->q_class >> 8);
    w[pos++] = (unsigned char)(orig->q_class & 0xFF);
    if (orig->edns_present) {
        w[pos++] = 0;                                   /* OPT owner = root */
        w[pos++] = 0; w[pos++] = T_OPT;
        w[pos++] = 1232 >> 8; w[pos++] = 1232 & 0xFF;
        w[pos++] = 0; w[pos++] = 0;
        w[pos++] = orig->do_bit ? 0x80 : 0; w[pos++] = 0;
        w[pos++] = 0; w[pos++] = 0;
        w[11] = 1;                                      /* ARCOUNT = 1 */
    }
    q->recv_len      = pos;
    q->id            = orig->id;
    q->rd            = orig->rd;
    q->cd            = orig->cd;
    q->q_type        = orig->q_type;
    q->q_class       = orig->q_class;
    q->qdcount       = 1;
    q->arcount       = orig->edns_present ? 1 : 0;
    q->edns_present  = orig->edns_present;
    q->edns_udp_size = orig->edns_udp_size;
    q->do_bit        = orig->do_bit;
    return q;

fail:
    free(q->request);
    free(q->full_domain);
    free(q);
    return NULL;
}

/* Rewrite `count` RRs of `in` starting at *ip into out[*op], decompressing the
 * owner and the names embedded in the legacy compressible RDATA types.  OPT
 * records are skipped.  Returns the number of RRs written, or -1. */
static int copy_rrs(const unsigned char* in, int len, int* ip, int count,
                    unsigned char* out, int cap, int* op)
{
    int written = 0;
    for (int i = 0; i < count; i++) {
        int ne = name_end(in, len, *ip);
        if (ne < 0 || ne + 10 > len) return -1;
        uint16_t type  = (uint16_t)((in[ne] << 8) | in[ne + 1]);
        uint16_t rdlen = (uint16_t)((in[ne + 8] << 8) | in[ne + 9]);
        int rd = ne + 10;
        if (rd + rdlen > len) return -1;
        if (type == T_OPT) { *ip = rd + rdlen; continue; }

        if (copy_name(in, len, *ip, out, cap, op) < 0) return -1;
        if (*op + 10 > cap) return -1;
        memcpy(out + *op, in + ne, 8);                  /* type, class, TTL */
        int rdlen_at = *op + 8;
        *op += 10;
        int rstart = *op;
        int p;
        switch (type) {
            case T_CNAME: case T_NS: case T_PTR:
                if (copy_name(in, len, rd, out, cap, op) < 0) return -1;
                break;
            case T_MX:
                if (rdlen < 3 || *op + 2 > cap) return -1;
                memcpy(out + *op, in + rd, 2); *op += 2;
                if (copy_name(in, len, rd + 2, out, cap, op) < 0) return -1;
                break;
            case T_SOA:
                p = copy_name(in, len, rd, out, cap, op);
                if (p < 0) return -1;
                p = copy_name(in, len, p, out, cap, op);
                if (p < 0 || p + 20 > rd + rdlen || *op + 20 > cap) return -1;
                memcpy(out + *op, in + p, 20); *op += 20;
                break;
            default:
                if (*op + rdlen > cap) return -1;
                memcpy(out + *op, in + rd, rdlen); *op += rdlen;
                break;
        }
        int nl = *op - rstart;
        out[rdlen_at]     = (unsigned char)(nl >> 8);
        out[rdlen_at + 1] = (unsigned char)(nl & 0xFF);
        *ip = rd + rdlen;
        written++;
    }
    return written;
}

int merge_chased_answer(struct Packet* resp, const struct Packet* sub)
{
    if (!resp || !resp->request || !sub || !sub->request || sub->recv_len < 12)
        return -1;
    unsigned char* r = (unsigned char*)resp->request;
    const unsigned char* m = (const unsigned char*)sub->request;
    int slen = (int)sub->recv_len;

    /* resp must still be answer-only (the chain so far), so appending to its
     * end appends to the answer section. */
    if (r[8] || r[9] || r[10] || r[11]) return -1;

    int an = (m[6] << 8) | m[7];
    int ns = (m[8] << 8) | m[9];
    int rcode = m[3] & 0x0F;
    if (rcode != 0 && rcode != 3) return -1;           /* only answers / NXDOMAIN */

    unsigned char* tmp = malloc(DNS_MSG_MAX);
    if (!tmp) return -1;
    int op = 0;
    int ip = skip_question(m, slen);
    if (ip < 0) { free(tmp); return -1; }
    int wan = copy_rrs(m, slen, &ip, an, tmp, DNS_MSG_MAX, &op);
    if (wan < 0) { free(tmp); return -1; }
    int wns = 0;
    if (an == 0) {                                      /* negative: keep the SOA */
        wns = copy_rrs(m, slen, &ip, ns, tmp, DNS_MSG_MAX, &op);
        if (wns < 0) { free(tmp); return -1; }
    }
    if (resp->recv_len + op > DNS_MSG_MAX) { free(tmp); return -1; }

    memcpy(r + resp->recv_len, tmp, (size_t)op);
    free(tmp);
    resp->recv_len += op;
    int ancount = ((r[6] << 8) | r[7]) + wan;
    r[6] = (unsigned char)(ancount >> 8); r[7] = (unsigned char)(ancount & 0xFF);
    r[8] = (unsigned char)(wns >> 8);     r[9] = (unsigned char)(wns & 0xFF);
    /* RFC 6604: the RCODE describes the last name in the chain. */
    r[3] = (unsigned char)((r[3] & 0xF0) | rcode);
    return 0;
}
