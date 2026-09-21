#include "dnssec_proof.h"
#include "dns_wire.h"
#include "dnssec_wire.h"
#include "types.h"

#include <ctype.h>

/* ---- NSEC denial (RFC 4034 §4) ----------------------------------------- */

/* Is qtype set in an NSEC type bitmap? */
static int nsec_type_covered(const uint8_t *bm, int bm_len, uint16_t qtype)
{
    for (int pos = 0; pos + 2 <= bm_len; ) {
        int window = bm[pos], bytes = bm[pos + 1];
        if (pos + 2 + bytes > bm_len) break;
        int bit = qtype & 0xFF;
        if (qtype >> 8 == window && bit / 8 < bytes)
            return (bm[pos + 2 + bit / 8] >> (7 - bit % 8)) & 1;
        pos += 2 + bytes;
    }
    return 0;
}

/* Canonical name order (RFC 4034 §6.1): compare labels right to left. */
static int wire_canon_cmp(const uint8_t *a, int a_len, const uint8_t *b, int b_len)
{
    int al[128], bl[128], na = 0, nb = 0;
    for (int p = 0; p < a_len && na < 128 && a[p]; p += 1 + a[p]) al[na++] = p;
    for (int p = 0; p < b_len && nb < 128 && b[p]; p += 1 + b[p]) bl[nb++] = p;

    for (int ia = na - 1, ib = nb - 1; ia >= 0 || ib >= 0; ia--, ib--) {
        if (ia < 0) return -1;
        if (ib < 0) return 1;
        const uint8_t *la = a + al[ia], *lb = b + bl[ib];
        int minl = la[0] < lb[0] ? la[0] : lb[0];
        for (int k = 1; k <= minl; k++) {
            int c = tolower(la[k]) - tolower(lb[k]);
            if (c) return c;
        }
        if (la[0] != lb[0]) return la[0] - lb[0];
    }
    return 0;
}

int verify_nsec_denial(const uint8_t *buf, int buf_len,
                       const uint8_t *qname_wire, int qname_len,
                       uint16_t qtype, int is_nxdomain)
{
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, buf_len); rr_next(&it, &rr); ) {
        if (rr.section != SEC_AUTHORITY || rr.type != QTYPE_NSEC) continue;

        uint8_t owner[256], next[256];
        int owner_len = expand_name_lc(buf, buf_len, rr.owner, owner, sizeof(owner));
        int next_len  = expand_name_lc(buf, buf_len, rr.rdata, next, sizeof(next));
        int bm_start  = dns_name_end(buf, buf_len, rr.rdata);
        if (owner_len <= 0 || next_len <= 0 || bm_start < 0 || bm_start > rr.rdata + rr.rdlen)
            continue;

        if (is_nxdomain) {
            /* Proof: owner < qname < next (or the wrap-around span at the zone end). */
            int qo = wire_canon_cmp(owner, owner_len, qname_wire, qname_len);
            int qn = wire_canon_cmp(qname_wire, qname_len, next, next_len);
            int on = wire_canon_cmp(owner, owner_len, next, next_len);
            if (on < 0 ? (qo < 0 && qn < 0) : (qo > 0 || qn < 0)) return 1;
        } else if (wire_canon_cmp(owner, owner_len, qname_wire, qname_len) == 0) {
            /* NODATA: the NSEC at qname must not list qtype. */
            if (!nsec_type_covered(buf + bm_start, rr.rdata + rr.rdlen - bm_start, qtype))
                return 1;
            fprintf(stderr, "DNSSEC: NSEC type bitmap contradicts NODATA\n");
            return 0;
        }
    }
    return -1;
}

/* ---- Answer coverage (RFC 4035 §5.3.2) ---------------------------------- */

int wire_name_is_suffix(const uint8_t *owner, int owner_len,
                        const uint8_t *signer, int signer_len)
{
    if (signer_len <= 0 || owner_len <= 0 || signer_len > owner_len) return 0;
    /* Step whole labels so a match can only land on a label boundary. */
    for (int off = 0; off <= owner_len - signer_len; off += 1 + owner[off]) {
        if (owner_len - off == signer_len && memcmp(owner + off, signer, (size_t)signer_len) == 0)
            return 1;
        if (owner[off] == 0 || (owner[off] & 0xC0)) break;
    }
    return 0;
}

static int rr_set_contains(const ValidatedRR *set, int n,
                           const uint8_t *owner, int owner_len, uint16_t type)
{
    for (int i = 0; i < n; i++)
        if (set[i].type == type && set[i].owner_len == owner_len &&
            memcmp(set[i].owner, owner, (size_t)owner_len) == 0)
            return 1;
    return 0;
}

/* Target (lc wire) of the answer CNAME owned by `owner`, or -1. */
static int find_cname_target(const uint8_t *buf, int buf_len,
                             const uint8_t *owner, int owner_len,
                             uint8_t *out, int out_size)
{
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, buf_len); rr_next(&it, &rr) && rr.section == SEC_ANSWER; ) {
        if (rr.type != QTYPE_CNAME) continue;
        uint8_t this_owner[256];
        int len = expand_name_lc(buf, buf_len, rr.owner, this_owner, sizeof(this_owner));
        if (len == owner_len && memcmp(this_owner, owner, (size_t)owner_len) == 0)
            return expand_name_lc(buf, buf_len, rr.rdata, out, out_size);
    }
    return -1;
}

int answer_is_validated(const uint8_t *buf, int buf_len, uint16_t qtype,
                        const ValidatedRR *set, int set_n)
{
    uint8_t name[256];
    int name_len = expand_name_lc(buf, buf_len, HEADER_LEN, name, sizeof(name));
    if (name_len < 0) return 0;

    /* Each hop consumes one CNAME RR; hard cap as well. */
    int ancount = rd16(buf + 6);
    int max_hops = ancount < 16 ? ancount : 16;
    for (int hop = 0; hop <= max_hops; hop++) {
        if (rr_set_contains(set, set_n, name, name_len, qtype)) return 1;
        if (qtype == QTYPE_CNAME || !rr_set_contains(set, set_n, name, name_len, QTYPE_CNAME))
            return 0;
        uint8_t target[256];
        int tlen = find_cname_target(buf, buf_len, name, name_len, target, sizeof(target));
        if (tlen < 0) return 0;
        memcpy(name, target, (size_t)tlen);
        name_len = tlen;
    }
    return 0;
}
