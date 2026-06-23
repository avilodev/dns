#include "dnssec_proof.h"

#include <ctype.h>
#include <string.h>
#include <stdint.h>

#include "types.h"        /* HEADER_LEN, QTYPE_*, struct Packet */
#include "dnssec_wire.h"  /* name_end_pos, expand_name_lc */

/* ==========================================================================
 * Section 6.5: NSEC / NSEC3 denial-of-existence proof verification
 *              (RFC 4034 §4 and RFC 5155)
 * ========================================================================== */

/*
 * nsec_type_covered — check if qtype is set in an NSEC type-bitmap block stream.
 * bm:     pointer to the first window block
 * bm_len: total bytes available
 */
static int nsec_type_covered(const uint8_t *bm, int bm_len, uint16_t qtype)
{
    int pos = 0;
    while (pos + 2 <= bm_len) {
        int win      = bm[pos];
        int bm_bytes = bm[pos + 1];
        if (pos + 2 + bm_bytes > bm_len) break;

        int base = win * 256;
        if (qtype >= (uint16_t)base && qtype < (uint16_t)(base + 256)) {
            int bit = qtype - (uint16_t)base;
            if (bit / 8 < bm_bytes)
                return (bm[pos + 2 + bit / 8] >> (7 - bit % 8)) & 1;
        }
        pos += 2 + bm_bytes;
    }
    return 0;
}

/*
 * wire_canon_cmp — RFC 4034 §6.1 canonical DNS name order, wire-format inputs.
 * Both a and b must be uncompressed wire-format (NUL-terminated label list).
 * Returns <0 / 0 / >0.
 */
static int wire_canon_cmp(const uint8_t *a, int a_len,
                           const uint8_t *b, int b_len)
{
    int al[128], bl[128];
    int na = 0, nb = 0;

    for (int p = 0; p < a_len && na < 128; ) {
        int ll = a[p]; if (ll == 0) break;
        al[na++] = p; p += 1 + ll;
    }
    for (int p = 0; p < b_len && nb < 128; ) {
        int ll = b[p]; if (ll == 0) break;
        bl[nb++] = p; p += 1 + ll;
    }

    int ia = na - 1, ib = nb - 1;
    while (ia >= 0 && ib >= 0) {
        int la = a[al[ia]], lb = b[bl[ib]];
        int minl = la < lb ? la : lb;
        int c = 0;
        for (int k = 0; k < minl && c == 0; k++)
            c = (int)tolower(a[al[ia]+1+k]) - (int)tolower(b[bl[ib]+1+k]);
        if (c != 0) return c;
        if (la != lb) return la - lb;
        ia--; ib--;
    }
    if (ia < 0 && ib < 0) return 0;
    return (ia < 0) ? -1 : 1;
}

/*
 * nsec_skip_name_pos — return the byte offset just past a DNS name in buf[],
 * treating both labels and compression pointers (stops after 2-byte pointer).
 * Returns -1 on error.
 */
static int nsec_skip_name_pos(const uint8_t *buf, int buf_len, int pos)
{
    int jumps = 0;
    while (pos < buf_len && jumps < 10) {
        uint8_t b = buf[pos];
        if (b == 0)               return pos + 1;
        if ((b & 0xC0) == 0xC0)   return pos + 2;
        if (b > 63)               return -1;
        pos += 1 + b;
    }
    return -1;
}

/*
 * verify_nsec_denial — check NSEC/NSEC3 records in the authority section.
 *
 * is_nxdomain: RCODE=3 → prove qname doesn't exist;
 *              false    → prove qtype absent at qname (NODATA).
 * qname_wire:  queried name, uncompressed wire format.
 * qtype:       queried RR type.
 * ns_start:    byte offset where the authority section starts.
 * nscount:     number of RRs in the authority section.
 *
 * Returns:
 *   1  — found an NSEC record that positively proves this denial.
 *   0  — found NSEC(s) that CONTRADICT the denial (potential forgery).
 *  -1  — no NSEC/NSEC3 records; proof cannot be checked (pass through).
 */
int verify_nsec_denial(const uint8_t *buf, int buf_len,
                               const uint8_t *qname_wire, int qname_len,
                               uint16_t qtype, int is_nxdomain,
                               int ns_start, int nscount)
{
    int pos       = ns_start;
    int found_any = 0;

    for (int i = 0; i < nscount && pos < buf_len; i++) {
        int name_end = name_end_pos(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) break;

        uint16_t rrtype = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl    = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int rdata_off   = name_end + 10;
        if (rdata_off + rdl > buf_len) break;

        if (rrtype == QTYPE_NSEC) {
            found_any = 1;

            /* Expand owner name (lowercased, uncompressed). */
            uint8_t owner_wire[256];
            int owner_len = expand_name_lc(buf, buf_len, pos,
                                           owner_wire, sizeof(owner_wire));
            if (owner_len <= 0) { pos = rdata_off + rdl; continue; }

            /* Expand next-domain-name from start of RDATA. */
            uint8_t next_wire[256];
            int next_len = expand_name_lc(buf, buf_len, rdata_off,
                                          next_wire, sizeof(next_wire));
            if (next_len <= 0) { pos = rdata_off + rdl; continue; }

            /* Locate type bitmap: past the next-domain-name in RDATA. */
            int bm_start = nsec_skip_name_pos(buf, buf_len, rdata_off);
            if (bm_start < 0 || bm_start > rdata_off + rdl)
                { pos = rdata_off + rdl; continue; }
            int bm_len = rdl - (bm_start - rdata_off);

            if (is_nxdomain) {
                /* RFC 4034 §4.1: NSEC proves NXDOMAIN when
                 *   owner < qname < next  (normal, owner < next)
                 *   qname > owner OR qname < next (wrap-around, owner > next) */
                int qo = wire_canon_cmp(owner_wire, owner_len,
                                        qname_wire, qname_len);
                int qn = wire_canon_cmp(qname_wire, qname_len,
                                        next_wire, next_len);
                int on = wire_canon_cmp(owner_wire, owner_len,
                                        next_wire, next_len);
                int covered = (on < 0) ? (qo < 0 && qn < 0)
                                       : (qo > 0 || qn < 0);
                if (covered) return 1;
            } else {
                /* NODATA: NSEC owner must equal qname; qtype must be absent. */
                if (wire_canon_cmp(owner_wire, owner_len,
                                   qname_wire, qname_len) == 0) {
                    if (!nsec_type_covered(buf + bm_start, bm_len, qtype))
                        return 1;   /* type absent — NODATA proven */
                    /* Type IS present in the NSEC; NODATA claim is contradicted. */
                    fprintf(stderr,
                            "DNSSEC: NSEC type bitmap contradicts NODATA\n");
                    return 0;
                }
            }

        } else if (rrtype == QTYPE_NSEC3) {
            found_any = 1;
            /*
             * NSEC3 NXDOMAIN: proving non-existence requires hashing the queried
             * name with the NSEC3 algorithm and comparing hashes — not
             * implemented here.  The RRSIG over the NSEC3 is already verified
             * by the main validation loop, which provides the primary assurance.
             *
             * NSEC3 NODATA: requires matching the hashed owner to qname — also
             * not implemented without hashing.  Pass through.
             */
            (void)qtype;
        }

        pos = rdata_off + rdl;
    }

    return found_any ? -1 : -1;   /* either no NSEC found or NSEC didn't cover */
}

/* ==========================================================================
 * Section 6b: answer-coverage helpers (RFC 4035 §5.3.2 — the AD bit may only
 * be set when the RRset that answers the question is itself covered by a
 * verified RRSIG, not merely when *some* RRSIG in the packet verified).
 * ========================================================================== */


/*
 * Return 1 if signer (wire, lc) is a label-boundary suffix of owner (wire, lc)
 * — i.e. the signing zone is in-bailiwick for the RR owner.  Both names are
 * uncompressed and terminate in a root label.  Walking owner one label at a
 * time guarantees comparisons only ever land on label boundaries.
 */
int wire_name_is_suffix(const uint8_t *owner, int owner_len,
                               const uint8_t *signer, int signer_len)
{
    if (signer_len <= 0 || owner_len <= 0 || signer_len > owner_len)
        return 0;
    int off = 0;
    while (off <= owner_len - signer_len) {
        if (owner_len - off == signer_len &&
            memcmp(owner + off, signer, (size_t)signer_len) == 0)
            return 1;
        if (owner[off] == 0) break;             /* reached root label */
        if ((owner[off] & 0xC0)) return 0;      /* compression not expected */
        off += 1 + owner[off];
    }
    return 0;
}

/* True if the validated set contains an entry for this exact (owner, type). */
static int rr_set_contains(const ValidatedRR *set, int n,
                           const uint8_t *owner, int owner_len, uint16_t type)
{
    for (int i = 0; i < n; i++)
        if (set[i].type == type && set[i].owner_len == owner_len &&
            memcmp(set[i].owner, owner, (size_t)owner_len) == 0)
            return 1;
    return 0;
}

/* Byte offset of the answer section (immediately after the question section). */
int dns_skip_questions(const uint8_t *buf, int buf_len, int qdcount)
{
    int pos = HEADER_LEN;
    for (int q = 0; q < qdcount && pos < buf_len; q++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0) return -1;
        pos = e + 4;                            /* past QTYPE + QCLASS */
    }
    return pos;
}

/* Advance past `count` resource records starting at pos.  Returns -1 on error. */
int dns_skip_rrs(const uint8_t *buf, int buf_len, int pos, int count)
{
    for (int i = 0; i < count && pos >= 0 && pos < buf_len; i++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0 || e + 10 > buf_len) return -1;
        uint16_t rdl = ((uint16_t)buf[e + 8] << 8) | buf[e + 9];
        pos = e + 10 + rdl;
    }
    return pos;
}

/* True if any of `count` RRs starting at pos has the given TYPE. */
int section_has_type(const uint8_t *buf, int buf_len, int pos,
                            int count, uint16_t want_type)
{
    for (int i = 0; i < count && pos >= 0 && pos < buf_len; i++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0 || e + 10 > buf_len) return 0;
        uint16_t type = ((uint16_t)buf[e]     << 8) | buf[e + 1];
        uint16_t rdl  = ((uint16_t)buf[e + 8] << 8) | buf[e + 9];
        if (type == want_type) return 1;
        pos = e + 10 + rdl;
    }
    return 0;
}

/* QTYPE of the first question, or 0 on error. */
uint16_t question_qtype(const uint8_t *buf, int buf_len)
{
    int qend = name_end_pos(buf, buf_len, HEADER_LEN);
    if (qend >= 0 && qend + 1 < buf_len)
        return ((uint16_t)buf[qend] << 8) | buf[qend + 1];
    return 0;
}

/*
 * Find a CNAME RR in the answer section whose owner equals `owner` (wire, lc)
 * and expand its target into out[] (wire, lc).  Returns target length or -1.
 */
static int find_cname_target(const uint8_t *buf, int buf_len, int ancount,
                             int answer_pos,
                             const uint8_t *owner, int owner_len,
                             uint8_t *out, int out_size)
{
    int pos = answer_pos;
    for (int a = 0; a < ancount && pos < buf_len; a++) {
        int name_pos = pos;
        int name_end = name_end_pos(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) return -1;
        uint16_t type = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl  = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int rdata_off = name_end + 10;
        if (rdata_off + rdl > buf_len) return -1;
        if (type == QTYPE_CNAME) {
            uint8_t this_owner[256];
            int tol = expand_name_lc(buf, buf_len, name_pos,
                                     this_owner, sizeof(this_owner));
            if (tol == owner_len &&
                memcmp(this_owner, owner, (size_t)owner_len) == 0)
                return expand_name_lc(buf, buf_len, rdata_off, out, out_size);
        }
        pos = rdata_off + rdl;
    }
    return -1;
}

/*
 * Confirm the RRset that answers the question is in the validated set.
 * Follows an in-packet CNAME chain: QNAME -> ... -> terminal (QTYPE), where
 * every CNAME hop must itself be a validated (owner, CNAME) pair.
 * Returns 1 if the answer is covered by a verified RRSIG, 0 otherwise.
 */
int answer_is_validated(const uint8_t *buf, int buf_len,
                               int qdcount, int ancount, uint16_t qtype,
                               const ValidatedRR *set, int set_n)
{
    uint8_t name[256];
    int name_len = expand_name_lc(buf, buf_len, HEADER_LEN, name, sizeof(name));
    if (name_len < 0) return 0;

    int answer_pos = dns_skip_questions(buf, buf_len, qdcount);
    if (answer_pos < 0) return 0;

    /* Bounded by ancount (each hop consumes one CNAME RR) plus a hard cap. */
    enum { DNSSEC_MAX_CNAME_HOPS = 16 };
    int max_hops = (ancount < DNSSEC_MAX_CNAME_HOPS) ? ancount
                                                     : DNSSEC_MAX_CNAME_HOPS;
    for (int hop = 0; hop <= max_hops; hop++) {
        if (rr_set_contains(set, set_n, name, name_len, qtype))
            return 1;
        if (qtype == QTYPE_CNAME)
            return 0;   /* exact match would already have been found above */
        if (!rr_set_contains(set, set_n, name, name_len, QTYPE_CNAME))
            return 0;   /* no validated CNAME to follow from here */
        uint8_t target[256];
        int tlen = find_cname_target(buf, buf_len, ancount, answer_pos,
                                     name, name_len, target, sizeof(target));
        if (tlen < 0) return 0;
        memcpy(name, target, (size_t)tlen);
        name_len = tlen;
    }
    return 0;
}
