#include "dnssec_wire.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ==========================================================================
 * Section 1: Wire-format helpers
 * ========================================================================== */

/*
 * Return the byte position in buf[] immediately after the DNS name that
 * starts at buf[pos].  Handles compression pointers (advances past 2 bytes).
 * Returns -1 on malformed input.
 */
int name_end_pos(const uint8_t *buf, int buf_len, int pos)
{
    int jumps = 0;
    while (pos < buf_len && jumps < 10) {
        uint8_t b = buf[pos];
        if (b == 0)               return pos + 1;
        if ((b & 0xC0) == 0xC0)   return pos + 2;   /* compression pointer */
        if (b > 63)               return -1;
        pos += 1 + b;
    }
    return -1;
}

/*
 * Expand a possibly-compressed DNS name at buf[pos] into dst[], lowercasing
 * every label byte.  The output is uncompressed wire format.
 * Returns number of bytes written to dst, or -1 on error.
 */
int expand_name_lc(const uint8_t *buf, int buf_len, int pos,
                           uint8_t *dst, int dst_size)
{
    int dpos = 0, jumps = 0;
    while (pos < buf_len && jumps < 10) {
        uint8_t b = buf[pos];
        if (b == 0) {
            if (dpos >= dst_size) return -1;
            dst[dpos++] = 0;
            return dpos;
        }
        if ((b & 0xC0) == 0xC0) {
            if (pos + 1 >= buf_len) return -1;
            pos = ((b & 0x3F) << 8) | buf[pos + 1];
            jumps++;
            continue;
        }
        if (b > 63 || dpos + b + 1 >= dst_size) return -1;
        dst[dpos++] = b;
        pos++;
        for (int i = 0; i < b; i++)
            dst[dpos++] = (uint8_t)tolower((unsigned char)buf[pos + i]);
        pos += b;
    }
    return (jumps < 10) ? dpos : -1;
}

/*
 * Encode a dot-notation name into uncompressed wire format, lowercasing all
 * label bytes.  Returns number of bytes written to dst, or -1 on error.
 */
int encode_name_lc(const char *name, uint8_t *dst, int dst_size)
{
    int pos = 0;
    const char *p = name;
    /* Root "." (or empty) is a valid name that encodes to a single zero byte.
     * Without this, the generic loop below sees a leading '.' as a zero-length
     * label and returns -1 — which made build_signed_data() fail for every
     * root-signed RRSIG (signer name "."), blocking DNSSEC chain bootstrap. */
    if (!p || p[0] == '\0' || (p[0] == '.' && p[1] == '\0')) {
        if (dst_size < 1) return -1;
        dst[0] = 0;
        return 1;
    }
    while (*p) {
        const char *dot = p;
        while (*dot && *dot != '.') dot++;
        int len = (int)(dot - p);
        if (len == 0 || len > 63 || pos + len + 1 >= dst_size) return -1;
        dst[pos++] = (uint8_t)len;
        for (int i = 0; i < len; i++)
            dst[pos++] = (uint8_t)tolower((unsigned char)p[i]);
        p = dot;
        if (*p == '.') p++;
    }
    if (pos >= dst_size) return -1;
    dst[pos++] = 0;
    return pos;
}

/*
 * Produce the canonical RDATA for a given RR type, expanding any compressed
 * domain names and lowercasing their labels.  Writes a malloc'd buffer to
 * *out and its length to *out_len.  Returns 0 on success, -1 on failure.
 */
static int canonical_rdata(const uint8_t *buf, int buf_len,
                            int rdata_off, int rdata_len,
                            uint16_t type,
                            uint8_t **out, int *out_len)
{
    int alloc = rdata_len + 512;
    uint8_t *dst = malloc((size_t)alloc);
    if (!dst) return -1;

    switch (type) {
    case 2:    /* NS   */
    case 5:    /* CNAME */
    case 12:   /* PTR */
    {
        int n = expand_name_lc(buf, buf_len, rdata_off, dst, alloc);
        if (n < 0) { free(dst); return -1; }
        *out = dst; *out_len = n;
        return 0;
    }

    case 15:   /* MX: preference(2) + exchange name */
    {
        if (rdata_len < 3) { free(dst); return -1; }
        dst[0] = buf[rdata_off];
        dst[1] = buf[rdata_off + 1];
        int n = expand_name_lc(buf, buf_len, rdata_off + 2, dst + 2, alloc - 2);
        if (n < 0) { free(dst); return -1; }
        *out = dst; *out_len = 2 + n;
        return 0;
    }

    case 6:    /* SOA: mname + rname + 5 uint32s */
    {
        /* Expand mname */
        int mlen = expand_name_lc(buf, buf_len, rdata_off, dst, alloc);
        if (mlen < 0) { free(dst); return -1; }

        /* Find where rname starts in the original buffer */
        int rname_src = name_end_pos(buf, buf_len, rdata_off);
        if (rname_src < 0) { free(dst); return -1; }

        /* Expand rname */
        int rlen = expand_name_lc(buf, buf_len, rname_src, dst + mlen, alloc - mlen);
        if (rlen < 0) { free(dst); return -1; }

        /* Copy the 5 fixed uint32 fields */
        int after_names = name_end_pos(buf, buf_len, rname_src);
        if (after_names < 0 || after_names + 20 > rdata_off + rdata_len) {
            free(dst); return -1;
        }
        memcpy(dst + mlen + rlen, buf + after_names, 20);
        *out = dst; *out_len = mlen + rlen + 20;
        return 0;
    }

    default:   /* A, AAAA, TXT, and all other types: no domain names */
        memcpy(dst, buf + rdata_off, (size_t)rdata_len);
        *out = dst; *out_len = rdata_len;
        return 0;
    }
}

/* ==========================================================================
 * Build the signed-data buffer for an RRSIG
 *
 * Per RFC 4034 §6.2 the data that is signed is:
 *   RRSIG_RDATA_no_sig | RR(1) | RR(2) | ...
 *
 * where RRSIG_RDATA_no_sig =
 *   type_covered(2) | algorithm(1) | labels(1) | orig_ttl(4) |
 *   sig_expiration(4) | sig_inception(4) | key_tag(2) | signer_name_wire
 *
 * and each RR =
 *   owner_wire_lc | type(2) | class(2) | orig_ttl(4) | rdlength(2) | canonical_rdata
 *
 * RRs are sorted by canonical RDATA (RFC 4034 §6.3).
 *
 * rrsig_owner_pos: byte offset in response->request of the RRSIG's owner name.
 * ========================================================================== */

typedef struct {
    uint8_t *rdata;
    int      rdata_len;
    uint8_t  owner[256];
    int      owner_len;
} CanonRR;

static int cmp_canon_rr(const void *a, const void *b)
{
    const CanonRR *ra = (const CanonRR *)a;
    const CanonRR *rb = (const CanonRR *)b;
    int minl = ra->rdata_len < rb->rdata_len ? ra->rdata_len : rb->rdata_len;
    int c = memcmp(ra->rdata, rb->rdata, (size_t)minl);
    return c ? c : ra->rdata_len - rb->rdata_len;
}

int build_signed_data(const struct Packet *response,
                              const RrsigRdata *rrsig,
                              int rrsig_owner_pos,
                              uint8_t **out_data, int *out_len)
{
    const uint8_t *buf = (const uint8_t *)response->request;
    int buf_len = (int)response->recv_len;

    /* --- RRSIG header (everything before the signature field) --- */
    uint8_t hdr[512];
    int hpos = 0;
    hdr[hpos++] = (rrsig->type_covered >> 8) & 0xFF;
    hdr[hpos++] =  rrsig->type_covered       & 0xFF;
    hdr[hpos++] =  rrsig->algorithm;
    hdr[hpos++] =  rrsig->labels;
    hdr[hpos++] = (rrsig->orig_ttl >> 24) & 0xFF;
    hdr[hpos++] = (rrsig->orig_ttl >> 16) & 0xFF;
    hdr[hpos++] = (rrsig->orig_ttl >>  8) & 0xFF;
    hdr[hpos++] =  rrsig->orig_ttl        & 0xFF;
    hdr[hpos++] = (rrsig->sig_expiration >> 24) & 0xFF;
    hdr[hpos++] = (rrsig->sig_expiration >> 16) & 0xFF;
    hdr[hpos++] = (rrsig->sig_expiration >>  8) & 0xFF;
    hdr[hpos++] =  rrsig->sig_expiration        & 0xFF;
    hdr[hpos++] = (rrsig->sig_inception >> 24) & 0xFF;
    hdr[hpos++] = (rrsig->sig_inception >> 16) & 0xFF;
    hdr[hpos++] = (rrsig->sig_inception >>  8) & 0xFF;
    hdr[hpos++] =  rrsig->sig_inception        & 0xFF;
    hdr[hpos++] = (rrsig->key_tag >> 8) & 0xFF;
    hdr[hpos++] =  rrsig->key_tag       & 0xFF;
    int sname_len = encode_name_lc(rrsig->signer_name, hdr + hpos,
                                   (int)sizeof(hdr) - hpos);
    if (sname_len < 0) return -1;
    hpos += sname_len;

    /* --- Canonical owner name (same for RRSIG and covered RRset) --- */
    uint8_t owner_wire[256];
    int owner_wire_len = expand_name_lc(buf, buf_len, rrsig_owner_pos,
                                        owner_wire, sizeof(owner_wire));
    if (owner_wire_len < 0) return -1;

    /*
     * RFC 4034 §6.2 step 3: wildcard owner name reconstruction.
     *
     * The RRSIG labels field counts the number of labels in the ORIGINAL
     * unsigned owner name, not counting the root label (the trailing zero
     * byte) or any leading wildcard label.
     *
     * When a wildcard record (e.g. *.example.com) is expanded to match a
     * query (e.g. foo.example.com), the RR that appears in the response
     * carries the expanded owner name.  The RRSIG, however, was computed
     * over the wildcard owner.  Detecting this condition:
     *
     *   label_count(owner_wire) > rrsig->labels
     *
     * When true, the canonical owner used in the signed data must be:
     *
     *   \x01 '*' | rightmost rrsig->labels labels of owner_wire
     *
     * The expanded owner (owner_wire) is still used below for RR matching
     * so we collect the correct records from the response packet.
     */
    int label_count = 0;
    for (int lp = 0; lp < owner_wire_len && owner_wire[lp] != 0; ) {
        label_count++;
        lp += 1 + owner_wire[lp];
    }

    uint8_t effective_owner[256];
    int     effective_owner_len;

    if (label_count > (int)rrsig->labels) {
        /* Locate where the rightmost rrsig->labels labels start */
        int skip_pos = 0;
        for (int s = 0; s < label_count - (int)rrsig->labels; s++)
            skip_pos += 1 + owner_wire[skip_pos];
        int suffix_len = owner_wire_len - skip_pos;
        /* suffix_len includes at least the root label (1 byte); prefix is 2 */
        if (suffix_len < 1 || 2 + suffix_len > (int)sizeof(effective_owner))
            return -1;
        effective_owner[0] = 1;    /* length of wildcard label */
        effective_owner[1] = '*';  /* the wildcard label itself */
        memcpy(effective_owner + 2, owner_wire + skip_pos, (size_t)suffix_len);
        effective_owner_len = 2 + suffix_len;
    } else {
        memcpy(effective_owner, owner_wire, (size_t)owner_wire_len);
        effective_owner_len = owner_wire_len;
    }

    /* --- Collect covered RRs from all sections --- */
    int pos = HEADER_LEN;
    for (int q = 0; q < response->qdcount && pos < buf_len; q++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0) return -1;
        pos = e + 4;
    }

    CanonRR *rrs = NULL;
    int rr_count = 0, rr_cap = 0;
    int total_rrs = response->ancount + response->nscount + response->arcount;

    for (int a = 0; a < total_rrs && pos < buf_len; a++) {
        int name_pos  = pos;
        int name_end  = name_end_pos(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) break;

        uint16_t type = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl  = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int rdata_off = name_end + 10;
        if (rdata_off + rdl > buf_len) break;

        if (type != rrsig->type_covered) {
            pos = rdata_off + rdl;
            continue;
        }

        /* Compare canonical owner names */
        uint8_t this_owner[256];
        int this_owner_len = expand_name_lc(buf, buf_len, name_pos,
                                            this_owner, sizeof(this_owner));
        if (this_owner_len != owner_wire_len ||
            memcmp(this_owner, owner_wire, (size_t)owner_wire_len) != 0) {
            pos = rdata_off + rdl;
            continue;
        }

        uint8_t *crdata = NULL;
        int crdata_len  = 0;
        if (canonical_rdata(buf, buf_len, rdata_off, rdl, type,
                            &crdata, &crdata_len) < 0) {
            pos = rdata_off + rdl;
            continue;
        }

        if (rr_count >= rr_cap) {
            int new_cap = rr_cap ? rr_cap * 2 : 8;
            CanonRR *tmp = realloc(rrs, (size_t)new_cap * sizeof(CanonRR));
            if (!tmp) {
                free(crdata);
                for (int i = 0; i < rr_count; i++) free(rrs[i].rdata);
                free(rrs);
                return -1;
            }
            rrs = tmp;
            rr_cap = new_cap;
        }
        rrs[rr_count].rdata     = crdata;
        rrs[rr_count].rdata_len = crdata_len;
        /* Store the effective owner (wildcard form if applicable) — this is
         * what RFC 4034 §6.2 mandates for the signed-data construction. */
        memcpy(rrs[rr_count].owner, effective_owner, (size_t)effective_owner_len);
        rrs[rr_count].owner_len = effective_owner_len;
        rr_count++;
        pos = rdata_off + rdl;
    }

    if (rr_count == 0) {
        free(rrs);
        return -1;
    }

    qsort(rrs, (size_t)rr_count, sizeof(CanonRR), cmp_canon_rr);

    /* --- Assemble signed data: header + sorted RRs --- */
    int total = hpos;
    for (int i = 0; i < rr_count; i++)
        total += rrs[i].owner_len + 2 + 2 + 4 + 2 + rrs[i].rdata_len;

    uint8_t *result = malloc((size_t)total);
    if (!result) {
        for (int i = 0; i < rr_count; i++) free(rrs[i].rdata);
        free(rrs);
        return -1;
    }

    int rpos = 0;
    memcpy(result, hdr, (size_t)hpos);
    rpos += hpos;

    for (int i = 0; i < rr_count; i++) {
        memcpy(result + rpos, rrs[i].owner, (size_t)rrs[i].owner_len);
        rpos += rrs[i].owner_len;

        result[rpos++] = (rrsig->type_covered >> 8) & 0xFF;
        result[rpos++] =  rrsig->type_covered       & 0xFF;
        result[rpos++] = 0x00;                         /* class IN hi */
        result[rpos++] = 0x01;                         /* class IN lo */
        result[rpos++] = (rrsig->orig_ttl >> 24) & 0xFF;
        result[rpos++] = (rrsig->orig_ttl >> 16) & 0xFF;
        result[rpos++] = (rrsig->orig_ttl >>  8) & 0xFF;
        result[rpos++] =  rrsig->orig_ttl        & 0xFF;
        result[rpos++] = (rrs[i].rdata_len >> 8) & 0xFF;
        result[rpos++] =  rrs[i].rdata_len       & 0xFF;
        memcpy(result + rpos, rrs[i].rdata, (size_t)rrs[i].rdata_len);
        rpos += rrs[i].rdata_len;
        free(rrs[i].rdata);
    }
    free(rrs);

    *out_data = result;
    *out_len  = rpos;
    return 0;
}
