#include "dnssec_wire.h"
#include "dns_name.h"
#include "dns_wire.h"

#include <ctype.h>

/* ---- Names ------------------------------------------------------------- */

int expand_name_lc(const uint8_t *buf, int buf_len, int pos, uint8_t *dst, int dst_size)
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
        if (b > 63 || pos + 1 + b > buf_len || dpos + b + 1 >= dst_size) return -1;
        dst[dpos++] = b;
        for (int i = 1; i <= b; i++)
            dst[dpos++] = (uint8_t)tolower(buf[pos + i]);
        pos += 1 + b;
    }
    return -1;
}

int encode_name_lc(const char *name, uint8_t *dst, int dst_size)
{
    /* Through the shared codec so escapes ("\.", "\DDD") match the signed octets. */
    int n = dname_to_wire(name, dst, dst_size);
    if (n < 0) return -1;
    for (int i = 0; dst[i] != 0; i += 1 + dst[i])
        for (int k = 1; k <= dst[i]; k++)
            dst[i + k] = (uint8_t)tolower(dst[i + k]);
    return n;
}

/* ---- RDATA parsers ----------------------------------------------------- */

/* malloc'd copy of len bytes (NULL for len 0).  False on allocation failure. */
static bool dup_bytes(const uint8_t *src, int len, uint8_t **out)
{
    *out = NULL;
    if (len <= 0) return true;
    if (!(*out = malloc((size_t)len))) return false;
    memcpy(*out, src, (size_t)len);
    return true;
}

int parse_dnskey_rdata(const uint8_t *rdata, int rdlength, DnskeyRdata *out)
{
    if (!rdata || !out || rdlength < 4) return -1;
    out->flags      = rd16(rdata);
    out->protocol   = rdata[2];
    out->algorithm  = rdata[3];
    out->pubkey_len = (uint16_t)(rdlength - 4);
    return dup_bytes(rdata + 4, rdlength - 4, &out->pubkey) ? 0 : -1;
}

int parse_ds_rdata(const uint8_t *rdata, int rdlength, DsRdata *out)
{
    if (!rdata || !out || rdlength < 4) return -1;
    out->key_tag     = rd16(rdata);
    out->algorithm   = rdata[2];
    out->digest_type = rdata[3];
    out->digest_len  = (uint16_t)(rdlength - 4);
    return dup_bytes(rdata + 4, rdlength - 4, &out->digest) ? 0 : -1;
}

int parse_rrsig_rdata(const uint8_t *msg, int msg_len, int rdata_off, int rdlength,
                      RrsigRdata *out)
{
    if (!msg || !out || rdlength < 18) return -1;
    const uint8_t *r = msg + rdata_off;
    out->type_covered   = rd16(r);
    out->algorithm      = r[2];
    out->labels         = r[3];
    out->orig_ttl       = rd32(r + 4);
    out->sig_expiration = rd32(r + 8);
    out->sig_inception  = rd32(r + 12);
    out->key_tag        = rd16(r + 16);

    int sig_start = dname_from_wire(msg, msg_len, rdata_off + 18, false,
                                    out->signer_name, sizeof(out->signer_name));
    int sig_len = rdata_off + rdlength - sig_start;
    if (sig_start < 0 || sig_len < 0) return -1;
    out->sig_len = (uint16_t)sig_len;
    return dup_bytes(msg + sig_start, sig_len, &out->signature) ? 0 : -1;
}

uint16_t compute_key_tag(uint16_t flags, uint8_t protocol, uint8_t algorithm,
                         const uint8_t *pubkey, uint16_t pubkey_len)
{
    /* Sum of big-endian 16-bit words over the DNSKEY RDATA, folded once. */
    unsigned long ac = ((unsigned long)flags) + ((unsigned long)protocol << 8) + algorithm;
    for (int i = 0; i < pubkey_len; i++)
        ac += (i & 1) ? pubkey[i] : (unsigned long)pubkey[i] << 8;
    ac += (ac >> 16) & 0xFFFF;
    return (uint16_t)(ac & 0xFFFF);
}

/* ---- Signed data (RFC 4034 §6.2) ---------------------------------------- */

/* Canonical RDATA: embedded names expanded and lowercased.  malloc'd. */
static int canonical_rdata(const uint8_t *buf, int buf_len, const DnsRR *rr,
                           uint8_t **out, int *out_len)
{
    int alloc = rr->rdlen + 512;
    uint8_t *dst = malloc((size_t)alloc);
    if (!dst) return -1;
    int n = -1;

    switch (rr->type) {
    case QTYPE_NS: case QTYPE_CNAME: case QTYPE_PTR:
        n = expand_name_lc(buf, buf_len, rr->rdata, dst, alloc);
        break;
    case QTYPE_MX:
        if (rr->rdlen < 3) break;
        memcpy(dst, buf + rr->rdata, 2);                           /* preference */
        n = expand_name_lc(buf, buf_len, rr->rdata + 2, dst + 2, alloc - 2);
        if (n >= 0) n += 2;
        break;
    case QTYPE_SOA: {
        int mlen = expand_name_lc(buf, buf_len, rr->rdata, dst, alloc);
        int rname = dns_name_end(buf, buf_len, rr->rdata);
        int rlen = (mlen < 0 || rname < 0) ? -1
                 : expand_name_lc(buf, buf_len, rname, dst + mlen, alloc - mlen);
        int fixed = rlen < 0 ? -1 : dns_name_end(buf, buf_len, rname);
        if (fixed < 0 || fixed + 20 > rr->rdata + rr->rdlen) break;
        memcpy(dst + mlen + rlen, buf + fixed, 20);                /* serial..minimum */
        n = mlen + rlen + 20;
        break;
    }
    default:                                                       /* no names inside */
        memcpy(dst, buf + rr->rdata, rr->rdlen);
        n = rr->rdlen;
    }

    if (n < 0) { free(dst); return -1; }
    *out = dst;
    *out_len = n;
    return 0;
}

typedef struct {
    uint8_t *rdata;
    int      rdata_len;
} CanonRR;

/* RRs sort by canonical RDATA (RFC 4034 §6.3). */
static int cmp_canon_rr(const void *a, const void *b)
{
    const CanonRR *ra = a, *rb = b;
    int minl = ra->rdata_len < rb->rdata_len ? ra->rdata_len : rb->rdata_len;
    int c = memcmp(ra->rdata, rb->rdata, (size_t)minl);
    return c ? c : ra->rdata_len - rb->rdata_len;
}

static void free_canon(CanonRR *rrs, int n)
{
    for (int i = 0; i < n; i++) free(rrs[i].rdata);
    free(rrs);
}

/* Label count of an uncompressed wire name. */
static int wire_labels(const uint8_t *name)
{
    int n = 0;
    for (int p = 0; name[p]; p += 1 + name[p]) n++;
    return n;
}

int build_signed_data(const struct Packet *response, const RrsigRdata *rrsig,
                      int rrsig_owner_pos, uint8_t **out_data, int *out_len)
{
    const uint8_t *buf = (const uint8_t *)response->request;
    int buf_len = (int)response->recv_len;

    /* RRSIG RDATA up to (not including) the signature. */
    uint8_t hdr[512];
    wr16(hdr, rrsig->type_covered);
    hdr[2] = rrsig->algorithm;
    hdr[3] = rrsig->labels;
    wr32(hdr + 4, rrsig->orig_ttl);
    wr32(hdr + 8, rrsig->sig_expiration);
    wr32(hdr + 12, rrsig->sig_inception);
    wr16(hdr + 16, rrsig->key_tag);
    int sname_len = encode_name_lc(rrsig->signer_name, hdr + 18, (int)sizeof(hdr) - 18);
    if (sname_len < 0) return -1;
    int hlen = 18 + sname_len;

    uint8_t owner[256];
    int owner_len = expand_name_lc(buf, buf_len, rrsig_owner_pos, owner, sizeof(owner));
    if (owner_len < 0) return -1;

    /* Wildcard expansion (RFC 4034 §6.2 step 3): an owner with more labels
     * than the RRSIG's `labels` was synthesized from "*.<rightmost labels>",
     * and that form is what was signed. */
    uint8_t signed_owner[256];
    int signed_owner_len = owner_len;
    memcpy(signed_owner, owner, (size_t)owner_len);
    int extra = wire_labels(owner) - rrsig->labels;
    if (extra > 0) {
        int skip = 0;
        while (extra-- > 0) skip += 1 + owner[skip];
        int suffix_len = owner_len - skip;
        if (2 + suffix_len > (int)sizeof(signed_owner)) return -1;
        signed_owner[0] = 1;
        signed_owner[1] = '*';
        memcpy(signed_owner + 2, owner + skip, (size_t)suffix_len);
        signed_owner_len = 2 + suffix_len;
    }

    /* Collect the covered RRset: same type, same (canonical) owner. */
    CanonRR *rrs = NULL;
    int n = 0, cap = 0;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, buf_len); rr_next(&it, &rr); ) {
        if (rr.type != rrsig->type_covered) continue;
        uint8_t this_owner[256];
        int this_len = expand_name_lc(buf, buf_len, rr.owner, this_owner, sizeof(this_owner));
        if (this_len != owner_len || memcmp(this_owner, owner, (size_t)owner_len) != 0)
            continue;

        CanonRR c;
        if (canonical_rdata(buf, buf_len, &rr, &c.rdata, &c.rdata_len) < 0) continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 8;
            CanonRR *tmp = realloc(rrs, (size_t)cap * sizeof(CanonRR));
            if (!tmp) { free(c.rdata); free_canon(rrs, n); return -1; }
            rrs = tmp;
        }
        rrs[n++] = c;
    }
    if (n == 0) { free(rrs); return -1; }
    qsort(rrs, (size_t)n, sizeof(CanonRR), cmp_canon_rr);

    /* header | owner type class orig_ttl rdlen rdata | ... */
    int total = hlen;
    for (int i = 0; i < n; i++) total += signed_owner_len + 10 + rrs[i].rdata_len;
    uint8_t *out = malloc((size_t)total);
    if (!out) { free_canon(rrs, n); return -1; }

    memcpy(out, hdr, (size_t)hlen);
    int pos = hlen;
    for (int i = 0; i < n; i++) {
        memcpy(out + pos, signed_owner, (size_t)signed_owner_len);
        pos += signed_owner_len;
        wr16(out + pos, rrsig->type_covered);
        wr16(out + pos + 2, CLASS_IN);
        wr32(out + pos + 4, rrsig->orig_ttl);
        wr16(out + pos + 8, (uint16_t)rrs[i].rdata_len);
        memcpy(out + pos + 10, rrs[i].rdata, (size_t)rrs[i].rdata_len);
        pos += 10 + rrs[i].rdata_len;
    }
    free_canon(rrs, n);

    *out_data = out;
    *out_len  = pos;
    return 0;
}
