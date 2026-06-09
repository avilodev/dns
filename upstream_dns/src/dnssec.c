#include "dnssec.h"
#include "dnssec_chain.h"
#include "dns_wire.h"

#include <ctype.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/param_build.h>
#else
#  include <openssl/rsa.h>
#  include <openssl/ec.h>
/* Suppress deprecation warnings for legacy API used in the OpenSSL 1.1 path */
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

/* ==========================================================================
 * Section 1: Wire-format helpers
 * ========================================================================== */

/*
 * Return the byte position in buf[] immediately after the DNS name that
 * starts at buf[pos].  Handles compression pointers (advances past 2 bytes).
 * Returns -1 on malformed input.
 */
static int name_end_pos(const uint8_t *buf, int buf_len, int pos)
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
static int expand_name_lc(const uint8_t *buf, int buf_len, int pos,
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
static int encode_name_lc(const char *name, uint8_t *dst, int dst_size)
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

static int build_signed_data(const struct Packet *response,
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

/* ==========================================================================
 * Section 3: Public key import
 * ========================================================================== */

static EVP_PKEY *import_dnskey_pubkey(const DnskeyRdata *dk)
{
    EVP_PKEY *pkey = NULL;

    switch (dk->algorithm) {

    case 5:    /* RSASHA1            (RFC 3110) */
    case 7:    /* RSASHA1-NSEC3-SHA1 (RFC 5155) — same RSA key format */
    case 8:    /* RSASHA256 */
    case 10:   /* RSASHA512 */
    {
        /* RFC 3110 §2: exponent length encoding */
        const uint8_t *p = dk->pubkey;
        int plen = dk->pubkey_len;
        if (plen < 2) return NULL;
        int elen, eoff;
        if (p[0] == 0) {
            if (plen < 3) return NULL;
            elen = ((int)p[1] << 8) | p[2];
            eoff = 3;
        } else {
            elen = p[0];
            eoff = 1;
        }
        if (eoff + elen >= plen) return NULL;
        int mlen = plen - eoff - elen;
        if (mlen <= 0) return NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        BIGNUM *n_bn = BN_bin2bn(p + eoff + elen, mlen, NULL);
        BIGNUM *e_bn = BN_bin2bn(p + eoff,         elen, NULL);
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (!n_bn || !e_bn || !bld ||
            !OSSL_PARAM_BLD_push_BN(bld, "n", n_bn) ||
            !OSSL_PARAM_BLD_push_BN(bld, "e", e_bn)) {
            BN_free(n_bn); BN_free(e_bn); OSSL_PARAM_BLD_free(bld);
            return NULL;
        }
        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        BN_free(n_bn); BN_free(e_bn);
        if (!params) return NULL;
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (kctx && EVP_PKEY_fromdata_init(kctx) == 1)
            EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(kctx);
        OSSL_PARAM_free(params);
#else
        BIGNUM *n = BN_bin2bn(p + eoff + elen, mlen, NULL);
        BIGNUM *e = BN_bin2bn(p + eoff,         elen, NULL);
        RSA    *rsa = RSA_new();
        if (!n || !e || !rsa || RSA_set0_key(rsa, n, e, NULL) != 1) {
            BN_free(n); BN_free(e); RSA_free(rsa);
            return NULL;
        }
        pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            EVP_PKEY_free(pkey); RSA_free(rsa); pkey = NULL;
        }
#endif
        break;
    }

    case 13:   /* ECDSAP256SHA256 — 64 raw bytes: x(32) || y(32) */
    case 14:   /* ECDSAP384SHA384 — 96 raw bytes: x(48) || y(48) */
    {
        int coord = (dk->algorithm == 13) ? 32 : 48;
        if (dk->pubkey_len != (uint16_t)(2 * coord)) return NULL;
        /* Build uncompressed point: 0x04 | x | y */
        int pt_len = 1 + 2 * coord;
        uint8_t *pt = malloc((size_t)pt_len);
        if (!pt) return NULL;
        pt[0] = 0x04;
        memcpy(pt + 1, dk->pubkey, (size_t)(2 * coord));

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        const char *grp_name = (dk->algorithm == 13) ? "P-256" : "P-384";
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (bld &&
            OSSL_PARAM_BLD_push_utf8_string(bld, "group", grp_name,
                                             strlen(grp_name)) &&
            OSSL_PARAM_BLD_push_octet_string(bld, "pub", pt,
                                              (size_t)pt_len)) {
            OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
            OSSL_PARAM_BLD_free(bld);
            if (params) {
                EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
                if (kctx && EVP_PKEY_fromdata_init(kctx) == 1)
                    EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
                EVP_PKEY_CTX_free(kctx);
                OSSL_PARAM_free(params);
            }
        } else {
            OSSL_PARAM_BLD_free(bld);
        }
#else
        int nid = (dk->algorithm == 13) ? NID_X9_62_prime256v1 : NID_secp384r1;
        EC_GROUP *grp = EC_GROUP_new_by_curve_name(nid);
        EC_POINT *ec_pt = grp ? EC_POINT_new(grp) : NULL;
        if (grp && ec_pt &&
            EC_POINT_oct2point(grp, ec_pt, pt, (size_t)pt_len, NULL) == 1) {
            EC_KEY *eck = EC_KEY_new_by_curve_name(nid);
            if (eck && EC_KEY_set_public_key(eck, ec_pt) == 1) {
                pkey = EVP_PKEY_new();
                if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, eck) != 1) {
                    EVP_PKEY_free(pkey); EC_KEY_free(eck); pkey = NULL;
                }
            } else {
                EC_KEY_free(eck);
            }
        }
        EC_GROUP_free(grp);
        EC_POINT_free(ec_pt);
#endif
        free(pt);
        break;
    }

    case 15:   /* Ed25519 — 32 bytes raw public key */
        if (dk->pubkey_len != 32) return NULL;
        pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                           dk->pubkey, 32);
        break;

    default:
        break;   /* unsupported algorithm */
    }

    return pkey;
}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#  pragma GCC diagnostic pop
#endif

/* ==========================================================================
 * Section 4: ECDSA raw-signature ↔ DER conversion
 * ========================================================================== */

/*
 * DNS wire format for ECDSA is raw (r || s), each coordinate padded to the
 * curve's half-size.  OpenSSL EVP_DigestVerifyFinal expects DER.
 * Returns a malloc'd DER buffer (caller must free), sets *der_len.
 */
static uint8_t *ecdsa_raw_to_der(const uint8_t *sig, int sig_len, int *der_len)
{
    if (sig_len % 2 != 0) return NULL;
    int coord = sig_len / 2;
    BIGNUM *r = BN_bin2bn(sig,        coord, NULL);
    BIGNUM *s = BN_bin2bn(sig + coord, coord, NULL);
    if (!r || !s) { BN_free(r); BN_free(s); return NULL; }
    ECDSA_SIG *esig = ECDSA_SIG_new();
    if (!esig || ECDSA_SIG_set0(esig, r, s) != 1) {
        ECDSA_SIG_free(esig); BN_free(r); BN_free(s); return NULL;
    }
    /* r, s are now owned by esig */
    uint8_t *der = NULL;
    int len = i2d_ECDSA_SIG(esig, &der);
    ECDSA_SIG_free(esig);
    if (len <= 0) return NULL;
    *der_len = len;
    return der;
}

/* ==========================================================================
 * Section 5: dnssec_verify_rrsig  (public)
 * ========================================================================== */

int dnssec_verify_rrsig(const RrsigRdata *rrsig,
                        const DnskeyRdata *dnskey,
                        const unsigned char *rrset_data, size_t rrset_len)
{
    if (!rrsig || !dnskey || !rrset_data || rrset_len == 0) return -1;
    if (rrsig->algorithm != dnskey->algorithm) return -1;

    /* Signature time validity */
    uint32_t now = (uint32_t)time(NULL);
    if (now < rrsig->sig_inception) {
        fprintf(stderr, "DNSSEC: signature not yet valid "
                "(inception=%u now=%u)\n", rrsig->sig_inception, now);
        return 0;
    }
    if (now > rrsig->sig_expiration) {
        fprintf(stderr, "DNSSEC: signature expired "
                "(expiration=%u now=%u)\n", rrsig->sig_expiration, now);
        return 0;
    }

    EVP_PKEY *pkey = import_dnskey_pubkey(dnskey);
    if (!pkey) {
        fprintf(stderr, "DNSSEC: cannot import public key (alg=%u)\n",
                dnskey->algorithm);
        return -1;
    }

    /* ECDSA: convert wire (r||s) to DER that OpenSSL expects */
    const uint8_t *sig     = rrsig->signature;
    int            sig_len = rrsig->sig_len;
    uint8_t       *der_sig = NULL;
    if (rrsig->algorithm == 13 || rrsig->algorithm == 14) {
        int dlen = 0;
        der_sig = ecdsa_raw_to_der(rrsig->signature, rrsig->sig_len, &dlen);
        if (!der_sig) { EVP_PKEY_free(pkey); return -1; }
        sig     = der_sig;
        sig_len = dlen;
    }

    /* Select digest (NULL = implicit, used for Ed25519) */
    const EVP_MD *md = NULL;
    switch (rrsig->algorithm) {
    case 5:  md = EVP_sha1();   break;   /* RSASHA1            */
    case 7:  md = EVP_sha1();   break;   /* RSASHA1-NSEC3-SHA1 */
    case 8:  md = EVP_sha256(); break;
    case 10: md = EVP_sha512(); break;
    case 13: md = EVP_sha256(); break;
    case 14: md = EVP_sha384(); break;
    case 15: md = NULL;         break;
    default:
        free(der_sig); EVP_PKEY_free(pkey); return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = -1;
    if (ctx) {
        /* Ed25519 (RFC 8080) only supports one-shot verification — the
         * streaming EVP_DigestVerifyUpdate/Final API errors out for
         * edwards-curve keys, so use EVP_DigestVerify() for alg 15. */
        int rv = -1;
        if (rrsig->algorithm == 15) {
            if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1)
                rv = EVP_DigestVerify(ctx, sig, (size_t)sig_len,
                                      rrset_data, rrset_len);
        } else if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1 &&
                   EVP_DigestVerifyUpdate(ctx, rrset_data, rrset_len) == 1) {
            rv = EVP_DigestVerifyFinal(ctx, sig, (size_t)sig_len);
        }
        if (rv == 1) {
            result = 1;
        } else if (rv == 0) {
            result = 0;
            unsigned long e = ERR_get_error();
            char ebuf[256];
            ERR_error_string_n(e, ebuf, sizeof(ebuf));
            fprintf(stderr, "DNSSEC: signature verify failed (alg=%u): %s\n",
                    rrsig->algorithm, ebuf);
        }
        EVP_MD_CTX_free(ctx);
    }

    free(der_sig);
    EVP_PKEY_free(pkey);
    return result;
}

/* ==========================================================================
 * Section 6: find_dnskey helper  (used by dnssec_validate_response)
 * ========================================================================== */

/*
 * Search for a DNSKEY matching (key_tag, algorithm) in three places, in order:
 *
 *  1. The response packet itself — covers the common case where the DNSKEY
 *     is returned alongside the answer (e.g. explicit DNSKEY query).
 *
 *  2. The root trust anchor list — covers RRSIG(DNSKEY) at the root zone.
 *
 *  3. The per-resolution chain context (optional, may be NULL) — covers
 *     intermediate-zone keys validated earlier in the delegation walk.
 *     The signer_name (dot-notation) identifies which zone to look up.
 *
 * On success, fills *dk_out (caller must free_dnskey_rdata on it) and
 * returns 1.  Returns 0 if not found.
 */
static int find_dnskey(const struct Packet *response,
                       const TrustAnchor *anchors,
                       const DnssecChainCtx *chain,   /* may be NULL */
                       const char *signer_name,        /* for chain lookup; may be NULL */
                       uint16_t key_tag, uint8_t algorithm,
                       DnskeyRdata *dk_out)
{
    const uint8_t *buf    = (const uint8_t *)response->request;
    int            buf_len = (int)response->recv_len;
    int total_rrs = response->ancount + response->nscount + response->arcount;

    int pos = HEADER_LEN;
    for (int q = 0; q < response->qdcount && pos < buf_len; q++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0) goto check_anchors;
        pos = e + 4;
    }

    for (int a = 0; a < total_rrs && pos < buf_len; a++) {
        int name_end = name_end_pos(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) break;
        uint16_t type = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl  = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int rdata_off = name_end + 10;
        if (rdata_off + rdl > buf_len) break;

        if (type == QTYPE_DNSKEY) {
            DnskeyRdata tmp;
            if (parse_dnskey_rdata(buf + rdata_off, rdl, &tmp) == 0) {
                uint16_t tag = compute_key_tag(tmp.flags, tmp.protocol,
                                               tmp.algorithm,
                                               tmp.pubkey, tmp.pubkey_len);
                if (tag == key_tag && tmp.algorithm == algorithm) {
                    *dk_out = tmp;
                    return 1;
                }
                free_dnskey_rdata(&tmp);
            }
        }
        pos = rdata_off + rdl;
    }

check_anchors:
    for (const TrustAnchor *ta = anchors; ta; ta = ta->next) {
        if (ta->key_tag == key_tag && ta->algorithm == algorithm) {
            dk_out->flags     = ta->flags;
            dk_out->protocol  = ta->protocol;
            dk_out->algorithm = ta->algorithm;
            dk_out->pubkey    = malloc(ta->pubkey_len);
            if (!dk_out->pubkey) return 0;
            memcpy(dk_out->pubkey, ta->pubkey, ta->pubkey_len);
            dk_out->pubkey_len = ta->pubkey_len;
            return 1;
        }
    }

    /*
     * 3. Consult the per-resolution chain context (RFC 4035 §5 chain-of-trust).
     *
     * During iterative resolution each referral step may have validated a zone
     * DNSKEY against its parent DS record.  Those keys are accumulated in
     * the chain context and used here to verify RRSIGs in deeper zones.
     */
    if (chain && signer_name &&
        dnssec_chain_find_key(chain, signer_name, key_tag, algorithm, dk_out))
        return 1;

    return 0;
}

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
static int verify_nsec_denial(const uint8_t *buf, int buf_len,
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

/* One validated (owner, type) pair recorded during the RRSIG loop. */
typedef struct {
    uint8_t  owner[256];
    int      owner_len;       /* uncompressed, lowercased wire length */
    uint16_t type;            /* the RRSIG's type_covered */
} ValidatedRR;

/*
 * Return 1 if signer (wire, lc) is a label-boundary suffix of owner (wire, lc)
 * — i.e. the signing zone is in-bailiwick for the RR owner.  Both names are
 * uncompressed and terminate in a root label.  Walking owner one label at a
 * time guarantees comparisons only ever land on label boundaries.
 */
static int wire_name_is_suffix(const uint8_t *owner, int owner_len,
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
static int dns_skip_questions(const uint8_t *buf, int buf_len, int qdcount)
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
static int dns_skip_rrs(const uint8_t *buf, int buf_len, int pos, int count)
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
static int section_has_type(const uint8_t *buf, int buf_len, int pos,
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
static uint16_t question_qtype(const uint8_t *buf, int buf_len)
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
static int answer_is_validated(const uint8_t *buf, int buf_len,
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

/* ==========================================================================
 * Section 7: dnssec_validate_with_chain / dnssec_validate_response  (public)
 * ========================================================================== */

/*
 * Core validation loop shared by both public entry points.
 *
 * chain: the per-resolution DnssecChainCtx accumulated during the iterative
 *        delegation walk.  May be NULL, in which case key lookup falls back
 *        to the response packet and root trust anchors only.
 *
 * Returns  1 if at least one RRSIG validated and none failed,
 *          0 if at least one RRSIG failed verification (caller: SERVFAIL),
 *         -1 if the response carries no RRSIG, or no matching DNSKEY was
 *            found for any RRSIG (treat as unsigned / unverifiable).
 */
int dnssec_validate_with_chain(struct Packet *response,
                               const TrustAnchor *anchors,
                               const DnssecChainCtx *chain)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN)
        return -1;

    const uint8_t *buf    = (const uint8_t *)response->request;
    int            buf_len = (int)response->recv_len;
    int total_rrs = response->ancount + response->nscount + response->arcount;

    int pos = HEADER_LEN;
    for (int q = 0; q < response->qdcount && pos < buf_len; q++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0) return -1;
        pos = e + 4;
    }

    int has_rrsig = 0;
    int validated = 0;
    int failed    = 0;

    /* (owner,type) pairs covered by a verified, in-bailiwick RRSIG.  Used after
     * the loop to confirm the *answering* RRset is signed before AD is set. */
    ValidatedRR vset[64];
    int         vset_n = 0;

    for (int a = 0; a < total_rrs && pos < buf_len; a++) {
        int name_pos = pos;
        int name_end = name_end_pos(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) break;

        uint16_t type = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl  = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int rdata_off = name_end + 10;
        if (rdata_off + rdl > buf_len) break;

        if (type == QTYPE_RRSIG) {
            has_rrsig = 1;
            RrsigRdata rrsig;
            if (parse_rrsig_rdata(buf, buf_len, rdata_off, rdl, &rrsig) != 0) {
                pos = rdata_off + rdl;
                continue;
            }

            DnskeyRdata dk;
            if (!find_dnskey(response, anchors, chain, rrsig.signer_name,
                             rrsig.key_tag, rrsig.algorithm, &dk)) {
                /*
                 * No matching DNSKEY found in the response, trust anchors,
                 * or chain context — treat as "unverifiable", not "failed".
                 * RFC 4035 §4.7: a validating resolver SHOULD NOT set AD bit
                 * when it cannot obtain the necessary DNSKEY.
                 */
                free_rrsig_rdata(&rrsig);
                pos = rdata_off + rdl;
                continue;
            }

            uint8_t *signed_data = NULL;
            int      signed_len  = 0;
            if (build_signed_data(response, &rrsig, name_pos,
                                  &signed_data, &signed_len) < 0) {
                free_rrsig_rdata(&rrsig);
                free_dnskey_rdata(&dk);
                pos = rdata_off + rdl;
                continue;
            }

            uint16_t type_covered = rrsig.type_covered;   /* save before free */

            /* Capture covered owner + signer (wire, lc) before freeing rrsig,
             * for the in-bailiwick check and validated-set bookkeeping. */
            uint8_t cov_owner[256];
            int     cov_owner_len = expand_name_lc(buf, buf_len, name_pos,
                                                   cov_owner, sizeof(cov_owner));
            uint8_t signer_wire[256];
            int     signer_wire_len = encode_name_lc(rrsig.signer_name,
                                                     signer_wire,
                                                     sizeof(signer_wire));

            int result = dnssec_verify_rrsig(&rrsig, &dk,
                                             signed_data, (size_t)signed_len);
            free(signed_data);
            free_rrsig_rdata(&rrsig);
            free_dnskey_rdata(&dk);

            if (result == 1) {
                /* RFC 4035 §5.3.1: the signer must be in-bailiwick for the
                 * owner (signer is a label-suffix of the RR owner).  A
                 * cross-zone signature is a forgery attempt — do not count it
                 * as validating the RRset (the answer-coverage gate then
                 * withholds AD). */
                if (cov_owner_len < 0 || signer_wire_len < 0 ||
                    !wire_name_is_suffix(cov_owner, cov_owner_len,
                                         signer_wire, signer_wire_len)) {
                    fprintf(stderr, "DNSSEC: RRSIG signer not in-bailiwick "
                                    "(type_covered=%u)\n", type_covered);
                } else {
                    validated++;
                    if (vset_n < (int)(sizeof(vset) / sizeof(vset[0]))) {
                        memcpy(vset[vset_n].owner, cov_owner,
                               (size_t)cov_owner_len);
                        vset[vset_n].owner_len = cov_owner_len;
                        vset[vset_n].type      = type_covered;
                        vset_n++;
                    }
                }
            } else if (result == 0) {
                fprintf(stderr, "DNSSEC: RRSIG INVALID (type_covered=%u)\n",
                        type_covered);
                failed++;
            }
            /* result == -1: unsupported algorithm — skip silently */
        }

        pos = rdata_off + rdl;
    }

    if (!has_rrsig)     return -1;  /* unsigned or DO bit not honoured upstream  */
    if (failed > 0)     return 0;   /* at least one explicit failure             */
    if (validated == 0) return -1;  /* had RRSIGs but no matching DNSKEY found   */

    uint16_t rcode   = (((uint16_t)buf[2] << 8) | buf[3]) & 0x000Fu;
    int      ancount = (int)response->ancount;

    /* Authority section start (after questions + answers). */
    int answer_pos = dns_skip_questions(buf, buf_len, response->qdcount);
    int auth_pos   = (answer_pos < 0)
                   ? -1 : dns_skip_rrs(buf, buf_len, answer_pos, ancount);

    /*
     * Distinguish a true denial-of-existence from a delegation referral.  Both
     * carry ancount == 0, but a denial is served by the zone's authoritative
     * server and carries a SOA in the authority section, whereas a referral
     * comes from the parent and carries NS (no SOA).  Only denials are gated by
     * the NSEC proof; referrals fall through to the chain-step return below so
     * verified DS records are still stored (see resolve.c referral handling).
     */
    int auth_has_soa = (auth_pos >= 0) &&
        section_has_type(buf, buf_len, auth_pos, (int)response->nscount,
                         QTYPE_SOA);
    int is_nxdomain = (rcode == 3);
    int is_nodata   = (rcode == 0 && ancount == 0 && auth_has_soa);

    if (is_nxdomain || is_nodata) {
        /*
         * Denial of existence: AD is justified only if the NSEC/NSEC3 records
         * actually prove the denial for THIS (QNAME, QTYPE) — a validated but
         * irrelevant signature (e.g. RRSIG(SOA)) is not enough (RFC 4035 §5.4).
         */
        if (response->nscount == 0 || auth_pos < 0 || auth_pos >= buf_len)
            return -1;

        uint8_t qname_wire[256];
        int qname_len = expand_name_lc(buf, buf_len, HEADER_LEN,
                                       qname_wire, sizeof(qname_wire));
        uint16_t qtype = question_qtype(buf, buf_len);
        if (qname_len <= 0)
            return -1;

        int nsec_result = verify_nsec_denial(buf, buf_len, qname_wire, qname_len,
                                             qtype, is_nxdomain, auth_pos,
                                             response->nscount);
        if (nsec_result == 1) return 1;    /* denial proven                     */
        if (nsec_result == 0) {            /* denial contradicted               */
            fprintf(stderr, "DNSSEC: NSEC denial-of-existence proof"
                            " is invalid\n");
            return 0;
        }
        return -1;   /* could not prove denial (NSEC3/complex) — withhold AD    */
    }

    if (ancount > 0) {
        /*
         * Positive answer: require the RRset answering the question (or the
         * terminal RRset of an in-packet CNAME chain) to be covered by a
         * verified, in-bailiwick RRSIG.  This is the core 4.2 fix — without it,
         * a forged/unsigned answer alongside one genuine RRSIG would set AD.
         */
        uint16_t qtype = question_qtype(buf, buf_len);
        if (qtype != 0 &&
            answer_is_validated(buf, buf_len, response->qdcount, ancount,
                                qtype, vset, vset_n))
            return 1;
        fprintf(stderr, "DNSSEC: answer RRset (qtype=%u) not covered by a"
                        " validated RRSIG — withholding AD\n", qtype);
        return -1;
    }

    /*
     * Referral or other signed non-answer (ancount == 0, no SOA): at least one
     * in-bailiwick RRSIG verified.  Report success so the chain-of-trust step
     * (DS storage) proceeds; this path never reaches the client AD bit because
     * the final-answer caller always has ancount > 0.
     */
    return 1;
}

/*
 * Convenience wrapper: validate without a chain context (root zone or cases
 * where chain-of-trust was not accumulated).
 */
int dnssec_validate_response(struct Packet *response,
                             const TrustAnchor *anchors)
{
    return dnssec_validate_with_chain(response, anchors, NULL);
}

/*
 * Bootstrap validator for the root DNSKEY RRset.
 *
 * Verifies the RRSIG covering the root DNSKEY RRset using ONLY a trust-anchor
 * key (the root KSK loaded at startup) as the verifier — deliberately NOT
 * find_dnskey(), which would also accept a key contained in the response and
 * thus self-validate a forged RRset.  This anchors the root ZSK to the static
 * trust anchor so the caller can safely add the whole RRset to the chain.
 *
 * Returns 1 if a trust-anchor key verifies the DNSKEY RRSIG, else 0.
 */
int dnssec_validate_root_dnskey(struct Packet *response,
                                const TrustAnchor *anchors)
{
    if (!response || !response->request ||
        response->recv_len < HEADER_LEN || !anchors)
        return 0;

    const uint8_t *buf     = (const uint8_t *)response->request;
    int            buf_len = (int)response->recv_len;
    int total_rrs = response->ancount + response->nscount + response->arcount;

    int pos = HEADER_LEN;
    for (int q = 0; q < response->qdcount && pos < buf_len; q++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0) return 0;
        pos = e + 4;
    }

    for (int a = 0; a < total_rrs && pos < buf_len; a++) {
        int name_pos = pos;
        int name_end = name_end_pos(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) break;

        uint16_t type = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl  = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int rdata_off = name_end + 10;
        if (rdata_off + rdl > buf_len) break;

        if (type == QTYPE_RRSIG) {
            RrsigRdata rrsig;
            if (parse_rrsig_rdata(buf, buf_len, rdata_off, rdl, &rrsig) == 0) {
                if (rrsig.type_covered == QTYPE_DNSKEY) {
                    /* Verifier MUST be a trust anchor (not a response key). */
                    for (const TrustAnchor *ta = anchors; ta; ta = ta->next) {
                        if (ta->key_tag != rrsig.key_tag ||
                            ta->algorithm != rrsig.algorithm)
                            continue;

                        /* Borrowed pubkey — do NOT free_dnskey_rdata(&dk). */
                        DnskeyRdata dk;
                        dk.flags      = ta->flags;
                        dk.protocol   = ta->protocol;
                        dk.algorithm  = ta->algorithm;
                        dk.pubkey     = ta->pubkey;
                        dk.pubkey_len = ta->pubkey_len;

                        uint8_t *signed_data = NULL;
                        int      signed_len  = 0;
                        if (build_signed_data(response, &rrsig, name_pos,
                                              &signed_data, &signed_len) >= 0) {
                            int r = dnssec_verify_rrsig(&rrsig, &dk, signed_data,
                                                        (size_t)signed_len);
                            free(signed_data);
                            if (r == 1) {
                                free_rrsig_rdata(&rrsig);
                                return 1;
                            }
                        }
                    }
                }
                free_rrsig_rdata(&rrsig);
            }
        }

        pos = rdata_off + rdl;
    }

    return 0;
}

/*
 * Verify a zone's DNSKEY RRset self-signature using a key already validated in
 * the chain (typically the zone KSK, just promoted via its DS digest), and
 * report success so the caller can then trust the whole RRset — including the
 * ZSK(s).  The verifier is taken ONLY from the chain (never from the response),
 * so a forged DNSKEY/RRSIG cannot self-validate.
 *
 * Returns 1 if the DNSKEY RRset RRSIG verifies against a chain key for `zone`.
 */
int dnssec_validate_dnskey_with_chain(struct Packet *response, const char *zone,
                                      const DnssecChainCtx *chain)
{
    if (!response || !response->request ||
        response->recv_len < HEADER_LEN || !zone || !chain)
        return 0;

    const uint8_t *buf     = (const uint8_t *)response->request;
    int            buf_len = (int)response->recv_len;
    int total_rrs = response->ancount + response->nscount + response->arcount;

    int pos = HEADER_LEN;
    for (int q = 0; q < response->qdcount && pos < buf_len; q++) {
        int e = name_end_pos(buf, buf_len, pos);
        if (e < 0) return 0;
        pos = e + 4;
    }

    for (int a = 0; a < total_rrs && pos < buf_len; a++) {
        int name_pos = pos;
        int name_end = name_end_pos(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) break;

        uint16_t type = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl  = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int rdata_off = name_end + 10;
        if (rdata_off + rdl > buf_len) break;

        if (type == QTYPE_RRSIG) {
            RrsigRdata rrsig;
            if (parse_rrsig_rdata(buf, buf_len, rdata_off, rdl, &rrsig) == 0) {
                if (rrsig.type_covered == QTYPE_DNSKEY) {
                    DnskeyRdata dk;
                    if (dnssec_chain_find_key(chain, zone, rrsig.key_tag,
                                              rrsig.algorithm, &dk)) {
                        uint8_t *signed_data = NULL;
                        int      signed_len  = 0;
                        if (build_signed_data(response, &rrsig, name_pos,
                                              &signed_data, &signed_len) >= 0) {
                            int r = dnssec_verify_rrsig(&rrsig, &dk, signed_data,
                                                        (size_t)signed_len);
                            free(signed_data);
                            free_dnskey_rdata(&dk);
                            if (r == 1) {
                                free_rrsig_rdata(&rrsig);
                                return 1;
                            }
                        } else {
                            free_dnskey_rdata(&dk);
                        }
                    }
                }
                free_rrsig_rdata(&rrsig);
            }
        }

        pos = rdata_off + rdl;
    }

    return 0;
}
