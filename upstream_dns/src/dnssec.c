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
        if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1 &&
            EVP_DigestVerifyUpdate(ctx, rrset_data, rrset_len) == 1) {
            int rv = EVP_DigestVerifyFinal(ctx, sig, (size_t)sig_len);
            if (rv == 1) {
                result = 1;
            } else {
                result = 0;
                unsigned long e = ERR_get_error();
                char ebuf[256];
                ERR_error_string_n(e, ebuf, sizeof(ebuf));
                fprintf(stderr, "DNSSEC: signature verify failed (alg=%u): %s\n",
                        rrsig->algorithm, ebuf);
            }
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
            int result = dnssec_verify_rrsig(&rrsig, &dk,
                                             signed_data, (size_t)signed_len);
            free(signed_data);
            free_rrsig_rdata(&rrsig);
            free_dnskey_rdata(&dk);

            if (result == 1) {
                validated++;
            } else if (result == 0) {
                fprintf(stderr, "DNSSEC: ✗ RRSIG INVALID (type_covered=%u)\n",
                        type_covered);
                failed++;
            }
            /* result == -1: unsupported algorithm — skip silently */
        }

        pos = rdata_off + rdl;
    }

    if (!has_rrsig) return -1;    /* unsigned or DO bit not honoured by upstream */
    if (failed > 0) return 0;     /* at least one explicit failure              */
    if (validated > 0) return 1;  /* all attempted verifications passed         */
    return -1;                    /* had RRSIGs but no matching DNSKEY found    */
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
