#include "dnssec.h"
#include "dns_wire.h"
#include "dnssec_proof.h"
#include "dnssec_wire.h"

#include <time.h>

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

/* ---- Public key import (DNSKEY wire format -> OpenSSL) ------------------ */

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

/* ---- Signature verification ------------------------------------------- */

/* DNS carries ECDSA signatures as raw r||s; OpenSSL wants DER (malloc'd). */
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

/* Verify one RRSIG over `rrset_data` with `dnskey`, including the validity
 * window.  1 valid, 0 bad signature/expired, -1 unsupported or error. */
static int dnssec_verify_rrsig(const RrsigRdata *rrsig,
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

/* Verify the RRSIG whose RR owner is at owner_pos against dk. */
static int verify_with_key(struct Packet *response, const RrsigRdata *rrsig,
                           int owner_pos, const DnskeyRdata *dk)
{
    uint8_t *data = NULL;
    int len = 0;
    if (build_signed_data(response, rrsig, owner_pos, &data, &len) < 0) return -1;
    int r = dnssec_verify_rrsig(rrsig, dk, data, (size_t)len);
    free(data);
    return r;
}

/* Trust-anchor key as DnskeyRdata (pubkey borrowed: do not free). */
static DnskeyRdata anchor_key(const TrustAnchor *ta)
{
    return (DnskeyRdata){ ta->flags, ta->protocol, ta->algorithm, ta->pubkey, ta->pubkey_len };
}

/*
 * Verifier for an RRSIG, searched in: the response itself, the trust
 * anchors, then keys the chain validated for `signer`.  Fills *dk_out
 * (caller frees).  Returns 1 if found.
 */
static int find_dnskey(const struct Packet *response, const TrustAnchor *anchors,
                       const DnssecChainCtx *chain, const char *signer,
                       uint16_t key_tag, uint8_t algorithm, DnskeyRdata *dk_out)
{
    const uint8_t *buf = (const uint8_t *)response->request;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, (int)response->recv_len); rr_next(&it, &rr); ) {
        if (rr.type != QTYPE_DNSKEY || parse_dnskey_rdata(buf + rr.rdata, rr.rdlen, dk_out) != 0)
            continue;
        if (dk_out->algorithm == algorithm &&
            compute_key_tag(dk_out->flags, dk_out->protocol, dk_out->algorithm,
                            dk_out->pubkey, dk_out->pubkey_len) == key_tag)
            return 1;
        free_dnskey_rdata(dk_out);
    }

    for (const TrustAnchor *ta = anchors; ta; ta = ta->next) {
        if (ta->key_tag != key_tag || ta->algorithm != algorithm) continue;
        *dk_out = anchor_key(ta);
        dk_out->pubkey = malloc(ta->pubkey_len);
        if (!dk_out->pubkey) return 0;
        memcpy(dk_out->pubkey, ta->pubkey, ta->pubkey_len);
        return 1;
    }
    return chain && signer && dnssec_chain_find_key(chain, signer, key_tag, algorithm, dk_out);
}

/* After the RRSIGs verified: is the answer itself proven?  NXDOMAIN/NODATA
 * need a matching NSEC proof; positive answers need the answering RRset
 * (through any CNAME chain) to be covered.  Referrals pass (DS storage). */
static int check_coverage(struct Packet *response, const ValidatedRR *vset, int vset_n)
{
    const uint8_t *buf = (const uint8_t *)response->request;
    int len = (int)response->recv_len;
    int rcode = buf[3] & 0x0F;
    int qend = dns_name_end(buf, len, HEADER_LEN);
    uint16_t qtype = qend >= 0 && qend + 2 <= len ? rd16(buf + qend) : 0;

    /* A denial carries the zone's SOA; a referral (also ancount 0) carries NS. */
    bool auth_has_soa = false;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, len); rr_next(&it, &rr); )
        if (rr.section == SEC_AUTHORITY && rr.type == QTYPE_SOA) auth_has_soa = true;

    bool is_nxdomain = rcode == RCODE_NAME_ERROR;
    if (is_nxdomain || (rcode == RCODE_NO_ERROR && response->ancount == 0 && auth_has_soa)) {
        uint8_t qname[256];
        int qname_len = expand_name_lc(buf, len, HEADER_LEN, qname, sizeof(qname));
        if (response->nscount == 0 || qname_len <= 0) return -1;
        int r = verify_nsec_denial(buf, len, qname, qname_len, qtype, is_nxdomain);
        if (r == 0) fprintf(stderr, "DNSSEC: NSEC denial-of-existence proof is invalid\n");
        return r;          /* -1: unproven (e.g. NSEC3) — withhold AD */
    }

    if (response->ancount > 0) {
        if (qtype != 0 && answer_is_validated(buf, len, qtype, vset, vset_n)) return 1;
        fprintf(stderr, "DNSSEC: answer RRset (qtype=%u) not covered by a"
                        " validated RRSIG — withholding AD\n", qtype);
        return -1;
    }
    return 1;
}

int dnssec_validate_with_chain(struct Packet *response, const TrustAnchor *anchors,
                               const DnssecChainCtx *chain)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) return -1;
    const uint8_t *buf = (const uint8_t *)response->request;
    int len = (int)response->recv_len;

    bool has_rrsig = false;
    int validated = 0, failed = 0;
    ValidatedRR vset[64];     /* RRsets covered by a good, in-bailiwick RRSIG */
    int vset_n = 0;

    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, len); rr_next(&it, &rr); ) {
        if (rr.type != QTYPE_RRSIG) continue;
        has_rrsig = true;

        RrsigRdata rrsig;
        if (parse_rrsig_rdata(buf, len, rr.rdata, rr.rdlen, &rrsig) != 0) continue;
        DnskeyRdata dk;
        /* No key anywhere: unverifiable, not failed (RFC 4035 §4.7). */
        if (!find_dnskey(response, anchors, chain, rrsig.signer_name,
                         rrsig.key_tag, rrsig.algorithm, &dk)) {
            free_rrsig_rdata(&rrsig);
            continue;
        }

        ValidatedRR v = { .type = rrsig.type_covered };
        v.owner_len = expand_name_lc(buf, len, rr.owner, v.owner, sizeof(v.owner));
        uint8_t signer[256];
        int signer_len = encode_name_lc(rrsig.signer_name, signer, sizeof(signer));

        int result = verify_with_key(response, &rrsig, rr.owner, &dk);
        free_rrsig_rdata(&rrsig);
        free_dnskey_rdata(&dk);

        if (result == 0) {
            fprintf(stderr, "DNSSEC: RRSIG INVALID (type_covered=%u)\n", v.type);
            failed++;
        } else if (result == 1) {
            /* The signer must be the owner or its ancestor (RFC 4035 §5.3.1);
             * a cross-zone signature proves nothing about this RRset. */
            if (v.owner_len < 0 || signer_len < 0 ||
                !wire_name_is_suffix(v.owner, v.owner_len, signer, signer_len)) {
                fprintf(stderr, "DNSSEC: RRSIG signer not in-bailiwick (type_covered=%u)\n", v.type);
            } else {
                validated++;
                if (vset_n < (int)(sizeof(vset) / sizeof(vset[0]))) vset[vset_n++] = v;
            }
        }
    }

    if (!has_rrsig)     return -1;   /* unsigned */
    if (failed > 0)     return 0;
    if (validated == 0) return -1;   /* signed, but no key to check with */
    return check_coverage(response, vset, vset_n);
}

/* Root DNSKEY RRset: the verifier must be a trust anchor, never a key from
 * the response (that would let a forged RRset validate itself). */
int dnssec_validate_root_dnskey(struct Packet *response, const TrustAnchor *anchors)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN || !anchors)
        return 0;
    const uint8_t *buf = (const uint8_t *)response->request;
    int len = (int)response->recv_len;

    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, len); rr_next(&it, &rr); ) {
        RrsigRdata rrsig;
        if (rr.type != QTYPE_RRSIG || parse_rrsig_rdata(buf, len, rr.rdata, rr.rdlen, &rrsig) != 0)
            continue;
        int ok = 0;
        for (const TrustAnchor *ta = anchors; ta && !ok && rrsig.type_covered == QTYPE_DNSKEY;
             ta = ta->next) {
            DnskeyRdata dk = anchor_key(ta);
            ok = ta->key_tag == rrsig.key_tag && ta->algorithm == rrsig.algorithm &&
                 verify_with_key(response, &rrsig, rr.owner, &dk) == 1;
        }
        free_rrsig_rdata(&rrsig);
        if (ok) return 1;
    }
    return 0;
}

/* A zone's DNSKEY RRset, verified with a key the chain already trusts (the
 * KSK promoted via DS) — again never a key from the response. */
int dnssec_validate_dnskey_with_chain(struct Packet *response, const char *zone,
                                      const DnssecChainCtx *chain)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN || !zone || !chain)
        return 0;
    const uint8_t *buf = (const uint8_t *)response->request;
    int len = (int)response->recv_len;

    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, buf, len); rr_next(&it, &rr); ) {
        RrsigRdata rrsig;
        if (rr.type != QTYPE_RRSIG || parse_rrsig_rdata(buf, len, rr.rdata, rr.rdlen, &rrsig) != 0)
            continue;
        DnskeyRdata dk;
        int ok = 0;
        if (rrsig.type_covered == QTYPE_DNSKEY &&
            dnssec_chain_find_key(chain, zone, rrsig.key_tag, rrsig.algorithm, &dk)) {
            ok = verify_with_key(response, &rrsig, rr.owner, &dk) == 1;
            free_dnskey_rdata(&dk);
        }
        free_rrsig_rdata(&rrsig);
        if (ok) return 1;
    }
    return 0;
}
