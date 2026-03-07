#include "dnssec_chain.h"
#include "dns_wire.h"    /* parse_dnskey_rdata, parse_ds_rdata, compute_key_tag */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include <openssl/evp.h>

/* ==========================================================================
 * Section 1: Internal wire-format helpers
 *
 * These are intentionally local to this translation unit.  The analogous
 * functions in dnssec.c are also static; once the codebase requires them in
 * a third place they should be promoted to dns_wire.c/h.
 * ========================================================================== */

/*
 * Return the byte position immediately after the DNS name that starts at
 * buf[pos].  Compression pointers are resolved in a single step (the result
 * position is pos+2, not the target of the pointer).
 * Returns -1 on malformed input or if the jump limit is reached.
 */
static int dc_name_end(const uint8_t *buf, int len, int pos)
{
    int jumps = 0;
    while (pos < len && jumps < 10) {
        uint8_t b = buf[pos];
        if (b == 0)              return pos + 1;
        if ((b & 0xC0) == 0xC0) return pos + 2;  /* 2-byte compression ptr */
        if (b > 63)              return -1;        /* illegal label length   */
        pos += 1 + b;
    }
    return -1;
}

/*
 * Expand a possibly-compressed DNS name starting at buf[pos] into dst[],
 * lower-casing every label byte (canonical form, RFC 4034 §6.2).
 * Follows compression pointers up to 10 levels deep.
 * Returns number of bytes written to dst on success, -1 on error.
 */
static int dc_expand_name(const uint8_t *buf, int len, int pos,
                           uint8_t *dst, int dst_size)
{
    int dpos = 0, jumps = 0;
    while (pos < len && jumps < 10) {
        uint8_t b = buf[pos];
        if (b == 0) {
            if (dpos >= dst_size) return -1;
            dst[dpos++] = 0;
            return dpos;
        }
        if ((b & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
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
 * Convert an uncompressed, lower-cased wire-format name into a dot-notation
 * string suitable for use as a hash key or log message.
 *
 * The root zone is represented as "." (a single dot).
 * Returns 0 on success, -1 on truncation or malformed input.
 */
static int dc_wire_to_str(const uint8_t *wire, int wire_len,
                           char *out, int out_size)
{
    int pos = 0, opos = 0;
    while (pos < wire_len) {
        int llen = (int)(unsigned char)wire[pos++];
        if (llen == 0) {
            /* root terminator — if nothing was written yet it's the root zone */
            if (opos == 0) {
                if (opos + 1 >= out_size) return -1;
                out[opos++] = '.';
            }
            break;
        }
        if (opos > 0) {
            if (opos + 1 >= out_size) return -1;
            out[opos++] = '.';
        }
        if (opos + llen >= out_size || pos + llen > wire_len) return -1;
        memcpy(out + opos, wire + pos, (size_t)llen);
        opos += llen;
        pos  += llen;
    }
    if (opos >= out_size) return -1;
    out[opos] = '\0';
    return 0;
}

/* ==========================================================================
 * Section 2: Lifecycle
 * ========================================================================== */

void dnssec_chain_init(DnssecChainCtx *ctx)
{
    if (ctx) {
        ctx->keys       = NULL;
        ctx->pending_ds = NULL;
    }
}

void dnssec_chain_free(DnssecChainCtx *ctx)
{
    if (!ctx) return;

    /* Free validated key chain */
    ValidatedKey *vk = ctx->keys;
    while (vk) {
        ValidatedKey *next = vk->next;
        free_dnskey_rdata(&vk->dk);
        free(vk);
        vk = next;
    }
    ctx->keys = NULL;

    /* Free pending DS chain */
    PendingDS *pd = ctx->pending_ds;
    while (pd) {
        PendingDS *next = pd->next;
        free_ds_rdata(&pd->ds);
        free(pd);
        pd = next;
    }
    ctx->pending_ds = NULL;
}

/* ==========================================================================
 * Section 3: Key lookup
 * ========================================================================== */

int dnssec_chain_find_key(const DnssecChainCtx *ctx,
                           const char *zone,
                           uint16_t key_tag, uint8_t algorithm,
                           DnskeyRdata *dk_out)
{
    if (!ctx || !zone || !dk_out) return 0;

    for (const ValidatedKey *vk = ctx->keys; vk; vk = vk->next) {
        if (vk->key_tag       == key_tag   &&
            vk->dk.algorithm  == algorithm &&
            strcasecmp(vk->zone, zone) == 0) {

            /* Deep-copy so the caller can call free_dnskey_rdata independently */
            dk_out->flags      = vk->dk.flags;
            dk_out->protocol   = vk->dk.protocol;
            dk_out->algorithm  = vk->dk.algorithm;
            dk_out->pubkey_len = vk->dk.pubkey_len;
            dk_out->pubkey     = malloc(vk->dk.pubkey_len);
            if (!dk_out->pubkey) return 0;
            memcpy(dk_out->pubkey, vk->dk.pubkey, vk->dk.pubkey_len);
            return 1;
        }
    }
    return 0;
}

/* ==========================================================================
 * Section 4: DS digest verification (RFC 4034 §5.1.4)
 * ========================================================================== */

int dnssec_chain_verify_ds(const DsRdata *ds,
                            const DnskeyRdata *dk,
                            const uint8_t *owner_wire, int owner_len)
{
    if (!ds || !dk || !owner_wire || owner_len <= 0) return -1;

    /*
     * The DS algorithm field must equal the DNSKEY algorithm field.
     * The DS key_tag must equal compute_key_tag(DNSKEY) — the caller is
     * expected to have already pre-filtered on key_tag before calling here,
     * so we just sanity-check the algorithm.
     */
    if (ds->algorithm != dk->algorithm) return 0;

    /* Select hash function based on digest type (RFC 4034 §5.1, RFC 6605 §2) */
    const EVP_MD *md;
    switch (ds->digest_type) {
    case 1: md = EVP_sha1();   break;   /* SHA-1   — deprecated, RFC 3658  */
    case 2: md = EVP_sha256(); break;   /* SHA-256 — mandatory, RFC 4509   */
    case 4: md = EVP_sha384(); break;   /* SHA-384 — ECDSA/P-384, RFC 6605 */
    default:
        fprintf(stderr, "DNSSEC chain: unsupported DS digest type %u\n",
                ds->digest_type);
        return -1;
    }

    /*
     * DS digest input (RFC 4034 §5.1.4):
     *   owner_name_wire_lc | DNSKEY_flags(2) | DNSKEY_protocol(1) |
     *   DNSKEY_algorithm(1) | DNSKEY_public_key
     */
    int data_len = owner_len + 4 + (int)dk->pubkey_len;
    uint8_t *data = malloc((size_t)data_len);
    if (!data) return -1;

    int p = 0;
    memcpy(data + p, owner_wire, (size_t)owner_len);  p += owner_len;
    data[p++] = (dk->flags >> 8) & 0xFF;
    data[p++] =  dk->flags       & 0xFF;
    data[p++] =  dk->protocol;
    data[p++] =  dk->algorithm;
    memcpy(data + p, dk->pubkey, dk->pubkey_len);

    /* SHA-384 produces 48 bytes — 64 bytes is a safe upper bound */
    uint8_t digest[64];
    unsigned int dlen = 0;
    int ok = EVP_Digest(data, (size_t)data_len, digest, &dlen, md, NULL);
    free(data);

    if (!ok) return -1;

    /* Length mismatch is a definitive mismatch, not an error */
    if ((unsigned int)ds->digest_len != dlen) return 0;

    return (memcmp(digest, ds->digest, dlen) == 0) ? 1 : 0;
}

/* ==========================================================================
 * Section 5: Add a validated key
 * ========================================================================== */

int dnssec_chain_add_key(DnssecChainCtx *ctx,
                          const char *zone,
                          const DnskeyRdata *dk,
                          uint16_t key_tag)
{
    if (!ctx || !zone || !dk) return -1;

    /* Skip exact duplicates (same zone + key_tag + algorithm) */
    for (const ValidatedKey *vk = ctx->keys; vk; vk = vk->next) {
        if (vk->key_tag      == key_tag      &&
            vk->dk.algorithm == dk->algorithm &&
            strcasecmp(vk->zone, zone) == 0)
            return 0;
    }

    ValidatedKey *vk = calloc(1, sizeof(*vk));
    if (!vk) return -1;

    strncpy(vk->zone, zone, sizeof(vk->zone) - 1);
    vk->zone[sizeof(vk->zone) - 1] = '\0';
    vk->key_tag       = key_tag;
    vk->dk.flags      = dk->flags;
    vk->dk.protocol   = dk->protocol;
    vk->dk.algorithm  = dk->algorithm;
    vk->dk.pubkey_len = dk->pubkey_len;
    vk->dk.pubkey     = malloc(dk->pubkey_len);
    if (!vk->dk.pubkey) { free(vk); return -1; }
    memcpy(vk->dk.pubkey, dk->pubkey, dk->pubkey_len);

    /* Prepend — order within the list does not matter for lookup */
    vk->next   = ctx->keys;
    ctx->keys  = vk;
    return 0;
}

/* ==========================================================================
 * Section 6: Internal helper — try to promote a DNSKEY to validated
 *
 * Walks the pending_ds list looking for a DS record whose key_tag matches
 * the candidate DNSKEY.  On a successful digest comparison, promotes the
 * DNSKEY to ctx->keys and removes the matching PendingDS entry.
 *
 * Returns the number of DS records matched and promoted (0 = none).
 * ========================================================================== */
static int try_promote_dnskey(DnssecChainCtx *ctx,
                               const char *zone,
                               const DnskeyRdata *dk,
                               uint16_t key_tag,
                               const uint8_t *owner_wire, int owner_len)
{
    int promoted = 0;
    PendingDS *prev = NULL;
    PendingDS *pd   = ctx->pending_ds;

    while (pd) {
        PendingDS *next = pd->next;

        /* Only consider DS records for this specific zone and key_tag */
        if (pd->ds.key_tag != key_tag ||
            strcasecmp(pd->zone, zone) != 0) {
            prev = pd;
            pd   = next;
            continue;
        }

        int r = dnssec_chain_verify_ds(&pd->ds, dk, owner_wire, owner_len);
        if (r == 1) {
            fprintf(stderr,
                    "DNSSEC chain: ✓ DS verified for zone '%s' "
                    "key_tag=%u alg=%u — key added to trust chain\n",
                    zone, key_tag, dk->algorithm);
            dnssec_chain_add_key(ctx, zone, dk, key_tag);

            /* Unlink and free this PendingDS */
            if (prev) prev->next     = next;
            else      ctx->pending_ds = next;
            free_ds_rdata(&pd->ds);
            free(pd);
            promoted++;
            /* Do not update prev — it still points to the node before next */
            pd = next;
        } else {
            if (r == 0) {
                fprintf(stderr,
                        "DNSSEC chain: ✗ DS digest mismatch for zone '%s' "
                        "key_tag=%u alg=%u\n",
                        zone, key_tag, dk->algorithm);
            }
            prev = pd;
            pd   = next;
        }
    }
    return promoted;
}

/* ==========================================================================
 * Section 7: Referral processing
 * ========================================================================== */

/*
 * Internal scan loop shared by dnssec_chain_process_referral and
 * dnssec_chain_try_validate_dnskeys.
 *
 * pass == 1: collect DS  records → store as PendingDS
 * pass == 2: collect DNSKEY records → match against pending_ds
 */
static void scan_pass(DnssecChainCtx *ctx,
                       const uint8_t *buf, int buf_len,
                       int rr_start_pos, int total_rrs,
                       int pass, int referral_validated)
{
    int pos = rr_start_pos;

    for (int a = 0; a < total_rrs && pos < buf_len; a++) {
        int name_pos = pos;
        int name_end = dc_name_end(buf, buf_len, pos);
        if (name_end < 0 || name_end + 10 > buf_len) break;

        uint16_t type    = ((uint16_t)buf[name_end]     << 8) | buf[name_end + 1];
        uint16_t rdl     = ((uint16_t)buf[name_end + 8] << 8) | buf[name_end + 9];
        int      rdata_off = name_end + 10;
        if (rdata_off + rdl > buf_len) break;

        /* ---------- Pass 1: collect DS records ----------
         * Only store DS records if the referral's RRSIGs were verified
         * (referral_validated == 1).  Accepting DS records from an unsigned
         * or unverifiable referral would let an on-path attacker inject
         * fake delegation information and bypass DNSSEC for a signed zone. */
        if (pass == 1 && type == QTYPE_DS && referral_validated == 1) {
            /* The DS owner name is the child zone being delegated */
            uint8_t owner_wire[256];
            int owner_len = dc_expand_name(buf, buf_len, name_pos,
                                           owner_wire, sizeof(owner_wire));
            char zone_str[256];
            if (owner_len < 0 ||
                dc_wire_to_str(owner_wire, owner_len,
                               zone_str, sizeof(zone_str)) < 0)
                goto next;

            DsRdata ds;
            if (parse_ds_rdata(buf + rdata_off, rdl, &ds) != 0) goto next;

            /* Skip exact duplicates already in the pending list */
            int dup = 0;
            for (PendingDS *p = ctx->pending_ds; p; p = p->next) {
                if (p->ds.key_tag   == ds.key_tag   &&
                    p->ds.algorithm == ds.algorithm  &&
                    strcasecmp(p->zone, zone_str) == 0) {
                    dup = 1;
                    break;
                }
            }
            if (dup) { free_ds_rdata(&ds); goto next; }

            PendingDS *pd = calloc(1, sizeof(*pd));
            if (!pd) { free_ds_rdata(&ds); goto next; }
            snprintf(pd->zone, sizeof(pd->zone), "%s", zone_str);
            pd->ds          = ds;
            pd->next        = ctx->pending_ds;
            ctx->pending_ds = pd;

            fprintf(stderr,
                    "DNSSEC chain: stored DS for zone '%s' "
                    "key_tag=%u alg=%u digest_type=%u\n",
                    zone_str, ds.key_tag, ds.algorithm, ds.digest_type);
        }

        /* ---------- Pass 2: match DNSKEY records against pending DS ---------- */
        if (pass == 2 && type == QTYPE_DNSKEY) {
            uint8_t owner_wire[256];
            int owner_len = dc_expand_name(buf, buf_len, name_pos,
                                           owner_wire, sizeof(owner_wire));
            char zone_str[256];
            if (owner_len < 0 ||
                dc_wire_to_str(owner_wire, owner_len,
                               zone_str, sizeof(zone_str)) < 0)
                goto next;

            DnskeyRdata dk;
            if (parse_dnskey_rdata(buf + rdata_off, rdl, &dk) != 0) goto next;

            uint16_t kt = compute_key_tag(dk.flags, dk.protocol, dk.algorithm,
                                          dk.pubkey, dk.pubkey_len);
            try_promote_dnskey(ctx, zone_str, &dk, kt, owner_wire, owner_len);
            free_dnskey_rdata(&dk);
        }

next:
        pos = rdata_off + rdl;
    }
}

void dnssec_chain_process_referral(DnssecChainCtx *ctx,
                                    const struct Packet *referral,
                                    const TrustAnchor *anchors,
                                    int referral_validated)
{
    /*
     * referral_validated is used by scan_pass (pass 1) to guard DS storage.
     * anchors is reserved for future NSEC-absence verification.
     */
    (void)anchors;

    if (!ctx || !referral || !referral->request ||
        referral->recv_len < HEADER_LEN) return;

    const uint8_t *buf    = (const uint8_t *)referral->request;
    int            buf_len = (int)referral->recv_len;
    int total_rrs = referral->ancount + referral->nscount + referral->arcount;

    /* Skip the question section to find the first RR */
    int rr_start = HEADER_LEN;
    for (int q = 0; q < referral->qdcount && rr_start < buf_len; q++) {
        int e = dc_name_end(buf, buf_len, rr_start);
        if (e < 0) return;
        rr_start = e + 4;   /* skip QTYPE(2) + QCLASS(2) */
    }

    /*
     * Two-pass strategy:
     *   Pass 1: collect DS records into pending_ds (only if referral_validated).
     *   Pass 2: promote any DNSKEY in this packet against pending_ds.
     *
     * The two-pass approach ensures that a DS and its matching DNSKEY that
     * appear in the same packet (unusual but valid) are correctly correlated
     * regardless of their order in the wire format.
     *
     * Pass 2 always runs regardless of referral_validated — promoting a
     * DNSKEY against an already-stored DS is safe because the digest check
     * in dnssec_chain_verify_ds() provides the integrity verification.
     */
    scan_pass(ctx, buf, buf_len, rr_start, total_rrs, 1, referral_validated);
    scan_pass(ctx, buf, buf_len, rr_start, total_rrs, 2, referral_validated);
}

void dnssec_chain_try_validate_dnskeys(DnssecChainCtx *ctx,
                                        const struct Packet *dnskey_response,
                                        const char *zone)
{
    if (!ctx || !dnskey_response || !zone ||
        !dnskey_response->request ||
        dnskey_response->recv_len < HEADER_LEN) return;

    /* Short-circuit: if no DS is pending for this zone there is nothing to do */
    int has_pending = 0;
    for (PendingDS *pd = ctx->pending_ds; pd; pd = pd->next) {
        if (strcasecmp(pd->zone, zone) == 0) { has_pending = 1; break; }
    }
    if (!has_pending) return;

    /*
     * Re-use process_referral for the DNSKEY scanning and promotion.
     * Pass referral_validated=0 — the DS-collection pass is skipped (no DS
     * in a DNSKEY response anyway), and DNSKEY promotion is safe regardless
     * because the DS digest provides the integrity guarantee.
     */
    dnssec_chain_process_referral(ctx, dnskey_response, NULL, 0);
}
