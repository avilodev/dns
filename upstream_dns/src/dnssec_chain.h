#ifndef DNSSEC_CHAIN_H
#define DNSSEC_CHAIN_H

/*
 * DNSSEC chain-of-trust context for iterative resolution.
 *
 * Background
 * ----------
 * A DNSSEC-validating resolver cannot verify records in a zone (e.g. google.com)
 * using only the root trust anchor.  It must walk the full delegation chain:
 *
 *   root KSK  →  root ZSK signs DS(com)
 *   com  KSK  ← DS(com)  proved by root ZSK
 *   com  ZSK  signs DS(google.com)
 *   google.com KSK ← DS(google.com) proved by com ZSK
 *   google.com ZSK signs A/AAAA/…
 *
 * Each referral response from a parent zone carries DS records (signed by the
 * parent ZSK) that act as the "fingerprint" for the child zone's KSK.  Once a
 * DNSKEY matching those DS records is obtained from the child zone, it is
 * considered validated and can be used to verify RRSIGs in the child zone.
 *
 * This module
 * -----------
 * DnssecChainCtx is allocated on the stack for each top-level resolution
 * (send_resolver) and threaded through the entire iterative delegation walk.
 *
 *  1. At every referral step, dnssec_chain_process_referral() scans the
 *     referral packet for DS records and stores them as PendingDS entries.
 *
 *  2. When a zone's DNSKEY is encountered (in a subsequent response or in the
 *     same referral packet), dnssec_chain_try_validate_dnskeys() matches it
 *     against pending DS records via dnssec_chain_verify_ds() and, on success,
 *     promotes it to a ValidatedKey in the chain.
 *
 *  3. At the final answer, dnssec_validate_with_chain() extends the normal
 *     RRSIG-verification loop so that find_dnskey() also searches the chain
 *     context, enabling validation of RRSIGs signed by intermediate zone keys.
 *
 * RFC references
 * --------------
 *   RFC 4033 §5   — DNSSEC overview
 *   RFC 4034 §5   — DS record format and digest algorithm
 *   RFC 4035 §5   — Validating resolver algorithm
 */

#include "dnssec_types.h"
#include "config.h"    /* TrustAnchor */
#include "types.h"     /* struct Packet, QTYPE_*, HEADER_LEN */

#include <stdint.h>

/* --------------------------------------------------------------------------
 * Data structures
 * -------------------------------------------------------------------------- */

/*
 * A DNSKEY that has been validated through the trust chain — either directly
 * against the root trust anchor, or against a parent DS record whose own RRSIG
 * was verified by an already-validated key higher up the chain.
 *
 * Forms a singly-linked list headed by DnssecChainCtx.keys.
 */
typedef struct ValidatedKey {
    char             zone[256];  /* Canonical owner zone, e.g. "example.com"  */
    DnskeyRdata      dk;         /* Full DNSKEY RDATA (deep-copied)           */
    uint16_t         key_tag;    /* Pre-computed key tag (RFC 4034 Appendix B)*/
    struct ValidatedKey *next;
} ValidatedKey;

/*
 * A DS record received from a parent zone that is waiting to be matched against
 * a DNSKEY from the child zone.  Once the child DNSKEY is seen and verified,
 * the PendingDS entry is removed and a ValidatedKey is added instead.
 *
 * Forms a singly-linked list headed by DnssecChainCtx.pending_ds.
 */
typedef struct PendingDS {
    char          zone[256];  /* Child zone this DS covers, e.g. "example.com" */
    DsRdata       ds;         /* DS RDATA including the digest blob             */
    struct PendingDS *next;
} PendingDS;

/*
 * Per-resolution DNSSEC chain-of-trust context.
 *
 * Created by the public entry point (send_resolver / send_resolver_with_ns_context)
 * and threaded through every recursive call to send_resolver_internal so that
 * validated keys and pending DS records accumulate across delegation hops.
 */
typedef struct {
    ValidatedKey *keys;        /* Validated DNSKEYs accumulated this resolution */
    PendingDS    *pending_ds;  /* DS records awaiting a matching child DNSKEY   */
} DnssecChainCtx;

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

/* Zero-initialise a context before the first resolution step. */
void dnssec_chain_init(DnssecChainCtx *ctx);

/* Release all memory owned by the context. */
void dnssec_chain_free(DnssecChainCtx *ctx);

/* --------------------------------------------------------------------------
 * Key lookup
 * -------------------------------------------------------------------------- */

/*
 * Search the validated-key chain for a DNSKEY matching (zone, key_tag, alg).
 *
 * On success, deep-copies the DNSKEY into *dk_out (caller must call
 * free_dnskey_rdata on it) and returns 1.  Returns 0 if not found.
 */
int dnssec_chain_find_key(const DnssecChainCtx *ctx,
                          const char *zone,
                          uint16_t key_tag, uint8_t algorithm,
                          DnskeyRdata *dk_out);

/* --------------------------------------------------------------------------
 * DS digest verification
 * -------------------------------------------------------------------------- */

/*
 * Verify that a DNSKEY matches a DS record.
 *
 * Per RFC 4034 §5.1.4 the DS digest covers:
 *   owner_wire_lc || DNSKEY_flags(2) || DNSKEY_protocol(1) ||
 *   DNSKEY_algorithm(1) || DNSKEY_public_key
 *
 * owner_wire: canonical (lower-case, uncompressed) wire-format owner name.
 * owner_len:  length of owner_wire in bytes.
 *
 * Supported digest types (RFC 4034 §5.1, RFC 6605 §2):
 *   1 = SHA-1     (deprecated but still encountered)
 *   2 = SHA-256   (mandatory to implement, RFC 4509)
 *   4 = SHA-384   (ECDSA/P-384 deployments, RFC 6605)
 *
 * Returns  1 on digest match,
 *          0 on mismatch,
 *         -1 on unsupported digest type or internal error.
 */
int dnssec_chain_verify_ds(const DsRdata *ds,
                           const DnskeyRdata *dk,
                           const uint8_t *owner_wire, int owner_len);

/*
 * Add a validated DNSKEY to the chain context.
 *
 * Duplicates (same zone + key_tag + algorithm) are silently ignored.
 * Returns 0 on success, -1 on allocation failure.
 */
int dnssec_chain_add_key(DnssecChainCtx *ctx,
                         const char *zone,
                         const DnskeyRdata *dk,
                         uint16_t key_tag);

/* --------------------------------------------------------------------------
 * Referral processing
 * -------------------------------------------------------------------------- */

/*
 * Scan a DNS response (typically a referral) for DS and DNSKEY records.
 *
 * referral_validated: return value of dnssec_validate_with_chain() called on
 *   the same packet by the caller BEFORE invoking this function.
 *
 *   Pass  1: the referral's RRSIGs were cryptographically verified — DS
 *            records are trusted and stored as PendingDS entries.
 *   Pass  0 or -1: unsigned or unverifiable referral — DS records are NOT
 *            stored (accepting unverified DS would break the chain-of-trust
 *            guarantee: an on-path attacker could inject fake DS records to
 *            bypass validation of a signed child zone).
 *
 * The DNSKEY promotion pass (pass 2) always runs regardless of
 * referral_validated, since promoting a DNSKEY against a stored PendingDS
 * is safe — the DS digest already acts as the integrity check.
 *
 * anchors: reserved for future use (e.g. verifying NSEC-covered DS absence).
 *
 * Best-effort: any parse error in a single record is skipped silently so
 * resolution can continue with the records that did parse correctly.
 */
void dnssec_chain_process_referral(DnssecChainCtx *ctx,
                                   const struct Packet *referral,
                                   const TrustAnchor *anchors,
                                   int referral_validated);

/*
 * Try to validate DNSKEYs in a response packet against pending DS records
 * for the given zone.  Called when the resolver receives the delegated zone's
 * DNSKEY response (either in-band with the answer or after an explicit query).
 *
 * Validated keys are moved from pending_ds → keys.
 */
void dnssec_chain_try_validate_dnskeys(DnssecChainCtx *ctx,
                                       const struct Packet *dnskey_response,
                                       const char *zone);

#endif /* DNSSEC_CHAIN_H */
