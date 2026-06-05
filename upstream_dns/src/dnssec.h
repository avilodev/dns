#ifndef DNSSEC_H
#define DNSSEC_H

/*
 * DNSSEC response validation for upstream_dns.
 *
 * Verifies RRSIG records against DNSKEY records using OpenSSL EVP,
 * anchored at the root trust anchor loaded at startup.
 * Returns SERVFAIL to the client when validation fails (RFC 4035 §5.5).
 *
 * Supported algorithms:
 *   8  = RSASHA256        (RFC 5702)
 *   10 = RSASHA512        (RFC 5702)
 *   13 = ECDSAP256SHA256  (RFC 6605)
 *   14 = ECDSAP384SHA384  (RFC 6605)
 *   15 = Ed25519          (RFC 8080)
 */

#include "types.h"
#include "dnssec_types.h"
#include "config.h"        /* TrustAnchor */
#include "dnssec_chain.h"  /* DnssecChainCtx — no circular dependency */

/*
 * Verify a single RRSIG against a DNSKEY.
 * rrset_data / rrset_len: canonical wire-format RRset to be signed.
 * Returns  1 on successful verification,
 *          0 on signature mismatch,
 *         -1 on unsupported algorithm or internal error.
 */
int dnssec_verify_rrsig(const RrsigRdata* rrsig,
                        const DnskeyRdata* dnskey,
                        const unsigned char* rrset_data, size_t rrset_len);

/*
 * Validate the DNSSEC chain for a complete DNS response.
 * anchors: loaded root trust anchors (from load_trust_anchors()).
 * Returns  1 if chain validates successfully,
 *          0 if validation fails (caller should return SERVFAIL),
 *         -1 if response carries no DNSSEC data (DO not set or unsigned zone).
 */
int dnssec_validate_response(struct Packet* response,
                             const TrustAnchor* anchors);

/*
 * Extended variant that also consults a per-resolution chain context for
 * keys validated at intermediate delegation hops (RFC 4035 §5 chain-of-trust).
 *
 * chain: accumulated by dnssec_chain_process_referral() during the iterative
 *        resolution walk.  May be NULL (equivalent to dnssec_validate_response).
 *
 * Returns the same codes as dnssec_validate_response.
 */
int dnssec_validate_with_chain(struct Packet* response,
                               const TrustAnchor* anchors,
                               const DnssecChainCtx* chain);

/*
 * Securely validate a root-zone ('.') DNSKEY RRset for chain bootstrap.
 *
 * Unlike dnssec_validate_with_chain(), the RRSIG(DNSKEY) is verified using
 * ONLY a configured trust-anchor key — never a key taken from the response
 * itself.  This is mandatory for bootstrap: trusting a self-signed DNSKEY
 * RRset would let an on-path attacker inject a forged root ZSK.
 *
 * Returns 1 if the DNSKEY RRset is signed by a trust-anchor KSK, else 0.
 */
int dnssec_validate_root_dnskey(struct Packet* response,
                                const TrustAnchor* anchors);

/*
 * Verify a zone's DNSKEY RRset self-signature using a key already in the chain
 * (e.g. the zone KSK just validated via its DS).  On success the caller may add
 * the whole RRset — including ZSKs — to the chain.  The verifier comes only
 * from the chain, never from the response, so forged keys cannot self-validate.
 *
 * Returns 1 if the DNSKEY RRset RRSIG verifies against a chain key for `zone`.
 */
int dnssec_validate_dnskey_with_chain(struct Packet* response, const char* zone,
                                      const DnssecChainCtx* chain);

#endif /* DNSSEC_H */
