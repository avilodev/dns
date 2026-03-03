#ifndef DNSSEC_H
#define DNSSEC_H

/*
 * DNSSEC validation skeleton for upstream_dns.
 *
 * Implementation is stubbed — functions return -1 (not yet implemented).
 * Full implementation requires:
 *   1. Walking the chain of trust from root anchors down to the queried zone.
 *   2. Verifying RRSIG records against the matching DNSKEY (via OpenSSL EVP).
 *   3. Validating DS records link parent zone DNSKEY to child zone DNSKEY.
 *   4. Returning SERVFAIL to client when validation fails (RFC 4035 §5.5).
 *
 * Algorithms to support (per plan):
 *   8  = RSASHA256   (RFC 5702)
 *   10 = RSASHA512   (RFC 5702)
 *   13 = ECDSAP256SHA256 (RFC 6605)
 *   14 = ECDSAP384SHA384 (RFC 6605)
 *   15 = Ed25519     (RFC 8080)
 */

#include "types.h"
#include "dnssec_types.h"
#include "config.h"   /* TrustAnchor */

/*
 * Verify a single RRSIG against a DNSKEY.
 * rrset_data / rrset_len: canonical wire-format RRset to be signed.
 * Returns  1 on successful verification,
 *          0 on signature mismatch,
 *         -1 on unsupported algorithm or internal error (stub).
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

#endif /* DNSSEC_H */
