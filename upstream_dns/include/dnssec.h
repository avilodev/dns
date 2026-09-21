#ifndef DNSSEC_H
#define DNSSEC_H

/*
 * DNSSEC validation (OpenSSL EVP).  Algorithms: RSASHA1 (5, 7), RSASHA256 (8),
 * RSASHA512 (10), ECDSAP256SHA256 (13), ECDSAP384SHA384 (14), Ed25519 (15).
 */

#include "types.h"
#include "config.h"
#include "dnssec_chain.h"

/*
 * Validate a response's RRSIGs with keys from the response, the trust
 * anchors, and `chain` (may be NULL).  Returns
 *    1  every checkable RRSIG verified and the answer (or denial) is covered
 *    0  a signature or NSEC proof is bad — SERVFAIL
 *   -1  unsigned, or nothing could be checked — pass through without AD
 */
int dnssec_validate_with_chain(struct Packet* response, const TrustAnchor* anchors,
                               const DnssecChainCtx* chain);

/* 1 if the root DNSKEY RRset is signed by a trust anchor (bootstrap). */
int dnssec_validate_root_dnskey(struct Packet* response, const TrustAnchor* anchors);

/* 1 if zone's DNSKEY RRset is signed by a key already in the chain. */
int dnssec_validate_dnskey_with_chain(struct Packet* response, const char* zone,
                                      const DnssecChainCtx* chain);

#endif /* DNSSEC_H */
