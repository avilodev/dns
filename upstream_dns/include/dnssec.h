#ifndef DNSSEC_H
#define DNSSEC_H

// DNSSEC validation (OpenSSL EVP).

#include "types.h"
#include "config.h"
#include "dnssec_chain.h"

// Validate a response's RRSIGs with keys from the response, the trust anchors
int dnssec_validate_with_chain(struct packet* response, const trust_anchor* anchors,
							   const dnssec_chain_ctx* chain);

// 1 if the root DNSKEY RRset is signed by a trust anchor (bootstrap).
int dnssec_validate_root_dnskey(struct packet* response, const trust_anchor* anchors);

// 1 if zone's DNSKEY RRset is signed by a key already in the chain.
int dnssec_validate_dnskey_with_chain(struct packet* response, const char* zone,
									  const dnssec_chain_ctx* chain);

#endif /* DNSSEC_H */
