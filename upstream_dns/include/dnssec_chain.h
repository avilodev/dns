#ifndef DNSSEC_CHAIN_H
#define DNSSEC_CHAIN_H

// Chain of trust for one resolution (RFC 4035 §5).

#include "dns_name.h"
#include "dnssec_types.h"
#include "types.h"

// A DNSKEY trusted through the chain.
typedef struct validated_key {
	char         zone[DNAME_TEXT_MAX];
	dnskey_rdata  dk;
	uint16_t     key_tag;
	struct validated_key *next;
} validated_key;

// A verified DS waiting for its child DNSKEY.
typedef struct pending_ds_node {
	char      zone[DNAME_TEXT_MAX];
	ds_rdata   ds;
	struct pending_ds_node *next;
} pending_ds_node;

typedef struct {
	validated_key *keys;
	pending_ds_node    *pending_ds;
	bool          bogus;       // a DS matched no DNSKEY: SERVFAIL (RFC 4035 §5.5)
} dnssec_chain_ctx;

void dnssec_chain_init(dnssec_chain_ctx *ctx);
void dnssec_chain_free(dnssec_chain_ctx *ctx);

// Deep copy of the chain key (zone, key_tag, algorithm) into *dk_out.
int dnssec_chain_find_key(const dnssec_chain_ctx *ctx, const char *zone,
						  uint16_t key_tag, uint8_t algorithm, dnskey_rdata *dk_out);

// Store the referral's DS records — only when referral_validated == 1
void dnssec_chain_process_referral(dnssec_chain_ctx *ctx, const struct packet *referral,
								   int referral_validated);

bool dnssec_chain_has_pending_ds(const dnssec_chain_ctx *ctx, const char *zone);

// Promote DNSKEYs from a DNSKEY response that match a pending DS for zone.
void dnssec_chain_try_validate_dnskeys(dnssec_chain_ctx *ctx, const struct packet *dnskey_response,
									   const char *zone);

// Trust every DNSKEY in the response for `zone`.
int dnssec_chain_add_response_keys(dnssec_chain_ctx *ctx, const struct packet *response,
								   const char *zone);

// 1 if zone has a DS with a supported digest but no trusted key
int dnssec_chain_zone_bogus(const dnssec_chain_ctx *ctx, const char *zone);

#endif /* DNSSEC_CHAIN_H */
