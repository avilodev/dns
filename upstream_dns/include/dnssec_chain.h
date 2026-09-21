#ifndef DNSSEC_CHAIN_H
#define DNSSEC_CHAIN_H

/*
 * Chain of trust for one resolution (RFC 4035 §5).  Walking root -> TLD ->
 * zone, each signed referral carries DS records for the child; once the
 * child's DNSKEY matches a DS digest it becomes a trusted key, and the keys
 * it signs (the ZSKs) are trusted in turn.  Final answers are then verified
 * against keys collected here.
 */

#include "dns_name.h"
#include "dnssec_types.h"
#include "types.h"

/* A DNSKEY trusted through the chain. */
typedef struct ValidatedKey {
    char         zone[DNAME_TEXT_MAX];
    DnskeyRdata  dk;
    uint16_t     key_tag;
    struct ValidatedKey *next;
} ValidatedKey;

/* A verified DS waiting for its child DNSKEY. */
typedef struct PendingDS {
    char      zone[DNAME_TEXT_MAX];
    DsRdata   ds;
    struct PendingDS *next;
} PendingDS;

typedef struct {
    ValidatedKey *keys;
    PendingDS    *pending_ds;
    bool          bogus;       /* a DS matched no DNSKEY: SERVFAIL (RFC 4035 §5.5) */
} DnssecChainCtx;

void dnssec_chain_init(DnssecChainCtx *ctx);
void dnssec_chain_free(DnssecChainCtx *ctx);

/* Deep copy of the chain key (zone, key_tag, algorithm) into *dk_out.
 * Returns 1 if found. */
int dnssec_chain_find_key(const DnssecChainCtx *ctx, const char *zone,
                          uint16_t key_tag, uint8_t algorithm, DnskeyRdata *dk_out);

/* Store the referral's DS records — only when referral_validated == 1, so
 * an on-path attacker cannot inject DS — then promote any DNSKEY in it. */
void dnssec_chain_process_referral(DnssecChainCtx *ctx, const struct Packet *referral,
                                   int referral_validated);

bool dnssec_chain_has_pending_ds(const DnssecChainCtx *ctx, const char *zone);

/* Promote DNSKEYs from a DNSKEY response that match a pending DS for zone. */
void dnssec_chain_try_validate_dnskeys(DnssecChainCtx *ctx, const struct Packet *dnskey_response,
                                       const char *zone);

/* Trust every DNSKEY in the response for `zone`.  No verification here: the
 * caller must already have verified the RRset's RRSIG.  Returns keys added. */
int dnssec_chain_add_response_keys(DnssecChainCtx *ctx, const struct Packet *response,
                                   const char *zone);

/* 1 if zone has a DS with a supported digest but no trusted key (signed but
 * broken), 0 if secure or insecure. */
int dnssec_chain_zone_bogus(const DnssecChainCtx *ctx, const char *zone);

#endif /* DNSSEC_CHAIN_H */
