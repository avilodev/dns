#ifndef DNSSEC_TYPES_H
#define DNSSEC_TYPES_H

/* Parsed DNSSEC RDATA (RFC 4034).  Pointer fields are malloc'd by
 * parse_*_rdata(); release with the matching free_*_rdata(). */

#include "dns_name.h"   /* DNAME_TEXT_MAX */
#include <stdint.h>
#include <stdlib.h>   /* free() used in inline free_*_rdata helpers below */

/* DNSKEY RDATA (RFC 4034 §2.1) */
typedef struct {
    uint16_t flags;       /* Zone Key (bit 8) + SEP (bit 15) */
    uint8_t  protocol;    /* must be 3 */
    uint8_t  algorithm;   /* 8=RSASHA256, 13=ECDSAP256, 15=Ed25519, … */
    uint8_t* pubkey;      /* DER-encoded public key — malloc'd */
    uint16_t pubkey_len;
} DnskeyRdata;

/* RRSIG RDATA (RFC 4034 §3.1) */
typedef struct {
    uint16_t type_covered;
    uint8_t  algorithm;
    uint8_t  labels;
    uint32_t orig_ttl;
    uint32_t sig_expiration;  /* Unix timestamp */
    uint32_t sig_inception;   /* Unix timestamp */
    uint16_t key_tag;
    char     signer_name[DNAME_TEXT_MAX]; /* wire-decoded owner name of signing zone */
    uint8_t* signature;        /* DER signature blob — malloc'd */
    uint16_t sig_len;
} RrsigRdata;

/* DS RDATA (RFC 4034 §5.1) */
typedef struct {
    uint16_t key_tag;
    uint8_t  algorithm;
    uint8_t  digest_type; /* 1=SHA-1, 2=SHA-256, 4=SHA-384 */
    uint8_t* digest;      /* malloc'd */
    uint16_t digest_len;
} DsRdata;

/* Free helpers */
static inline void free_dnskey_rdata(DnskeyRdata* r)
    { if (r) { free(r->pubkey); } }
static inline void free_rrsig_rdata(RrsigRdata* r)
    { if (r) { free(r->signature); } }
static inline void free_ds_rdata(DsRdata* r)
    { if (r) { free(r->digest); } }

#endif /* DNSSEC_TYPES_H */
