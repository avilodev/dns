#ifndef DNSSEC_WIRE_H
#define DNSSEC_WIRE_H

#include <stdint.h>

#include "types.h"
#include "dnssec_types.h"

/* DNSSEC wire formats and canonical forms (RFC 4034 §6). */

/* Name at buf[pos] expanded to uncompressed, lowercased wire.  Returns its
 * length or -1. */
int expand_name_lc(const uint8_t *buf, int buf_len, int pos, uint8_t *dst, int dst_size);

/* Text name to uncompressed, lowercased wire.  Returns its length or -1. */
int encode_name_lc(const char *name, uint8_t *dst, int dst_size);

/* RDATA parsers: 0 on success (free with free_*_rdata), -1 if malformed.
 * The RRSIG parser takes the whole message (its signer name may be compressed). */
int parse_dnskey_rdata(const uint8_t *rdata, int rdlength, DnskeyRdata *out);
int parse_ds_rdata(const uint8_t *rdata, int rdlength, DsRdata *out);
int parse_rrsig_rdata(const uint8_t *msg, int msg_len, int rdata_off, int rdlength,
                      RrsigRdata *out);

/* Key tag of a DNSKEY (RFC 4034 Appendix B). */
uint16_t compute_key_tag(uint16_t flags, uint8_t protocol, uint8_t algorithm,
                         const uint8_t *pubkey, uint16_t pubkey_len);

/* The data an RRSIG signs: its RDATA minus the signature, then the covered
 * RRset in canonical form and order.  malloc'd into *out_data. */
int build_signed_data(const struct Packet *response, const RrsigRdata *rrsig,
                      int rrsig_owner_pos, uint8_t **out_data, int *out_len);

#endif /* DNSSEC_WIRE_H */
