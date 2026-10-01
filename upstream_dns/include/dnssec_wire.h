#ifndef DNSSEC_WIRE_H
#define DNSSEC_WIRE_H

#include <stdint.h>

#include "types.h"
#include "dnssec_types.h"

// DNSSEC wire formats and canonical forms (RFC 4034 §6).

// Name at buf[pos] expanded to uncompressed, lowercased wire.
int expand_name_lc(const uint8_t *buf, int buf_len, int pos, uint8_t *dst, int dst_size);

// Text name to uncompressed, lowercased wire.
int encode_name_lc(const char *name, uint8_t *dst, int dst_size);

// RDATA parsers: 0 on success (free with free_*_rdata), -1 if malformed.
int parse_dnskey_rdata(const uint8_t *rdata, int rdlength, dnskey_rdata *out);
int parse_ds_rdata(const uint8_t *rdata, int rdlength, ds_rdata *out);
int parse_rrsig_rdata(const uint8_t *msg, int msg_len, int rdata_off, int rdlength,
					  rrsig_rdata *out);

// Key tag of a DNSKEY (RFC 4034 Appendix B).
uint16_t compute_key_tag(uint16_t flags, uint8_t protocol, uint8_t algorithm,
						 const uint8_t *pubkey, uint16_t pubkey_len);

// The data an RRSIG signs: its RDATA minus the signature
int build_signed_data(const struct packet *response, const rrsig_rdata *rrsig,
					  int rrsig_owner_pos, uint8_t **out_data, int *out_len);

#endif /* DNSSEC_WIRE_H */
