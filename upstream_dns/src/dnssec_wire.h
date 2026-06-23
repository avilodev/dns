#ifndef DNSSEC_WIRE_H
#define DNSSEC_WIRE_H

#include <stdint.h>

#include "types.h"          /* struct Packet */
#include "dnssec_types.h"   /* RrsigRdata */

/* DNSSEC canonical wire-format helpers (RFC 4034 §6): DNS name end-position,
 * case-lowered name expansion/encoding, and construction of the canonical
 * "signed data" blob that an RRSIG covers. */

int name_end_pos(const uint8_t *buf, int buf_len, int pos);

int expand_name_lc(const uint8_t *buf, int buf_len, int pos,
                   uint8_t *dst, int dst_size);

int encode_name_lc(const char *name, uint8_t *dst, int dst_size);

int build_signed_data(const struct Packet *response,
                      const RrsigRdata *rrsig,
                      int rrsig_owner_pos,
                      uint8_t **out_data, int *out_len);

#endif /* DNSSEC_WIRE_H */
