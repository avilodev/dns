#ifndef AUTH_ANSWER_H
#define AUTH_ANSWER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "types.h"     /* struct Packet */
#include "dnssec.h"    /* ZoneKey */

/*
 * One resource record's canonical RDATA, used to order and sign an RRset.
 * Sized for the largest RDATA we emit (DNSKEY public keys, SOA, multi-string
 * TXT).  Embedded names must already be in §6.2 canonical form (downcased)
 * where the type requires it; this struct is type-agnostic.
 */
typedef struct { unsigned char data[1024]; uint16_t len; } RrBlob;

/* Response/header construction + DNSSEC signing helpers shared by the per-type
 * record builders (auth_records.c) and the dispatcher (check_internal). */

/* Zone-key selection (longest-suffix ZSK; exact-apex KSK). */
const ZoneKey *find_zsk_for_owner(const char *owner);
const ZoneKey *find_ksk_for_zone(const char *zone);

struct Packet *begin_response(const struct Packet *req,
                              int *pos_out, uint16_t ancount);

void wire_name_lc(unsigned char *p, int max);

void canon_rr_append(unsigned char *out, size_t *out_pos, size_t out_cap,
                     const char *owner_name, uint16_t type, uint32_t ttl,
                     const unsigned char *rdata, size_t rdlen);

int append_rrsig(char *buf, int *pos,
                 const char *owner_name,
                 uint16_t type_covered, uint32_t ttl,
                 const unsigned char *canon_rrset, size_t canon_rrset_len,
                 const ZoneKey *zsk,
                 bool is_wildcard,
                 const char *explicit_rr_owner);

int emit_signed_rrset(struct Packet *r, int *pos, const char *owner,
                      uint16_t type, uint32_t ttl,
                      RrBlob *blobs, int n,
                      bool do_bit, const ZoneKey *key);

#endif /* AUTH_ANSWER_H */
