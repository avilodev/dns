#ifndef AUTH_ANSWER_H
#define AUTH_ANSWER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "types.h"     // struct Packet
#include "dnssec.h"    // ZoneKey

// One resource record's canonical RDATA, used to order and sign an RRset.
typedef struct { unsigned char data[1024]; uint16_t len; } rr_blob;

// Response construction and DNSSEC signing helpers for the record builders

// Zone-key selection (longest-suffix ZSK; exact-apex KSK).
const zone_key *find_zsk_for_owner(const char *owner);
const zone_key *find_ksk_for_zone(const char *zone);

struct packet *begin_response(const struct packet *req,
							  int *pos_out, uint16_t ancount);

void wire_name_lc(unsigned char *p, int max);

void canon_rr_append(unsigned char *out, size_t *out_pos, size_t out_cap,
					 const char *owner_name, uint16_t type, uint32_t ttl,
					 const unsigned char *rdata, size_t rdlen);

int append_rrsig(char *buf, int *pos,
				 const char *owner_name,
				 uint16_t type_covered, uint32_t ttl,
				 const unsigned char *canon_rrset, size_t canon_rrset_len,
				 const zone_key *zsk,
				 bool is_wildcard,
				 const char *explicit_rr_owner);

int emit_signed_rrset(struct packet *r, int *pos, const char *owner,
					  uint16_t type, uint32_t ttl,
					  rr_blob *blobs, int n,
					  bool do_bit, const zone_key *key);

#endif /* AUTH_ANSWER_H */
