#ifndef AUTH_CHASE_H
#define AUTH_CHASE_H

#include <stdbool.h>
#include <stdint.h>

#include "types.h"   // struct Packet
#include "dns_name.h"   // DNAME_TEXT_MAX

// CNAME chasing for answers served to clients (RFC 1034 §3.6.2, §4.3.2).

// If `resp` answers `qtype` with nothing but a CNAME chain
bool cname_needs_chase(const struct packet* resp, uint16_t qtype,
					   char target[DNAME_TEXT_MAX]);

// Build a standalone query for `name` that mirrors `orig`
struct packet* make_chase_query(const struct packet* orig, const char* name);

// Append the answer section of `sub` to `resp`.
int merge_chased_answer(struct packet* resp, const struct packet* sub);

#endif /* AUTH_CHASE_H */
