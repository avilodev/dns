#ifndef AUTH_CHASE_H
#define AUTH_CHASE_H

#include <stdbool.h>
#include <stdint.h>

#include "types.h"   /* struct Packet */
#include "dns_name.h"   /* DNAME_TEXT_MAX */

/*
 * CNAME chasing for answers served to clients (RFC 1034 §3.6.2, §4.3.2).
 *
 * auth_dns is the resolver clients point at, so an answer whose owner is an
 * alias must also carry the target's records: stub resolvers (glibc, musl,
 * Android) do not chase a bare CNAME themselves and report "no address".
 */

/* If `resp` answers `qtype` with nothing but a CNAME chain (plus RRSIGs), copy
 * the last CNAME's target into target[DNAME_TEXT_MAX] and return true. */
bool cname_needs_chase(const struct Packet* resp, uint16_t qtype,
                       char target[DNAME_TEXT_MAX]);

/* Build a standalone query for `name` that mirrors `orig` (TX ID, flags, type,
 * class, EDNS/DO), suitable for check_internal() or forwarding upstream. */
struct Packet* make_chase_query(const struct Packet* orig, const char* name);

/* Append the answer section of `sub` (and, when `sub` is a negative answer,
 * its RCODE and authority section) to `resp`.  Names are written uncompressed
 * so no pointer ever refers into `sub`'s buffer.  All-or-nothing: returns 0 on
 * success, -1 (resp untouched) if the result would not fit or `sub` is bad. */
int merge_chased_answer(struct Packet* resp, const struct Packet* sub);

#endif /* AUTH_CHASE_H */
