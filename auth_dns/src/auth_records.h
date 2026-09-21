#ifndef AUTH_RECORDS_H
#define AUTH_RECORDS_H

#include "types.h"   /* struct Packet */

/* Per-type authoritative response builders, dispatched by check_internal().
 * Each builds a complete response Packet for `owner` from the record store. */

struct Packet *build_a_response(struct Packet *req, const char *owner);
struct Packet *build_aaaa_response(struct Packet *req, const char *owner);
struct Packet *build_mx_response(struct Packet *req, const char *owner);
struct Packet *build_ns_response(struct Packet *req, const char *owner);
struct Packet *build_txt_response(struct Packet *req, const char *owner);
struct Packet *build_srv_response(struct Packet *req, const char *owner);
struct Packet *build_https_response(struct Packet *req, const char *owner);
struct Packet *build_cname_response(struct Packet *req, const char *owner);
struct Packet *build_soa_response(struct Packet *req, const char *owner);
struct Packet *build_dnskey_response(struct Packet *req, const char *owner);
struct Packet *build_hinfo_response(struct Packet *req);

/* Referral to the child zone at `cut` (RFC 1034 §4.3.2 step 3b): AA=0, the
 * cut's NS RRset in the authority section, in-data glue in additional. */
struct Packet *build_referral_response(struct Packet *req, const char *cut);

#endif /* AUTH_RECORDS_H */
