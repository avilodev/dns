#ifndef AUTH_RECORDS_H
#define AUTH_RECORDS_H

#include "types.h"   // struct Packet

// Per-type authoritative response builders, dispatched by check_internal().

struct packet *build_a_response(struct packet *req, const char *owner);
struct packet *build_aaaa_response(struct packet *req, const char *owner);
struct packet *build_mx_response(struct packet *req, const char *owner);
struct packet *build_ns_response(struct packet *req, const char *owner);
struct packet *build_txt_response(struct packet *req, const char *owner);
struct packet *build_srv_response(struct packet *req, const char *owner);
struct packet *build_https_response(struct packet *req, const char *owner);
struct packet *build_cname_response(struct packet *req, const char *owner);
struct packet *build_soa_response(struct packet *req, const char *owner);
struct packet *build_dnskey_response(struct packet *req, const char *owner);
struct packet *build_hinfo_response(struct packet *req);

// Referral to the child zone at `cut`: AA=0
struct packet *build_referral_response(struct packet *req, const char *cut);

#endif /* AUTH_RECORDS_H */
