#ifndef RESPONSE_HANDLER_H
#define RESPONSE_HANDLER_H

#include "types.h"
#include "dns_wire.h"

// Readers and rewriters for responses received from authoritative servers.

typedef struct {
	char* ns_name;
	char* ns_ip;          // glue address, or NULL
} ns_candidate;

typedef struct {
	ns_candidate* candidates;
	int count;
	int capacity;
	int glueless_left;    // NS-name lookups still allowed for this referral
} ns_candidate_list;

// NXNSAttack caps: NS names taken per referral
#define MAX_REFERRAL_NS      13
#define MAX_GLUELESS_LOOKUPS 4

// True when the answer is a CNAME with no `qtype` record in `server_zone`
bool cname_answer_needs_rechase(struct packet* response, uint16_t qtype,
								const char* server_zone);

// True if some answer RR is owned by the question name.
bool answer_owned_by_question(struct packet* response);

// Target of the CNAME owned by the question name (malloc'd), or NULL.
char* extract_cname_target(struct packet* response);

// First A/AAAA (per qtype) in the answer section as text (malloc'd).
char* extract_ip_from_answer(struct packet* response, uint16_t qtype);

// NS names from a referral's authority section
ns_candidate_list* extract_all_ns_with_glue(struct packet* response,
										  const char* server_zone);
void free_ns_candidate_list(ns_candidate_list* list);

// True when the authority section holds an SOA
bool authority_has_soa(struct packet* response);

// Owner of the first NS in the authority section (malloc'd), or NULL.
char* extract_zone_apex(struct packet* response);

// ". NS" answered from the root hints
struct packet* build_root_hints_response(struct packet* query);

// Append TYPE/CLASS/TTL/RDLEN/RDATA of `rr` to out[*op]
bool emit_rr_body(const uint8_t* m, int len, const dns_rr* rr,
				  uint8_t* out, int out_cap, int* op);

// For a client without DO: drop RRSIG/NSEC/NSEC3/NSEC3PARAM, clear AD
void strip_dnssec_for_non_do(char** bufp, ssize_t* lenp, uint16_t qtype);

// Drop the far end's OPT — it is hop-by-hop (RFC 6891 §6.1.1).
void strip_opt_rr(char** bufp, ssize_t* lenp);

#endif /* RESPONSE_HANDLER_H */
