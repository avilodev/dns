#ifndef RESPONSE_HANDLER_H
#define RESPONSE_HANDLER_H

#include "types.h"
#include "dns_wire.h"

/* Readers and rewriters for responses received from authoritative servers. */

typedef struct {
    char* ns_name;
    char* ns_ip;          /* glue address, or NULL */
} NSCandidate;

typedef struct {
    NSCandidate* candidates;
    int count;
    int capacity;
    int glueless_left;    /* NS-name lookups still allowed for this referral */
} NSCandidateList;

/* NXNSAttack caps (CVE-2020-12662): NS names taken per referral, and how
 * many glueless ones may be resolved. */
#define MAX_REFERRAL_NS      13
#define MAX_GLUELESS_LOOKUPS 4

/* True when the answer is a CNAME with no record of `qtype` owned inside
 * `server_zone`: bare CNAMEs, and CNAMEs with out-of-bailiwick address
 * records stapled on (RFC 2181 §5.4.1), must be re-chased. */
bool cname_answer_needs_rechase(struct Packet* response, uint16_t qtype,
                                const char* server_zone);

/* True if some answer RR is owned by the question name. */
bool answer_owned_by_question(struct Packet* response);

/* Target of the CNAME owned by the question name (malloc'd), or NULL. */
char* extract_cname_target(struct Packet* response);

/* First A/AAAA (per qtype) in the answer section as text (malloc'd). */
char* extract_ip_from_answer(struct Packet* response, uint16_t qtype);

/* NS names from a referral's authority section, each with glue from the
 * additional section when the glue owner is inside `server_zone` (the zone
 * the answering server serves — out-of-bailiwick glue is dropped). */
NSCandidateList* extract_all_ns_with_glue(struct Packet* response,
                                          const char* server_zone);
void free_ns_candidate_list(NSCandidateList* list);

/* Owner of the first NS in the authority section (malloc'd), or NULL. */
char* extract_zone_apex(struct Packet* response);

/* ". NS" answered from the root hints. */
struct Packet* build_root_hints_response(struct Packet* query);

/* Append TYPE/CLASS/TTL/RDLEN/RDATA of `rr` to out[*op], decompressing
 * names inside NS/CNAME/PTR/MX/SOA RDATA.  False on malformed/overflow. */
bool emit_rr_body(const uint8_t* m, int len, const DnsRR* rr,
                  uint8_t* out, int out_cap, int* op);

/* For a client without DO: drop RRSIG/NSEC/NSEC3/NSEC3PARAM (unless asked
 * for), clear AD and the OPT DO bit (RFC 4035 §3.2.1, RFC 6840 §5.7). */
void strip_dnssec_for_non_do(char** bufp, ssize_t* lenp, uint16_t qtype);

/* Drop the far end's OPT — it is hop-by-hop (RFC 6891 §6.1.1). */
void strip_opt_rr(char** bufp, ssize_t* lenp);

#endif /* RESPONSE_HANDLER_H */
