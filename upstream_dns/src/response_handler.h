#ifndef RESPONSE_HANDLER_H
#define RESPONSE_HANDLER_H

#include "types.h"
#include "shared_types.h"


#include "utils.h"
#include "dns_wire.h"
#include "dns_packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

typedef struct {
    char* ns_name;
    char* ns_ip;
} NSCandidate;

typedef struct {
    NSCandidate* candidates;
    int count;
    int capacity;
} NSCandidateList;

bool is_cname_only_answer(struct Packet* response, uint16_t original_qtype);
char* extract_cname_target(struct Packet* response);
char* extract_ip_from_answer(struct Packet* response, uint16_t qtype);
char* extract_ns_server_ip(struct Packet* response, const char* ns_name);
char* extract_ns_name(struct Packet* response);

/* Collect all NS candidates from a referral's authority section.  Glue A
   records are only attached when their owner is within the bailiwick of
   `server_zone` — the zone the answering server is authoritative for (i.e. the
   current zone being descended, NOT the delegated child).  Out-of-bailiwick
   glue is dropped to prevent cache poisoning (4.1); legitimate cross-zone glue
   such as a TLD's *.gtld-servers.net is in-bailiwick of the parent (root) and
   is kept.  Pass the current zone (empty string for the root). */
NSCandidateList* extract_all_ns_with_glue(struct Packet* response,
                                          const char* server_zone);
void free_ns_candidate_list(NSCandidateList* list);

/* Return the zone apex (owner name of the first NS record in the authority
   section of a referral response).  Caller must free the returned string. */
char* extract_zone_apex(struct Packet* response);

struct Packet* build_root_hints_response(struct Packet* query);

#endif /* RESPONSE_HANDLER_H */