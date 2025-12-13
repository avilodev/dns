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

NSCandidateList* extract_all_ns_with_glue(struct Packet* response);
void free_ns_candidate_list(NSCandidateList* list);
bool test_nameserver_reachable(const char* ns_ip, struct Packet* query);

struct Packet* build_root_hints_response(struct Packet* query);

#endif /* RESPONSE_HANDLER_H */