#ifndef RESPONSE_HANDLER_H
#define RESPONSE_HANDLER_H

#include "types.h"
#include "resolve.h"
#include "utils.h"

bool is_cname_only_answer(struct Packet* response, uint16_t original_qtype);
char* extract_cname_target(struct Packet* response);
char* extract_ip_from_answer(struct Packet* response, uint16_t qtype);
char* extract_ns_server_ip(struct Packet* response, const char* ns_name);
char* extract_ns_name(struct Packet* response);

#endif /* RESPONSE_HANDLER_H */