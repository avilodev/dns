#ifndef AUTH_H
#define AUTH_H

#include "types.h"
#include "utils.h"
#include "response.h"

struct AuthDomain {
    char domain[256];
    char ip[16];
    bool is_blocked;  // true if this should return NXDOMAIN
};

struct Packet* check_internal(struct Packet* request);

int load_auth_domains(const char* filename);
const char* lookup_auth_domain(const char* full_domain);

#endif /* AUTH_H */