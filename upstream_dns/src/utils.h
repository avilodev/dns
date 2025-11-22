#ifndef UTILS_H
#define UTILS_H

#include "types.h"
#include "shared_types.h"
#include "dns_wire.h"

#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

int get_random_id();
int get_random_server();

const char* qtype_to_string(uint16_t qtype);

#endif /* UTILS_H */