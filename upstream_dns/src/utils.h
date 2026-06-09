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

/*
 * Bailiwick test (cache-poisoning defence, RFC 2181 §5.4.1).
 * Return true when `name` is at or below `zone` in the DNS hierarchy
 * (name == zone, or name is a subdomain of zone), compared label-by-label
 * and case-insensitively.  The root zone ("" or ".") contains every name.
 */
bool name_in_bailiwick(const char* name, const char* zone);

#endif /* UTILS_H */