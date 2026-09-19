#ifndef UTILS_H
#define UTILS_H

#include "types.h"
#include "shared_types.h"
#include "dns_wire.h"

#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>

int get_random_id(void);
int get_random_server(void);

const char* qtype_to_string(uint16_t qtype);

/*
 * Bailiwick test (cache-poisoning defence, RFC 2181 §5.4.1).
 * Return true when `name` is at or below `zone` in the DNS hierarchy
 * (name == zone, or name is a subdomain of zone), compared label-by-label
 * and case-insensitively.  The root zone ("" or ".") contains every name.
 */
bool name_in_bailiwick(const char* name, const char* zone);

/*
 * Privilege-drop-safe file access.  path_pin() opens the file's parent
 * directory while still root and keeps the fd; path_open() then reaches the
 * file with openat() relative to it, so a reopen after the drop needs only
 * permission on that directory and the file itself — not on every ancestor
 * (e.g. a 0700 /home/<user> the drop user cannot traverse).  Unpinned paths
 * fall back to plain open().
 */
void path_pin(const char* path);
int  path_open(const char* path, int flags, int mode);

#endif /* UTILS_H */