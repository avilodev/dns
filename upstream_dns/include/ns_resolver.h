#ifndef NS_RESOLVER_H
#define NS_RESOLVER_H

#include "types.h"

#define MAX_NS_RESOLUTION_DEPTH 5
#define MAX_NS_NAMES_TRACKED    20

// NS names being resolved on the current path (glueless-delegation loops).
typedef struct ns_resolution_context {
	char* ns_names[MAX_NS_NAMES_TRACKED];
	int count;
	int depth;
} ns_resolution_context;

bool already_resolving_ns(const ns_resolution_context* ctx, const char* ns_name);

// Address of a nameserver by name, malloc'd
char* resolve_ns_addr(const char* ns_name, ns_resolution_context* ctx);

#endif /* NS_RESOLVER_H */
