#ifndef NS_RESOLVER_H
#define NS_RESOLVER_H

#include "types.h"

#define MAX_NS_RESOLUTION_DEPTH 5
#define MAX_NS_NAMES_TRACKED    20

/* NS names being resolved on the current path (glueless-delegation loops). */
typedef struct NSResolutionContext {
    char* ns_names[MAX_NS_NAMES_TRACKED];
    int count;
    int depth;
} NSResolutionContext;

bool already_resolving_ns(const NSResolutionContext* ctx, const char* ns_name);

/* Address (A, else AAAA) of a nameserver by name, malloc'd; NULL on failure.
 * ctx may be NULL for a top-level lookup. */
char* resolve_ns_addr(const char* ns_name, NSResolutionContext* ctx);

#endif /* NS_RESOLVER_H */
