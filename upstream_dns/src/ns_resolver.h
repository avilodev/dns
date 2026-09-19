#ifndef NS_RESOLVER_H
#define NS_RESOLVER_H

#include "types.h"
#include "shared_types.h"

// Forward declaration only
struct NSResolutionContext;

char* resolve_ns_name(const char* ns_name, uint16_t qtype);
char* resolve_ns_name_internal(const char* ns_name, uint16_t qtype, 
                               struct NSResolutionContext* context);

#endif // NS_RESOLVER_H