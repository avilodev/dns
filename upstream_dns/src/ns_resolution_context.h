#ifndef NS_RESOLUTION_CONTEXT_H
#define NS_RESOLUTION_CONTEXT_H

#include "response_handler.h"
#include "cname_handler.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NS_RESOLUTION_DEPTH 5
#define MAX_NS_NAMES_TRACKED 20


// Context for tracking NS resolution to prevent loops
 
typedef struct NSResolutionContext {
    char* ns_names[MAX_NS_NAMES_TRACKED];
    int count;
    int depth;
} NSResolutionContext;

void init_ns_context(NSResolutionContext* context);
bool already_resolving_ns(NSResolutionContext* context, const char* ns_name);
bool add_ns_to_context(NSResolutionContext* context, const char* ns_name);
void remove_ns_from_context(NSResolutionContext* context, const char* ns_name);
void free_ns_context(NSResolutionContext* context);

#endif // NS_RESOLUTION_CONTEXT_H