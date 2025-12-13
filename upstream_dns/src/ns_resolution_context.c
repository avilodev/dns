#include "ns_resolution_context.h"
#include "response_handler.h"

/**
 * Initialize NS resolution context
 */
void init_ns_context(NSResolutionContext* context)
{
    if (!context) return;
    
    memset(context, 0, sizeof(NSResolutionContext));
    context->count = 0;
    context->depth = 0;
}

/**
 * Check if NS name is already being resolved
 */
bool already_resolving_ns(NSResolutionContext* context, const char* ns_name)
{
    if (!context || !ns_name) return false;
    
    for (int i = 0; i < context->count; i++) {
        if (context->ns_names[i] && strcasecmp(context->ns_names[i], ns_name) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Add NS name to resolution context
 */
bool add_ns_to_context(NSResolutionContext* context, const char* ns_name)
{
    if (!context || !ns_name) return false;
    
    if (context->count >= MAX_NS_NAMES_TRACKED) {
        return false;
    }
    
    // Check if already exists
    if (already_resolving_ns(context, ns_name)) {
        return false;
    }
    
    context->ns_names[context->count] = strdup(ns_name);
    if (!context->ns_names[context->count]) {
        return false;
    }
    
    context->count++;
    return true;
}

/**
 * Remove NS name from resolution context
 */
void remove_ns_from_context(NSResolutionContext* context, const char* ns_name)
{
    if (!context || !ns_name) return;
    
    for (int i = 0; i < context->count; i++) {
        if (context->ns_names[i] && strcasecmp(context->ns_names[i], ns_name) == 0) {
            free(context->ns_names[i]);
            
            // Shift remaining entries down
            for (int j = i; j < context->count - 1; j++) {
                context->ns_names[j] = context->ns_names[j + 1];
            }
            
            context->ns_names[context->count - 1] = NULL;
            context->count--;
            return;
        }
    }
}

/**
 * Free NS resolution context
 */
void free_ns_context(NSResolutionContext* context)
{
    if (!context) return;
    
    for (int i = 0; i < context->count; i++) {
        free(context->ns_names[i]);
        context->ns_names[i] = NULL;
    }
    context->count = 0;
    context->depth = 0;
}