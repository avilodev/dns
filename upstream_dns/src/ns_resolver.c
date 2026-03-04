#include "ns_resolver.h"
#include "ns_resolution_context.h"
#include "resolve.h"        
 

/*
 * Resolve a nameserver name to an IP address
 */
char* resolve_ns_name(const char* ns_name, uint16_t qtype)
{
    if (!ns_name) return NULL;
    
    NSResolutionContext context;
    init_ns_context(&context);
    
    char* result = resolve_ns_name_internal(ns_name, qtype, &context);
    
    free_ns_context(&context);
    return result;
}

/*
 * Internal NS resolution with depth and loop tracking
 */
char* resolve_ns_name_internal(const char* ns_name, uint16_t qtype, 
                               NSResolutionContext* context)
{
    if (!ns_name || !context) return NULL;
    
    // Check depth limit
    if (context->depth >= MAX_NS_RESOLUTION_DEPTH) {
        return NULL;
    }

    // Check for resolution loop
    if (already_resolving_ns(context, ns_name)) {
        return NULL;
    }

    // Add to context
    if (!add_ns_to_context(context, ns_name)) {
        return NULL;
    }
    
    // Increment depth
    context->depth++;
    
    // Create temporary packet for NS resolution
    struct Packet temp_query = {0};
    temp_query.full_domain = strdup(ns_name);
    temp_query.q_type = qtype;
    temp_query.q_class = 1; // IN
    
    temp_query.request = malloc(512);
    if (!temp_query.request) {
        free(temp_query.full_domain);
        context->depth--;
        remove_ns_from_context(context, ns_name);
        return NULL;
    }
    temp_query.recv_len = 512;
    
    // Format and construct the query
    struct Packet* formatted = format_resolver(&temp_query);
    free(temp_query.request);
    free(temp_query.full_domain);
    
    if (!formatted) {
        context->depth--;
        remove_ns_from_context(context, ns_name);
        return NULL;
    }
    
    // Recursively resolve the NS name with context
    struct Packet* ns_response = send_resolver_with_ns_context(formatted, context);
    free_packet(formatted);
    
    // Decrement depth and remove from context
    context->depth--;
    remove_ns_from_context(context, ns_name);
    
    if (!ns_response || ns_response->ancount == 0) {
        if (ns_response) free_packet(ns_response);
        return NULL;
    }
    
    // Extract IP from answer section
    char* ip = extract_ip_from_answer(ns_response, qtype);
    free_packet(ns_response);
    return ip;
}

/*
 * Extract TLD from domain name
 */
char* get_tld_from_domain(const char* domain)
{
    if (!domain) return NULL;
    
    const char* last_dot = strrchr(domain, '.');
    if (!last_dot || last_dot == domain) return NULL;
    
    // Return everything after the last dot
    return strdup(last_dot + 1);
}