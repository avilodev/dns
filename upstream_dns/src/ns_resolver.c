#include "ns_resolver.h"


/**
 * Resolve a nameserver name to an IP address
 * Creates a new query and recursively resolves it
 */
char* resolve_ns_name(const char* ns_name, uint16_t qtype)
{
    if (!ns_name) return NULL;
    
    printf("    [NS Resolution] Resolving %s for %s record\n", 
           ns_name, qtype_to_string(qtype));
    
    // Create temporary packet for NS resolution
    struct Packet temp_query = {0};
    temp_query.full_domain = strdup(ns_name);
    temp_query.q_type = qtype;
    temp_query.q_class = 1; // IN
    
    temp_query.request = malloc(512);
    if (!temp_query.request) {
        free(temp_query.full_domain);
        return NULL;
    }
    temp_query.recv_len = 512;
    
    // Format and construct the query
    struct Packet* formatted = format_resolver(&temp_query);
    free(temp_query.request);
    free(temp_query.full_domain);
    
    if (!formatted) {
        return NULL;
    }
    
    // Recursively resolve the NS name
    struct Packet* ns_response = send_resolver(formatted);
    free_packet(formatted);
    
    if (!ns_response || ns_response->ancount == 0) {
        if (ns_response) free_packet(ns_response);
        return NULL;
    }
    
    // Extract IP from answer section
    char* ip = extract_ip_from_answer(ns_response, qtype);
    free_packet(ns_response);
    
    if (ip) {
        printf("    [NS Resolution] ✓ Resolved %s -> %s\n", ns_name, ip);
    }
    
    return ip;
}


/**
 * Extract TLD from domain name
 */
char* get_tld_from_domain(const char* domain)
{
    if (!domain) return NULL;
    
    const char* last_dot = strrchr(domain, '.');
    if (!last_dot || last_dot == domain) return NULL;
    
    return strdup(last_dot + 1);
}