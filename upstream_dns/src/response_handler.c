#include "response_handler.h"


/**
 * Check if response contains only CNAME (no final answer)
 */
bool is_cname_only_answer(struct Packet* response, uint16_t original_qtype)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return false;
    }
    
    if (response->ancount == 0) {
        return false;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;
    
    bool has_cname = false;
    bool has_final = false;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4; // QTYPE + QCLASS
    }

    // Check answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        if (type == QTYPE_CNAME) {
            has_cname = true;
        } else if (type == original_qtype) {
            has_final = true;
        }
        
        pos += 10 + rdlength;
    }
    
    return has_cname && !has_final;
}

/**
 * Extract CNAME target from answer section
 */
char* extract_cname_target(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }
    
    if (response->ancount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Parse answer section looking for CNAME
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Found CNAME record
        if (type == QTYPE_CNAME && rdlength > 0) {
            int rdata_pos = pos + 10;
            char* cname_target = parse_dns_name_from_wire(buffer, buffer_len, rdata_pos);
            if (cname_target) {
                return cname_target;
            }
        }
        
        pos += 10 + rdlength;
    }

    return NULL;
}

/**
 * Extract IP address (A or AAAA) from answer section
 */
char* extract_ip_from_answer(struct Packet* response, uint16_t qtype)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    if (response->ancount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Parse answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Found A record
        if (type == QTYPE_A && qtype == QTYPE_A && rdlength == 4 && 
            pos + 10 + 4 <= buffer_len) {
            char* ip = malloc(INET_ADDRSTRLEN);
            if (ip) {
                struct in_addr addr;
                memcpy(&addr.s_addr, buffer + pos + 10, 4);
                if (inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN)) {
                    return ip;
                }
                free(ip);
            }
        }
        
        // Found AAAA record
        if (type == QTYPE_AAAA && qtype == QTYPE_AAAA && rdlength == 16 && 
            pos + 10 + 16 <= buffer_len) {
            char* ip = malloc(INET6_ADDRSTRLEN);
            if (ip) {
                struct in6_addr addr;
                memcpy(&addr.s6_addr, buffer + pos + 10, 16);
                if (inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN)) {
                    return ip;
                }
                free(ip);
            }
        }
        
        pos += 10 + rdlength;
    }

    return NULL;
}

/**
 * Extract nameserver IP from additional section (glue records)
 * Validates that the glue record matches the NS name
 */
char* extract_ns_server_ip(struct Packet* response, const char* ns_name)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    if (response->arcount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Skip answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    // Skip authority section
    for (int i = 0; i < response->nscount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    // Parse additional section - prefer IPv4 (A records)
    int saved_pos = pos;
    for (int i = 0; i < response->arcount && pos < buffer_len; i++) {
        char* record_name = parse_dns_name_from_wire(buffer, buffer_len, pos);
        
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) {
            free(record_name);
            break;
        }
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Check if this glue record is for our NS (if ns_name provided)
        bool name_matches = true;
        if (ns_name && record_name) {
            name_matches = (strcasecmp(record_name, ns_name) == 0);
        }
        
        // Found matching A record
        if (name_matches && type == QTYPE_A && rdlength == 4 && 
            pos + 10 + 4 <= buffer_len) {
            char* ip = malloc(INET_ADDRSTRLEN);
            if (ip) {
                struct in_addr addr;
                memcpy(&addr.s_addr, buffer + pos + 10, 4);
                if (inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN)) {
                    printf("    ✓ Found glue A record: %s -> %s\n", 
                           record_name ? record_name : "unknown", ip);
                    free(record_name);
                    return ip;
                }
                free(ip);
            }
        }
        
        free(record_name);
        pos += 10 + rdlength;
    }

    // Second pass: Look for AAAA records if no A records found
    pos = saved_pos;
    for (int i = 0; i < response->arcount && pos < buffer_len; i++) {
        char* record_name = parse_dns_name_from_wire(buffer, buffer_len, pos);
        
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) {
            free(record_name);
            break;
        }
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Check if this glue record is for our NS
        bool name_matches = true;
        if (ns_name && record_name) {
            name_matches = (strcasecmp(record_name, ns_name) == 0);
        }
        
        // Found matching AAAA record
        if (name_matches && type == QTYPE_AAAA && rdlength == 16 && 
            pos + 10 + 16 <= buffer_len) {
            // Skip IPv6 for now since query_server() doesn't support it
            printf("    ! Skipping IPv6 glue record (not supported yet)\n");
        }
        
        free(record_name);
        pos += 10 + rdlength;
    }

    return NULL;
}


/**
 * Extract first NS name from authority section
 */
char* extract_ns_name(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }
    
    if (response->nscount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Skip answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    // Parse authority section for NS records
    for (int i = 0; i < response->nscount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Found NS record
        if (type == QTYPE_NS && rdlength > 0) {
            int rdata_pos = pos + 10;
            char* ns_name = parse_dns_name_from_wire(buffer, buffer_len, rdata_pos);
            if (ns_name) {
                printf("    ✓ Found NS name: %s\n", ns_name);
                return ns_name;
            }
        }
        
        pos += 10 + rdlength;
    }

    return NULL;
}
