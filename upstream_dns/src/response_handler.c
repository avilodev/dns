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

/**
 * Extract ALL nameservers with their glue records
 */
NSCandidateList* extract_all_ns_with_glue(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    if (response->nscount == 0) {
        return NULL;
    }

    NSCandidateList* list = calloc(1, sizeof(NSCandidateList));
    if (!list) return NULL;
    
    list->capacity = response->nscount;
    list->candidates = calloc(list->capacity, sizeof(NSCandidate));
    if (!list->candidates) {
        free(list);
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

    // Parse authority section - collect ALL NS records
    for (int i = 0; i < response->nscount && pos < buffer_len && list->count < list->capacity; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        if (type == QTYPE_NS && rdlength > 0) {
            int rdata_pos = pos + 10;
            char* ns_name = parse_dns_name_from_wire(buffer, buffer_len, rdata_pos);
            if (ns_name) {
                list->candidates[list->count].ns_name = ns_name;
                list->candidates[list->count].ns_ip = NULL;
                list->count++;
            }
        }
        
        pos += 10 + rdlength;
    }

    // Now match glue records from additional section
    int glue_pos = pos;
    
    for (int i = 0; i < list->count; i++) {
        pos = glue_pos;
        
        for (int j = 0; j < response->arcount && pos < buffer_len; j++) {
            char* record_name = parse_dns_name_from_wire(buffer, buffer_len, pos);
            skip_dns_name(buffer, buffer_len, &pos);
            
            if (pos + 10 > buffer_len) {
                free(record_name);
                break;
            }
            
            uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
            uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
            
            // Found matching A record
            if (record_name && strcasecmp(record_name, list->candidates[i].ns_name) == 0 &&
                type == QTYPE_A && rdlength == 4 && pos + 10 + 4 <= buffer_len) {
                
                char* ip = malloc(INET_ADDRSTRLEN);
                if (ip) {
                    struct in_addr addr;
                    memcpy(&addr.s_addr, buffer + pos + 10, 4);
                    if (inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN)) {
                        list->candidates[i].ns_ip = ip;
                        printf("    ✓ Found glue: %s -> %s\n", record_name, ip);
                    } else {
                        free(ip);
                    }
                }
            }
            
            free(record_name);
            pos += 10 + rdlength;
        }
    }

    return list;
}

void free_ns_candidate_list(NSCandidateList* list)
{
    if (!list) return;
    
    for (int i = 0; i < list->count; i++) {
        free(list->candidates[i].ns_name);
        free(list->candidates[i].ns_ip);
    }
    
    free(list->candidates);
    free(list);
}

/**
 * Test if a nameserver responds (quick probe)
 */
bool test_nameserver_reachable(const char* ns_ip, struct Packet* query)
{
    if (!ns_ip || !query) return false;
    
    int test_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (test_sock < 0) return false;
    
    // Very short timeout for testing
    struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(test_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in test_addr = {0};
    test_addr.sin_family = AF_INET;
    test_addr.sin_port = htons(DNS_PORT);
    
    if (inet_pton(AF_INET, ns_ip, &test_addr.sin_addr) <= 0) {
        close(test_sock);
        return false;
    }
    
    ssize_t sent = sendto(test_sock, query->request, query->recv_len, 0,
                         (struct sockaddr*)&test_addr, sizeof(test_addr));
    
    bool reachable = false;
    if (sent > 0) {
        char test_buf[512];
        struct sockaddr_in recv_addr;
        socklen_t recv_len = sizeof(recv_addr);
        
        ssize_t received = recvfrom(test_sock, test_buf, sizeof(test_buf), 0,
                                   (struct sockaddr*)&recv_addr, &recv_len);
        
        reachable = (received > 0);
    }
    
    close(test_sock);
    return reachable;
}

extern Hints* g_hints[13];

struct Packet* build_root_hints_response(struct Packet* query)
{
    if (!query) return NULL;
    
    // Create response packet
    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) return NULL;
    
    // Allocate buffer for response
    response->request = malloc(MAXLINE);
    if (!response->request) {
        free(response);
        return NULL;
    }
    
    unsigned char* buf = (unsigned char*)response->request;
    int pos = 0;
    
    // Copy header from query
    if (query->request && query->recv_len >= HEADER_LEN) {
        memcpy(buf, query->request, HEADER_LEN);
    }
    
    // Update header flags
    buf[2] = 0x84;  // QR=1, AA=1, RD=0
    buf[3] = 0x00;  // RA=0, RCODE=0
    
    // Set ANCOUNT to number of root servers
    int root_count = 0;
    for (int i = 0; i < 13; i++) {
        if (g_hints[i] && g_hints[i]->name) {
            root_count++;
        }
    }
    buf[6] = (root_count >> 8) & 0xFF;
    buf[7] = root_count & 0xFF;
    
    pos = HEADER_LEN;
    
    // Skip question section (already in buffer from query)
    skip_dns_name(buf, MAXLINE, &pos);
    pos += 4;  // QTYPE + QCLASS
    
    // Add answer section with root NS records
    for (int i = 0; i < 13; i++) {
        if (!g_hints[i] || !g_hints[i]->name) continue;
        
        // Write name (.) - compression pointer to question
        buf[pos++] = 0xC0;
        buf[pos++] = 0x0C;
        
        // TYPE: NS
        buf[pos++] = 0x00;
        buf[pos++] = 0x02;
        
        // CLASS: IN
        buf[pos++] = 0x00;
        buf[pos++] = 0x01;
        
        // TTL: 518400 (6 days)
        buf[pos++] = 0x00;
        buf[pos++] = 0x07;
        buf[pos++] = 0xE9;
        buf[pos++] = 0x00;
        
        // RDLENGTH: calculate
        int name_len = encode_dns_name(g_hints[i]->name, buf + pos + 2, MAXLINE - pos - 2);
        if (name_len < 0) continue;
        
        buf[pos++] = (name_len >> 8) & 0xFF;
        buf[pos++] = name_len & 0xFF;
        
        pos += name_len;
    }
    
    response->recv_len = pos;
    response->id = query->id;
    response->ancount = root_count;
    response->qdcount = 1;
    response->nscount = 0;
    response->arcount = 0;
    response->rcode = RCODE_NO_ERROR;
    response->aa = 1;
    
    return response;
}