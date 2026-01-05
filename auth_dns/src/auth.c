#include "auth.h"
#include "response.h"  // For build_nxdomain_response
#include "utils.h"     // For free_packet

// Add QTYPE_MX if not already defined in types.h
#ifndef QTYPE_MX
#define QTYPE_MX 15
#endif

#ifndef QTYPE_AAAA
#define QTYPE_AAAA 28
#endif

static struct AuthDomain auth_domains[100];
static int auth_domain_count = 0;

/**
 * Build MX response packet
 */
static struct Packet* build_mx_response(struct Packet* request, const char* full_domain) {
    // Find MX record for this domain
    struct AuthDomain* mx_entry = NULL;
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].has_mx && 
            strcmp(auth_domains[i].domain, full_domain) == 0) {
            mx_entry = &auth_domains[i];
            break;
        }
    }
    
    if (!mx_entry) {
        return NULL;
    }
    
    printf("→ Handling authoritative MX query for %s -> %s (priority %d)\n", 
           full_domain, mx_entry->mx_hostname, mx_entry->mx_priority);
    
    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        return NULL;
    }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    // Copy transaction ID from request
    memcpy(response->request + pos, request->request, 2);
    pos += 2;

    // Set response flags
    uint16_t flags = 0;
    flags |= (1 << 15);           // QR: Response
    flags |= (1 << 10);           // AA: Authoritative Answer
    flags |= (request->rd << 8);  // RD: Copy recursion desired from request
    flags |= (1 << 7);            // RA: Recursion Available
    flags |= RCODE_NO_ERROR;      // RCODE: No error
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    // Set counts
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 answer
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);
    pos += 2;

    // Copy question section
    if (request->authoritative_domain) {
        uint8_t auth_len = strlen(request->authoritative_domain);
        response->request[pos++] = auth_len;
        memcpy(response->request + pos, request->authoritative_domain, auth_len);
        pos += auth_len;
    }
    
    if (request->domain) {
        uint8_t domain_len = strlen(request->domain);
        response->request[pos++] = domain_len;
        memcpy(response->request + pos, request->domain, domain_len);
        pos += domain_len;
    }

    if (request->top_level_domain) {
        uint8_t tld_len = strlen(request->top_level_domain);
        response->request[pos++] = tld_len;
        memcpy(response->request + pos, request->top_level_domain, tld_len);
        pos += tld_len;
    }

    response->request[pos++] = 0;

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    // Build answer section with compression pointer
    *(uint16_t*)(response->request + pos) = htons(0xC00C); // Pointer to question name
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(QTYPE_MX);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // Class IN
    pos += 2;
    *(uint32_t*)(response->request + pos) = htonl(3600);  // TTL: 1 hour
    pos += 4;
    
    // Calculate RDATA length
    // We need to encode the MX hostname: mail.avilo.com -> 4mail5avilo3com0
    char* mx_host = mx_entry->mx_hostname;
    int rdata_len = 2; // Priority field
    
    // Calculate encoded hostname length
    char* token = strtok(strdup(mx_host), ".");
    while (token) {
        rdata_len += 1 + strlen(token); // length byte + label
        token = strtok(NULL, ".");
    }
    rdata_len += 1; // Null terminator
    
    *(uint16_t*)(response->request + pos) = htons(rdata_len);
    pos += 2;
    
    // Write priority
    *(uint16_t*)(response->request + pos) = htons(mx_entry->mx_priority);
    pos += 2;
    
    // Encode MX hostname in DNS format
    char mx_copy[256];
    strncpy(mx_copy, mx_entry->mx_hostname, sizeof(mx_copy) - 1);
    mx_copy[sizeof(mx_copy) - 1] = '\0';
    
    token = strtok(mx_copy, ".");
    while (token) {
        uint8_t label_len = strlen(token);
        response->request[pos++] = label_len;
        memcpy(response->request + pos, token, label_len);
        pos += label_len;
        token = strtok(NULL, ".");
    }
    response->request[pos++] = 0; // Null terminator

    response->recv_len = pos;
    return response;
}

/**
 * Build AAAA response packet
 */
static struct Packet* build_aaaa_response(struct Packet* request, const char* full_domain, const char* ipv6_address) {
    printf("→ Handling authoritative AAAA query for %s -> %s\n", full_domain, ipv6_address);

    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        return NULL;
    }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    // Copy transaction ID from request
    memcpy(response->request + pos, request->request, 2);
    pos += 2;

    // Set response flags
    uint16_t flags = 0;
    flags |= (1 << 15);           // QR: Response
    flags |= (1 << 10);           // AA: Authoritative Answer
    flags |= (request->rd << 8);  // RD: Copy recursion desired from request
    flags |= (1 << 7);            // RA: Recursion Available
    flags |= RCODE_NO_ERROR;      // RCODE: No error
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    // Set counts
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 answer
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);
    pos += 2;

    // Copy question section
    if (request->authoritative_domain) {
        uint8_t auth_len = strlen(request->authoritative_domain);
        response->request[pos++] = auth_len;
        memcpy(response->request + pos, request->authoritative_domain, auth_len);
        pos += auth_len;
    }
    
    if (request->domain) {
        uint8_t domain_len = strlen(request->domain);
        response->request[pos++] = domain_len;
        memcpy(response->request + pos, request->domain, domain_len);
        pos += domain_len;
    }

    if (request->top_level_domain) {
        uint8_t tld_len = strlen(request->top_level_domain);
        response->request[pos++] = tld_len;
        memcpy(response->request + pos, request->top_level_domain, tld_len);
        pos += tld_len;
    }

    response->request[pos++] = 0;

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    // Build answer section with compression pointer
    *(uint16_t*)(response->request + pos) = htons(0xC00C); // Pointer offset
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(QTYPE_AAAA);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // IN
    pos += 2;
    *(uint32_t*)(response->request + pos) = htonl(3600);  // 1 hour TTL
    pos += 4;
    *(uint16_t*)(response->request + pos) = htons(16);  // IPv6 is 16 bytes
    pos += 2;

    // RDATA: Parse and insert IPv6 address
    struct in6_addr addr;
    if (inet_pton(AF_INET6, ipv6_address, &addr) == 1) {
        memcpy(response->request + pos, &addr, 16);
        pos += 16;
    } else {
        fprintf(stderr, "Error: Failed to parse IPv6 address %s\n", ipv6_address);
        free_packet(response);
        return NULL;
    }

    response->recv_len = pos;
    return response;
}

/**
 * Check if domain should be handled as authoritative
 * @param request Parsed DNS request
 * @return Response packet if authoritative, NULL otherwise
 */
struct Packet* check_internal(struct Packet* request) {
    if (!request || !request->domain || !request->top_level_domain) {
        return NULL;
    }

    char full_domain[MAXLINE];
    
    if (request->authoritative_domain) {
        snprintf(full_domain, sizeof(full_domain), "%s.%s.%s", 
                 request->authoritative_domain, request->domain, request->top_level_domain);
    } else {
        snprintf(full_domain, sizeof(full_domain), "%s.%s", 
                 request->domain, request->top_level_domain);
    }

    // Check if this is an MX query
    if (request->q_type == QTYPE_MX) {
        return build_mx_response(request, full_domain);
    }

    // Check if this is an AAAA query
    if (request->q_type == QTYPE_AAAA) {
        // Look up AAAA record
        for (int i = 0; i < auth_domain_count; i++) {
            if (auth_domains[i].has_ipv6 && 
                strcmp(auth_domains[i].domain, full_domain) == 0) {
                return build_aaaa_response(request, full_domain, auth_domains[i].ipv6);
            }
        }
        return NULL;  // No AAAA record found
    }

    // Handle A record queries (existing code)
    const char* ip_address = lookup_auth_domain(full_domain);
    if (!ip_address) {
        return NULL;  // Not authoritative
    }

    // Check if this domain is blocked (should return NXDOMAIN)
    if (strcmp(ip_address, "NXDOMAIN") == 0) {
        printf("→ Blocking domain: %s (returning NXDOMAIN)\n", full_domain);
        return build_nxdomain_response(request);
    }

    printf("→ Handling authoritative query for %s -> %s\n", full_domain, ip_address);

    // Build DNS response packet
    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        return NULL;
    }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    // Copy transaction ID from request
    memcpy(response->request + pos, request->request, 2);
    pos += 2;

    // Set response flags
    uint16_t flags = 0;
    flags |= (1 << 15);           // QR: Response
    flags |= (1 << 10);           // AA: Authoritative Answer
    flags |= (request->rd << 8);  // RD: Copy recursion desired from request
    flags |= (1 << 7);            // RA: Recursion Available
    flags |= RCODE_NO_ERROR;      // RCODE: No error
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    // Set counts
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 answer
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);
    pos += 2;

    // Copy question section
    if (request->authoritative_domain) {
        uint8_t auth_len = strlen(request->authoritative_domain);
        response->request[pos++] = auth_len;
        memcpy(response->request + pos, request->authoritative_domain, auth_len);
        pos += auth_len;
    }
    
    if (request->domain) {
        uint8_t domain_len = strlen(request->domain);
        response->request[pos++] = domain_len;
        memcpy(response->request + pos, request->domain, domain_len);
        pos += domain_len;
    }

    if (request->top_level_domain) {
        uint8_t tld_len = strlen(request->top_level_domain);
        response->request[pos++] = tld_len;
        memcpy(response->request + pos, request->top_level_domain, tld_len);
        pos += tld_len;
    }

    response->request[pos++] = 0;

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    // Build answer section with compression pointer
    *(uint16_t*)(response->request + pos) = htons(0xC00C); // Pointer offset
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(QTYPE_A);  // A
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // IN
    pos += 2;
    *(uint32_t*)(response->request + pos) = htonl(3600);  // 1 hour
    pos += 4;
    *(uint16_t*)(response->request + pos) = htons(4);
    pos += 2;

    // RDATA: Parse and insert IP address from file
    unsigned int ip_parts[4];
    if (sscanf(ip_address, "%u.%u.%u.%u", 
               &ip_parts[0], &ip_parts[1], &ip_parts[2], &ip_parts[3]) == 4) {
        response->request[pos++] = (uint8_t)ip_parts[0];
        response->request[pos++] = (uint8_t)ip_parts[1];
        response->request[pos++] = (uint8_t)ip_parts[2];
        response->request[pos++] = (uint8_t)ip_parts[3];
    } else {
        fprintf(stderr, "Error: Failed to parse IP address %s\n", ip_address);
        free_packet(response);
        return NULL;
    }

    response->recv_len = pos;
    return response;
}


/**
 * Load authoritative domains from file
 * File format: 
 *   domain_name ip_address              (A record)
 *   domain_name MX priority hostname    (MX record)
 *   domain_name NXDOMAIN                (blocked domain)
 */
int load_auth_domains(const char* filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error: Failed to open auth_domains.txt");
        return -1;
    }

    char* buffer = malloc(MAXLINE);
    if (!buffer) {
        perror("Error: Memory allocation failed");
        close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, buffer, MAXLINE - 1);
    close(fd);

    if (bytes_read < 0) {
        perror("Error: Failed to read auth_domains.txt");
        free(buffer);
        return -1;
    }

    buffer[bytes_read] = '\0';

    // Parse line by line
    char* line = buffer;
    char* next_line;
    
    while (line && *line && auth_domain_count < 100) {
        // Find next newline
        next_line = strchr(line, '\n');
        if (next_line) {
            *next_line = '\0';
            next_line++;
        }

        // Skip empty lines and comments
        if (*line == '\0' || *line == '#' || *line == '\n') {
            line = next_line;
            continue;
        }

        char domain[256];
        char type_or_ip[64];  // Increased size for IPv6
        char priority_str[16];
        char mx_host[256];
        
        // Try to parse as MX record first (4 fields)
        int parsed = sscanf(line, "%255s %63s %15s %255s", 
                           domain, type_or_ip, priority_str, mx_host);
        
        if (parsed == 4 && strcasecmp(type_or_ip, "MX") == 0) {
            // It's an MX record
            size_t domain_len = strlen(domain);
            size_t copy_len = domain_len < sizeof(auth_domains[auth_domain_count].domain) - 1 ? 
                             domain_len : sizeof(auth_domains[auth_domain_count].domain) - 1;
            memcpy(auth_domains[auth_domain_count].domain, domain, copy_len);
            auth_domains[auth_domain_count].domain[copy_len] = '\0';
            
            auth_domains[auth_domain_count].has_mx = true;
            auth_domains[auth_domain_count].is_blocked = false;
            auth_domains[auth_domain_count].has_ipv6 = false;
            auth_domains[auth_domain_count].mx_priority = atoi(priority_str);
            
            size_t mx_len = strlen(mx_host);
            size_t mx_copy_len = mx_len < sizeof(auth_domains[auth_domain_count].mx_hostname) - 1 ?
                                mx_len : sizeof(auth_domains[auth_domain_count].mx_hostname) - 1;
            memcpy(auth_domains[auth_domain_count].mx_hostname, mx_host, mx_copy_len);
            auth_domains[auth_domain_count].mx_hostname[mx_copy_len] = '\0';
            
            strcpy(auth_domains[auth_domain_count].ip, "0.0.0.0"); // No IP for MX records
            
            printf("  Loaded: %-30s -> MX %d %s\n", domain, auth_domains[auth_domain_count].mx_priority, mx_host);
            auth_domain_count++;
            
        } else {
            // Try to parse as A/AAAA record or NXDOMAIN (2 fields)
            parsed = sscanf(line, "%255s %63s", domain, type_or_ip);
            
            if (parsed == 2) {
                size_t domain_len = strlen(domain);
                size_t copy_len = domain_len < 255 ? domain_len : 254;
                memcpy(auth_domains[auth_domain_count].domain, domain, copy_len);
                auth_domains[auth_domain_count].domain[copy_len] = '\0';
                auth_domains[auth_domain_count].has_mx = false;
                
                // Check if this is a blocked domain (NXDOMAIN)
                if (strcasecmp(type_or_ip, "NXDOMAIN") == 0) {
                    auth_domains[auth_domain_count].is_blocked = true;
                    auth_domains[auth_domain_count].has_ipv6 = false;
                    strcpy(auth_domains[auth_domain_count].ip, "0.0.0.0");
                    printf("  Loaded: %-30s -> BLOCKED (NXDOMAIN)\n", domain);
                    auth_domain_count++;
                    
                } else {
                    // Check if it's IPv6 (contains colons)
                    if (strchr(type_or_ip, ':') != NULL) {
                        // It's an IPv6 address (AAAA record)
                        struct in6_addr addr;
                        if (inet_pton(AF_INET6, type_or_ip, &addr) == 1) {
                            auth_domains[auth_domain_count].is_blocked = false;
                            auth_domains[auth_domain_count].has_ipv6 = true;
                            strcpy(auth_domains[auth_domain_count].ip, "0.0.0.0");
                            size_t ipv6_len = strlen(type_or_ip);
                            size_t ipv6_copy_len = ipv6_len < 40 ? ipv6_len : 39;
                            memcpy(auth_domains[auth_domain_count].ipv6, type_or_ip, ipv6_copy_len);
                            auth_domains[auth_domain_count].ipv6[ipv6_copy_len] = '\0';
                            
                            printf("  Loaded: %-30s -> %s (AAAA)\n", domain, type_or_ip);
                            auth_domain_count++;
                        } else {
                            fprintf(stderr, "Warning: Invalid IPv6 '%s' for domain '%s'\n", type_or_ip, domain);
                        }
                    } else {
                        // It's an IPv4 address (A record)
                        struct in_addr addr;
                        if (inet_pton(AF_INET, type_or_ip, &addr) == 1) {
                            auth_domains[auth_domain_count].is_blocked = false;
                            auth_domains[auth_domain_count].has_ipv6 = false;
                            size_t ip_len = strlen(type_or_ip);
                            size_t ip_copy_len = ip_len < 16 ? ip_len : 15;
                            memcpy(auth_domains[auth_domain_count].ip, type_or_ip, ip_copy_len);
                            auth_domains[auth_domain_count].ip[ip_copy_len] = '\0';
                            
                            printf("  Loaded: %-30s -> %s\n", domain, type_or_ip);
                            auth_domain_count++;
                        } else {
                            fprintf(stderr, "Warning: Invalid IP '%s' for domain '%s'\n", type_or_ip, domain);
                        }
                    }
                }
            } else {
                fprintf(stderr, "Warning: Malformed line: '%s'\n", line);
            }
        }

        line = next_line;
    }

    free(buffer);
    
    if (auth_domain_count == 0) {
        fprintf(stderr, "Warning: No valid domains loaded from %s\n", filename);
        return -1;
    }

    printf("✓ Loaded %d authoritative domain(s)\n\n", auth_domain_count);
    return auth_domain_count;
}


/**
 * Lookup authoritative domain and return IP
 * Returns NULL if not found
 * Returns "NXDOMAIN" if domain is blocked
 * Note: Only looks up A records, not MX records
 */
const char* lookup_auth_domain(const char* full_domain) {
    if (!full_domain) {
        return NULL;
    }

    for (int i = 0; i < auth_domain_count; i++) {
        // Skip MX records when looking up A records
        if (auth_domains[i].has_mx) {
            continue;
        }
        
        if (strcmp(auth_domains[i].domain, full_domain) == 0) {
            if (auth_domains[i].is_blocked) {
                return "NXDOMAIN";
            }
            return auth_domains[i].ip;
        }
    }

    return NULL;
}