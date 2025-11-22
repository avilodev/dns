#include "auth.h"

static struct AuthDomain auth_domains[100];
static int auth_domain_count = 0;

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

    // Lookup in authoritative domains from file
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
    *(uint16_t*)(response->request + pos) = htons(1);  // QDCOUNT: 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // ANCOUNT: 1 answer
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // NSCOUNT: 0
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // ARCOUNT: 0
    pos += 2;

    // Copy question section
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

    response->request[pos++] = 0;  // Null terminator

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    // Build answer section with compression pointer
    *(uint16_t*)(response->request + pos) = htons(0xC00C);  // Name: pointer to offset 12
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(QTYPE_A);  // Type: A
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);  // Class: IN
    pos += 2;
    *(uint32_t*)(response->request + pos) = htonl(3600);  // TTL: 1 hour
    pos += 4;
    *(uint16_t*)(response->request + pos) = htons(4);  // RDLENGTH: 4 bytes
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
 * File format: domain_name ip_address
 * Special: Use NXDOMAIN to block domains
 * Example:
 *   avilodev.com 192.168.1.18
 *   pi5.local 192.168.1.3
 *   youtube.com NXDOMAIN
 *   ads.example.com NXDOMAIN
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

        // Parse: domain ip_or_NXDOMAIN
        char domain[256];
        char ip[16];
        int parsed = sscanf(line, "%255s %15s", domain, ip);

        if (parsed == 2) {
            size_t domain_len = strlen(domain);
            size_t copy_len = domain_len < 255 ? domain_len : 254;
            memcpy(auth_domains[auth_domain_count].domain, domain, copy_len);
            auth_domains[auth_domain_count].domain[copy_len] = '\0';
            
            // Check if this is a blocked domain (NXDOMAIN)
            if (strcasecmp(ip, "NXDOMAIN") == 0) {
                auth_domains[auth_domain_count].is_blocked = true;
                strcpy(auth_domains[auth_domain_count].ip, "0.0.0.0");
                printf("  Loaded: %-30s -> BLOCKED (NXDOMAIN)\n", domain);
                auth_domain_count++;
                
            } else {
                // Validate IP address format
                struct in_addr addr;
                if (inet_pton(AF_INET, ip, &addr) == 1) {
                    auth_domains[auth_domain_count].is_blocked = false;
                    size_t ip_len = strlen(ip);
                    size_t ip_copy_len = ip_len < 16 ? ip_len : 15;
                    memcpy(auth_domains[auth_domain_count].ip, ip, ip_copy_len);
                    auth_domains[auth_domain_count].ip[ip_copy_len] = '\0';
                    
                    printf("  Loaded: %-30s -> %s\n", domain, ip);
                    auth_domain_count++;
                } else {
                    fprintf(stderr, "Warning: Invalid IP '%s' for domain '%s'\n", ip, domain);
                }
            }
        } else {
            fprintf(stderr, "Warning: Malformed line: '%s'\n", line);
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
 */
const char* lookup_auth_domain(const char* full_domain) {
    if (!full_domain) {
        return NULL;
    }

    for (int i = 0; i < auth_domain_count; i++) {
        if (strcmp(auth_domains[i].domain, full_domain) == 0) {
            if (auth_domains[i].is_blocked) {
                return "NXDOMAIN";
            }
            return auth_domains[i].ip;
        }
    }

    return NULL;
}
