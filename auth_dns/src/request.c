#include "request.h"

static void parse_domain_components(struct Packet* pkt, const char* domain);

/**
 * Parse DNS request headers and question section
 * @param buffer Raw DNS packet buffer
 * @param recv_len Length of received data
 * @return Parsed packet structure or NULL on error
 */
struct Packet* parse_request_headers(char* buffer, ssize_t recv_len) {
    if (!buffer) {
        fprintf(stderr, "Error: NULL buffer provided\n");
        return NULL;
    }

    if (recv_len < HEADER_LEN) {
        fprintf(stderr, "Error: Buffer too short for DNS header (%zd bytes)\n", recv_len);
        return NULL;
    }

    struct Packet* pkt = calloc(1, sizeof(struct Packet));
    if (!pkt) {
        perror("Error: Memory allocation failed for packet");
        return NULL;
    }

    // Copy raw request
    pkt->request = malloc(recv_len);
    if (!pkt->request) {
        perror("Error: Memory allocation failed for request buffer");
        free(pkt);
        return NULL;
    }
    memcpy(pkt->request, buffer, recv_len);
    pkt->recv_len = recv_len;

    // Parse DNS header (12 bytes, all fields in network byte order)
    pkt->id = ntohs(*(uint16_t*)(buffer + 0));
    pkt->flags = ntohs(*(uint16_t*)(buffer + 2));
    pkt->qdcount = ntohs(*(uint16_t*)(buffer + 4));
    pkt->ancount = ntohs(*(uint16_t*)(buffer + 6));
    pkt->nscount = ntohs(*(uint16_t*)(buffer + 8));
    pkt->arcount = ntohs(*(uint16_t*)(buffer + 10));

    // Extract individual flag bits
    pkt->qr = (pkt->flags >> 15) & 0x1;
    pkt->opcode = (pkt->flags >> 11) & 0xF;
    pkt->aa = (pkt->flags >> 10) & 0x1;
    pkt->tc = (pkt->flags >> 9) & 0x1;
    pkt->rd = (pkt->flags >> 8) & 0x1;
    pkt->ra = (pkt->flags >> 7) & 0x1;
    pkt->z = (pkt->flags >> 6) & 0x1;
    pkt->ad = (pkt->flags >> 5) & 0x1;
    pkt->cd = (pkt->flags >> 4) & 0x1;
    pkt->rcode = pkt->flags & 0xF;

    // Validate question count
    if (pkt->qdcount == 0) {
        fprintf(stderr, "Error: No questions in DNS query\n");
        free_packet(pkt);
        return NULL;
    }

    // Parse domain name from question section
    char domain[MAXLINE];
    memset(domain, 0, sizeof(domain));
    
    int pos = HEADER_LEN;
    int domain_len = 0;
    
    // Parse DNS label format
    while (pos < recv_len) {
        uint8_t label_len = (uint8_t)buffer[pos];
        
        if (label_len == 0) {
            break;
        }
        
        // Check for DNS compression
        if ((label_len & 0xC0) == 0xC0) {
            fprintf(stderr, "Error: Unexpected compression in question section\n");
            free_packet(pkt);
            return NULL;
        }
        
        if (label_len > 63) {
            fprintf(stderr, "Error: Invalid label length %u\n", label_len);
            free_packet(pkt);
            return NULL;
        }
        
        if (domain_len > 0 && domain_len < MAXLINE - 1) {
            domain[domain_len++] = '.';
        }
        
        pos++; // Skip length
        
        if (pos + label_len > recv_len) {
            fprintf(stderr, "Error: Label extends beyond packet boundary\n");
            free_packet(pkt);
            return NULL;
        }
        
        if (domain_len + label_len >= MAXLINE) {
            fprintf(stderr, "Error: Domain name too long\n");
            free_packet(pkt);
            return NULL;
        }
        
        memcpy(domain + domain_len, buffer + pos, label_len);
        domain_len += label_len;
        pos += label_len;
    }
    
    pos++; // Skip null terminator
    domain[domain_len] = '\0';
    
    pkt->full_domain = strdup(domain);
    if (!pkt->full_domain) {
        perror("Error: Failed to allocate domain string");
        free_packet(pkt);
        return NULL;
    }

    // Parse domain into components
    parse_domain_components(pkt, domain);

    // Parse question type and class
    if (pos + 4 > recv_len) {
        fprintf(stderr, "Error: Buffer too short for question type/class\n");
        free_packet(pkt);
        return NULL;
    }
    
    pkt->q_type = ntohs(*(uint16_t*)(buffer + pos));
    pkt->q_class = ntohs(*(uint16_t*)(buffer + pos + 2));

    return pkt;
}

/**
 * Parse domain into TLD, domain, and subdomain components
 */
static void parse_domain_components(struct Packet* pkt, const char* domain) {
    if (!pkt || !domain) {
        return;
    }

    pkt->top_level_domain = NULL;
    pkt->domain = NULL;
    pkt->authoritative_domain = NULL;

    size_t len = strlen(domain);
    if (len == 0) {
        return;
    }

    // Find last dot to extract TLD
    const char* last_dot = strrchr(domain, '.');
    if (!last_dot || last_dot == domain) {
        pkt->domain = strdup(domain);
        return;
    }

    // Extract TLD
    pkt->top_level_domain = strdup(last_dot + 1);
    
    // Find second-to-last dot to extract domain
    const char* second_last_dot = last_dot - 1;
    while (second_last_dot > domain && *second_last_dot != '.') {
        second_last_dot--;
    }

    if (*second_last_dot == '.') {
        // subdomain
        size_t domain_len = last_dot - second_last_dot - 1;
        pkt->domain = strndup(second_last_dot + 1, domain_len);
        
        size_t auth_len = second_last_dot - domain;
        pkt->authoritative_domain = strndup(domain, auth_len);
    } else {
        // No subdomain
        size_t domain_len = last_dot - domain;
        pkt->domain = strndup(domain, domain_len);
    }
}
