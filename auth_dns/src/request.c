#include "request.h"
#include <ctype.h>

static void parse_domain_components(struct Packet* pkt, const char* domain);

/* Parse a raw DNS request buffer into a Packet struct.
 * Returns the populated Packet, or NULL if the request is malformed. */
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

    // Drop response packets — a QR=1 packet arriving as a query is invalid
    if (pkt->qr == 1) {
        free_packet(pkt);
        return NULL;
    }

    // Only standard queries (opcode=0) supported; flag others for NOTIMP reply
    if (pkt->opcode != 0) {
        pkt->rcode = RCODE_NOTIMP;
        return pkt;
    }

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
        
        /* Lowercase each byte while copying — DNS names are case-insensitive
         * (RFC 1035 §3.1) and auth_domains.txt stores only lowercase. */
        for (int j = 0; j < label_len; j++)
            domain[domain_len + j] = (char)tolower((unsigned char)buffer[pos + j]);
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

    // Validate QCLASS — only IN (1) and ANY/QCLASS_ANY (255) are valid (RFC 1035)
    if (pkt->q_class != 1 && pkt->q_class != 255) {
        fprintf(stderr, "Warning: Unsupported QCLASS %u — returning FORMERR\n", pkt->q_class);
        pkt->rcode = RCODE_FORMAT_ERROR;
        return pkt;
    }

    /* Scan additional section for EDNS0 OPT record to detect DO bit.
     * arcount additional RRs immediately follow the question section
     * (ancount and nscount are always 0 in a standard query).
     * OPT owner = root (0x00), type = 41; DO = bit 15 of OPT TTL flags. */
    pos += 4; /* advance past QTYPE + QCLASS */
    for (int rri = 0; rri < (int)pkt->arcount && pos < recv_len; rri++) {
        /* Skip owner name */
        if ((uint8_t)buffer[pos] == 0) {
            pos++;                             /* root label */
        } else {
            while (pos < recv_len) {
                uint8_t llen = (uint8_t)buffer[pos];
                if (llen == 0)              { pos++; break; }
                if ((llen & 0xC0) == 0xC0) { pos += 2; break; }
                pos += 1 + llen;
            }
        }
        if (pos + 10 > recv_len) break;
        uint16_t rr_type  = ntohs(*(uint16_t*)(buffer + pos));     pos += 2;
        uint16_t rr_class = ntohs(*(uint16_t*)(buffer + pos));     pos += 2;
        uint32_t rr_ttl   = ntohl(*(uint32_t*)(buffer + pos));     pos += 4;
        uint16_t rr_rdlen = ntohs(*(uint16_t*)(buffer + pos));     pos += 2;
        if (rr_type == 41 /* OPT */) {
            pkt->edns_present  = 1;
            pkt->edns_udp_size = rr_class ? rr_class : 512; /* CLASS = UDP payload size */
            pkt->edns_version  = (uint8_t)((rr_ttl >> 16) & 0xFF);
            pkt->do_bit        = (rr_ttl >> 15) & 1;
            break;
        }
        if (pos + rr_rdlen > recv_len) break;
        pos += rr_rdlen;
    }

    return pkt;
}

/* Split a FQDN into top_level_domain, domain, and authoritative_domain components. */
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
