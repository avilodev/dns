#include "utils.h"

extern Config g_config;

static void init_default_config(void) {
    g_config.upstream_dns = strdup(DEFAULT_UPSTREAM_DNS);
    g_config.upstream_port = UPSTREAM_PORT;
    
    g_config.thread_count = NUM_THREADS;
    g_config.queue_size = QUEUE_SIZE;
}

/**
 * Updates the arguments for the server startup configuration.
 * 
 * Calls init_default_config() to set default server configuration, then
 * update webroot, ports, and thread sizes through server flags. If a 
 * parameter is unknown, it returns an error. Otherwise successful.
 * 
 * @param argc Counts how many argument were passed in when executed
 * @param argv Stores the arguments passed in on execution
 *
 * @return 0 on successful updates, -1 on unknown parameters.
 *
 * @see init_default_config()
 */
int load_config(int argc, char** argv) {
    // Initialize defaults
    init_default_config();
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:t:u:q:")) != -1) {
        switch (opt) {
            case 'p':
                g_config.upstream_port = atoi(optarg);
                break;
            case 't':
                g_config.thread_count = atoi(optarg);
                break;
            case 'u':
                free(g_config.upstream_dns);
                g_config.upstream_dns = strdup(optarg);
                break;
            case 'q':
                g_config.queue_size = atoi(optarg);
                break;
            default:
                printf("Uasge: ./auth_dns/bin/dns <-p Upstream DNS port> <-t thread_count> <-u upstream_dns> <-q queue_size>\n");
                return -1;
        }
    }
    
    return 0;
}

/**
 * Extract ALL IP addresses from DNS response packet
 * Returns comma-separated IPs, record type info, or NULL if error
 */
char* extract_ip_from_response(struct Packet* response) {
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    uint16_t qdcount = ntohs(*(uint16_t*)(response->request + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(response->request + 6));
    
    if (ancount == 0) {
        return strdup("NXDOMAIN");
    }

    unsigned char* ptr = (unsigned char*)response->request + HEADER_LEN;
    unsigned char* end = (unsigned char*)response->request + response->recv_len;
    
    // Skip question section
    for (int i = 0; i < qdcount; i++) {
        while (ptr < end) {
            if (*ptr == 0) {
                ptr++;
                break;
            }
            if ((*ptr & 0xC0) == 0xC0) {
                ptr += 2;
                break;
            }
            uint8_t len = *ptr;
            ptr += len + 1;
        }
        if (ptr + 4 > end) return NULL;
        ptr += 4; // QTYPE + QCLASS
    }
    
    if (ptr >= end) return NULL;

    // Build result with all IPs
    char result[1024] = "";
    int ip_count = 0;
    uint16_t first_non_ip_type = 0;  // Track first non-A/AAAA record type

    // Parse answer section
    for (int i = 0; i < ancount && ptr < end; i++) {
        // Skip answer name
        while (ptr < end) {
            if (*ptr == 0) {
                ptr++;
                break;
            }
            if ((*ptr & 0xC0) == 0xC0) {
                ptr += 2;
                break;
            }
            uint8_t len = *ptr;
            ptr += len + 1;
        }
        
        if (ptr + 10 > end) break;
        
        uint16_t atype = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        ptr += 2; // Skip CLASS
        ptr += 4; // Skip TTL
        uint16_t rdlength = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        
        if (ptr + rdlength > end) break;
        
        // A record (IPv4)
        if (atype == 1 && rdlength == 4) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                    ptr[0], ptr[1], ptr[2], ptr[3]);
            
            if (ip_count > 0) {
                strncat(result, ", ", sizeof(result) - strlen(result) - 1);
            }
            strncat(result, ip_str, sizeof(result) - strlen(result) - 1);
            ip_count++;
        }
        // AAAA record (IPv6)
        else if (atype == 28 && rdlength == 16) {
            char ip_str[40];
            snprintf(ip_str, sizeof(ip_str), "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                    ntohs(*(uint16_t*)(ptr)),
                    ntohs(*(uint16_t*)(ptr + 2)),
                    ntohs(*(uint16_t*)(ptr + 4)),
                    ntohs(*(uint16_t*)(ptr + 6)),
                    ntohs(*(uint16_t*)(ptr + 8)),
                    ntohs(*(uint16_t*)(ptr + 10)),
                    ntohs(*(uint16_t*)(ptr + 12)),
                    ntohs(*(uint16_t*)(ptr + 14)));
            
            if (ip_count > 0) {
                strncat(result, ", ", sizeof(result) - strlen(result) - 1);
            }
            strncat(result, ip_str, sizeof(result) - strlen(result) - 1);
            ip_count++;
        }
        // Track first non-IP record type
        else if (first_non_ip_type == 0) {
            first_non_ip_type = atype;
        }
        
        ptr += rdlength;
    }

    if (ip_count > 0) {
        return strdup(result);
    }

    // No A/AAAA records found, return the record type instead
    if (first_non_ip_type > 0) {
        const char* type_name;
        switch (first_non_ip_type) {
            case 5:  type_name = "CNAME"; break;
            case 2:  type_name = "NS"; break;
            case 6:  type_name = "SOA"; break;
            case 15: type_name = "MX"; break;
            case 16: type_name = "TXT"; break;
            case 33: type_name = "SRV"; break;
            case 65: type_name = "HTTPS"; break;
            default: 
                snprintf(result, sizeof(result), "TYPE_%u", first_non_ip_type);
                return strdup(result);
        }
        snprintf(result, sizeof(result), "%s_RECORD", type_name);
        return strdup(result);
    }

    return NULL;
}

/**
 * Print packet information for debugging
 */
void print_packet_info(const char* label, struct Packet* pkt) {
    if (!pkt) {
        return;
    }

    printf("\n=== %s ===\n", label);
    printf("Transaction ID: 0x%04x\n", pkt->id);
    printf("Flags: 0x%04x [QR=%d AA=%d RD=%d RA=%d RCODE=%d]\n", 
           pkt->flags, pkt->qr, pkt->aa, pkt->rd, pkt->ra, pkt->rcode);
    printf("Questions: %u, Answers: %u, Authority: %u, Additional: %u\n",
           pkt->qdcount, pkt->ancount, pkt->nscount, pkt->arcount);
    
    if (pkt->full_domain) {
        printf("Domain: %s\n", pkt->full_domain);
    }
    
    printf("Query Type: %u, Class: %u\n", pkt->q_type, pkt->q_class);
    printf("========================\n\n");
}

/**
 * Print hexadecimal dump of data
 */
void print_hex_dump(const char* data, ssize_t len) {
    printf("Hex dump (%zd bytes): ", len);
    for (ssize_t i = 0; i < len && i < 64; i++) {
        printf("%02X ", (unsigned char)data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n                      ");
        }
    }
    if (len > 64) {
        printf("... (truncated)");
    }
    printf("\n");
}

/**
 * Free packet structure and all allocated memory
 */
int free_packet(struct Packet* pkt) {
    if (!pkt) {
        return -1;
    }

    free(pkt->request);
    free(pkt->full_domain);
    free(pkt->authoritative_domain);
    free(pkt->domain);
    free(pkt->top_level_domain);
    free(pkt);

    return 0;
}