#include "utils.h"

extern Config g_config;

static void init_default_config(void) {
    g_config.upstream_dns = strdup(DEFAULT_UPSTREAM_DNS);
    g_config.upstream_port = UPSTREAM_PORT;
    
    g_config.thread_count = NUM_THREADS;
    g_config.queue_size = QUEUE_SIZE;
}

/* Parse command-line flags (-p/-t/-u/-q) into g_config. Returns 0 on success, -1 on unknown flag. */
int load_config(int argc, char** argv) {
    // Initialize defaults
    init_default_config();
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:t:u:q:")) != -1) {
        char *end;
        long v;
        switch (opt) {
            case 'p':
                v = strtol(optarg, &end, 10);
                if (*end != '\0' || v < 1 || v > 65535) {
                    fprintf(stderr, "Invalid upstream port: %s\n", optarg);
                    return -1;
                }
                g_config.upstream_port = (int)v;
                break;
            case 't':
                v = strtol(optarg, &end, 10);
                if (*end != '\0' || v < 1 || v > 1024) {
                    fprintf(stderr, "Invalid thread count: %s\n", optarg);
                    return -1;
                }
                g_config.thread_count = (int)v;
                break;
            case 'u':
                free(g_config.upstream_dns);
                g_config.upstream_dns = strdup(optarg);
                break;
            case 'q':
                v = strtol(optarg, &end, 10);
                if (*end != '\0' || v < 1 || v > 1048576) {
                    fprintf(stderr, "Invalid queue size: %s\n", optarg);
                    return -1;
                }
                g_config.queue_size = (int)v;
                break;
            default:
                printf("Usage: ./auth_dns/bin/dns <-p Upstream DNS port> <-t thread_count> <-u upstream_dns> <-q queue_size>\n");
                return -1;
        }
    }
    
    return 0;
}

/*
 * Write a domain name (e.g. "mail.example.com") into DNS wire-format label
 * encoding at buf[*pos], advancing *pos.  Each dot-separated label is written
 * as: <length-byte> <label-bytes>.  A final zero-length byte terminates the name.
 */
void write_dns_labels(const char* name, char* buf, int* pos) {
    if (!name || !buf || !pos) return;
    char copy[256];
    strncpy(copy, name, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    char *saveptr;
    char* label = strtok_r(copy, ".", &saveptr);
    while (label) {
        uint8_t label_len = (uint8_t)strlen(label);
        buf[(*pos)++] = (char)label_len;
        memcpy(buf + *pos, label, label_len);
        *pos += label_len;
        label = strtok_r(NULL, ".", &saveptr);
    }
    buf[(*pos)++] = 0;  // Null terminator
}

/*
 * Extract IP addresses from a DNS response packet.
 * Returns comma-separated IPs, a record type label (e.g. "MX_RECORD"), or NULL.
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
    uint16_t first_non_ip_type = 0;  /* first non-A/AAAA record type seen */

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

/* Print packet header fields (for debugging). */
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

/* Print a hex dump of data (for debugging). */
void print_hex_dump(const char* data, ssize_t len) {
    printf("Hex dump (%zd bytes): ", len);
    for (ssize_t i = 0; i < len && i < 4096; i++) {
        printf("%02X ", (unsigned char)data[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n                      ");
        }
    }
    if (len > 4096) {
        printf("... (truncated)");
    }
    printf("\n");
}

/* Free a Packet and all its heap-allocated fields. */
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