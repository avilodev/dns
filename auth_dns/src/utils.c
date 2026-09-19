#include "utils.h"
#include "dns_name.h"
#include <pthread.h>

/* ---- Pinned paths (see utils.h) ---------------------------------------- */

#define MAX_PINS 8
static struct { char* path; char* base; int dirfd; } g_pins[MAX_PINS];
static int g_pin_count = 0;
static pthread_mutex_t g_pin_lock = PTHREAD_MUTEX_INITIALIZER;

void path_pin(const char* path)
{
    if (!path || !*path) return;
    pthread_mutex_lock(&g_pin_lock);
    for (int i = 0; i < g_pin_count; i++)
        if (strcmp(g_pins[i].path, path) == 0) { pthread_mutex_unlock(&g_pin_lock); return; }
    if (g_pin_count < MAX_PINS) {
        const char* slash = strrchr(path, '/');
        char dir[1024];
        if (!slash)             snprintf(dir, sizeof(dir), ".");
        else if (slash == path) snprintf(dir, sizeof(dir), "/");
        else                    snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path), path);
        int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) {
            g_pins[g_pin_count].path  = strdup(path);
            g_pins[g_pin_count].base  = strdup(slash ? slash + 1 : path);
            g_pins[g_pin_count].dirfd = fd;
            if (g_pins[g_pin_count].path && g_pins[g_pin_count].base) g_pin_count++;
            else { free(g_pins[g_pin_count].path); free(g_pins[g_pin_count].base); close(fd); }
        }
    }
    pthread_mutex_unlock(&g_pin_lock);
}

int path_open(const char* path, int flags, int mode)
{
    if (!path) return -1;
    pthread_mutex_lock(&g_pin_lock);
    for (int i = 0; i < g_pin_count; i++) {
        if (strcmp(g_pins[i].path, path) == 0) {
            int fd = openat(g_pins[i].dirfd, g_pins[i].base, flags | O_CLOEXEC, mode);
            pthread_mutex_unlock(&g_pin_lock);
            return fd;
        }
    }
    pthread_mutex_unlock(&g_pin_lock);
    return open(path, flags | O_CLOEXEC, mode);
}

FILE* path_fopen(const char* path)
{
    int fd = path_open(path, O_RDONLY, 0);
    if (fd < 0) return NULL;
    FILE* f = fdopen(fd, "r");
    if (!f) close(fd);
    return f;
}

extern Config g_config;

static void init_default_config(void) {
    g_config.upstream_dns = strdup(DEFAULT_UPSTREAM_DNS);
    g_config.upstream_port = UPSTREAM_PORT;

    g_config.thread_count = NUM_THREADS;
    g_config.queue_size = QUEUE_SIZE;

    g_config.bind_addr = NULL;
    g_config.acl_csv = NULL;
    g_config.rate_limit_qps = 0;
    g_config.drop_user = NULL;
    g_config.block_mode = NULL;
    g_config.config_path = NULL;
}

/* Parse command-line flags (-p/-t/-u/-q/-b/-a/-r/-U) into g_config. Returns 0 on success, -1 on unknown flag. */
int load_config(int argc, char** argv) {
    // Initialize defaults
    init_default_config();

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:t:u:q:b:a:r:U:S:c:")) != -1) {
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
            case 'u': {
                /* Validate the upstream address now: a typo would otherwise make
                 * every forwarded query silently SERVFAIL at resolve time. */
                struct in_addr  a4;
                struct in6_addr a6;
                if (inet_pton(AF_INET, optarg, &a4) != 1 &&
                    inet_pton(AF_INET6, optarg, &a6) != 1) {
                    fprintf(stderr, "Invalid upstream address: %s\n", optarg);
                    return -1;
                }
                free(g_config.upstream_dns);
                g_config.upstream_dns = strdup(optarg);
                break;
            }
            case 'q':
                v = strtol(optarg, &end, 10);
                if (*end != '\0' || v < 1 || v > 1048576) {
                    fprintf(stderr, "Invalid queue size: %s\n", optarg);
                    return -1;
                }
                g_config.queue_size = (int)v;
                break;
            case 'b':
                g_config.bind_addr = strdup(optarg);
                break;
            case 'a':
                g_config.acl_csv = strdup(optarg);
                break;
            case 'r':
                v = strtol(optarg, &end, 10);
                if (*end != '\0' || v < 0 || v > 1000000) {
                    fprintf(stderr, "Invalid rate limit: %s\n", optarg);
                    return -1;
                }
                g_config.rate_limit_qps = (int)v;
                break;
            case 'U':
                g_config.drop_user = strdup(optarg);
                break;
            case 'S':
                g_config.block_mode = strdup(optarg);
                break;
            case 'c':
                g_config.config_path = strdup(optarg);
                break;
            default:
                printf("Usage: ./bin/auth_dns <-p upstream_port> <-t thread_count> "
                       "<-u upstream_dns> <-q queue_size> <-b bind_addr> "
                       "<-a recursion_allow_cidrs> <-r per_source_qps> "
                       "<-U user[:group]> <-S block_mode> <-c config_file>\n");
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
void write_dns_labels(const char* name, char* buf, int* pos, int buf_size) {
    if (!name || !buf || !pos || *pos >= buf_size) return;
    int n = dname_to_wire(name, (uint8_t*)buf + *pos, buf_size - *pos);
    if (n < 0) {
        /* Malformed or oversized name: emit the root label so the message
         * stays well-formed rather than writing a partial name. */
        fprintf(stderr, "Warning: cannot encode name '%s'\n", name);
        buf[(*pos)++] = 0;
        return;
    }
    *pos += n;
}

/*
 * Extract IP addresses from a DNS response packet.
 * Returns comma-separated IPs, a record type label (e.g. "MX_RECORD"), or NULL.
 */
char* extract_ip_from_response(const struct Packet* response) {
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    uint16_t qdcount = rd16(response->request + 4);
    uint16_t ancount = rd16(response->request + 6);
    
    if (ancount == 0) {
        /* The RCODE column already says NXDOMAIN/SERVFAIL; an empty NOERROR
         * answer is NODATA (the name exists, not with that type). */
        uint8_t rcode = (uint8_t)(response->request[3] & 0x0F);
        return rcode == RCODE_NO_ERROR ? strdup("NODATA") : NULL;
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
        
        uint16_t atype = rd16(ptr);
        ptr += 2;
        ptr += 2; // Skip CLASS
        ptr += 4; // Skip TTL
        uint16_t rdlength = rd16(ptr);
        ptr += 2;
        
        if (ptr + rdlength > end) break;
        
        // A record (IPv4)
        if (atype == 1 && rdlength == 4) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                    ptr[0], ptr[1], ptr[2], ptr[3]);
            
            if (ip_count > 0) {
                /* Space-separate multiple IPs so the CSV log's info column
                 * stays a single comma-free field. */
                strncat(result, " ", sizeof(result) - strlen(result) - 1);
            }
            strncat(result, ip_str, sizeof(result) - strlen(result) - 1);
            ip_count++;
        }
        // AAAA record (IPv6)
        else if (atype == 28 && rdlength == 16) {
            char ip_str[40];
            snprintf(ip_str, sizeof(ip_str), "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                    rd16(ptr),
                    rd16(ptr + 2),
                    rd16(ptr + 4),
                    rd16(ptr + 6),
                    rd16(ptr + 8),
                    rd16(ptr + 10),
                    rd16(ptr + 12),
                    rd16(ptr + 14));
            
            if (ip_count > 0) {
                /* Space-separate multiple IPs so the CSV log's info column
                 * stays a single comma-free field. */
                strncat(result, " ", sizeof(result) - strlen(result) - 1);
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

/* Free a Packet and all its heap-allocated fields. */
int free_packet(struct Packet* pkt) {
    if (!pkt) {
        return -1;
    }

    free(pkt->request);
    free(pkt->full_domain);
    free(pkt);

    return 0;
}