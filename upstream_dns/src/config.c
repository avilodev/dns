#include "config.h"
#include "dns_wire.h"
#include <openssl/evp.h>

extern Config g_config;

static void init_default_config(void) {
    g_config.port = PORT;
    g_config.thread_count = NUM_THREADS;
    g_config.queue_size = QUEUE_SIZE;
    g_config.bind_addr = NULL;
    g_config.acl_csv = NULL;
    g_config.rate_limit_qps = 0;
    g_config.drop_user = NULL;
}

/*
 * Parse command-line arguments and populate the server configuration.
 *
 * Initializes defaults then applies -p (port), -t (thread count),
 * -q (queue size), -b (bind address), -a (allow-list CIDRs), and
 * -r (per-source rate limit) flags. Returns -1 on unrecognized flags.
 */
int load_config(int argc, char** argv) {
    // Initialize defaults
    init_default_config();

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:t:q:b:a:r:U:")) != -1) {
        char *end;
        long v;
        switch (opt) {
            case 'p':
                v = strtol(optarg, &end, 10);
                if (*end != '\0' || v < 1 || v > 65535) {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return -1;
                }
                g_config.port = (int)v;
                break;
            case 't':
                v = strtol(optarg, &end, 10);
                if (*end != '\0' || v < 1 || v > 1024) {
                    fprintf(stderr, "Invalid thread count: %s\n", optarg);
                    return -1;
                }
                g_config.thread_count = (int)v;
                break;
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
            default:
                printf("Usage: ./bin/upstream_dns <-p port> <-t thread_count> "
                       "<-q queue_size> <-b bind_addr> <-a allow_cidrs> "
                       "<-r per_source_qps> <-U user[:group]>\n");
                return -1;
        }
    }

    printf("Config: port=%d threads=%d queue=%d\n",
           g_config.port, g_config.thread_count, g_config.queue_size);
    return 0;
}

/*
 * Resolve the configured -b bind address for a given address family.
 *
 *   AF_INET : writes the network address into *out4
 *   AF_INET6: writes the network address into *out6
 *
 * Returns  1 if a bind address was applied for this family,
 *          0 if no -b was given (caller should use the wildcard address),
 *         -1 if -b was given but is not of this family (skip this socket).
 */
static int resolve_bind_addr(int family, struct in_addr *out4,
                             struct in6_addr *out6) {
    if (!g_config.bind_addr) {
        if (family == AF_INET)  out4->s_addr = INADDR_ANY;
        if (family == AF_INET6) *out6 = in6addr_any;
        return 0;
    }
    if (family == AF_INET)
        return (inet_pton(AF_INET, g_config.bind_addr, out4) == 1) ? 1 : -1;
    return (inet_pton(AF_INET6, g_config.bind_addr, out6) == 1) ? 1 : -1;
}

/*
 * Sets up and opens a new socket on a specified port
 *
 * Creates a socket, and specifies the option to rebind to the port if still open.
 *  This socket binds and listens on a specified port for IPv4 connections only.
 *
 * @param port Port for which OS will bind and listen for connections on
 *
 * @return File Descriptor for the new socket opened
 *
 * @warning Caller must close() the returned socket when done
 */
int create_server_socket(int port) {
    // DNS socket definition
    int dns_sock;
    struct sockaddr_in dns_addr;

    // Create UDP socket for DNS
    dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dns_sock < 0) {
        perror("Error: Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Set socket options for address reuse
    int opt = 1;
    if (setsockopt(dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Error: SO_REUSEADDR failed");
        close(dns_sock);
        exit(EXIT_FAILURE);
    }
    if (setsockopt(dns_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        perror("Warning: SO_REUSEPORT unavailable");

    // Configure server address
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(port);
    // Honor -b bind address; -1 means a non-IPv4 address was given (IPv6-only),
    // so skip the IPv4 UDP socket entirely rather than binding the wildcard.
    if (resolve_bind_addr(AF_INET, &dns_addr.sin_addr, NULL) < 0) {
        close(dns_sock);
        return -1;
    }

    // Bind socket to port
    if (bind(dns_sock, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        perror("Error: Bind failed");
        printf("Note: Port %d requires root privileges. Try 'sudo' or use port >= 1024\n", port);
        close(dns_sock);
        exit(EXIT_FAILURE);
    }

    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dns_addr.sin_addr, ip, sizeof(ip));
        printf("DNS Server listening on %s:%d (UDP IPv4)\n", ip, port);
    }
    return dns_sock;
}

/*
 * Create an IPv6 UDP socket bound to port with IPV6_V6ONLY.
 * Returns -1 (without exiting) if the kernel has no IPv6 support.
 */
int create_server_socket_v6(int port) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Warning: socket() IPv6 UDP; IPv6 not available");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET,   SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, SOL_SOCKET,   SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,  &opt, sizeof(opt));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    if (resolve_bind_addr(AF_INET6, NULL, &addr.sin6_addr) < 0) {
        close(sock);   /* -b is an IPv4 address: no IPv6 socket */
        return -1;
    }
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Warning: bind() IPv6 UDP");
        close(sock);
        return -1;
    }
    {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr.sin6_addr, ip, sizeof(ip));
        printf("DNS Server listening on [%s]:%d (UDP IPv6)\n", ip, port);
    }
    return sock;
}

/*
 * Create an IPv4 TCP listener bound to port.
 * Returns -1 on failure (without exiting).
 */
int create_tcp_socket_v4(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Warning: socket() IPv4 TCP");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    if (resolve_bind_addr(AF_INET, &addr.sin_addr, NULL) < 0) {
        close(sock); return -1;   /* -b is IPv6: no IPv4 TCP socket */
    }
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Warning: bind() IPv4 TCP"); close(sock); return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) {
        perror("Warning: listen() IPv4 TCP"); close(sock); return -1;
    }
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        printf("DNS Server listening on %s:%d (TCP IPv4)\n", ip, port);
    }
    return sock;
}

/*
 * Create an IPv6 TCP listener bound to port with IPV6_V6ONLY.
 * Returns -1 if IPv6 is unavailable (without exiting).
 */
int create_tcp_socket_v6(int port) {
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Warning: socket() IPv6 TCP; IPv6 not available");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET,   SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY,  &opt, sizeof(opt));
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    if (resolve_bind_addr(AF_INET6, NULL, &addr.sin6_addr) < 0) {
        close(sock); return -1;   /* -b is IPv4: no IPv6 TCP socket */
    }
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Warning: bind() IPv6 TCP"); close(sock); return -1;
    }
    if (listen(sock, SOMAXCONN) < 0) {
        perror("Warning: listen() IPv6 TCP"); close(sock); return -1;
    }
    {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr.sin6_addr, ip, sizeof(ip));
        printf("DNS Server listening on [%s]:%d (TCP IPv6)\n", ip, port);
    }
    return sock;
}

extern Hints* g_hints[13];

/* Free a single root-hint Record (ip + type + struct). */
static void free_hint_record(Record* r)
{
    if (!r) return;
    free(r->ip);
    free(r->type);
    free(r);
}

int load_hints(const char* filename)
{
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open hints file");
        return -1;
    }

    char line[512];
    int hint_index = -1;
    
    // Initialize all hints to NULL
    for (int i = 0; i < 13; i++) {
        g_hints[i] = NULL;
    }

    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == ';' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }

        // Trim leading whitespace (cast to unsigned char: isspace() is UB for
        // negative values other than EOF, which a signed char can produce).
        char* start = line;
        while (*start && isspace((unsigned char)*start)) start++;
        
        if (*start == '\0') continue;

        // Parse the line
        char domain[256], record_type[16], value[256];
        int ttl;
        
        // Read the remaining line after domain and TTL to get type and value
        int parsed = sscanf(start, "%255s %d %15s %255s", domain, &ttl, record_type, value);
        
        if (parsed < 4) continue;

        // Check if this is a root NS record (new root server)
        if (strcmp(domain, ".") == 0 && strcmp(record_type, "NS") == 0) {
            hint_index++;
            if (hint_index >= 13) break;
            
            // Allocate new Hints structure
            g_hints[hint_index] = (Hints*)malloc(sizeof(Hints));
            if (!g_hints[hint_index]) {
                fclose(fp);
                return -1;
            }
            
            // Store the server name
            g_hints[hint_index]->name = strdup(value);
            g_hints[hint_index]->ipv4_record = NULL;
            g_hints[hint_index]->ipv6_record = NULL;
        }
        // Check if this is an A record (IPv4)
        else if (strcmp(record_type, "A") == 0 && hint_index >= 0) {
            Record* rec = (Record*)malloc(sizeof(Record));
            if (!rec) {
                fclose(fp);
                return -1;
            }
            rec->ip = strdup(value);
            rec->type = strdup("A");
            rec->ttl = ttl;
            free_hint_record(g_hints[hint_index]->ipv4_record);  /* no leak on dup */
            g_hints[hint_index]->ipv4_record = rec;
        }
        // Check if this is an AAAA record (IPv6)
        else if (strcmp(record_type, "AAAA") == 0 && hint_index >= 0) {
            Record* rec = (Record*)malloc(sizeof(Record));
            if (!rec) {
                fclose(fp);
                return -1;
            }
            rec->ip = strdup(value);
            rec->type = strdup("AAAA");
            rec->ttl = ttl;
            free_hint_record(g_hints[hint_index]->ipv6_record);  /* no leak on dup */
            g_hints[hint_index]->ipv6_record = rec;
        }
    }

    fclose(fp);
    return hint_index + 1; // Return number of root servers loaded
}

// Helper function to free the hints data
void free_hints(void)
{
    for (int i = 0; i < 13; i++) {
        if (g_hints[i]) {
            free(g_hints[i]->name);

            if (g_hints[i]->ipv4_record) {
                free(g_hints[i]->ipv4_record->ip);
                free(g_hints[i]->ipv4_record->type);
                free(g_hints[i]->ipv4_record);
            }

            if (g_hints[i]->ipv6_record) {
                free(g_hints[i]->ipv6_record->ip);
                free(g_hints[i]->ipv6_record->type);
                free(g_hints[i]->ipv6_record);
            }

            free(g_hints[i]);
            g_hints[i] = NULL;
        }
    }
}

/* -------------------------------------------------------------------------
 * Built-in root hints fallback — used when the hints file is missing.
 * IPs are the official IANA root server addresses (as of 2024).
 * ------------------------------------------------------------------------- */
int load_hints_builtin(void)
{
    static const struct { const char* name; const char* ip; } roots[13] = {
        { "a.root-servers.net.", "198.41.0.4"    },
        { "b.root-servers.net.", "170.247.170.2"  },
        { "c.root-servers.net.", "192.33.4.12"    },
        { "d.root-servers.net.", "199.7.91.13"    },
        { "e.root-servers.net.", "192.203.230.10" },
        { "f.root-servers.net.", "192.5.5.241"    },
        { "g.root-servers.net.", "192.112.36.4"   },
        { "h.root-servers.net.", "198.97.190.53"  },
        { "i.root-servers.net.", "192.36.148.17"  },
        { "j.root-servers.net.", "192.58.128.30"  },
        { "k.root-servers.net.", "193.0.14.129"   },
        { "l.root-servers.net.", "199.7.83.42"    },
        { "m.root-servers.net.", "202.12.27.33"   },
    };

    for (int i = 0; i < 13; i++) {
        g_hints[i] = malloc(sizeof(Hints));
        if (!g_hints[i]) return -1;

        g_hints[i]->name = strdup(roots[i].name);
        g_hints[i]->ipv6_record = NULL;

        Record* rec = malloc(sizeof(Record));
        if (!rec) return -1;
        rec->ip   = strdup(roots[i].ip);
        rec->type = strdup("A");
        rec->ttl  = 518400;
        g_hints[i]->ipv4_record = rec;
    }
    return 13;
}

/* -------------------------------------------------------------------------
 * Trust anchor loading
 * File format (one per line, comment lines begin with ';' or '#'):
 *   owner TTL IN DNSKEY flags protocol algorithm pubkey_base64
 * Example:
 *   . 172800 IN DNSKEY 257 3 8 AwEAAaz/...
 * ------------------------------------------------------------------------- */

TrustAnchor* load_trust_anchors(const char* filename)
{
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Warning: Cannot open trust anchor file");
        return NULL;
    }

    TrustAnchor* head = NULL;
    TrustAnchor* tail = NULL;
    char line[4096];

    while (fgets(line, sizeof(line), fp)) {
        /* Skip comment and blank lines */
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ';' || *p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;

        /* Parse: owner TTL IN DNSKEY flags protocol algorithm pubkey_base64 */
        char owner[256], class_str[8], rtype[16], b64key[4096];
        int ttl;
        uint16_t flags;
        uint8_t protocol, algorithm;
        unsigned int flags_u, protocol_u, algorithm_u;

        int n = sscanf(p, "%255s %d %7s %15s %u %u %u %4095s",
                       owner, &ttl, class_str, rtype,
                       &flags_u, &protocol_u, &algorithm_u, b64key);
        if (n < 8) continue;
        if (strcasecmp(rtype, "DNSKEY") != 0) continue;

        flags     = (uint16_t)flags_u;
        protocol  = (uint8_t)protocol_u;
        algorithm = (uint8_t)algorithm_u;

        /* Base64-decode the public key using OpenSSL */
        size_t b64_len = strlen(b64key);
        /* EVP_DecodeBlock output is at most ceil(b64_len * 3/4) bytes */
        int max_out = (int)((b64_len * 3) / 4 + 4);
        uint8_t* pubkey = malloc((size_t)max_out);
        if (!pubkey) continue;

        int decoded_len = EVP_DecodeBlock(pubkey, (const unsigned char*)b64key,
                                          (int)b64_len);
        if (decoded_len <= 0) {
            free(pubkey);
            fprintf(stderr, "Warning: Failed to base64-decode trust anchor key for %s\n", owner);
            continue;
        }
        /* EVP_DecodeBlock may pad output; trim trailing padding bytes */
        uint16_t pubkey_len = (uint16_t)decoded_len;
        /* Count '=' padding to subtract */
        for (int i = (int)b64_len - 1; i >= 0 && b64key[i] == '='; i--)
            pubkey_len--;

        /* Allocate and populate TrustAnchor */
        TrustAnchor* ta = calloc(1, sizeof(TrustAnchor));
        if (!ta) { free(pubkey); continue; }

        snprintf(ta->owner, sizeof(ta->owner), "%s", owner);
        ta->flags      = flags;
        ta->protocol   = protocol;
        ta->algorithm  = algorithm;
        ta->pubkey     = pubkey;
        ta->pubkey_len = pubkey_len;
        ta->key_tag    = compute_key_tag(flags, protocol, algorithm,
                                         pubkey, pubkey_len);
        ta->next = NULL;

        if (!head) head = tail = ta;
        else { tail->next = ta; tail = ta; }

        printf("Loaded trust anchor: %s DNSKEY flags=%u alg=%u key_tag=%u\n",
               owner, flags, algorithm, ta->key_tag);
    }

    fclose(fp);
    return head;
}

void free_trust_anchors(TrustAnchor* anchors)
{
    while (anchors) {
        TrustAnchor* next = anchors->next;
        free(anchors->pubkey);
        free(anchors);
        anchors = next;
    }
}
