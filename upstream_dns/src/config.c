#include "config.h"

extern Config g_config;

static void init_default_config(void) {
    g_config.port = PORT;
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
    while ((opt = getopt(argc, argv, "p:t:q:")) != -1) {
        switch (opt) {
            case 'p':
                g_config.port = atoi(optarg);
                break;
            case 't':
                g_config.thread_count = atoi(optarg);
                break;
            case 'q':
                g_config.queue_size = atoi(optarg);
                break;
            default:
                printf("Uasge: ./upstream_dns/bin/dns <-p Upstream DNS port> <-t thread_count> <-q queue_size>\n");
                return -1;
        }
    }

    
    printf("Config Loaded\n");
    printf("Port: %d\n", g_config.port);
    printf("Thread Count: %d\n", g_config.thread_count);
    printf("Queue Size: %d\n", g_config.queue_size);
    
    
    return 0;
}

/**
 * Sets up and opens a new socket on a specified port
 *
 * Creates a socket, and specifies the option to rebind to the port if still open.
 *  This socket binds and listens on a specified port for IPv4 connections only.
 *
 * @param port Port for which OS will bind and listen for connections on
 *
 * @return File Descriptor for the new socket opened
 *
 * @note This function is called by both the HTTP and HTTPS sockets
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

    // Configure server address
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_addr.s_addr = INADDR_ANY;
    dns_addr.sin_port = htons(port);

    // Bind socket to port
    if (bind(dns_sock, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) < 0) {
        perror("Error: Bind failed");
        printf("Note: Port %d requires root privileges. Try 'sudo' or use port >= 1024\n", port);
        close(dns_sock);
        exit(EXIT_FAILURE);
    }
    
    printf("✓ DNS Server listening on 0.0.0.0:%d\n", port);
    return dns_sock;
}

extern Hints* g_hints[13];

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

        // Trim leading whitespace
        char* start = line;
        while (*start && isspace(*start)) start++;
        
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
            g_hints[hint_index]->ipv6_record = rec;
        }
    }

    fclose(fp);
    return hint_index + 1; // Return number of root servers loaded
}

// Helper function to free the hints data
void free_hints()
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
