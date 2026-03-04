#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define VERSION "v2.1"

#define MAXLINE 4096
#define HEADER_LEN 12
#define SOCKET_TIMEOUT 5
#define DNS_PORT 53

// DNS Query Types
#define QTYPE_A          1
#define QTYPE_NS         2
#define QTYPE_CNAME      5
#define QTYPE_SOA        6
#define QTYPE_PTR        12
#define QTYPE_MX         15
#define QTYPE_TXT        16
#define QTYPE_AAAA       28
#define QTYPE_SRV        33   // Service Locator (RFC 2782)
#define QTYPE_DS         43   // Delegation Signer (RFC 4034)
#define QTYPE_RRSIG      46   // Resource Record Signature (RFC 4034)
#define QTYPE_NSEC       47   // Next Secure (RFC 4034)
#define QTYPE_DNSKEY     48   // DNS Key (RFC 4034)
#define QTYPE_NSEC3      50   // Next Secure v3 (RFC 5155)
#define QTYPE_NSEC3PARAM 51   // NSEC3 Parameters (RFC 5155)
#define QTYPE_ANY        255  // Any type (RFC 1035 §3.2.3)

// DNS Response Codes
#define RCODE_NO_ERROR       0
#define RCODE_FORMAT_ERROR   1
#define RCODE_SERVER_FAILURE 2
#define RCODE_NAME_ERROR     3
#define RCODE_NOTIMP         4
#define RCODE_NOTAUTH        9   // Not Authoritative (RFC 2136)
#define RCODE_BADVERS        16  // Bad OPT Version (RFC 6891)

// Timeouts and concurrency limits for parallel query strategies
#define TIMEOUT_PARALLEL_FAST 1    // Timeout for parallel queries
#define TIMEOUT_SEQUENTIAL 2       // Timeout for sequential query
#define MAX_PARALLEL_QUERIES 3     // Query 3 servers simultaneously

#define SERVER_PATH "/home/avilo/dns/upstream_dns"
#define HINTS_FILE "/misc/root_hints.txt"
#define LOG_FILE_PATH "/home/avilo/dns/logs/upstream.log"

#define PORT 5335
#define NUM_THREADS 20
#define QUEUE_SIZE 100

struct Packet {
    char* request;
    ssize_t recv_len;

    // DNS Header fields
    uint16_t id;
    uint16_t flags;
    uint8_t qr;        // Query/Response flag
    uint8_t opcode;    // Operation code
    uint8_t aa;        // Authoritative answer
    uint8_t tc;        // Truncation
    uint8_t rd;        // Recursion desired
    uint8_t ra;        // Recursion available
    uint8_t z;         // Reserved
    uint8_t ad;        // Authenticated data
    uint8_t cd;        // Checking disabled
    uint8_t rcode;     // Response code

    // DNS Record counts
    uint16_t qdcount;  // Question count
    uint16_t ancount;  // Answer count
    uint16_t nscount;  // Authority count
    uint16_t arcount;  // Additional count

    // Domain components
    char* full_domain;
    char* authoritative_domain;
    char* domain;
    char* top_level_domain;

    uint16_t q_type;   // Query type
    uint16_t q_class;  // Query class (1=IN)

    // EDNS0 fields (RFC 6891) — populated by parse_request_headers()
    bool     edns_present;    // Client sent an OPT record
    uint8_t  edns_version;    // Client's EDNS version (must be 0)
    uint16_t edns_udp_size;   // Client's advertised UDP payload size
    bool     do_bit;          // DNSSEC OK bit from client OPT
};

typedef struct ServerConfig {
    int thread_count;
    int queue_size;
    int port;
} Config;

typedef struct ServerRecord {
    char* ip;
    char* type;
    int ttl;
} Record;

typedef struct RootHints {
    char* name;
    Record* ipv4_record;
    Record* ipv6_record;
} Hints;


#endif /* TYPES_H */
