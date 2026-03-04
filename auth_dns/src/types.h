#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 53
#define VERSION "v1.2"

#define MAXLINE 4096
#define HEADER_LEN 12
#define SOCKET_TIMEOUT 5
#define MAX_INTERNAL_HOSTS 500   // entries (each record type = one entry)

// Default TTL for authoritative records (seconds)
#define DEFAULT_RECORD_TTL 3600

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
#define QTYPE_ANY        255  // Any record type (RFC 1035 §3.2.3)
#define QTYPE_DS         43   // Delegation Signer (RFC 4034)
#define QTYPE_RRSIG      46   // Resource Record Signature (RFC 4034)
#define QTYPE_NSEC       47   // Next Secure (RFC 4034)
#define QTYPE_DNSKEY     48   // DNS Key (RFC 4034)
#define QTYPE_NSEC3      50   // Next Secure v3 (RFC 5155)
#define QTYPE_NSEC3PARAM 51   // NSEC3 Parameters (RFC 5155)

// DNS Response Codes
#define RCODE_NO_ERROR      0
#define RCODE_FORMAT_ERROR  1
#define RCODE_SERVER_FAILURE 2
#define RCODE_NAME_ERROR    3
#define RCODE_NOTIMP        4
#define RCODE_NOTAUTH       9   // Not Authoritative (RFC 2136)
#define RCODE_BADVERS       16  // Bad OPT Version (RFC 6891)

#ifndef SERVER_PATH
#define SERVER_PATH "/home/avilo/dns/auth_dns"
#endif
#ifndef LOG_FILE_PATH
#define LOG_FILE_PATH "/home/avilo/dns/logs/server.log"
#endif
#define AUTH_FILE_PATH "/misc/auth_domains.txt"

#define DEFAULT_UPSTREAM_DNS "1.1.1.1"
#define UPSTREAM_PORT 53
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
    uint8_t do_bit;       // DNSSEC OK (EDNS DO bit, RFC 4035 §3.2.1)
    uint8_t edns_present; // 1 if client sent an EDNS0 OPT record
    uint8_t edns_version; // EDNS version from OPT (RFC 6891 §6.1.3)
    uint16_t edns_udp_size; // client-advertised UDP payload size (RFC 6891 §6.1.2)

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
};

typedef struct ServerConfig {
    int thread_count;
    int queue_size;

    char* upstream_dns;
    int upstream_port;
} Config;

#endif /* TYPES_H */