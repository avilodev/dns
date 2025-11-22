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

#include <openssl/err.h>


#define VERSION "v1.0"
/*
    1.0 - Basic Functionality
*/

#define MAXLINE 4096
#define HEADER_LEN 12
#define SOCKET_TIMEOUT 5
#define MAX_INTERNAL_HOSTS 100

#define DNS_PORT 53

// DNS Query Types
#define QTYPE_A 1
#define QTYPE_NS 2
#define QTYPE_CNAME 5
#define QTYPE_SOA 6 
#define QTYPE_PTR 12
#define QTYPE_MX 15
#define QTYPE_TXT 16
#define QTYPE_AAAA 28

// DNS Response Codes
#define RCODE_NO_ERROR 0
#define RCODE_FORMAT_ERROR 1
#define RCODE_SERVER_FAILURE 2
#define RCODE_NAME_ERROR 3

#define SERVER_PATH "/home/avilo/dns/upstream_dns"
#define HINTS_FILE "/misc/root_hints.txt"
#define LOG_FILE_PATH "/server.log"

#define PORT 5335
#define NUM_THREADS 20
#define QUEUE_SIZE 100

#define SEED_RANDOM() do { \
    struct timeval tv; \
    gettimeofday(&tv, NULL); \
    srand(tv.tv_usec ^ getpid()); \
} while(0)

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