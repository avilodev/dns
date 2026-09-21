#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "wire_io.h"

/* True for the errno of a timed-out or would-block socket call. */
static inline bool errno_is_timeout(int e)
{
#if EAGAIN == EWOULDBLOCK
    return e == EAGAIN;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}

#define MAXLINE        4096   /* max UDP datagram we read */
#define HEADER_LEN     12
#define SOCKET_TIMEOUT 5
#define DNS_PORT       53

/* EDNS UDP size we advertise: avoids IP fragmentation (DNS Flag Day 2020). */
#define EDNS_UDP_PAYLOAD 1232

/* Wall-clock cap for one whole resolution (keep below auth_dns's forward
 * timeout) and for any single nameserver hop. */
#define RECURSION_BUDGET_SEC 4
#define PER_HOP_TIMEOUT_SEC  2

/* Idle time a TCP client may hold a worker. */
#define TCP_IDLE_TIMEOUT 2

/* RR types */
#define QTYPE_A          1
#define QTYPE_NS         2
#define QTYPE_CNAME      5
#define QTYPE_SOA        6
#define QTYPE_PTR        12
#define QTYPE_MX         15
#define QTYPE_TXT        16
#define QTYPE_AAAA       28
#define QTYPE_SRV        33
#define QTYPE_HTTPS      65   /* forwarded, not served (RFC 9460) */
#define QTYPE_OPT        41
#define QTYPE_DS         43
#define QTYPE_RRSIG      46
#define QTYPE_NSEC       47
#define QTYPE_DNSKEY     48
#define QTYPE_NSEC3      50
#define QTYPE_NSEC3PARAM 51
#define QTYPE_ANY        255

#define CLASS_IN  1
#define CLASS_ANY 255

/* Response codes */
#define RCODE_NO_ERROR       0
#define RCODE_FORMAT_ERROR   1
#define RCODE_SERVER_FAILURE 2
#define RCODE_NAME_ERROR     3
#define RCODE_NOTIMP         4
#define RCODE_REFUSED        5
#define RCODE_NOTAUTH        9
#define RCODE_BADVERS        16

/* Header flag bits (in the 16-bit flags word) */
#define FLAG_QR 0x8000
#define FLAG_AA 0x0400
#define FLAG_TC 0x0200
#define FLAG_RD 0x0100
#define FLAG_RA 0x0080
#define FLAG_AD 0x0020
#define FLAG_CD 0x0010

/* Paths come from the Makefile (-D); fallbacks assume cwd = upstream_dns/. */
#ifndef SERVER_PATH
#define SERVER_PATH "."
#endif
#ifndef LOG_FILE_PATH
#define LOG_FILE_PATH "../logs/upstream.log"
#endif
#ifndef PID_FILE_PATH
#define PID_FILE_PATH "/run/upstream_dns.pid"
#endif

/* Relative to SERVER_PATH. */
#define HINTS_FILE        "/misc/root_hints.txt"
#define TRUST_ANCHOR_FILE "/config/root-trust-anchor.key"

/* CLI defaults */
#define PORT        5335
#define NUM_THREADS 20
#define QUEUE_SIZE  100

/* A DNS message plus its parsed header and question. */
struct Packet {
    char*   request;       /* wire bytes (malloc'd) */
    ssize_t recv_len;

    uint16_t id;
    uint8_t  qr, opcode, aa, tc, rd, ad, cd, rcode;
    uint16_t qdcount, ancount, nscount, arcount;

    char*    full_domain;  /* question name, presentation text (dns_name.h) */
    uint16_t q_type;
    uint16_t q_class;

    /* Client EDNS (parse_request_headers only) */
    bool     edns_present;
    uint8_t  edns_version;
    uint16_t edns_udp_size;
    bool     do_bit;
};

typedef struct ServerConfig {
    int   thread_count;
    int   queue_size;
    int   port;
    char* bind_addr;       /* -b; NULL = wildcard */
    char* acl_csv;         /* -a; NULL = built-in allow-list */
    int   rate_limit_qps;  /* -r; 0 = off */
    char* drop_user;       /* -U user[:group]; NULL = no drop */
} Config;

#endif /* TYPES_H */
