#ifndef AUTH_H
#define AUTH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include "types.h"

/* DNS name compression pointer back to byte 12 (the QNAME in the question
 * section, RFC 1035 §4.1.4).  Valid because our response buffers always start
 * with the 12-byte header immediately followed by the question section, so the
 * QNAME is always at offset 12 = 0xC000 | 0x000C = 0xC00C. */
#define DNS_NAME_PTR 0xC00C

/* Reader-writer lock protecting the auth_domains array.
 * Callers take rdlock for reads (lookup, check_internal), wrlock for reloads. */
extern pthread_rwlock_t g_auth_domains_lock;

/*
 * AuthDomain: one flat record entry.  Multiple entries may share the same
 * domain name to represent different record types (MX, NS, TXT, SRV, …).
 * has_* flags identify which record type this entry carries.
 */
struct AuthDomain {
    char     domain[256];      // Owner name (lowercased)
    bool     is_wildcard;      // true → domain is "*.parent.zone"
    uint32_t ttl;              // Per-record TTL override (0 = DEFAULT_RECORD_TTL)

    // A record (plain IPv4)
    char     ip[16];           // "0.0.0.0" if not an A record
    bool     is_blocked;       // Return NXDOMAIN for this name

    // AAAA record
    bool     has_ipv6;
    char     ipv6[40];

    // CNAME record
    bool     has_cname;
    char     cname_target[256];

    // MX record
    bool     has_mx;
    char     mx_hostname[256];
    uint16_t mx_priority;

    // NS record
    bool     has_ns;
    char     ns_name[256];

    // TXT record (one string per entry; multiple entries = RRset)
    bool     has_txt;
    char     txt_data[512];

    // SRV record (_service._proto.owner)
    bool     has_srv;
    uint16_t srv_priority;
    uint16_t srv_weight;
    uint16_t srv_port;
    char     srv_target[256];

    // SOA record fields (RFC 1035 §3.3.13, RFC 2308)
    bool     has_soa;
    char     soa_mname[256];
    char     soa_rname[256];
    uint32_t soa_serial;
    uint32_t soa_refresh;
    uint32_t soa_retry;
    uint32_t soa_expire;
    uint32_t soa_minimum;   // Negative-caching TTL (RFC 2308 §5)
    uint32_t soa_ttl;       // TTL for the SOA RR itself
};

/* Check if domain should be handled authoritatively.
 * Returns a response Packet, or NULL to forward to upstream. */
struct Packet* check_internal(struct Packet* request);

/* Load authoritative domains from file.  Call before threads start.
 * Returns number of records loaded, 0 if none, -1 on I/O error. */
int load_auth_domains(const char* filename);

/* Reload under write-lock (SIGHUP handler). */
void reload_auth_domains(const char* filename);

/* Thread-safe A-record lookup.
 * Returns IP string, "NXDOMAIN" if blocked, or NULL if not found. */
const char* lookup_auth_domain(const char* full_domain);

#endif // AUTH_H
