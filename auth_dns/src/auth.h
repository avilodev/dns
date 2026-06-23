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

/* DNS name compression pointer to the QNAME in the question section
 * (RFC 1035 §4.1.4).  begin_response() always writes the question section
 * immediately after the 12-byte header, so the QNAME is always at offset
 * HEADER_LEN.  Computing the pointer from HEADER_LEN makes the dependency
 * explicit: if the header layout ever changes, this stays correct. */
#define DNS_NAME_PTR ((uint16_t)(0xC000u | (unsigned)(HEADER_LEN)))

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

    // HTTPS record (RFC 9460) — priority + TargetName, no SvcParams
    bool     has_https;
    uint16_t https_priority;
    char     https_target[256];  // "." means same-as-owner (root label)

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

/* The authoritative record store. Defined in auth_zonefile.c (which owns
 * loading); the serving path (check_internal) reads it. Guard with
 * g_auth_domains_lock. */
extern struct AuthDomain auth_domains[];
extern int auth_domain_count;

/* Check if domain should be handled authoritatively.
 * Returns a response Packet, or NULL to forward to upstream. */
struct Packet* check_internal(struct Packet* request);

/* Load authoritative domains from file.  Call before threads start.
 * Returns number of records loaded, 0 if none, -1 on I/O error. */
int load_auth_domains(const char* filename);

/* Reload under write-lock (SIGHUP handler). */
void reload_auth_domains(const char* filename);

/* Thread-safe A-record lookup.
 * Returns IP string, or NULL if not found. */
const char* lookup_auth_domain(const char* full_domain);

#endif // AUTH_H
