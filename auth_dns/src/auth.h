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

    // Record type flags: exactly one is set.
    bool     has_a, has_ipv6, has_cname, has_mx, has_ns, has_txt, has_srv,
             has_https, has_soa;

    // A record address (valid only when has_a).  A record carried no flag of
    // its own and was identified by ip[] not holding the placeholder
    // "0.0.0.0", which made a deliberate null-route "A 0.0.0.0" unservable.
    char     ip[16];

    /* Type-specific data.  Only the member matching the has_* flag is valid;
     * sharing storage keeps each record ~1 KB instead of ~3 KB. */
    union {
        char ipv6[INET6_ADDRSTRLEN];                 // AAAA (46: the
                                                     //  longest form is
                                                     //  "…:255.255.255.255")
        char cname_target[256];                      // CNAME
        struct { char mx_hostname[256];  uint16_t mx_priority; };    // MX
        char ns_name[256];                           // NS
        struct { unsigned char txt_wire[512];        // TXT RDATA: one or
                 uint16_t txt_wire_len; };           //  more <len><bytes>
        struct { uint16_t srv_priority, srv_weight, srv_port;         // SRV
                 char srv_target[256]; };
        struct { uint16_t https_priority;            // HTTPS (RFC 9460)
                 char https_target[256]; };          //  "." = owner itself
        struct { char soa_mname[256];                // SOA (RFC 1035
                 char soa_rname[256];                //  §3.3.13, RFC 2308)
                 uint32_t soa_serial, soa_refresh, soa_retry, soa_expire;
                 uint32_t soa_minimum;               // negative-caching TTL
                 uint32_t soa_ttl; };                // TTL of the SOA RR
    };
};

/* The authoritative record store: a heap array sorted by owner name (records
 * of one owner are contiguous, in file order).  Defined in auth_zonefile.c,
 * which owns loading; swapped as a whole on reload.  Guard with
 * g_auth_domains_lock. */
extern struct AuthDomain *auth_domains;
extern int auth_domain_count;

/* Check if domain should be handled authoritatively.
 * Returns a response Packet, or NULL to forward to upstream. */
struct Packet* check_internal(struct Packet* request);

/* Load authoritative domains from file.  Call before threads start.
 * Returns number of records loaded, 0 if none, -1 on I/O error. */
int load_auth_domains(const char* filename);

/* Reload under write-lock (SIGHUP handler). */
void reload_auth_domains(const char* filename);


#endif // AUTH_H
