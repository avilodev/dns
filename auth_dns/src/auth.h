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

// DNS name compression pointer to the QNAME in the question section
#define DNS_NAME_PTR ((uint16_t)(0xC000u | (unsigned)(HEADER_LEN)))

// Reader-writer lock protecting the auth_domains array.
extern pthread_rwlock_t g_auth_domains_lock;

// AuthDomain: one flat record entry.
struct auth_domain {
	char     domain[256];      // Owner name (lowercased)
	bool     is_wildcard;      // true → domain is "*.parent.zone"
	uint32_t ttl;              // Per-record TTL override (0 = DEFAULT_RECORD_TTL)

	// Record type flags: exactly one is set.
	bool     has_a, has_ipv6, has_cname, has_mx, has_ns, has_txt, has_srv,
			 has_https, has_soa;

	// A record address (valid only when has_a).
	char     ip[16];

	// Type-specific data.
	union {
		char ipv6[INET6_ADDRSTRLEN];                 // AAAA (46: the longest form is "…:255.255.255.255")
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

// The authoritative record store: a heap array sorted by owner name.
extern struct auth_domain *auth_domains;
extern int auth_domain_count;

// Check if domain should be handled authoritatively.
struct packet* check_internal(struct packet* request);

// Load authoritative domains from file.
int load_auth_domains(const char* filename);

// Reload under write-lock (SIGHUP handler).
void reload_auth_domains(const char* filename);

#endif /* AUTH_H */
