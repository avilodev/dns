#ifndef AUTH_H
#define AUTH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include "types.h"

// Structure to hold authoritative domain information
struct AuthDomain {
    char domain[256];
    char ip[16];          // IPv4 address
    char ipv6[40];        // IPv6 address (AAAA record)
    bool is_blocked;
    bool has_ipv6;        // Whether this domain has an AAAA record
    // MX record fields
    bool has_mx;
    char mx_hostname[256];
    uint16_t mx_priority;
};

/**
 * Check if domain should be handled as authoritative
 * @param request Parsed DNS request
 * @return Response packet if authoritative, NULL otherwise
 */
struct Packet* check_internal(struct Packet* request);

/**
 * Load authoritative domains from file
 * @param filename Path to auth domains file
 * @return Number of domains loaded, -1 on error
 */
int load_auth_domains(const char* filename);

/**
 * Lookup authoritative domain and return IP
 * @param full_domain Full domain name to lookup
 * @return IP address string, "NXDOMAIN" if blocked, NULL if not found
 */
const char* lookup_auth_domain(const char* full_domain);

#endif // AUTH_H