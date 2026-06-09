#ifndef RESPONSE_H
#define RESPONSE_H

#include "types.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/socket.h>

struct AuthDomain;  /* forward declaration — full definition in auth.h */

/* Send a DNS response over UDP (works for both IPv4 and IPv6). */
int send_response(int sock, struct Packet* response,
                  const struct sockaddr* client_addr, socklen_t addr_len);

/* Send a DNS response over an established TCP connection (2-byte length prefix). */
int send_tcp_response(int fd, struct Packet* response);

/*
 * build_nxdomain_response / build_nodata_response:
 *   soa: if non-NULL, appends a SOA record in the authority section (RFC 2308).
 *        The SOA TTL used is min(soa->soa_ttl, soa->soa_minimum) per RFC 2308 §5.
 */
struct Packet* build_nxdomain_response(struct Packet* request,
                                        const struct AuthDomain* soa);
struct Packet* build_nodata_response(struct Packet* request,
                                      const struct AuthDomain* soa);
struct Packet* build_servfail_response(struct Packet* request);
struct Packet* build_badvers_response(struct Packet* request);
char* extract_ip_from_response(struct Packet* response);

/*
 * Echo the question section (QNAME + QTYPE + QCLASS) into a response, advancing
 * *pos.  Copies the original question bytes verbatim from request->request so
 * the client's QNAME case is preserved (RFC 1035 §4.1.2; matters for 0x20
 * mixed-case anti-spoofing — known_issues 4.8).  Falls back to re-encoding from
 * the lowercased full_domain for internally-built requests with no wire copy.
 */
void echo_question(char* buf, int* pos, const struct Packet* request);

/*
 * Append an EDNS0 OPT RR to a response if the client sent EDNS (RFC 6891
 * §6.1.1), mirroring the DO bit.  No-op if no EDNS, an OPT is already present,
 * or it won't fit.  Used by both the UDP and TCP send paths.
 */
void append_edns_opt(struct Packet* response, const struct Packet* request);

/*
 * Post-process a UDP response before sending:
 *   1. Append an EDNS0 OPT RR if the client sent one (RFC 6891 §6.1.1).
 *   2. Set TC=1 and truncate to the question section if the response exceeds
 *      the client's advertised UDP payload size (or 512 without EDNS).
 * Must only be called for UDP responses; TCP has no size limit.
 */
void finalize_udp_response(struct Packet* response, const struct Packet* request);

#endif // RESPONSE_H