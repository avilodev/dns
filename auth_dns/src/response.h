#ifndef RESPONSE_H
#define RESPONSE_H

#include "types.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/socket.h>

struct auth_domain;  // forward declaration — full definition in auth.h

// Send a DNS response over UDP (works for both IPv4 and IPv6).
int send_response(int sock, struct packet* response,
				  const struct sockaddr* client_addr, socklen_t addr_len);

// Send a DNS response over an established TCP connection.
int send_tcp_response(int fd, struct packet* response);

// Build NXDOMAIN/NODATA responses; a non-NULL soa adds a SOA to authority
struct packet* build_nxdomain_response(struct packet* request,
										const struct auth_domain* soa);
struct packet* build_nodata_response(struct packet* request,
									  const struct auth_domain* soa);
struct packet* build_servfail_response(struct packet* request);
struct packet* build_badvers_response(struct packet* request);
char* extract_ip_from_response(const struct packet* response);

// Echo the question section into a response, advancing *pos.
void echo_question(char* buf, int* pos, const struct packet* request);

// Append an EDNS0 OPT RR to a response if the client sent EDNS
void append_edns_opt(struct packet* response, const struct packet* request);

// Post-process a UDP response before sending: 1.
void finalize_udp_response(struct packet* response, const struct packet* request);

#endif /* RESPONSE_H */