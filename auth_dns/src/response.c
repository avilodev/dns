#include "response.h"
#include "auth.h"
#include "utils.h"
#include "dns_name.h"   // dname_to_wire
#include "diag.h"
#include <string.h>

// Echo the question section into a response
void echo_question(char* buf, int* pos, const struct packet* request)
{
	if(request->request && request->recv_len > HEADER_LEN) {
		const unsigned char* r = (const unsigned char*)request->request;
		int len = (int)request->recv_len;
		int q = HEADER_LEN;

		while(q < len) {
			unsigned char l = r[q];
			if(l == 0) {
				q++;
				break;
			}   // root label: QNAME ends
			if(l & 0xC0) {
				q = -1;
				break;
			}// compression: shouldn't occur
			q += 1 + l;
		}

		if(q >= HEADER_LEN && q + 4 <= len) {
			int qlen = (q + 4) - HEADER_LEN;     // QNAME + QTYPE + QCLASS
			if(*pos + qlen <= DNS_MSG_MAX) {
				memcpy(buf + *pos, r + HEADER_LEN, (size_t)qlen);
				*pos += qlen;
				return;
			}
		}
	}

	// Fallback: re-encode from the (lowercased) parsed name.
	if(*pos + 5 > DNS_MSG_MAX)
		return;
	if(request->full_domain)
		write_dns_labels(request->full_domain, buf, pos, DNS_MSG_MAX - 4);
	else
		buf[(*pos)++] = 0;
	wr16(buf + *pos, request->q_type);   *pos += 2;
	wr16(buf + *pos, request->q_class);  *pos += 2;
}

// Append a SOA authority record to a response that has its question section
static void append_soa_authority(char* buf, int* pos, const struct auth_domain* soa)
{
	if(!soa)
		return;

	// Build SOA RDATA in a temp buffer: MNAME + RNAME + 5×uint32_t
	char rdata[1024];
	int rdata_len = 0;
	write_dns_labels(soa->soa_mname, rdata, &rdata_len, sizeof(rdata));
	write_dns_labels(soa->soa_rname, rdata, &rdata_len, sizeof(rdata));
	if(rdata_len + 20 > (int)sizeof(rdata))
		return;      // names too long
	wr32(rdata + rdata_len, soa->soa_serial);   rdata_len += 4;
	wr32(rdata + rdata_len, soa->soa_refresh);  rdata_len += 4;
	wr32(rdata + rdata_len, soa->soa_retry);    rdata_len += 4;
	wr32(rdata + rdata_len, soa->soa_expire);   rdata_len += 4;
	wr32(rdata + rdata_len, soa->soa_minimum);  rdata_len += 4;

	// SOA RR TTL: min(soa_ttl, soa_minimum) per RFC 2308 §5
	uint32_t ttl = (soa->soa_ttl < soa->soa_minimum) ? soa->soa_ttl : soa->soa_minimum;

	// Owner name: the zone apex, uncompressed.
	uint8_t owner[256];
	int owner_len = dname_to_wire(soa->domain, owner, sizeof(owner));
	if(owner_len < 0)
		return;
	if(*pos + owner_len + 10 + rdata_len > DNS_MSG_MAX)
		return;

	memcpy(buf + *pos, owner, (size_t)owner_len); *pos += owner_len;
	wr16(buf + *pos, QTYPE_SOA);   *pos += 2;
	wr16(buf + *pos, 1);            *pos += 2;  // CLASS IN
	wr32(buf + *pos, ttl);          *pos += 4;
	wr16(buf + *pos, (uint16_t)rdata_len); *pos += 2;
	memcpy(buf + *pos, rdata, rdata_len);
	*pos += rdata_len;

	// One more authority record (increment, don't assume this is the first)
	wr16(buf + 8, (uint16_t)(rd16(buf + 8) + 1));
}

// Send DNS response to client over UDP.
int send_response(int sock, struct packet* response,
				  const struct sockaddr* client_addr, socklen_t addr_len) {
	if(!response || !response->request || !client_addr) {
		fprintf(stderr, "Error: Invalid parameters for send_response\n");
		return -1;
	}

	ssize_t sent = sendto(sock, response->request, response->recv_len, 0,
						  client_addr, addr_len);

	if(sent < 0) {
		DIAG(DIAG_DEBUG, "Error: Failed to send response to client: %s\n", strerror(errno));
		return -1;
	}

	if(sent != response->recv_len) {
		DIAG(DIAG_DEBUG, "Warning: Partial send to client (%zd/%zd bytes)\n",
				sent, response->recv_len);
		return -1;
	}

	return 0;
}

// Send DNS response over an established TCP connection.
int send_tcp_response(int fd, struct packet* response) {
	if(!response || !response->request || response->recv_len <= 0)
		return -1;

	uint16_t len_net = htons((uint16_t)response->recv_len);

	// Write length prefix (2 bytes) — loop to handle short writes
	const uint8_t* p = (const uint8_t*)&len_net;
	size_t rem = 2;
	while(rem > 0) {
		ssize_t n = write(fd, p, rem);
		if(n <= 0) {
			DIAG(DIAG_DEBUG, "Error: Failed to send TCP length prefix: %s\n", strerror(errno));
			return -1;
		}
		p += n; rem -= (size_t)n;
	}

	// Write body — loop to handle short writes
	p = (const uint8_t*)response->request;
	rem = (size_t)response->recv_len;
	while(rem > 0) {
		ssize_t n = write(fd, p, rem);
		if(n <= 0) {
			DIAG(DIAG_DEBUG, "Error: Failed to send TCP response body: %s\n", strerror(errno));
			return -1;
		}
		p += n; rem -= (size_t)n;
	}

	return 0;
}

// Build an NXDOMAIN response, with a SOA in authority if soa is non-NULL
struct packet* build_nxdomain_response(struct packet* request,
										const struct auth_domain* soa) {
	if(!request)
		return NULL;

	struct packet* response = calloc(1, sizeof(struct packet));
	if(!response) {
		perror("Error: Failed to allocate response packet");
		return NULL;
	}

	response->request = calloc(1, DNS_MSG_MAX);
	if(!response->request) {
		perror("Error: Failed to allocate response buffer");
		free(response);
		return NULL;
	}

	int pos = 0;

	// Copy transaction ID from request
	memcpy(response->request + pos, request->request, 2);
	pos += 2;

	// Set response flags with NXDOMAIN
	uint16_t flags = 0;
	flags |= (1 << 15);           // Response
	flags |= (1 << 10);           // Authoritative Answer
	flags |= (request->rd << 8);  // Copy recursion desired
	flags |= (request->cd << 4);  // Copy CD (RFC 4035 §3.2.2)
	flags |= (1 << 7);            // Recursion Available
	flags |= RCODE_NAME_ERROR;    // RCODE: NXDOMAIN = 3
	wr16(response->request + pos, flags);
	pos += 2;

	// Set counts (NSCOUNT updated to 1 by append_soa_authority when soa != NULL)
	wr16(response->request + pos, 1);  // 1 question
	pos += 2;
	wr16(response->request + pos, 0);  // 0 answers
	pos += 2;
	wr16(response->request + pos, 0);  // 0 authority (updated below)
	pos += 2;
	wr16(response->request + pos, 0);  // 0 additional
	pos += 2;

	// Echo the question verbatim (preserves QNAME case — 4.8)
	echo_question(response->request, &pos, request);

	// Append SOA in authority section (RFC 2308 §3)
	if(soa)
		append_soa_authority(response->request, &pos, soa);

	response->recv_len = pos;

	return response;
}

// Build NODATA response (domain exists, but no records of the requested type).
struct packet* build_nodata_response(struct packet* request,
									  const struct auth_domain* soa) {
	if(!request)
		return NULL;

	struct packet* response = calloc(1, sizeof(struct packet));
	if(!response) {
		perror("Error: Failed to allocate response packet");
		return NULL;
	}

	response->request = calloc(1, DNS_MSG_MAX);
	if(!response->request) {
		perror("Error: Failed to allocate response buffer");
		free(response);
		return NULL;
	}

	int pos = 0;

	memcpy(response->request + pos, request->request, 2);
	pos += 2;

	uint16_t flags = 0;
	flags |= (1 << 15);           // QR: Response
	flags |= (1 << 10);           // AA: Authoritative Answer
	flags |= (request->rd << 8);  // Copy recursion desired
	flags |= (request->cd << 4);  // Copy CD (RFC 4035 §3.2.2)
	flags |= (1 << 7);            // RA: Recursion Available
	flags |= RCODE_NO_ERROR;      // RCODE: 0 (no error, but no data)
	wr16(response->request + pos, flags);
	pos += 2;

	// NSCOUNT updated to 1 by append_soa_authority when soa != NULL
	wr16(response->request + pos, 1);  // 1 question
	pos += 2;
	wr16(response->request + pos, 0);  // 0 answers
	pos += 2;
	wr16(response->request + pos, 0);  // 0 authority (updated below)
	pos += 2;
	wr16(response->request + pos, 0);  // 0 additional
	pos += 2;

	// Echo the question verbatim (preserves QNAME case — 4.8)
	echo_question(response->request, &pos, request);

	// Append SOA in authority section (RFC 2308 §3)
	if(soa)
		append_soa_authority(response->request, &pos, soa);

	response->recv_len = pos;

	return response;
}

// Build SERVFAIL response (RCODE=2, server failure).
struct packet* build_servfail_response(struct packet* request) {
	if(!request)
		return NULL;

	struct packet* response = calloc(1, sizeof(struct packet));
	if(!response) {
		perror("Error: Failed to allocate response packet");
		return NULL;
	}

	response->request = calloc(1, DNS_MSG_MAX);
	if(!response->request) {
		perror("Error: Failed to allocate response buffer");
		free(response);
		return NULL;
	}

	int pos = 0;

	memcpy(response->request + pos, request->request, 2);
	pos += 2;

	uint16_t flags = 0;
	flags |= (1 << 15);               // QR: Response
	flags |= (request->rd << 8);      // Copy recursion desired
	flags |= (request->cd << 4);      // Copy CD
	flags |= (1 << 7);                // RA: Recursion Available
	flags |= RCODE_SERVER_FAILURE;    // RCODE: 2 (SERVFAIL)
	wr16(response->request + pos, flags);
	pos += 2;

	wr16(response->request + pos, 1);  // 1 question
	pos += 2;
	wr16(response->request + pos, 0);  // 0 answers
	pos += 2;
	wr16(response->request + pos, 0);
	pos += 2;
	wr16(response->request + pos, 0);
	pos += 2;

	// Echo the question verbatim (preserves QNAME case — 4.8)
	echo_question(response->request, &pos, request);

	response->recv_len = pos;

	return response;
}

// Build BADVERS response (extended RCODE=16, RFC 6891 §6.1.3).
struct packet* build_badvers_response(struct packet* request) {
	if(!request)
		return NULL;

	struct packet* response = calloc(1, sizeof(struct packet));
	if(!response) {
		perror("Error: Failed to allocate BADVERS response");
		return NULL;
	}

	response->request = calloc(1, DNS_MSG_MAX);
	if(!response->request) {
		perror("Error: Failed to allocate BADVERS response buffer");
		free(response);
		return NULL;
	}

	int pos = 0;

	memcpy(response->request + pos, request->request, 2);   // TX ID
	pos += 2;

	// Flags: QR=1, RD copy, RA=1, RCODE=0 (extended RCODE in OPT)
	uint16_t flags = 0;
	flags |= (1u << 15);              // QR
	flags |= ((unsigned)request->rd << 8); // RD
	flags |= ((unsigned)request->cd << 4); // CD
	flags |= (1u << 7);              // RA
	wr16(response->request + pos, flags);
	pos += 2;

	wr16(response->request + pos, 1);   // QDCOUNT = 1
	pos += 2;
	wr16(response->request + pos, 0);   // ANCOUNT = 0
	pos += 2;
	wr16(response->request + pos, 0);   // NSCOUNT = 0
	pos += 2;
	wr16(response->request + pos, 1);   // ARCOUNT = 1 (OPT)
	pos += 2;

	// Question section — echo verbatim to preserve QNAME case (4.8)
	echo_question(response->request, &pos, request);

	// OPT RR: root name, type 41, payload, TTL = BADVERS ext RCODE, RDLEN 0
	if(pos + 11 <= DNS_MSG_MAX) {
		response->request[pos++] = 0x00;                              // root name
		wr16(response->request + pos, 41);            pos += 2; // OPT
		wr16(response->request + pos, EDNS_UDP_PAYLOAD); pos += 2; // payload
		// The OPT extended-RCODE byte holds the UPPER 8 bits of the 12-bit RCODE
		wr32(response->request + pos, (uint32_t)(RCODE_BADVERS >> 4) << 24); pos += 4;
		wr16(response->request + pos, 0);             pos += 2; // RDLEN=0
	}

	response->recv_len = pos;

	return response;
}

// Skip a wire-format name at pos; return the offset past it, or -1
static int skip_wire_name(const unsigned char* buf, int len, int pos)
{
	while(pos >= 0 && pos < len) {
		uint8_t l = buf[pos];
		if(l == 0)
			return pos + 1;
		if((l & 0xC0) == 0xC0)
			return pos + 2;   // compression pointer
		pos += 1 + l;
	}

	return -1;
}

// Returns 1 if the DNS message already contains an OPT (type 41) RR.
static int message_has_opt(const unsigned char* buf, int len)
{
	if(!buf || len < HEADER_LEN)
		return 0;
	uint16_t qd = rd16(buf + 4);
	uint16_t an = rd16(buf + 6);
	uint16_t ns = rd16(buf + 8);
	uint16_t ar = rd16(buf + 10);

	int pos = HEADER_LEN;

	for(int i = 0; i < qd; i++) {
		pos = skip_wire_name(buf, len, pos);
		if(pos < 0 || pos + 4 > len)
			return 0;
		pos += 4;                                   // QTYPE + QCLASS
	}

	long rr = (long)an + ns + ar;
	for(long i = 0; i < rr; i++) {
		pos = skip_wire_name(buf, len, pos);
		if(pos < 0 || pos + 10 > len)
			return 0;
		uint16_t type  = rd16(buf + pos);
		uint16_t rdlen = rd16(buf + pos + 8);
		if(type == 41)
			return 1;                   // OPT
		pos += 10 + rdlen;
	}

	return 0;
}

// append_edns_opt — append an EDNS0 OPT RR mirroring the client's request
void append_edns_opt(struct packet *response, const struct packet *request)
{
	if(!response || !response->request || !request)
		return;
	if(!request->edns_present)
		return;
	if(message_has_opt((const unsigned char*)response->request,
						(int)response->recv_len))
		return;

	int pos = (int)response->recv_len;
	if(pos + 11 > DNS_MSG_MAX)
		return;
	response->request[pos++] = 0x00;                          // root name
	wr16(response->request + pos, 41);        pos += 2; // OPT
	wr16(response->request + pos, EDNS_UDP_PAYLOAD); pos += 2; // payload
	// TTL: [ext_rcode=0][version=0][flags] — mirror DO bit
	uint32_t opt_ttl = request->do_bit ? 0x00008000u : 0u;
	wr32(response->request + pos, opt_ttl);   pos += 4;
	wr16(response->request + pos, 0);         pos += 2; // RDLEN=0
	response->recv_len = pos;
	uint16_t arcount = rd16(response->request + 10);
	wr16(response->request + 10, arcount + 1);
}

// finalize_udp_response — post-processing for all UDP responses.
void finalize_udp_response(struct packet *response, const struct packet *request)
{
	if(!response || !response->request || !request)
		return;

	// 1. Append EDNS0 OPT RR if client sent EDNS
	append_edns_opt(response, request);

	// 2. Truncate if response exceeds UDP payload limit
	int udp_limit = request->edns_present ? (int)request->edns_udp_size : 512;
	if(udp_limit < 512)
		udp_limit = 512;          // minimum enforced by RFC
	// Never send more than we advertise: avoids IP fragmentation
	if(udp_limit > EDNS_UDP_PAYLOAD)
		udp_limit = EDNS_UDP_PAYLOAD;

	if((int)response->recv_len > udp_limit) {
		// Walk to end of question section (QNAME labels + QTYPE + QCLASS).
		int qend = HEADER_LEN;
		const char *buf = response->request;
		while(qend < (int)response->recv_len) {
			uint8_t llen = (uint8_t)buf[qend];
			if(llen == 0) {
				qend++;
				break;
			}    // null terminator
			if((llen & 0xC0) == 0xC0) {
				qend += 2;
				break;
			} // compression ptr
			qend += 1 + llen;
		}

		qend += 4; // QTYPE (2) + QCLASS (2)

		// Set TC=1 (bit 9 of flags word, 0-indexed from MSB).
		uint16_t flags = rd16(response->request + 2);
		flags |= (1u << 9);
		wr16(response->request + 2, flags);
		wr16(response->request + 6, 0);   // ANCOUNT = 0
		wr16(response->request + 8, 0);   // NSCOUNT = 0

		// RFC 6891 §7: every response to an EDNS query must carry an OPT record
		if(request->edns_present && qend + 11 <= DNS_MSG_MAX) {
			char *p = response->request + qend;
			p[0] = 0x00;                                          // root name
			wr16(p + 1, 41);                      // OPT
			wr16(p + 3, EDNS_UDP_PAYLOAD);        // payload
			uint32_t opt_ttl = request->do_bit ? 0x00008000u : 0u;
			wr32(p + 5, opt_ttl);                 // TTL/flags
			wr16(p + 9, 0);                       // RDLEN = 0
			wr16(response->request + 10, 1);      // ARCOUNT = 1
			response->recv_len = qend + 11;
		} else {
			wr16(response->request + 10, 0);             // ARCOUNT = 0
			response->recv_len = qend;
		}
	}
}
