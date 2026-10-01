#include "request.h"
#include "dns_name.h"
#include "diag.h"

// Parse a raw DNS request buffer into a Packet struct.
struct packet* parse_request_headers(char* buffer, ssize_t recv_len) {
	if(!buffer) {
		fprintf(stderr, "Error: NULL buffer provided\n");
		return NULL;
	}

	if(recv_len < HEADER_LEN) {
		DIAG(DIAG_DEBUG, "Error: Buffer too short for DNS header (%zd bytes)\n", recv_len);
		return NULL;
	}

	struct packet* pkt = calloc(1, sizeof(struct packet));
	if(!pkt) {
		perror("Error: Memory allocation failed for packet");
		return NULL;
	}

	// Copy raw request
	pkt->request = malloc(recv_len);
	if(!pkt->request) {
		perror("Error: Memory allocation failed for request buffer");
		free(pkt);
		return NULL;
	}
	memcpy(pkt->request, buffer, recv_len);
	pkt->recv_len = recv_len;

	// Parse DNS header (12 bytes, all fields in network byte order)
	pkt->id = rd16(buffer + 0);
	pkt->flags = rd16(buffer + 2);
	pkt->qdcount = rd16(buffer + 4);
	pkt->ancount = rd16(buffer + 6);
	pkt->nscount = rd16(buffer + 8);
	pkt->arcount = rd16(buffer + 10);

	// Extract individual flag bits
	pkt->qr = (pkt->flags >> 15) & 0x1;
	pkt->opcode = (pkt->flags >> 11) & 0xF;
	pkt->aa = (pkt->flags >> 10) & 0x1;
	pkt->tc = (pkt->flags >> 9) & 0x1;
	pkt->rd = (pkt->flags >> 8) & 0x1;
	pkt->ra = (pkt->flags >> 7) & 0x1;
	pkt->z = (pkt->flags >> 6) & 0x1;
	pkt->ad = (pkt->flags >> 5) & 0x1;
	pkt->cd = (pkt->flags >> 4) & 0x1;
	pkt->rcode = pkt->flags & 0xF;

	// Drop response packets — a QR=1 packet arriving as a query is invalid
	if(pkt->qr == 1) {
		free_packet(pkt);
		return NULL;
	}

	// Only standard queries (opcode=0) supported; flag others for NOTIMP reply
	if(pkt->opcode != 0) {
		pkt->rcode = RCODE_NOTIMP;
		return pkt;
	}

	// Validate question count — exactly one question (RFC 1035).
	if(pkt->qdcount != 1) {
		DIAG(DIAG_DEBUG, "Error: qdcount=%u (expected 1) — FORMERR\n", pkt->qdcount);
		pkt->rcode = RCODE_FORMAT_ERROR;
		return pkt;
	}

	// Question name: literal labels only, decoded to escaped lowercase text
	for(int p = HEADER_LEN; ; ) {
		if(p >= recv_len) {
			DIAG(DIAG_DEBUG, "Error: Question name runs past the packet\n");
			free_packet(pkt);
			return NULL;
		}
		uint8_t l = (uint8_t)buffer[p];
		if(l == 0)
			break;
		if(l & 0xC0) {
			DIAG(DIAG_DEBUG, "Error: Unexpected compression in question section\n");
			free_packet(pkt);
			return NULL;
		}
		p += 1 + l;
	}

	char domain[DNAME_TEXT_MAX];
	int pos = dname_from_wire((const uint8_t*)buffer, (int)recv_len, HEADER_LEN, true,
							  domain, sizeof(domain));
	if(pos < 0) {
		DIAG(DIAG_DEBUG, "Error: Malformed question name\n");
		free_packet(pkt);
		return NULL;
	}
	// The root query keeps the historical empty-string form
	pkt->full_domain = strdup(strcmp(domain, ".") == 0 ? "" : domain);
	if(!pkt->full_domain) {
		perror("Error: Failed to allocate domain string");
		free_packet(pkt);
		return NULL;
	}

	// Parse question type and class
	if(pos + 4 > recv_len) {
		DIAG(DIAG_DEBUG, "Error: Buffer too short for question type/class\n");
		free_packet(pkt);
		return NULL;
	}

	pkt->q_type = rd16(buffer + pos);
	pkt->q_class = rd16(buffer + pos + 2);

	// Only IN (1) and QCLASS ANY (255) are served.
	if(pkt->q_class != 1 && pkt->q_class != 255) {
		pkt->rcode = RCODE_NOTIMP;
		return pkt;
	}

	// Walk every RR after the question looking for the EDNS0 OPT record.
	pos += 4; // advance past QTYPE + QCLASS
	int qend = pos;
	{
		int total    = (int)pkt->ancount + (int)pkt->nscount + (int)pkt->arcount;
		int ar_start = (int)pkt->ancount + (int)pkt->nscount;
		int opt_count = 0;
		bool opt_bad = false;

		for(int rri = 0; rri < total && pos < recv_len; rri++) {
			bool root_owner = ((uint8_t)buffer[pos] == 0);
			while(pos < recv_len) {                 // skip owner name
				uint8_t llen = (uint8_t)buffer[pos];
				if(llen == 0) {
					pos++;
					break;
				}
				if((llen & 0xC0) == 0xC0) {
					pos += 2;
					break;
				}
				pos += 1 + llen;
			}

			if(pos + 10 > recv_len)
				break;
			uint16_t rr_type  = rd16(buffer + pos);     pos += 2;
			uint16_t rr_class = rd16(buffer + pos);     pos += 2;
			uint32_t rr_ttl   = rd32(buffer + pos);     pos += 4;
			uint16_t rr_rdlen = rd16(buffer + pos);     pos += 2;

			if(rr_type == 41) { // OPT
				if(++opt_count > 1 || !root_owner || rri < ar_start)
					opt_bad = true;
				pkt->edns_present  = 1;
				pkt->edns_udp_size = rr_class ? rr_class : 512; // CLASS = UDP payload size
				pkt->edns_version  = (uint8_t)((rr_ttl >> 16) & 0xFF);
				pkt->do_bit        = (rr_ttl >> 15) & 1;
			}

			if(pos + rr_rdlen > recv_len)
				break;
			pos += rr_rdlen;
		}

		// QTYPE OPT is not a valid question either.
		if(opt_bad || pkt->q_type == 41) {
			pkt->rcode = RCODE_FORMAT_ERROR;
			return pkt;
		}
		// Zone transfers are not offered; the other meta types are NOTIMP.
		if(pkt->q_type == 251 || pkt->q_type == 252) {
			pkt->rcode = RCODE_REFUSED;
			return pkt;
		}
		if(pkt->q_type >= 249 && pkt->q_type <= 254) {
			pkt->rcode = RCODE_NOTIMP;
			return pkt;
		}
	}

	// Keep only header + question (+ a fresh OPT for EDNS clients).
	{
		int keep = qend + (pkt->edns_present ? 11 : 0);
		char* clean = malloc((size_t)keep);
		if(!clean) {
			perror("Error: Failed to allocate clean request buffer");
			free_packet(pkt);
			return NULL;
		}
		memcpy(clean, buffer, (size_t)qend);
		wr16(clean + 6, 0);                              // ANCOUNT
		wr16(clean + 8, 0);                              // NSCOUNT
		wr16(clean + 10, pkt->edns_present ? 1 : 0);     // ARCOUNT
		if(pkt->edns_present) {
			char* o = clean + qend;
			o[0] = 0;                                    // root owner
			wr16(o + 1, 41);                             // OPT
			wr16(o + 3, EDNS_UDP_PAYLOAD);               // UDP payload
			wr32(o + 5, pkt->do_bit ? 0x00008000u : 0u); // ver 0, DO
			wr16(o + 9, 0);                              // RDLEN
		}

		free(pkt->request);
		pkt->request  = clean;
		pkt->recv_len = keep;
		pkt->ancount = pkt->nscount = 0;
		pkt->arcount = pkt->edns_present ? 1 : 0;
	}

	return pkt;
}
