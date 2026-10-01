#include "request.h"
#include "dns_name.h"
#include "dns_wire.h"

// false if OPT is repeated or misplaced (RFC 6891 6.1.1)
static bool scan_client_opt(struct packet* pkt, const uint8_t* m, int len)
{
	int opt_count = 0;
	bool ok = true;

	rr_iter it; dns_rr rr;
	for(rr_iter_init(&it, m, len); rr_next(&it, &rr); ) {
		if(rr.type != QTYPE_OPT)
			continue;
		if(++opt_count > 1 || m[rr.owner] != 0 || rr.section != SEC_ADDITIONAL)
			ok = false;
		pkt->edns_present  = true;
		pkt->edns_udp_size = rr.rclass;                 // CLASS = UDP size
		pkt->edns_version  = (uint8_t)(rr.ttl >> 16);
		pkt->do_bit        = (rr.ttl & 0x8000) != 0;
	}

	return ok;
}

struct packet* parse_request_headers(char* buffer, ssize_t recv_len)
{
	if(!buffer || recv_len < HEADER_LEN)
		return NULL;
	const uint8_t* m = (const uint8_t*)buffer;

	struct packet* pkt = calloc(1, sizeof(*pkt));
	if(!pkt)
		return NULL;
	packet_read_header(pkt, m);

	if(pkt->qr)
		goto drop;                             // a response
	if(pkt->opcode != 0) {
		pkt->rcode = RCODE_NOTIMP;
		return pkt;
	}
	if(pkt->qdcount != 1) {
		pkt->rcode = RCODE_FORMAT_ERROR;
		return pkt;
	}

	// no compression allowed in the question
	for(int p = HEADER_LEN; ; p += 1 + m[p]) {
		if(p >= recv_len || (m[p] & 0xC0))
			goto drop;
		if(m[p] == 0)
			break;
	}

	char domain[DNAME_TEXT_MAX];
	int pos = dname_from_wire(m, (int)recv_len, HEADER_LEN, true, domain, sizeof(domain));
	if(pos < 0 || pos + 4 > recv_len || !(pkt->full_domain = strdup(domain)))
		goto drop;
	pkt->q_type  = rd16(m + pos);
	pkt->q_class = rd16(m + pos + 2);
	int question_end = pos + 4;

	// e.g. CH version.bind
	if(pkt->q_class != CLASS_IN && pkt->q_class != CLASS_ANY) {
		pkt->rcode = RCODE_NOTIMP;
		return pkt;
	}
	if(!scan_client_opt(pkt, m, (int)recv_len) || pkt->q_type == QTYPE_OPT) {
		pkt->rcode = RCODE_FORMAT_ERROR;
		return pkt;
	}
	// TKEY/TSIG/IXFR/AXFR/MAILB/MAILA
	if(pkt->q_type >= 249 && pkt->q_type <= 254) {
		pkt->rcode = RCODE_NOTIMP;
		return pkt;
	}

	// keep header + question only
	pkt->request = malloc((size_t)question_end);
	if(!pkt->request)
		goto drop;
	memcpy(pkt->request, buffer, (size_t)question_end);
	memset(pkt->request + 6, 0, 6);                     // AN/NS/AR = 0
	pkt->recv_len = question_end;
	pkt->ancount = pkt->nscount = pkt->arcount = 0;

	return pkt;

drop:
	free_packet(pkt);

	return NULL;
}
