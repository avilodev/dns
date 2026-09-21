#include "dns_packet.h"
#include "dns_name.h"
#include "dns_wire.h"
#include "utils.h"

void packet_read_header(struct Packet* pkt, const uint8_t* m)
{
    uint16_t flags = rd16(m + 2);
    pkt->id      = rd16(m);
    pkt->qr      = (flags >> 15) & 1;
    pkt->opcode  = (flags >> 11) & 0xF;
    pkt->aa      = (flags >> 10) & 1;
    pkt->tc      = (flags >> 9) & 1;
    pkt->rd      = (flags >> 8) & 1;
    pkt->ad      = (flags >> 5) & 1;
    pkt->cd      = (flags >> 4) & 1;
    pkt->rcode   = flags & 0xF;
    pkt->qdcount = rd16(m + 4);
    pkt->ancount = rd16(m + 6);
    pkt->nscount = rd16(m + 8);
    pkt->arcount = rd16(m + 10);
}

struct Packet* parse_response(const char* buffer, ssize_t recv_len)
{
    if (!buffer || recv_len < HEADER_LEN) return NULL;

    struct Packet* pkt = calloc(1, sizeof(*pkt));
    if (!pkt || !(pkt->request = malloc((size_t)recv_len))) {
        free(pkt);
        return NULL;
    }
    memcpy(pkt->request, buffer, (size_t)recv_len);
    pkt->recv_len = recv_len;

    const uint8_t* m = (const uint8_t*)buffer;
    packet_read_header(pkt, m);

    /* Question, case preserved: matched against what we asked (RFC 5452). */
    if (pkt->qdcount > 0) {
        char domain[DNAME_TEXT_MAX];
        int pos = dname_from_wire(m, (int)recv_len, HEADER_LEN, false, domain, sizeof(domain));
        if (pos >= 0) {
            pkt->full_domain = strdup(domain);
            if (pos + 4 <= recv_len) {
                pkt->q_type  = rd16(m + pos);
                pkt->q_class = rd16(m + pos + 2);
            }
        }
    }
    return pkt;
}

struct Packet* build_query(const char* name, uint16_t qtype, uint16_t qclass)
{
    if (!name) return NULL;
    uint8_t buf[HEADER_LEN + 255 + 4 + OPT_RR_LEN] = {0};

    wr16(buf, (uint16_t)get_random_id());
    wr16(buf + 4, 1);                                   /* QDCOUNT */
    wr16(buf + 10, 1);                                  /* ARCOUNT: our OPT */
    int n = dname_to_wire(name, buf + HEADER_LEN, 255);
    if (n < 0) return NULL;
    int pos = HEADER_LEN + n;
    wr16(buf + pos, qtype);
    wr16(buf + pos + 2, qclass);
    pos += 4;
    /* DO=1 so authorities return RRSIGs; bigger answers come back TC=1. */
    write_opt_rr(buf + pos, true, 0);
    pos += OPT_RR_LEN;

    return parse_response((const char*)buf, pos);
}

void free_packet(struct Packet* pkt)
{
    if (!pkt) return;
    free(pkt->request);
    free(pkt->full_domain);
    free(pkt);
}
