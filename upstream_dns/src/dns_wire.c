#include "dns_wire.h"
#include "dns_name.h"
#include "types.h"

int dns_name_end(const uint8_t* msg, int len, int pos)
{
    while (pos >= 0 && pos < len) {
        uint8_t l = msg[pos];
        if (l == 0) return pos + 1;
        if ((l & 0xC0) == 0xC0) return pos + 2 <= len ? pos + 2 : -1;
        if (l > 63) return -1;
        pos += 1 + l;
    }
    return -1;
}

char* dns_name_text(const uint8_t* msg, int len, int pos)
{
    char name[DNAME_TEXT_MAX];
    if (!msg || dname_from_wire(msg, len, pos, false, name, sizeof(name)) < 0)
        return NULL;
    return strdup(name);
}

int dns_question_end(const uint8_t* msg, int len)
{
    if (!msg || len < HEADER_LEN) return -1;
    int pos = HEADER_LEN;
    for (int q = rd16(msg + 4); q > 0; q--) {
        pos = dns_name_end(msg, len, pos);
        if (pos < 0 || pos + 4 > len) return -1;
        pos += 4;
    }
    return pos;
}

bool rr_iter_init(RRIter* it, const void* msg, int len)
{
    const uint8_t* m = msg;
    it->msg = m;
    it->len = len;
    it->idx = 0;
    it->pos = dns_question_end(m, len);
    if (it->pos < 0) { it->total = 0; return false; }
    it->an = rd16(m + 6);
    it->ns = rd16(m + 8);
    it->total = it->an + it->ns + rd16(m + 10);
    return true;
}

bool rr_next(RRIter* it, DnsRR* rr)
{
    if (it->idx >= it->total) return false;
    int end = dns_name_end(it->msg, it->len, it->pos);
    if (end < 0 || end + 10 > it->len) { it->total = 0; return false; }

    const uint8_t* f = it->msg + end;
    rr->owner  = it->pos;
    rr->type   = rd16(f);
    rr->rclass = rd16(f + 2);
    rr->ttl    = rd32(f + 4);
    rr->rdlen  = rd16(f + 8);
    rr->rdata  = end + 10;
    if (rr->rdata + rr->rdlen > it->len) { it->total = 0; return false; }

    rr->section = it->idx < it->an              ? SEC_ANSWER
                : it->idx < it->an + it->ns     ? SEC_AUTHORITY
                                                : SEC_ADDITIONAL;
    it->pos = rr->rdata + rr->rdlen;
    it->idx++;
    return true;
}

void write_opt_rr(uint8_t* o, bool do_bit, uint8_t ext_rcode)
{
    o[0] = 0;                                   /* root owner */
    wr16(o + 1, QTYPE_OPT);
    wr16(o + 3, EDNS_UDP_PAYLOAD);              /* CLASS = UDP size */
    o[5] = ext_rcode;
    o[6] = 0;                                   /* version */
    o[7] = do_bit ? 0x80 : 0;                   /* DO */
    o[8] = 0;
    wr16(o + 9, 0);                             /* RDLEN */
}

bool find_opt_rr(const uint8_t* msg, int len, bool* do_bit)
{
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, msg, len); rr_next(&it, &rr); ) {
        if (rr.type == QTYPE_OPT) {
            if (do_bit) *do_bit = (rr.ttl & 0x8000) != 0;
            return true;
        }
    }
    return false;
}
