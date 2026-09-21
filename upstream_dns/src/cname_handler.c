#include "cname_handler.h"
#include "dns_name.h"
#include "dns_packet.h"
#include "dns_wire.h"
#include "response_handler.h"

#include <ctype.h>
#include <strings.h>

bool check_cname_loop(const CnameChain* chain, const char* domain)
{
    if (!chain || !domain) return false;
    for (int i = 0; i < chain->count; i++)
        if (chain->domains[i] && strcasecmp(chain->domains[i], domain) == 0)
            return true;
    return false;
}

void cname_chain_add(CnameChain* chain, const char* domain)
{
    if (chain && chain->count < MAX_CNAME_DEPTH && (chain->domains[chain->count] = strdup(domain)))
        chain->count++;
}

void free_cname_chain(CnameChain* chain)
{
    if (!chain) return;
    for (int i = 0; i < chain->count; i++) {
        free(chain->domains[i]);
        chain->domains[i] = NULL;
    }
    chain->count = 0;
}

/* ---- Message writer with name compression (RFC 1035 §4.1.4) ----------- */

#define MAX_NAME_OFFS 512

typedef struct {
    uint8_t* buf;
    int cap, pos;
    int offs[MAX_NAME_OFFS];   /* label starts of names written so far */
    int noffs;
} MsgWriter;

/* Pointers may only target recorded label starts, never RDATA bytes that
 * happen to look like a name (legal, but trips strict parsers). */
static void note_name(MsgWriter* w, int off)
{
    while (off < w->pos && off < 0x4000 && w->noffs < MAX_NAME_OFFS) {
        uint8_t l = w->buf[off];
        if (l == 0 || (l & 0xC0)) return;
        w->offs[w->noffs++] = off;
        off += 1 + l;
    }
}

/* Does the (possibly compressed) name at buf[off] equal wire name `want`,
 * ignoring ASCII case?  Wire compare keeps "a\.b" distinct from "a.b". */
static bool wire_name_equals(const uint8_t* buf, int len, int off, const uint8_t* want)
{
    int w = 0, hops = 0;
    while (off < len) {
        uint8_t l = buf[off];
        if ((l & 0xC0) == 0xC0) {
            if (off + 1 >= len || ++hops > 64) return false;
            off = ((l & 0x3F) << 8) | buf[off + 1];
            continue;
        }
        if (l > 63 || l != want[w]) return false;
        if (l == 0) return true;
        if (off + 1 + l > len) return false;
        for (int k = 1; k <= l; k++)
            if (tolower(buf[off + k]) != tolower(want[w + k])) return false;
        off += 1 + l;
        w += 1 + l;
    }
    return false;
}

/* Write `name`, replacing its longest already-written suffix with a pointer. */
static bool put_name(MsgWriter* w, const char* name)
{
    uint8_t wire[256];
    int wlen = dname_to_wire(name, wire, sizeof(wire));
    if (wlen < 0) return false;
    int start = w->pos;

    for (int off = 0; wire[off] != 0; off += 1 + wire[off]) {
        for (int k = 0; k < w->noffs; k++) {
            int target = w->offs[k];
            if (!wire_name_equals(w->buf, start, target, wire + off)) continue;
            if (start + off + 2 > w->cap) return false;
            memcpy(w->buf + start, wire, (size_t)off);           /* leading labels */
            wr16(w->buf + start + off, (uint16_t)(0xC000 | target));
            w->pos = start + off + 2;
            note_name(w, start);
            return true;
        }
    }
    if (start + wlen > w->cap) return false;
    memcpy(w->buf + start, wire, (size_t)wlen);
    w->pos = start + wlen;
    note_name(w, start);
    return true;
}

/* Copy one RR of `src` (owner re-compressed, RDATA names decompressed). */
static bool copy_rr(MsgWriter* w, const struct Packet* src, const DnsRR* rr)
{
    const uint8_t* m = (const uint8_t*)src->request;
    int start = w->pos;
    char* owner = dns_name_text(m, (int)src->recv_len, rr->owner);
    bool ok = owner && put_name(w, owner) &&
              emit_rr_body(m, (int)src->recv_len, rr, w->buf, w->cap, &w->pos);
    free(owner);
    if (!ok) w->pos = start;                            /* drop the partial RR */
    return ok;
}

struct Packet* reconstruct_cname_response(const struct Packet* query,
                                          const char* target, uint32_t ttl,
                                          struct Packet* final_answer)
{
    if (!query || !target || !final_answer || !final_answer->request ||
        final_answer->recv_len < HEADER_LEN)
        return final_answer;

    /* Sized from the final answer (TCP answers can exceed MAXLINE) plus room
     * for decompression; the transport applies UDP limits later. */
    MsgWriter w = { .cap = (int)final_answer->recv_len * 2 + 2048 };
    if (w.cap < MAXLINE) w.cap = MAXLINE;
    struct Packet* out = calloc(1, sizeof(*out));
    w.buf = calloc(1, (size_t)w.cap);
    if (!out || !w.buf) { free(out); free(w.buf); return final_answer; }

    /* Header: our ID, the final answer's AA/RD/RA/AD/CD/RCODE. */
    uint16_t final_flags = rd16(final_answer->request + 2);
    wr16(w.buf, query->id);
    wr16(w.buf + 2, FLAG_QR | (final_flags & (FLAG_AA | FLAG_RD | FLAG_RA | FLAG_AD | FLAG_CD | 0xF)));
    wr16(w.buf + 4, 1);
    w.pos = HEADER_LEN;

    if (!put_name(&w, query->full_domain) || w.pos + 4 > w.cap) {
        free(w.buf); free(out);
        free_packet(final_answer);
        return NULL;
    }
    wr16(w.buf + w.pos, query->q_type);
    wr16(w.buf + w.pos + 2, query->q_class);
    w.pos += 4;

    /* qname CNAME target */
    int an = 0, ns = 0;
    int rr_start = w.pos;
    if (w.pos + 12 <= w.cap) {
        wr16(w.buf + w.pos, 0xC000 | HEADER_LEN);        /* owner: the question */
        wr16(w.buf + w.pos + 2, QTYPE_CNAME);
        wr16(w.buf + w.pos + 4, CLASS_IN);
        wr32(w.buf + w.pos + 6, ttl);
        w.pos += 12;
        if (put_name(&w, target)) {
            wr16(w.buf + rr_start + 10, (uint16_t)(w.pos - rr_start - 12));
            an++;
        } else {
            w.pos = rr_start;
        }
    }

    /* Then the final answer's records: answers, or its authority for NODATA. */
    int want = final_answer->ancount > 0 ? SEC_ANSWER : SEC_AUTHORITY;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, final_answer->request, (int)final_answer->recv_len); rr_next(&it, &rr); ) {
        if (rr.section != want) continue;
        if (!copy_rr(&w, final_answer, &rr)) break;
        if (want == SEC_ANSWER) an++; else ns++;
    }
    wr16(w.buf + 6, (uint16_t)an);
    wr16(w.buf + 8, (uint16_t)ns);

    out->request     = (char*)w.buf;
    out->recv_len    = w.pos;
    out->full_domain = query->full_domain ? strdup(query->full_domain) : NULL;
    out->q_type      = query->q_type;
    out->q_class     = query->q_class;
    packet_read_header(out, w.buf);

    free_packet(final_answer);
    return out;
}
