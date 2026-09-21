#include "response_handler.h"
#include "config.h"
#include "dns_name.h"
#include "dns_packet.h"

#include <strings.h>

/* Owner name of rr as text; NULL on a malformed name. */
static char* rr_owner(const struct Packet* p, const DnsRR* rr)
{
    return dns_name_text((const uint8_t*)p->request, (int)p->recv_len, rr->owner);
}

static bool has_wire(const struct Packet* p)
{
    return p && p->request && p->recv_len >= HEADER_LEN;
}

bool cname_answer_needs_rechase(struct Packet* response, uint16_t qtype,
                                const char* server_zone)
{
    if (!has_wire(response) || response->ancount == 0) return false;
    const char* zone = server_zone ? server_zone : "";

    bool has_cname = false, has_final = false;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, response->request, (int)response->recv_len);
         rr_next(&it, &rr) && rr.section == SEC_ANSWER; ) {
        if (rr.type == QTYPE_CNAME) {
            has_cname = true;
        } else if (rr.type == qtype || qtype == QTYPE_ANY) {
            /* Only an in-bailiwick owner counts as a real final record. */
            char* owner = rr_owner(response, &rr);
            if (owner && dname_is_subdomain(owner, zone)) has_final = true;
            free(owner);
        }
    }
    return has_cname && !has_final;
}

bool answer_owned_by_question(struct Packet* response)
{
    if (!has_wire(response) || !response->full_domain) return false;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, response->request, (int)response->recv_len);
         rr_next(&it, &rr) && rr.section == SEC_ANSWER; ) {
        char* owner = rr_owner(response, &rr);
        bool match = owner && strcasecmp(owner, response->full_domain) == 0;
        free(owner);
        if (match) return true;
    }
    return false;
}

/* Answer RRs are unordered, so match the CNAME's owner to the question —
 * the first CNAME may be a later hop.  No question: take the first one. */
char* extract_cname_target(struct Packet* response)
{
    if (!has_wire(response) || response->ancount == 0) return NULL;
    const uint8_t* m = (const uint8_t*)response->request;
    const char* qname = response->full_domain;

    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, m, (int)response->recv_len);
         rr_next(&it, &rr) && rr.section == SEC_ANSWER; ) {
        if (rr.type != QTYPE_CNAME || rr.rdlen == 0) continue;
        bool owned = true;
        if (qname) {
            char* owner = rr_owner(response, &rr);
            owned = owner && strcasecmp(owner, qname) == 0;
            free(owner);
        }
        char* target = owned ? dns_name_text(m, (int)response->recv_len, rr.rdata) : NULL;
        if (target) return target;
    }
    return NULL;
}

/* A (4 bytes) or AAAA (16 bytes) RDATA as text. */
static char* addr_text(const uint8_t* rdata, uint16_t type)
{
    char* ip = malloc(INET6_ADDRSTRLEN);
    int af = type == QTYPE_A ? AF_INET : AF_INET6;
    if (ip && !inet_ntop(af, rdata, ip, INET6_ADDRSTRLEN)) { free(ip); ip = NULL; }
    return ip;
}

static bool is_addr_rr(const DnsRR* rr)
{
    return (rr->type == QTYPE_A && rr->rdlen == 4) ||
           (rr->type == QTYPE_AAAA && rr->rdlen == 16);
}

char* extract_ip_from_answer(struct Packet* response, uint16_t qtype)
{
    if (!has_wire(response) || response->ancount == 0) return NULL;
    const uint8_t* m = (const uint8_t*)response->request;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, m, (int)response->recv_len);
         rr_next(&it, &rr) && rr.section == SEC_ANSWER; ) {
        if (rr.type == qtype && is_addr_rr(&rr)) {
            char* ip = addr_text(m + rr.rdata, rr.type);
            if (ip) return ip;
        }
    }
    return NULL;
}

NSCandidateList* extract_all_ns_with_glue(struct Packet* response,
                                          const char* server_zone)
{
    if (!has_wire(response) || response->nscount == 0) return NULL;
    const uint8_t* m = (const uint8_t*)response->request;
    int len = (int)response->recv_len;

    NSCandidateList* list = calloc(1, sizeof(*list));
    if (!list) return NULL;
    list->capacity = response->nscount < MAX_REFERRAL_NS ? response->nscount : MAX_REFERRAL_NS;
    list->glueless_left = MAX_GLUELESS_LOOKUPS;
    list->candidates = calloc((size_t)list->capacity, sizeof(NSCandidate));
    if (!list->candidates) { free(list); return NULL; }

    char* v6_glue[MAX_REFERRAL_NS] = {0};   /* used only when an NS has no A glue */
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, m, len); rr_next(&it, &rr); ) {
        if (rr.section == SEC_AUTHORITY && rr.type == QTYPE_NS && rr.rdlen > 0 &&
            list->count < list->capacity) {
            char* name = dns_name_text(m, len, rr.rdata);
            if (name) list->candidates[list->count++].ns_name = name;
            continue;
        }
        if (rr.section != SEC_ADDITIONAL || !is_addr_rr(&rr)) continue;

        char* owner = rr_owner(response, &rr);
        if (!owner || !dname_is_subdomain(owner, server_zone)) { free(owner); continue; }
        for (int i = 0; i < list->count; i++) {
            NSCandidate* c = &list->candidates[i];
            if (strcasecmp(owner, c->ns_name) != 0) continue;
            char** slot = rr.type == QTYPE_A ? &c->ns_ip : &v6_glue[i];
            if (!*slot) *slot = addr_text(m + rr.rdata, rr.type);   /* first wins */
        }
        free(owner);
    }

    for (int i = 0; i < list->count; i++) {
        if (!list->candidates[i].ns_ip) list->candidates[i].ns_ip = v6_glue[i];
        else                            free(v6_glue[i]);
    }
    return list;
}

void free_ns_candidate_list(NSCandidateList* list)
{
    if (!list) return;
    for (int i = 0; i < list->count; i++) {
        free(list->candidates[i].ns_name);
        free(list->candidates[i].ns_ip);
    }
    free(list->candidates);
    free(list);
}

/* Filter by type: signed referrals put NSEC/RRSIG in the authority section too. */
char* extract_zone_apex(struct Packet* response)
{
    if (!has_wire(response) || response->nscount == 0) return NULL;
    RRIter it; DnsRR rr;
    for (rr_iter_init(&it, response->request, (int)response->recv_len); rr_next(&it, &rr); )
        if (rr.section == SEC_AUTHORITY && rr.type == QTYPE_NS)
            return rr_owner(response, &rr);
    return NULL;
}

struct Packet* build_root_hints_response(struct Packet* query)
{
    if (!has_wire(query)) return NULL;
    int qend = dns_question_end((const uint8_t*)query->request, (int)query->recv_len);
    if (qend < 0) return NULL;

    char names[ROOT_SERVERS][256];
    int count = hints_copy_names(names);

    uint8_t buf[MAXLINE];
    memcpy(buf, query->request, (size_t)qend);
    /* Served from the hints file, so this is a recursive answer, not an
     * authoritative one: RA, RD echoed, and no AA. */
    wr16(buf + 2, (uint16_t)(FLAG_QR | FLAG_RA |
                             (rd16((const uint8_t*)query->request + 2) & FLAG_RD)));
    memset(buf + 6, 0, 6);                   /* counts: set below */

    int pos = qend, written = 0;
    for (int i = 0; i < count; i++) {
        int n = dname_to_wire(names[i], buf + pos + 12, (int)sizeof(buf) - pos - 12);
        if (n < 0) continue;
        wr16(buf + pos, 0xC000 | HEADER_LEN); /* owner: pointer to "." */
        wr16(buf + pos + 2, QTYPE_NS);
        wr16(buf + pos + 4, CLASS_IN);
        wr32(buf + pos + 6, 518400);         /* 6 days, as in the root zone */
        wr16(buf + pos + 10, (uint16_t)n);
        pos += 12 + n;
        written++;
    }
    wr16(buf + 6, (uint16_t)written);
    return parse_response((const char*)buf, pos);
}

/* ---- Decompressing record copy ---------------------------------------- */

/* Copy the name at in[off] uncompressed to out[*op].  Pointers must point
 * backwards.  Returns the input offset past the name as stored, or -1. */
static int copy_name_decompressed(const uint8_t* in, int len, int off,
                                  uint8_t* out, int out_cap, int* op)
{
    int ret = -1, cur = off, hops = 0;
    while (cur >= 0 && cur < len) {
        uint8_t l = in[cur];
        if (l == 0) {
            if (ret < 0) ret = cur + 1;
            if (*op + 1 > out_cap) return -1;
            out[(*op)++] = 0;
            return ret;
        }
        if ((l & 0xC0) == 0xC0) {
            if (cur + 2 > len) return -1;
            int target = ((l & 0x3F) << 8) | in[cur + 1];
            if (target >= cur || ++hops > 128) return -1;
            if (ret < 0) ret = cur + 2;
            cur = target;
            continue;
        }
        if (l > 63 || cur + 1 + l > len || *op + 1 + l > out_cap) return -1;
        memcpy(out + *op, in + cur, (size_t)l + 1);
        *op += 1 + l;
        cur += 1 + l;
    }
    return -1;
}

/* Only the RFC 1035 types may compress names in RDATA (RFC 3597 §4);
 * everything else is opaque and copied verbatim. */
static bool emit_rdata_decompressed(const uint8_t* m, int len, const DnsRR* rr,
                                    uint8_t* out, int out_cap, int* op)
{
    int rd = rr->rdata;
    switch (rr->type) {
    case QTYPE_NS: case QTYPE_CNAME: case QTYPE_PTR:
        return copy_name_decompressed(m, len, rd, out, out_cap, op) >= 0;
    case QTYPE_MX:
        if (rr->rdlen < 3 || *op + 2 > out_cap) return false;
        memcpy(out + *op, m + rd, 2);                  /* preference */
        *op += 2;
        return copy_name_decompressed(m, len, rd + 2, out, out_cap, op) >= 0;
    case QTYPE_SOA: {
        int p = copy_name_decompressed(m, len, rd, out, out_cap, op);   /* MNAME */
        if (p >= 0) p = copy_name_decompressed(m, len, p, out, out_cap, op); /* RNAME */
        if (p < 0 || p + 20 > rd + rr->rdlen || *op + 20 > out_cap) return false;
        memcpy(out + *op, m + p, 20);                  /* serial..minimum */
        *op += 20;
        return true;
    }
    default:
        if (*op + rr->rdlen > out_cap) return false;
        memcpy(out + *op, m + rd, rr->rdlen);
        *op += rr->rdlen;
        return true;
    }
}

bool emit_rr_body(const uint8_t* m, int len, const DnsRR* rr,
                  uint8_t* out, int out_cap, int* op)
{
    if (*op + 10 > out_cap) return false;
    memcpy(out + *op, m + rr->rdata - 10, 8);          /* TYPE, CLASS, TTL */
    int rdlen_at = *op + 8;
    *op += 10;
    int start = *op;
    if (!emit_rdata_decompressed(m, len, rr, out, out_cap, op)) return false;
    wr16(out + rdlen_at, (uint16_t)(*op - start));
    return true;
}

/* ---- Record filtering -------------------------------------------------- */

static bool is_dnssec_meta_type(uint16_t t)
{
    return t == QTYPE_RRSIG || t == QTYPE_NSEC || t == QTYPE_NSEC3 || t == QTYPE_NSEC3PARAM;
}

static bool rr_dropped(uint16_t type, uint16_t qtype, bool drop_dnssec, bool drop_opt)
{
    if (drop_opt && type == QTYPE_OPT) return true;
    return drop_dnssec && is_dnssec_meta_type(type) && type != qtype;
}

/*
 * Rebuild the message without the RRs rr_dropped() selects (optionally also
 * clearing DO in a kept OPT).  Every name is decompressed, so dropping a
 * record can never orphan a compression pointer.  On malformed input or
 * overflow the original is left untouched.
 */
static void filter_rrs(char** bufp, ssize_t* lenp, uint16_t qtype,
                       bool drop_dnssec, bool drop_opt, bool clear_do)
{
    if (!bufp || !*bufp || !lenp || *lenp < HEADER_LEN) return;
    uint8_t* m = (uint8_t*)*bufp;
    int len = (int)*lenp;
    int total = rd16(m + 6) + rd16(m + 8) + rd16(m + 10);
    if (total == 0) return;

    /* Pass 1: clear OPT DO in place; is there anything to drop? */
    RRIter it; DnsRR rr;
    bool any_drop = false;
    int seen = 0;
    for (rr_iter_init(&it, m, len); rr_next(&it, &rr); seen++) {
        if (clear_do && rr.type == QTYPE_OPT) m[rr.rdata - 4] &= (uint8_t)~0x80;
        if (rr_dropped(rr.type, qtype, drop_dnssec, drop_opt)) any_drop = true;
    }
    if (seen != total || !any_drop) return;

    /* Pass 2: rebuild without the dropped records.
     *
     * Decompressing names expands a KEPT record far faster than the message
     * grows: the smallest input RR is 14 bytes (2-byte owner pointer + 10
     * fixed + 2-byte compressed target) and emits up to 520.  The old flat
     * len*4+2048 estimate therefore ran out at ~32 kept records — a 671-byte
     * reply, not some exotic 64 KB one.  Running out is not harmless: it
     * leaves in place exactly the OPT / DNSSEC records this function exists
     * to strip, so grow and retry rather than give up, starting small so
     * ordinary replies still allocate once.
     */
    int q_end = dns_question_end(m, len);
    if (q_end < 0) return;                  /* pass 1 walked it, so unreachable */

    /* Worst case: every kept RR emits a 255-byte owner, 10 fixed bytes and a
     * decompressed RDATA of at most 530 (SOA: two names plus 20 bytes). */
    const long cap_max = (long)q_end + (long)total * (255 + 10 + 530) + 16;

    for (long out_cap = (long)len * 4 + 2048; ; out_cap *= 4) {
        if (out_cap > cap_max) out_cap = cap_max;
        uint8_t* out = malloc((size_t)out_cap);
        if (!out) return;
        memcpy(out, m, (size_t)q_end);
        int op = q_end;
        int kept[3] = {0};
        bool ok = true;

        for (rr_iter_init(&it, m, len); ok && rr_next(&it, &rr); ) {
            if (rr_dropped(rr.type, qtype, drop_dnssec, drop_opt)) continue;
            if (copy_name_decompressed(m, len, rr.owner, out, (int)out_cap, &op) < 0 ||
                !emit_rr_body(m, len, &rr, out, (int)out_cap, &op))
                ok = false;                 /* no room, or a malformed record */
            else
                kept[rr.section]++;
        }

        if (!ok) {
            free(out);
            /* At the ceiling the input is malformed, not merely expansive. */
            if (out_cap >= cap_max) return;
            continue;
        }

        wr16(out + 6,  (uint16_t)kept[SEC_ANSWER]);
        wr16(out + 8,  (uint16_t)kept[SEC_AUTHORITY]);
        wr16(out + 10, (uint16_t)kept[SEC_ADDITIONAL]);

        free(*bufp);
        *bufp = (char*)out;
        *lenp = op;
        return;
    }
}

void strip_dnssec_for_non_do(char** bufp, ssize_t* lenp, uint16_t qtype)
{
    if (!bufp || !*bufp || !lenp || *lenp < HEADER_LEN) return;
    (*bufp)[3] &= (char)~0x20;               /* AD = 0 (RFC 6840 §5.7) */
    filter_rrs(bufp, lenp, qtype, true, false, true);
}

void strip_opt_rr(char** bufp, ssize_t* lenp)
{
    filter_rrs(bufp, lenp, 0, false, true, false);
}
