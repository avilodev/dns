#include "auth_records.h"
#include "auth_answer.h"   /* begin_response, emit_signed_rrset, append_rrsig, RrBlob */
#include "auth_lookup.h"   /* auth_records_for */
#include "dns_name.h"     /* dname_is_subdomain */
#include "auth.h"          /* struct AuthDomain, auth_domains[], g_auth_domains_lock */
#include "response.h"
#include "utils.h"        /* free_packet, write_dns_labels */
#include "types.h"
#include "dnssec.h"        /* ZoneKey */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

extern ZoneKey *g_zone_keys;   /* defined in auth.c */

/* =========================================================================
 * Response builders (called while rdlock held; access auth_domains[] directly)
 *
 * RRsets have no record-count cap: the limit is the message itself
 * (DNS_MSG_MAX).  UDP replies that exceed the client's size are truncated
 * (TC=1) later and the client retries over TCP, where the full set fits.
 * ========================================================================= */

/* Canonical RDATA (RFC 4034 §6.2) of one record into b.  Returns false if the
 * record cannot be encoded (it is then skipped). */
static bool rec_rdata(const struct AuthDomain *d, uint16_t type, RrBlob *b)
{
    int len = 0;
    switch (type) {
    case QTYPE_A: {
        struct in_addr ia;
        if (inet_pton(AF_INET, d->ip, &ia) != 1) return false;
        memcpy(b->data, &ia.s_addr, 4); len = 4;
        break;
    }
    case QTYPE_AAAA: {
        struct in6_addr ia6;
        if (inet_pton(AF_INET6, d->ipv6, &ia6) != 1) return false;
        memcpy(b->data, &ia6, 16); len = 16;
        break;
    }
    case QTYPE_MX:      /* priority + exchange (downcased: §6.2 list) */
        wr16(b->data, d->mx_priority); len = 2;
        write_dns_labels(d->mx_hostname, (char*)b->data, &len, sizeof(b->data));
        wire_name_lc(b->data + 2, len - 2);
        break;
    case QTYPE_NS:      /* single name (downcased: §6.2 list) */
        write_dns_labels(d->ns_name, (char*)b->data, &len, sizeof(b->data));
        wire_name_lc(b->data, len);
        break;
    case QTYPE_TXT:     /* pre-encoded character-strings; no names */
        if (d->txt_wire_len == 0 || d->txt_wire_len > sizeof(b->data)) return false;
        memcpy(b->data, d->txt_wire, d->txt_wire_len); len = d->txt_wire_len;
        break;
    case QTYPE_SRV:     /* priority, weight, port + target (downcased) */
        wr16(b->data,     d->srv_priority);
        wr16(b->data + 2, d->srv_weight);
        wr16(b->data + 4, d->srv_port);
        len = 6;
        write_dns_labels(d->srv_target, (char*)b->data, &len, sizeof(b->data));
        wire_name_lc(b->data + 6, len - 6);
        break;
    case QTYPE_HTTPS:   /* SvcPriority + TargetName; NOT downcased (RFC 6840 §5.1) */
        wr16(b->data, d->https_priority); len = 2;
        if (strcmp(d->https_target, ".") == 0) b->data[len++] = 0;
        else write_dns_labels(d->https_target, (char*)b->data, &len, sizeof(b->data));
        break;
    default:
        return false;
    }
    b->len = (uint16_t)len;
    return true;
}

/*
 * Answer `type` for `owner` with every matching record (one RRset): collect
 * the RDATA, then emit (and sign when DO is set) via emit_signed_rrset().
 * Returns NULL when owner holds no record of that type.
 */
static struct Packet *build_rrset_response(struct Packet *req, const char *owner,
                                           uint16_t type)
{
    int st, cnt = auth_records_for(owner, &st);
    if (cnt == 0) return NULL;

    RrBlob *blobs = malloc((size_t)cnt * sizeof(RrBlob));
    if (!blobs) return NULL;
    /* RFC 2181 §5.2: every RR in an RRset carries the same TTL.  Take the
     * smallest, rather than whichever record happened to be parsed last —
     * and treat ttl == 0 as "use the default" instead of leaving a sibling's
     * explicit TTL in place. */
    int n = 0;
    uint32_t ttl = 0;
    for (int i = st; i < st + cnt; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!rec_has_type(d, type) || !rec_rdata(d, type, &blobs[n])) continue;
        uint32_t rr_ttl = d->ttl ? d->ttl : DEFAULT_RECORD_TTL;
        if (n == 0 || rr_ttl < ttl) ttl = rr_ttl;
        n++;
    }
    if (n == 0) { free(blobs); return NULL; }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)n);
    if (r) {
        emit_signed_rrset(r, &pos, owner, type, ttl, blobs, n,
                          req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);
        r->recv_len = pos;
    }
    free(blobs);
    return r;
}

struct Packet *build_a_response(struct Packet *req, const char *owner)
{ return build_rrset_response(req, owner, QTYPE_A); }

struct Packet *build_aaaa_response(struct Packet *req, const char *owner)
{ return build_rrset_response(req, owner, QTYPE_AAAA); }

struct Packet *build_mx_response(struct Packet *req, const char *owner)
{ return build_rrset_response(req, owner, QTYPE_MX); }

struct Packet *build_ns_response(struct Packet *req, const char *owner)
{ return build_rrset_response(req, owner, QTYPE_NS); }

struct Packet *build_txt_response(struct Packet *req, const char *owner)
{ return build_rrset_response(req, owner, QTYPE_TXT); }

struct Packet *build_srv_response(struct Packet *req, const char *owner)
{ return build_rrset_response(req, owner, QTYPE_SRV); }

struct Packet *build_https_response(struct Packet *req, const char *owner)
{ return build_rrset_response(req, owner, QTYPE_HTTPS); }

/* ---- CNAME record ---- */
struct Packet *build_cname_response(struct Packet *req, const char *owner)
{
    const struct AuthDomain *d = NULL;
    int st, cnt = auth_records_for(owner, &st);
    for (int i = st; i < st + cnt && !d; i++)
        if (auth_domains[i].has_cname) d = &auth_domains[i];
    if (!d) return NULL;

    uint32_t ttl = d->ttl ? d->ttl : DEFAULT_RECORD_TTL;

    /* CNAME RDATA is a single name, downcased for canonical form (CNAME is in
     * the RFC 4034 §6.2 list); single-RR, so no §6.3 ordering is needed. */
    unsigned char rdata[300];
    int rdata_len = 0;
    write_dns_labels(d->cname_target, (char*)rdata, &rdata_len, sizeof(rdata));
    wire_name_lc(rdata, rdata_len);

    int pos;
    struct Packet *r = begin_response(req, &pos, 1);
    if (!r) return NULL;

    if (pos + 2+2+2+4+2+rdata_len > DNS_MSG_MAX) { free_packet(r); return NULL; }
    wr16(r->request + pos, DNS_NAME_PTR);             pos += 2;
    wr16(r->request + pos, QTYPE_CNAME);        pos += 2;
    wr16(r->request + pos, 1);                  pos += 2;
    wr32(r->request + pos, ttl);                pos += 4;
    wr16(r->request + pos, (uint16_t)rdata_len); pos += 2;
    memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

    if (req->do_bit) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk) {
            unsigned char canon[512];
            size_t canon_pos = 0;
            canon_rr_append(canon, &canon_pos, sizeof(canon),
                            owner, QTYPE_CNAME, ttl, rdata, rdata_len);
            if (append_rrsig(r->request, &pos, owner, QTYPE_CNAME, ttl,
                              canon, canon_pos, zsk, false, NULL))
                wr16(r->request + 6, 2);
        }
    }

    r->recv_len = pos;
    return r;
}

/* ---- SOA record ---- */
struct Packet *build_soa_response(struct Packet *req, const char *owner)
{
    /* Find the SOA entry for this exact owner (zone apex). */
    const struct AuthDomain *d = NULL;
    int st, cnt = auth_records_for(owner, &st);
    for (int i = st; i < st + cnt && !d; i++)
        if (auth_domains[i].has_soa) d = &auth_domains[i];
    if (!d) return NULL;

    uint32_t ttl = d->soa_ttl ? d->soa_ttl : DEFAULT_RECORD_TTL;

    /* SOA RDATA: mname_wire + rname_wire + serial + refresh + retry + expire +
     * minimum.  MNAME and RNAME are downcased for canonical form (SOA is in the
     * RFC 4034 §6.2 list); single-RR, so no §6.3 ordering is needed. */
    unsigned char rdata[600];
    int mname_end = 0;
    write_dns_labels(d->soa_mname, (char*)rdata, &mname_end, sizeof(rdata));
    wire_name_lc(rdata, mname_end);
    int rdata_len = mname_end;
    write_dns_labels(d->soa_rname, (char*)rdata, &rdata_len, sizeof(rdata));
    wire_name_lc(rdata + mname_end, rdata_len - mname_end);
    wr32(rdata + rdata_len, d->soa_serial);   rdata_len += 4;
    wr32(rdata + rdata_len, d->soa_refresh);  rdata_len += 4;
    wr32(rdata + rdata_len, d->soa_retry);    rdata_len += 4;
    wr32(rdata + rdata_len, d->soa_expire);   rdata_len += 4;
    wr32(rdata + rdata_len, d->soa_minimum);  rdata_len += 4;

    int pos;
    struct Packet *r = begin_response(req, &pos, 1);
    if (!r) return NULL;

    if (pos + 2+2+2+4+2+rdata_len > DNS_MSG_MAX) { free_packet(r); return NULL; }
    wr16(r->request + pos, DNS_NAME_PTR);             pos += 2;
    wr16(r->request + pos, QTYPE_SOA);          pos += 2;
    wr16(r->request + pos, 1);                  pos += 2;
    wr32(r->request + pos, ttl);                pos += 4;
    wr16(r->request + pos, (uint16_t)rdata_len); pos += 2;
    memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

    if (req->do_bit) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk) {
            unsigned char canon[700];
            size_t canon_pos = 0;
            canon_rr_append(canon, &canon_pos, sizeof(canon),
                            owner, QTYPE_SOA, ttl, rdata, rdata_len);
            if (append_rrsig(r->request, &pos, owner, QTYPE_SOA, ttl,
                              canon, canon_pos, zsk, false, NULL))
                wr16(r->request + 6, 2);
        }
    }

    r->recv_len = pos;
    return r;
}

/* ---- DNSKEY record ---- */
struct Packet *build_dnskey_response(struct Packet *req, const char *owner)
{
    if (!g_zone_keys) return NULL;

    typedef struct {
        uint16_t flags;
        uint8_t  alg;
        unsigned char pub[600];
        int pub_len;
        uint16_t key_tag;
    } DKEnt;
    DKEnt dkes[8];
    int rr_count = 0;

    for (const ZoneKey *k = g_zone_keys; k && rr_count < 8; k = k->next) {
        if (strcmp(k->zone, owner) != 0) continue;
        int plen = dnssec_pubkey_rdata(k, dkes[rr_count].pub,
                                       sizeof(dkes[rr_count].pub));
        if (plen < 0) continue;
        dkes[rr_count].flags   = k->flags;
        dkes[rr_count].alg     = k->algorithm;
        dkes[rr_count].pub_len = plen;
        dkes[rr_count].key_tag = k->key_tag;
        rr_count++;
    }
    if (rr_count == 0) return NULL;

    uint32_t ttl = DEFAULT_RECORD_TTL;

    /* DNSKEY RDATA: flags(2) + protocol(1=3) + algorithm(1) + public_key.
     * No embedded names; multiple keys (KSK + ZSK) must be ordered per §6.3. */
    RrBlob blobs[8];
    for (int i = 0; i < rr_count; i++) {
        int len = 0;
        wr16(blobs[i].data + len, dkes[i].flags); len += 2;
        blobs[i].data[len++] = 3;            /* protocol = 3 (DNSSEC) */
        blobs[i].data[len++] = dkes[i].alg;
        memcpy(blobs[i].data + len, dkes[i].pub, dkes[i].pub_len);
        len += dkes[i].pub_len;
        blobs[i].len = (uint16_t)len;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    /* DNSKEY RRset is signed with the KSK (RFC 4035 §2.2). */
    emit_signed_rrset(r, &pos, owner, QTYPE_DNSKEY, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_ksk_for_zone(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- HINFO response for QTYPE_ANY (RFC 8482) ---- */
struct Packet *build_hinfo_response(struct Packet *req)
{
    static const char cpu_str[] = "RFC8482";
    static const char os_str[]  = "";
    uint32_t ttl = DEFAULT_RECORD_TTL;

    unsigned char rdata[32];
    int rdata_len = 0;
    rdata[rdata_len++] = (uint8_t)strlen(cpu_str);
    memcpy(rdata + rdata_len, cpu_str, strlen(cpu_str));
    rdata_len += (int)strlen(cpu_str);
    rdata[rdata_len++] = (uint8_t)strlen(os_str);
    /* os_str is empty, nothing to copy */

    int pos;
    struct Packet *r = begin_response(req, &pos, 1);
    if (!r) return NULL;

    if (pos + 2+2+2+4+2+rdata_len > DNS_MSG_MAX) { free_packet(r); return NULL; }
    wr16(r->request + pos, DNS_NAME_PTR);             pos += 2;
    wr16(r->request + pos, 13 /* HINFO */);     pos += 2;
    wr16(r->request + pos, 1);                  pos += 2;
    wr32(r->request + pos, ttl);                pos += 4;
    wr16(r->request + pos, (uint16_t)rdata_len); pos += 2;
    memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

    r->recv_len = pos;
    return r;
}

/* ---- Referral to a delegated child zone ---- */
struct Packet *build_referral_response(struct Packet *req, const char *cut)
{
    int st, cnt = auth_records_for(cut, &st);
    if (cnt == 0) return NULL;

    int pos;
    struct Packet *r = begin_response(req, &pos, 0);
    if (!r) return NULL;

    /* Not authoritative for data below a zone cut: clear AA. */
    uint16_t flags = rd16(r->request + 2);
    wr16(r->request + 2, (uint16_t)(flags & ~(1u << 10)));

    /* Authority: the cut's whole NS RRset. */
    int ns_count = 0;
    for (int i = st; i < st + cnt; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!d->has_ns) continue;
        int rr_start = pos;
        write_dns_labels(cut, r->request, &pos, DNS_MSG_MAX);
        if (pos + 10 + 256 > DNS_MSG_MAX) { pos = rr_start; break; }
        wr16(r->request + pos, QTYPE_NS); pos += 2;
        wr16(r->request + pos, 1);        pos += 2;
        wr32(r->request + pos, d->ttl ? d->ttl : DEFAULT_RECORD_TTL); pos += 4;
        int rdlen_at = pos; pos += 2;
        int rstart = pos;
        write_dns_labels(d->ns_name, r->request, &pos, DNS_MSG_MAX);
        wr16(r->request + rdlen_at, (uint16_t)(pos - rstart));
        ns_count++;
    }
    if (ns_count == 0) { free_packet(r); return NULL; }
    wr16(r->request + 8, (uint16_t)ns_count);

    /* Additional: A/AAAA glue for each nameserver name.  Only glue at or below
     * the cut is in bailiwick — an address we happen to hold for a nameserver
     * outside the delegated zone is not ours to hand out in a referral. */
    int ar = 0;
    bool full = false;
    for (int i = st; i < st + cnt && !full; i++) {
        if (!auth_domains[i].has_ns) continue;
        const char *ns = auth_domains[i].ns_name;
        if (!dname_is_subdomain(ns, cut)) continue;
        int gst, gcnt = auth_records_for(ns, &gst);
        for (int g = gst; g < gst + gcnt; g++) {
            const struct AuthDomain *d = &auth_domains[g];
            uint16_t type = rec_has_type(d, QTYPE_A) ? QTYPE_A
                          : rec_has_type(d, QTYPE_AAAA) ? QTYPE_AAAA : 0;
            RrBlob b;
            if (!type || !rec_rdata(d, type, &b)) continue;
            int rr_start = pos;
            write_dns_labels(d->domain, r->request, &pos, DNS_MSG_MAX);
            if (pos + 10 + b.len > DNS_MSG_MAX) { pos = rr_start; full = true; break; }
            wr16(r->request + pos, type);  pos += 2;
            wr16(r->request + pos, 1);     pos += 2;
            wr32(r->request + pos, d->ttl ? d->ttl : DEFAULT_RECORD_TTL); pos += 4;
            wr16(r->request + pos, b.len); pos += 2;
            memcpy(r->request + pos, b.data, b.len); pos += b.len;
            ar++;
        }
    }
    wr16(r->request + 10, (uint16_t)ar);

    r->recv_len = pos;
    return r;
}
