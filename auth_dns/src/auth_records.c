#include "auth_records.h"
#include "auth_answer.h"   /* begin_response, emit_signed_rrset, append_rrsig, RrBlob */
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
 * ========================================================================= */

/* ---- A record ---- */
struct Packet *build_a_response(struct Packet *req, const char *owner)
{
    /* Collect up to 16 A-record RDATA entries for this owner. */
    unsigned char rdatas[16][4];
    int rr_count = 0;
    uint32_t ttl = DEFAULT_RECORD_TTL;

    for (int i = 0; i < auth_domain_count && rr_count < 16; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        /* Skip non-A entries */
        if (d->has_mx || d->has_ipv6 || d->has_cname ||
            d->has_ns || d->has_txt || d->has_srv || d->has_soa)
            continue;
        if (strcmp(d->domain, owner) != 0) continue;
        if (d->ip[0] == '\0' || strcmp(d->ip, "0.0.0.0") == 0) continue;

        struct in_addr ia;
        if (inet_pton(AF_INET, d->ip, &ia) != 1) continue;
        memcpy(rdatas[rr_count++], &ia.s_addr, 4);
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    /* A RDATA has no embedded names — canonical form is the 4 raw bytes. */
    RrBlob blobs[16];
    for (int i = 0; i < rr_count; i++) {
        memcpy(blobs[i].data, rdatas[i], 4);
        blobs[i].len = 4;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    emit_signed_rrset(r, &pos, owner, QTYPE_A, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- AAAA record ---- */
struct Packet *build_aaaa_response(struct Packet *req, const char *owner)
{
    unsigned char rdatas[16][16];
    int rr_count = 0;
    uint32_t ttl = DEFAULT_RECORD_TTL;

    for (int i = 0; i < auth_domain_count && rr_count < 16; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!d->has_ipv6 || strcmp(d->domain, owner) != 0) continue;
        struct in6_addr ia6;
        if (inet_pton(AF_INET6, d->ipv6, &ia6) != 1) continue;
        memcpy(rdatas[rr_count++], &ia6, 16);
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    /* AAAA RDATA has no embedded names — canonical form is the 16 raw bytes. */
    RrBlob blobs[16];
    for (int i = 0; i < rr_count; i++) {
        memcpy(blobs[i].data, rdatas[i], 16);
        blobs[i].len = 16;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    emit_signed_rrset(r, &pos, owner, QTYPE_AAAA, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- MX record ---- */
struct Packet *build_mx_response(struct Packet *req, const char *owner)
{
    typedef struct { uint16_t prio; char host[256]; } MXEnt;
    MXEnt mxes[16];
    int rr_count = 0;
    uint32_t ttl = DEFAULT_RECORD_TTL;

    for (int i = 0; i < auth_domain_count && rr_count < 16; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!d->has_mx || strcmp(d->domain, owner) != 0) continue;
        mxes[rr_count].prio = d->mx_priority;
        strncpy(mxes[rr_count].host, d->mx_hostname, 255);
        mxes[rr_count].host[255] = '\0';
        rr_count++;
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    /* MX RDATA: priority(2) + exchange.  The exchange name is downcased for
     * canonical form (MX is in the RFC 4034 §6.2 list). */
    RrBlob blobs[16];
    for (int i = 0; i < rr_count; i++) {
        int len = 0;
        *(uint16_t*)(blobs[i].data + len) = htons(mxes[i].prio); len += 2;
        write_dns_labels(mxes[i].host, (char*)blobs[i].data, &len, sizeof(blobs[i].data));
        wire_name_lc(blobs[i].data + 2, len - 2);
        blobs[i].len = (uint16_t)len;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    emit_signed_rrset(r, &pos, owner, QTYPE_MX, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- NS record ---- */
struct Packet *build_ns_response(struct Packet *req, const char *owner)
{
    char ns_names[16][256];
    int rr_count = 0;
    uint32_t ttl = DEFAULT_RECORD_TTL;

    for (int i = 0; i < auth_domain_count && rr_count < 16; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!d->has_ns || strcmp(d->domain, owner) != 0) continue;
        strncpy(ns_names[rr_count], d->ns_name, 255);
        ns_names[rr_count][255] = '\0';
        rr_count++;
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    /* NS RDATA is a single name, downcased for canonical form (NS is in the
     * RFC 4034 §6.2 list). */
    RrBlob blobs[16];
    for (int i = 0; i < rr_count; i++) {
        int len = 0;
        write_dns_labels(ns_names[i], (char*)blobs[i].data, &len, sizeof(blobs[i].data));
        wire_name_lc(blobs[i].data, len);
        blobs[i].len = (uint16_t)len;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    emit_signed_rrset(r, &pos, owner, QTYPE_NS, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- TXT record ---- */
struct Packet *build_txt_response(struct Packet *req, const char *owner)
{
    char txt_vals[16][512];
    int rr_count = 0;
    uint32_t ttl = DEFAULT_RECORD_TTL;

    for (int i = 0; i < auth_domain_count && rr_count < 16; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!d->has_txt || strcmp(d->domain, owner) != 0) continue;
        strncpy(txt_vals[rr_count], d->txt_data, 511);
        txt_vals[rr_count][511] = '\0';
        rr_count++;
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    /* TXT RDATA: one or more ≤255-byte character-strings (RFC 1035 §3.3.14);
     * no embedded names, so canonical RDATA == wire RDATA. */
    RrBlob blobs[16];
    for (int i = 0; i < rr_count; i++) {
        size_t tlen = strlen(txt_vals[i]);
        int len = 0;
        if (tlen == 0) {
            blobs[i].data[len++] = 0;   /* one zero-length character-string */
        } else {
            size_t off = 0;
            while (off < tlen && len < (int)sizeof(blobs[i].data) - 256) {
                size_t chunk = tlen - off;
                if (chunk > 255) chunk = 255;
                blobs[i].data[len++] = (unsigned char)chunk;
                memcpy(blobs[i].data + len, txt_vals[i] + off, chunk);
                len += (int)chunk;
                off += chunk;
            }
        }
        blobs[i].len = (uint16_t)len;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    emit_signed_rrset(r, &pos, owner, QTYPE_TXT, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- SRV record ---- */
struct Packet *build_srv_response(struct Packet *req, const char *owner)
{
    typedef struct { uint16_t prio, weight, port; char target[256]; } SRVEnt;
    SRVEnt srvs[16];
    int rr_count = 0;
    uint32_t ttl = DEFAULT_RECORD_TTL;

    for (int i = 0; i < auth_domain_count && rr_count < 16; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!d->has_srv || strcmp(d->domain, owner) != 0) continue;
        srvs[rr_count].prio   = d->srv_priority;
        srvs[rr_count].weight = d->srv_weight;
        srvs[rr_count].port   = d->srv_port;
        strncpy(srvs[rr_count].target, d->srv_target, 255);
        srvs[rr_count].target[255] = '\0';
        rr_count++;
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    /* SRV RDATA: priority(2) + weight(2) + port(2) + target.  The target name
     * is downcased for canonical form (SRV is in the RFC 4034 §6.2 list). */
    RrBlob blobs[16];
    for (int i = 0; i < rr_count; i++) {
        int len = 0;
        *(uint16_t*)(blobs[i].data + len) = htons(srvs[i].prio);   len += 2;
        *(uint16_t*)(blobs[i].data + len) = htons(srvs[i].weight); len += 2;
        *(uint16_t*)(blobs[i].data + len) = htons(srvs[i].port);   len += 2;
        write_dns_labels(srvs[i].target, (char*)blobs[i].data, &len, sizeof(blobs[i].data));
        wire_name_lc(blobs[i].data + 6, len - 6);
        blobs[i].len = (uint16_t)len;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    emit_signed_rrset(r, &pos, owner, QTYPE_SRV, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- HTTPS record (RFC 9460) ---- */
struct Packet *build_https_response(struct Packet *req, const char *owner)
{
    typedef struct { uint16_t prio; char target[256]; } HTTPSEnt;
    HTTPSEnt entries[16];
    int rr_count = 0;
    uint32_t ttl = DEFAULT_RECORD_TTL;

    for (int i = 0; i < auth_domain_count && rr_count < 16; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (!d->has_https || strcmp(d->domain, owner) != 0) continue;
        entries[rr_count].prio = d->https_priority;
        strncpy(entries[rr_count].target, d->https_target, 255);
        entries[rr_count].target[255] = '\0';
        rr_count++;
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    /* HTTPS/SVCB RDATA: SvcPriority(2) + TargetName + SvcParams.  Per RFC 6840
     * §5.1 the names in RDATA of types introduced after RFC 4034 are NOT
     * downcased, so the TargetName is kept as-is for canonical form. */
    RrBlob blobs[16];
    for (int i = 0; i < rr_count; i++) {
        int len = 0;
        *(uint16_t*)(blobs[i].data + len) = htons(entries[i].prio); len += 2;
        if (strcmp(entries[i].target, ".") == 0) {
            blobs[i].data[len++] = 0;   /* root label: "." */
        } else {
            write_dns_labels(entries[i].target, (char*)blobs[i].data, &len, sizeof(blobs[i].data));
        }
        blobs[i].len = (uint16_t)len;
    }

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    emit_signed_rrset(r, &pos, owner, QTYPE_HTTPS, ttl, blobs, rr_count,
                      req->do_bit, req->do_bit ? find_zsk_for_owner(owner) : NULL);

    r->recv_len = pos;
    return r;
}

/* ---- CNAME record ---- */
struct Packet *build_cname_response(struct Packet *req, const char *owner)
{
    const struct AuthDomain *d = NULL;
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].has_cname &&
            strcmp(auth_domains[i].domain, owner) == 0) {
            d = &auth_domains[i];
            break;
        }
    }
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

    if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { free_packet(r); return NULL; }
    *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
    *(uint16_t*)(r->request + pos) = htons(QTYPE_CNAME);        pos += 2;
    *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
    *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
    *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
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
                *(uint16_t*)(r->request + 6) = htons(2);
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
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].has_soa &&
            strcmp(auth_domains[i].domain, owner) == 0) {
            d = &auth_domains[i];
            break;
        }
    }
    if (!d) return NULL;

    uint32_t ttl = d->soa_ttl ? d->soa_ttl : d->soa_refresh;

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
    *(uint32_t*)(rdata + rdata_len) = htonl(d->soa_serial);   rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(d->soa_refresh);  rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(d->soa_retry);    rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(d->soa_expire);   rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(d->soa_minimum);  rdata_len += 4;

    int pos;
    struct Packet *r = begin_response(req, &pos, 1);
    if (!r) return NULL;

    if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { free_packet(r); return NULL; }
    *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
    *(uint16_t*)(r->request + pos) = htons(QTYPE_SOA);          pos += 2;
    *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
    *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
    *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
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
                *(uint16_t*)(r->request + 6) = htons(2);
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
        *(uint16_t*)(blobs[i].data + len) = htons(dkes[i].flags); len += 2;
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

    if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { free_packet(r); return NULL; }
    *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
    *(uint16_t*)(r->request + pos) = htons(13 /* HINFO */);     pos += 2;
    *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
    *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
    *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
    memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

    r->recv_len = pos;
    return r;
}
