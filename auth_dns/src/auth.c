/* auth.c — Authoritative DNS record handler.
 *
 * Design:
 *   - auth_domains[] flat array: one entry per record; multiple entries share
 *     the same owner name for different types (A, AAAA, MX, NS, TXT, SRV ...).
 *   - g_auth_domains_lock (pthread_rwlock) guards the array; all lookups take
 *     rdlock, reload (SIGHUP) takes wrlock.
 *   - All static builder functions are called from within the rdlock region;
 *     they access auth_domains[] without re-locking.
 *   - When the client sends EDNS DO=1 and g_zone_keys is loaded, an RRSIG is
 *     appended after each answer RRset (RFC 4035 §3.1).
 *   - SOA is appended to NXDOMAIN/NODATA authority sections (RFC 2308).
 */

#include "auth.h"
#include "response.h"
#include "utils.h"
#include "dnssec.h"

#include <time.h>
#include <ctype.h>

/* =========================================================================
 * Globals
 * ========================================================================= */

/* Defined here, declared extern in main.c.  NULL when DNSSEC signing is off. */
ZoneKey *g_zone_keys = NULL;

/* Reader-writer lock protecting auth_domains[] and auth_domain_count. */
pthread_rwlock_t g_auth_domains_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct AuthDomain auth_domains[MAX_INTERNAL_HOSTS];
static int auth_domain_count = 0;

/* =========================================================================
 * Utility helpers (all called while rdlock held)
 * ========================================================================= */

/* Count dot-separated labels: "a.b.c" → 3, "example.com" → 2 */
static int count_labels(const char *name)
{
    if (!name || *name == '\0') return 0;
    int n = 1;
    for (const char *p = name; *p; p++)
        if (*p == '.') n++;
    return n;
}

/*
 * find_zone_soa — longest-suffix SOA match.
 * "www.avilo.com" → finds SOA entry for "avilo.com".
 * Returns pointer into auth_domains[], or NULL.
 */
static const struct AuthDomain *find_zone_soa(const char *owner)
{
    if (!owner) return NULL;
    const struct AuthDomain *best = NULL;
    size_t best_len = 0;

    for (int i = 0; i < auth_domain_count; i++) {
        if (!auth_domains[i].has_soa) continue;
        const char *zone = auth_domains[i].domain;
        size_t zlen = strlen(zone);
        size_t olen = strlen(owner);
        bool match = (strcmp(owner, zone) == 0) ||
                     (olen > zlen &&
                      owner[olen - zlen - 1] == '.' &&
                      strcmp(owner + olen - zlen, zone) == 0);
        if (match && zlen > best_len) {
            best = &auth_domains[i];
            best_len = zlen;
        }
    }
    return best;
}

/*
 * find_wildcard — check if a wildcard record covers owner.
 * "www.avilo.com" → looks for "*.avilo.com" entry.
 */
static const struct AuthDomain *find_wildcard(const char *owner)
{
    if (!owner) return NULL;
    const char *dot = strchr(owner, '.');
    if (!dot) return NULL;
    char wc[264];
    snprintf(wc, sizeof(wc), "*%s", dot);   /* "*.parent.zone" */
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].is_wildcard &&
            strcmp(auth_domains[i].domain, wc) == 0)
            return &auth_domains[i];
    }
    return NULL;
}

/* Find the ZSK whose zone is a suffix of owner. */
static const ZoneKey *find_zsk_for_owner(const char *owner)
{
    if (!owner || !g_zone_keys) return NULL;
    const ZoneKey *best = NULL;
    size_t best_len = 0;
    for (const ZoneKey *k = g_zone_keys; k; k = k->next) {
        if (k->flags != 256) continue;   /* ZSK flag = 256 */
        size_t zlen = strlen(k->zone);
        size_t olen = strlen(owner);
        bool match = (strcmp(owner, k->zone) == 0) ||
                     (olen > zlen &&
                      owner[olen - zlen - 1] == '.' &&
                      strcmp(owner + olen - zlen, k->zone) == 0);
        if (match && zlen > best_len) {
            best = k;
            best_len = zlen;
        }
    }
    return best;
}

/* Find the KSK for an exact zone apex. */
static const ZoneKey *find_ksk_for_zone(const char *zone)
{
    if (!zone || !g_zone_keys) return NULL;
    for (const ZoneKey *k = g_zone_keys; k; k = k->next) {
        if (k->flags == 257 && strcmp(k->zone, zone) == 0)
            return k;
    }
    return NULL;
}

/* =========================================================================
 * Response buffer helpers
 * ========================================================================= */

static struct Packet *alloc_response(void)
{
    struct Packet *r = calloc(1, sizeof(struct Packet));
    if (!r) { perror("auth: calloc packet"); return NULL; }
    r->request = calloc(1, MAXLINE);
    if (!r->request) { perror("auth: calloc buf"); free(r); return NULL; }
    return r;
}

/* Write 12-byte DNS header (TX ID must already be at buf[0..1]). */
static void write_hdr(char *buf, uint16_t flags,
                      uint16_t qdcount, uint16_t ancount,
                      uint16_t nscount, uint16_t arcount)
{
    *(uint16_t*)(buf + 2)  = htons(flags);
    *(uint16_t*)(buf + 4)  = htons(qdcount);
    *(uint16_t*)(buf + 6)  = htons(ancount);
    *(uint16_t*)(buf + 8)  = htons(nscount);
    *(uint16_t*)(buf + 10) = htons(arcount);
}

/* Standard AA+RA response flags (NOERROR). */
static uint16_t aa_flags(const struct Packet *req)
{
    return (uint16_t)((1u << 15) |           /* QR = response    */
                      (1u << 10) |           /* AA = authoritative */
                      ((unsigned)req->rd << 8) | /* copy RD       */
                      (1u << 7));             /* RA = available   */
}

/* Write QNAME (via write_dns_labels) + QTYPE + QCLASS. Advances *pos. */
static void write_question(char *buf, int *pos, const struct Packet *req)
{
    if (req->full_domain)
        write_dns_labels(req->full_domain, buf, pos);
    else
        buf[(*pos)++] = 0;
    *(uint16_t*)(buf + *pos) = htons(req->q_type);   *pos += 2;
    *(uint16_t*)(buf + *pos) = htons(req->q_class);  *pos += 2;
}

/*
 * Allocate a response, copy TX ID, write header (AA, ancount), and
 * write the question section.  Returns the Packet with *pos_out pointing
 * just after the question section (start of the answer section).
 */
static struct Packet *begin_response(const struct Packet *req,
                                     int *pos_out, uint16_t ancount)
{
    struct Packet *r = alloc_response();
    if (!r) return NULL;
    memcpy(r->request, req->request, 2);          /* copy TX ID */
    write_hdr(r->request, aa_flags(req), 1, ancount, 0, 0);
    int pos = HEADER_LEN;
    write_question(r->request, &pos, req);
    *pos_out = pos;
    return r;
}

/* =========================================================================
 * Canonical RR wire form (for DNSSEC signing, RFC 4034 §6.2)
 * ========================================================================= */

/*
 * Append one canonical-form RR to out[*out_pos]:
 *   owner_wire (no compression) || type || class || ttl || rdlen || rdata
 */
static void canon_rr_append(unsigned char *out, size_t *out_pos, size_t out_cap,
                             const char *owner_name, uint16_t type, uint32_t ttl,
                             const unsigned char *rdata, size_t rdlen)
{
    char own_wire[280];
    int  own_len = 0;
    write_dns_labels(owner_name, own_wire, &own_len);

    size_t need = (size_t)own_len + 2 + 2 + 4 + 2 + rdlen;
    if (*out_pos + need > out_cap) return;

    memcpy(out + *out_pos, own_wire, own_len);        *out_pos += (size_t)own_len;
    *(uint16_t*)(out + *out_pos) = htons(type);       *out_pos += 2;
    *(uint16_t*)(out + *out_pos) = htons(1 /* IN */); *out_pos += 2;
    *(uint32_t*)(out + *out_pos) = htonl(ttl);        *out_pos += 4;
    *(uint16_t*)(out + *out_pos) = htons((uint16_t)rdlen); *out_pos += 2;
    memcpy(out + *out_pos, rdata, rdlen);             *out_pos += rdlen;
}

/* =========================================================================
 * RRSIG append (RFC 4034 §3 / RFC 4035 §3.1)
 * ========================================================================= */

/*
 * append_rrsig — build and append an RRSIG RR to buf[*pos].
 *
 * canon_rrset: pre-built canonical wire image of the full RRset (built with
 *              multiple canon_rr_append() calls by the response builder).
 * Returns 1 if the RRSIG was written, 0 on error.
 *
 * The owner name in the RRSIG RR uses the DNS_NAME_PTR (0xC00C) compression pointer
 * (valid when the question QNAME starts at offset 12, which is always true).
 * The canonical signed data uses fully-expanded labels (no compression).
 */
static int append_rrsig(char *buf, int *pos,
                         const char *owner_name,
                         uint16_t type_covered, uint32_t ttl,
                         const unsigned char *canon_rrset, size_t canon_rrset_len,
                         const ZoneKey *zsk,
                         bool is_wildcard)
{
    if (!buf || !pos || !owner_name || !canon_rrset || !zsk) return 0;

    time_t now = time(NULL);
    uint32_t inception  = (uint32_t)(now - 300);          /* 5 min grace   */
    uint32_t expiration = (uint32_t)(now + 86400UL * 30); /* 30-day window */

    /* Signer name (zone apex) in wire format */
    char signer_wire[280];
    int  signer_wire_len = 0;
    write_dns_labels(zsk->zone, signer_wire, &signer_wire_len);

    /* Build RRSIG RDATA header (everything before the signature field):
     *   type_covered(2) + alg(1) + labels(1) + orig_ttl(4)
     *   + sig_expiration(4) + sig_inception(4) + key_tag(2)
     *   + signer_name(var)                                           */
    unsigned char rrsig_hdr[320];
    int hdr_pos = 0;
    *(uint16_t*)(rrsig_hdr + hdr_pos) = htons(type_covered);      hdr_pos += 2;
    rrsig_hdr[hdr_pos++] = zsk->algorithm;
    /* RFC 4034 §3.1.3: for wildcard RRsets, labels = label count of owner
     * minus one (the '*' label is not counted in the RRSIG labels field). */
    int lcount = count_labels(owner_name);
    if (is_wildcard && lcount > 0) lcount--;
    rrsig_hdr[hdr_pos++] = (uint8_t)lcount;
    *(uint32_t*)(rrsig_hdr + hdr_pos) = htonl(ttl);               hdr_pos += 4;
    *(uint32_t*)(rrsig_hdr + hdr_pos) = htonl(expiration);        hdr_pos += 4;
    *(uint32_t*)(rrsig_hdr + hdr_pos) = htonl(inception);         hdr_pos += 4;
    *(uint16_t*)(rrsig_hdr + hdr_pos) = htons(zsk->key_tag);      hdr_pos += 2;
    memcpy(rrsig_hdr + hdr_pos, signer_wire, signer_wire_len);    hdr_pos += signer_wire_len;

    /* signed_data = RRSIG_hdr || canonical_rrset  (RFC 4034 §6.2) */
    size_t signed_len = (size_t)hdr_pos + canon_rrset_len;
    unsigned char *signed_data = malloc(signed_len);
    if (!signed_data) return 0;
    memcpy(signed_data,           rrsig_hdr,    hdr_pos);
    memcpy(signed_data + hdr_pos, canon_rrset, canon_rrset_len);

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int rc = dnssec_sign_rrset(zsk, signed_data, signed_len, &sig, &sig_len);
    free(signed_data);
    if (rc != 0 || !sig) return 0;

    size_t rrsig_rdlen = (size_t)hdr_pos + sig_len;
    int need = 2 + 2 + 2 + 4 + 2 + (int)rrsig_rdlen;
    if (*pos + need > MAXLINE) { free(sig); return 0; }

    *(uint16_t*)(buf + *pos) = htons(DNS_NAME_PTR);                     *pos += 2;
    *(uint16_t*)(buf + *pos) = htons(QTYPE_RRSIG);                *pos += 2;
    *(uint16_t*)(buf + *pos) = htons(1 /* IN */);                 *pos += 2;
    *(uint32_t*)(buf + *pos) = htonl(ttl);                        *pos += 4;
    *(uint16_t*)(buf + *pos) = htons((uint16_t)rrsig_rdlen);      *pos += 2;
    memcpy(buf + *pos, rrsig_hdr, hdr_pos);                       *pos += hdr_pos;
    memcpy(buf + *pos, sig, sig_len);                              *pos += (int)sig_len;
    free(sig);
    return 1;
}

/* =========================================================================
 * Response builders (called while rdlock held; access auth_domains[] directly)
 * ========================================================================= */

/* ---- A record ---- */
static struct Packet *build_a_response(struct Packet *req, const char *owner)
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
        if (d->is_blocked) continue;
        if (strcmp(d->domain, owner) != 0) continue;
        if (d->ip[0] == '\0' || strcmp(d->ip, "0.0.0.0") == 0) continue;

        struct in_addr ia;
        if (inet_pton(AF_INET, d->ip, &ia) != 1) continue;
        memcpy(rdatas[rr_count++], &ia.s_addr, 4);
        if (d->ttl) ttl = d->ttl;
    }
    if (rr_count == 0) return NULL;

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    for (int i = 0; i < rr_count; i++) {
        if (pos + 2+2+2+4+2+4 > MAXLINE) { rr_count = i; break; }
        *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);   pos += 2;
        *(uint16_t*)(r->request + pos) = htons(QTYPE_A);  pos += 2;
        *(uint16_t*)(r->request + pos) = htons(1);        pos += 2;
        *(uint32_t*)(r->request + pos) = htonl(ttl);      pos += 4;
        *(uint16_t*)(r->request + pos) = htons(4);        pos += 2;
        memcpy(r->request + pos, rdatas[i], 4);           pos += 4;
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)rr_count);

    if (req->do_bit) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk) {
            unsigned char canon[2048];
            size_t canon_pos = 0;
            for (int i = 0; i < rr_count; i++)
                canon_rr_append(canon, &canon_pos, sizeof(canon),
                                owner, QTYPE_A, ttl, rdatas[i], 4);
            if (append_rrsig(r->request, &pos, owner, QTYPE_A, ttl,
                              canon, canon_pos, zsk, false))
                *(uint16_t*)(r->request + 6) = htons((uint16_t)(rr_count + 1));
        }
    }

    r->recv_len = pos;
    return r;
}

/* ---- AAAA record ---- */
static struct Packet *build_aaaa_response(struct Packet *req, const char *owner)
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

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    for (int i = 0; i < rr_count; i++) {
        if (pos + 2+2+2+4+2+16 > MAXLINE) { rr_count = i; break; }
        *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);     pos += 2;
        *(uint16_t*)(r->request + pos) = htons(QTYPE_AAAA); pos += 2;
        *(uint16_t*)(r->request + pos) = htons(1);          pos += 2;
        *(uint32_t*)(r->request + pos) = htonl(ttl);        pos += 4;
        *(uint16_t*)(r->request + pos) = htons(16);         pos += 2;
        memcpy(r->request + pos, rdatas[i], 16);            pos += 16;
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)rr_count);

    if (req->do_bit) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk) {
            unsigned char canon[4096];
            size_t canon_pos = 0;
            for (int i = 0; i < rr_count; i++)
                canon_rr_append(canon, &canon_pos, sizeof(canon),
                                owner, QTYPE_AAAA, ttl, rdatas[i], 16);
            if (append_rrsig(r->request, &pos, owner, QTYPE_AAAA, ttl,
                              canon, canon_pos, zsk, false))
                *(uint16_t*)(r->request + 6) = htons((uint16_t)(rr_count + 1));
        }
    }

    r->recv_len = pos;
    return r;
}

/* ---- MX record ---- */
static struct Packet *build_mx_response(struct Packet *req, const char *owner)
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

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    unsigned char canon[4096];
    size_t canon_pos = 0;

    for (int i = 0; i < rr_count; i++) {
        /* MX RDATA: priority(2) + hostname in wire label format */
        unsigned char rdata[300];
        int rdata_len = 0;
        *(uint16_t*)(rdata + rdata_len) = htons(mxes[i].prio); rdata_len += 2;
        write_dns_labels(mxes[i].host, (char*)rdata, &rdata_len);

        if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { rr_count = i; break; }
        *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
        *(uint16_t*)(r->request + pos) = htons(QTYPE_MX);           pos += 2;
        *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
        *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
        *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
        memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

        canon_rr_append(canon, &canon_pos, sizeof(canon),
                        owner, QTYPE_MX, ttl, rdata, rdata_len);
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)rr_count);

    if (req->do_bit && canon_pos > 0) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk && append_rrsig(r->request, &pos, owner, QTYPE_MX, ttl,
                                 canon, canon_pos, zsk, false))
            *(uint16_t*)(r->request + 6) = htons((uint16_t)(rr_count + 1));
    }

    r->recv_len = pos;
    return r;
}

/* ---- NS record ---- */
static struct Packet *build_ns_response(struct Packet *req, const char *owner)
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

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    unsigned char canon[4096];
    size_t canon_pos = 0;

    for (int i = 0; i < rr_count; i++) {
        unsigned char rdata[300];
        int rdata_len = 0;
        write_dns_labels(ns_names[i], (char*)rdata, &rdata_len);

        if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { rr_count = i; break; }
        *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
        *(uint16_t*)(r->request + pos) = htons(QTYPE_NS);           pos += 2;
        *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
        *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
        *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
        memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

        canon_rr_append(canon, &canon_pos, sizeof(canon),
                        owner, QTYPE_NS, ttl, rdata, rdata_len);
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)rr_count);

    if (req->do_bit && canon_pos > 0) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk && append_rrsig(r->request, &pos, owner, QTYPE_NS, ttl,
                                 canon, canon_pos, zsk, false))
            *(uint16_t*)(r->request + 6) = htons((uint16_t)(rr_count + 1));
    }

    r->recv_len = pos;
    return r;
}

/* ---- TXT record ---- */
static struct Packet *build_txt_response(struct Packet *req, const char *owner)
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

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    unsigned char canon[8192];
    size_t canon_pos = 0;

    for (int i = 0; i < rr_count; i++) {
        size_t tlen = strlen(txt_vals[i]);
        /* TXT RDATA: sequence of ≤255-byte character-strings (RFC 1035 §3.3.14).
         * Strings longer than 255 bytes are split into multiple chunks.
         * txt_data[512] → at most 3 chunks → max RDATA = 3*256 = 768 bytes. */
        unsigned char rdata[800];
        int rdata_len = 0;
        if (tlen == 0) {
            rdata[rdata_len++] = 0;   /* empty string: one zero-length character-string */
        } else {
            size_t off = 0;
            while (off < tlen) {
                size_t chunk = tlen - off;
                if (chunk > 255) chunk = 255;
                rdata[rdata_len++] = (unsigned char)chunk;
                memcpy(rdata + rdata_len, txt_vals[i] + off, chunk);
                rdata_len += (int)chunk;
                off += chunk;
            }
        }

        if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { rr_count = i; break; }
        *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
        *(uint16_t*)(r->request + pos) = htons(QTYPE_TXT);          pos += 2;
        *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
        *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
        *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
        memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

        canon_rr_append(canon, &canon_pos, sizeof(canon),
                        owner, QTYPE_TXT, ttl, rdata, rdata_len);
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)rr_count);

    if (req->do_bit && canon_pos > 0) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk && append_rrsig(r->request, &pos, owner, QTYPE_TXT, ttl,
                                 canon, canon_pos, zsk, false))
            *(uint16_t*)(r->request + 6) = htons((uint16_t)(rr_count + 1));
    }

    r->recv_len = pos;
    return r;
}

/* ---- SRV record ---- */
static struct Packet *build_srv_response(struct Packet *req, const char *owner)
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

    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    unsigned char canon[4096];
    size_t canon_pos = 0;

    for (int i = 0; i < rr_count; i++) {
        /* SRV RDATA: priority(2) + weight(2) + port(2) + target_wire */
        unsigned char rdata[300];
        int rdata_len = 0;
        *(uint16_t*)(rdata + rdata_len) = htons(srvs[i].prio);   rdata_len += 2;
        *(uint16_t*)(rdata + rdata_len) = htons(srvs[i].weight); rdata_len += 2;
        *(uint16_t*)(rdata + rdata_len) = htons(srvs[i].port);   rdata_len += 2;
        write_dns_labels(srvs[i].target, (char*)rdata, &rdata_len);

        if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { rr_count = i; break; }
        *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
        *(uint16_t*)(r->request + pos) = htons(QTYPE_SRV);          pos += 2;
        *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
        *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
        *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
        memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

        canon_rr_append(canon, &canon_pos, sizeof(canon),
                        owner, QTYPE_SRV, ttl, rdata, rdata_len);
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)rr_count);

    if (req->do_bit && canon_pos > 0) {
        const ZoneKey *zsk = find_zsk_for_owner(owner);
        if (zsk && append_rrsig(r->request, &pos, owner, QTYPE_SRV, ttl,
                                 canon, canon_pos, zsk, false))
            *(uint16_t*)(r->request + 6) = htons((uint16_t)(rr_count + 1));
    }

    r->recv_len = pos;
    return r;
}

/* ---- CNAME record ---- */
static struct Packet *build_cname_response(struct Packet *req, const char *owner)
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

    unsigned char rdata[300];
    int rdata_len = 0;
    write_dns_labels(d->cname_target, (char*)rdata, &rdata_len);

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
                              canon, canon_pos, zsk, false))
                *(uint16_t*)(r->request + 6) = htons(2);
        }
    }

    r->recv_len = pos;
    return r;
}

/* ---- SOA record ---- */
static struct Packet *build_soa_response(struct Packet *req, const char *owner)
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

    /* SOA RDATA: mname_wire + rname_wire + serial + refresh + retry + expire + minimum */
    unsigned char rdata[600];
    int rdata_len = 0;
    write_dns_labels(d->soa_mname, (char*)rdata, &rdata_len);
    write_dns_labels(d->soa_rname, (char*)rdata, &rdata_len);
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
                              canon, canon_pos, zsk, false))
                *(uint16_t*)(r->request + 6) = htons(2);
        }
    }

    r->recv_len = pos;
    return r;
}

/* ---- DNSKEY record ---- */
static struct Packet *build_dnskey_response(struct Packet *req, const char *owner)
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
    int pos;
    struct Packet *r = begin_response(req, &pos, (uint16_t)rr_count);
    if (!r) return NULL;

    unsigned char canon[8192];
    size_t canon_pos = 0;

    for (int i = 0; i < rr_count; i++) {
        /* DNSKEY RDATA: flags(2) + protocol(1=3) + algorithm(1) + public_key */
        unsigned char rdata[640];
        int rdata_len = 0;
        *(uint16_t*)(rdata + rdata_len) = htons(dkes[i].flags); rdata_len += 2;
        rdata[rdata_len++] = 3;           /* protocol = 3 (DNSSEC) */
        rdata[rdata_len++] = dkes[i].alg;
        memcpy(rdata + rdata_len, dkes[i].pub, dkes[i].pub_len);
        rdata_len += dkes[i].pub_len;

        if (pos + 2+2+2+4+2+rdata_len > MAXLINE) { rr_count = i; break; }
        *(uint16_t*)(r->request + pos) = htons(DNS_NAME_PTR);             pos += 2;
        *(uint16_t*)(r->request + pos) = htons(QTYPE_DNSKEY);       pos += 2;
        *(uint16_t*)(r->request + pos) = htons(1);                  pos += 2;
        *(uint32_t*)(r->request + pos) = htonl(ttl);                pos += 4;
        *(uint16_t*)(r->request + pos) = htons((uint16_t)rdata_len); pos += 2;
        memcpy(r->request + pos, rdata, rdata_len);                  pos += rdata_len;

        canon_rr_append(canon, &canon_pos, sizeof(canon),
                        owner, QTYPE_DNSKEY, ttl, rdata, rdata_len);
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)rr_count);

    /* DNSKEY RRset is signed with the KSK (RFC 4035 §2.2). */
    if (req->do_bit && canon_pos > 0) {
        const ZoneKey *ksk = find_ksk_for_zone(owner);
        if (ksk && append_rrsig(r->request, &pos, owner, QTYPE_DNSKEY, ttl,
                                 canon, canon_pos, ksk, false))
            *(uint16_t*)(r->request + 6) = htons((uint16_t)(rr_count + 1));
    }

    r->recv_len = pos;
    return r;
}

/* ---- HINFO response for QTYPE_ANY (RFC 8482) ---- */
static struct Packet *build_hinfo_response(struct Packet *req)
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

/* =========================================================================
 * check_internal — main dispatch, called once per query
 * ========================================================================= */

struct Packet *check_internal(struct Packet *req)
{
    if (!req || !req->full_domain) return NULL;

    const char *owner = req->full_domain;

    pthread_rwlock_rdlock(&g_auth_domains_lock);

    /* Determine if we are authoritative for this owner.
     * We are if: (a) any record in auth_domains has this exact name, OR
     *            (b) a SOA entry covers this name as a zone suffix.      */
    bool has_entry = false;
    for (int i = 0; i < auth_domain_count && !has_entry; i++) {
        if (strcmp(auth_domains[i].domain, owner) == 0)
            has_entry = true;
    }
    const struct AuthDomain *soa = find_zone_soa(owner);
    bool owned = has_entry || (soa != NULL);

    if (!owned) {
        /* Try wildcard expansion (e.g. *.avilo.com matches www.avilo.com). */
        const struct AuthDomain *wc = find_wildcard(owner);
        if (!wc) {
            pthread_rwlock_unlock(&g_auth_domains_lock);
            return NULL;   /* not authoritative — forward to upstream */
        }

        /* Wildcard match: synthesize a response for the actual owner name. */
        struct Packet *r = NULL;
        uint32_t wttl = wc->ttl ? wc->ttl : DEFAULT_RECORD_TTL;

        if (req->q_type == QTYPE_A &&
            wc->ip[0] != '\0' && strcmp(wc->ip, "0.0.0.0") != 0) {
            struct in_addr ia;
            if (inet_pton(AF_INET, wc->ip, &ia) == 1) {
                int wpos;
                r = begin_response(req, &wpos, 1);
                if (r) {
                    *(uint16_t*)(r->request + wpos) = htons(DNS_NAME_PTR);  wpos += 2;
                    *(uint16_t*)(r->request + wpos) = htons(QTYPE_A); wpos += 2;
                    *(uint16_t*)(r->request + wpos) = htons(1);       wpos += 2;
                    *(uint32_t*)(r->request + wpos) = htonl(wttl);    wpos += 4;
                    *(uint16_t*)(r->request + wpos) = htons(4);       wpos += 2;
                    memcpy(r->request + wpos, &ia.s_addr, 4);         wpos += 4;
                    r->recv_len = wpos;
                }
            }
        } else if (req->q_type == QTYPE_AAAA && wc->has_ipv6) {
            struct in6_addr ia6;
            if (inet_pton(AF_INET6, wc->ipv6, &ia6) == 1) {
                int wpos;
                r = begin_response(req, &wpos, 1);
                if (r) {
                    *(uint16_t*)(r->request + wpos) = htons(DNS_NAME_PTR);     wpos += 2;
                    *(uint16_t*)(r->request + wpos) = htons(QTYPE_AAAA); wpos += 2;
                    *(uint16_t*)(r->request + wpos) = htons(1);          wpos += 2;
                    *(uint32_t*)(r->request + wpos) = htonl(wttl);       wpos += 4;
                    *(uint16_t*)(r->request + wpos) = htons(16);         wpos += 2;
                    memcpy(r->request + wpos, &ia6, 16);                 wpos += 16;
                    r->recv_len = wpos;
                }
            }
        } else {
            /* Wildcard-covered but no record of this type → NODATA */
            r = build_nodata_response(req, soa);
        }

        pthread_rwlock_unlock(&g_auth_domains_lock);
        return r;
    }

    /* Check for NXDOMAIN block. */
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].is_blocked &&
            strcmp(auth_domains[i].domain, owner) == 0) {
            struct Packet *r = build_nxdomain_response(req, soa);
            pthread_rwlock_unlock(&g_auth_domains_lock);
            return r;
        }
    }

    /* Dispatch by query type. */
    struct Packet *r = NULL;

    switch (req->q_type) {

    case QTYPE_A:
        r = build_a_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_AAAA:
        r = build_aaaa_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_MX:
        r = build_mx_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_NS:
        r = build_ns_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_TXT:
        r = build_txt_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_SRV:
        r = build_srv_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_CNAME:
        r = build_cname_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_SOA: {
        /* Try exact-name SOA first, then fall back to zone SOA. */
        const char *soa_owner = owner;
        const struct AuthDomain *soa_d = NULL;
        for (int i = 0; i < auth_domain_count; i++) {
            if (auth_domains[i].has_soa &&
                strcmp(auth_domains[i].domain, owner) == 0) {
                soa_d = &auth_domains[i];
                break;
            }
        }
        if (!soa_d && soa) {
            soa_d = soa;
            soa_owner = soa->domain;
        }
        if (soa_d) r = build_soa_response(req, soa_owner);
        if (!r)   r = build_nodata_response(req, soa);
        break;
    }

    case QTYPE_DNSKEY:
        r = build_dnskey_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_ANY:
        /* RFC 8482: respond with HINFO for all owned domains. */
        r = build_hinfo_response(req);
        break;

    /* DNSSEC types we don't synthesise — NODATA with SOA authority. */
    case QTYPE_DS:
    case QTYPE_RRSIG:
    case QTYPE_NSEC:
    case QTYPE_NSEC3:
    case QTYPE_NSEC3PARAM:
    default:
        r = build_nodata_response(req, soa);
        break;
    }

    pthread_rwlock_unlock(&g_auth_domains_lock);
    return r;
}

/* =========================================================================
 * Domain file loader
 * ========================================================================= */

/* Lowercase a NUL-terminated string in place. */
static void strlower(char *s)
{
    if (!s) return;
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/*
 * _load_domains_from_file — parse auth_domains.txt under wrlock.
 *
 * Supported record types (second token determines type):
 *   SOA    — domain SOA mname rname serial refresh retry expire minimum
 *   NS     — domain NS nameserver
 *   MX     — domain MX priority hostname
 *   CNAME  — domain CNAME target
 *   TXT    — domain TXT rest-of-line  (quoted or unquoted)
 *   SRV    — domain SRV priority weight port target
 *   NXDOMAIN — domain NXDOMAIN
 *   IPv6   — domain 2001:db8::1   (detected by ':' in token)
 *   IPv4   — domain 192.168.1.1   (default, validated)
 *
 * Wildcard: if the domain starts with '*' it is stored verbatim
 *           (e.g. "*.avilo.com") and marked is_wildcard = true.
 *
 * Returns number of records loaded, or -1 on I/O error.
 */
static int _load_domains_from_file(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n",
                filename, strerror(errno));
        return -1;
    }

    int  count               = 0;
    char line[1024];
    char current_domain[256] = {0};  /* set by [domain] section headers */

    while (fgets(line, sizeof(line), fp)) {
        /* Strip trailing whitespace / newline. */
        int llen = (int)strlen(line);
        while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r' ||
                            line[llen-1] == ' '  || line[llen-1] == '\t'))
            line[--llen] = '\0';

        if (llen == 0 || line[0] == '#') continue;

        /* --- Section header: [domain.name] -------------------------------- */
        if (line[0] == '[') {
            char *close = strchr(line, ']');
            if (close && close > line + 1) {
                size_t dlen = (size_t)(close - line - 1);
                if (dlen >= sizeof(current_domain))
                    dlen = sizeof(current_domain) - 1;
                memcpy(current_domain, line + 1, dlen);
                current_domain[dlen] = '\0';
                strlower(current_domain);
            }
            continue;
        }

        /* Ignore record lines that appear before any [domain] header. */
        if (current_domain[0] == '\0') continue;

        if (count >= MAX_INTERNAL_HOSTS) {
            fprintf(stderr,
                    "Warning: auth_domains limit (%d) reached; skipping rest\n",
                    MAX_INTERNAL_HOSTS);
            break;
        }

        char type_kw[64] = {0};
        if (sscanf(line, "%63s", type_kw) < 1) continue;

        bool is_wc = (current_domain[0] == '*');

        struct AuthDomain *d = &auth_domains[count];
        memset(d, 0, sizeof(*d));
        snprintf(d->domain, sizeof(d->domain), "%s", current_domain);
        d->is_wildcard = is_wc;

        /* --- SOA -------------------------------------------------------- */
        if (strcasecmp(type_kw, "SOA") == 0) {
            char mname[256] = {0}, rname[256] = {0};
            unsigned int serial = 0, refresh = 0, retry = 0,
                         expire = 0, minimum = 0;
            if (sscanf(line, "%*s %255s %255s %u %u %u %u %u",
                       mname, rname,
                       &serial, &refresh, &retry, &expire, &minimum) != 7) {
                fprintf(stderr, "Warning: Bad SOA line: %s\n", line);
                continue;
            }
            strlower(mname); strlower(rname);
            d->has_soa     = true;
            snprintf(d->soa_mname, sizeof(d->soa_mname), "%s", mname);
            snprintf(d->soa_rname, sizeof(d->soa_rname), "%s", rname);
            d->soa_serial  = serial;
            d->soa_refresh = refresh;
            d->soa_retry   = retry;
            d->soa_expire  = expire;
            d->soa_minimum = minimum;
            d->soa_ttl     = refresh;   /* default TTL = refresh interval */
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> SOA serial=%u\n",
                    current_domain, serial);
            count++;

        /* --- NS --------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "NS") == 0) {
            char ns[256] = {0};
            if (sscanf(line, "%*s %255s", ns) != 1) {
                fprintf(stderr, "Warning: Bad NS line: %s\n", line);
                continue;
            }
            strlower(ns);
            d->has_ns = true;
            snprintf(d->ns_name, sizeof(d->ns_name), "%s", ns);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> NS %s\n", current_domain, ns);
            count++;

        /* --- MX --------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "MX") == 0) {
            unsigned int prio = 0;
            char mx_host[256] = {0};
            if (sscanf(line, "%*s %u %255s", &prio, mx_host) != 2) {
                fprintf(stderr, "Warning: Bad MX line: %s\n", line);
                continue;
            }
            strlower(mx_host);
            d->has_mx      = true;
            d->mx_priority = (uint16_t)prio;
            snprintf(d->mx_hostname, sizeof(d->mx_hostname), "%s", mx_host);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> MX %u %s\n",
                    current_domain, prio, mx_host);
            count++;

        /* --- CNAME ------------------------------------------------------ */
        } else if (strcasecmp(type_kw, "CNAME") == 0) {
            char target[256] = {0};
            if (sscanf(line, "%*s %255s", target) != 1) {
                fprintf(stderr, "Warning: Bad CNAME line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_cname = true;
            snprintf(d->cname_target, sizeof(d->cname_target), "%s", target);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> CNAME %s\n",
                    current_domain, target);
            count++;

        /* --- TXT -------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "TXT") == 0) {
            /* Advance past the "TXT" keyword to the text content. */
            const char *p = line;
            while (*p && !isspace((unsigned char)*p)) p++;
            while (*p &&  isspace((unsigned char)*p)) p++;
            /* p now points to the text data (possibly quoted) */
            if (*p == '"') p++;
            char txt[512];
            snprintf(txt, sizeof(txt), "%s", p);
            int tlen = (int)strlen(txt);
            if (tlen > 0 && txt[tlen - 1] == '"') txt[--tlen] = '\0';
            d->has_txt = true;
            snprintf(d->txt_data, sizeof(d->txt_data), "%s", txt);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> TXT \"%s\"\n",
                    current_domain, txt);
            count++;

        /* --- SRV -------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "SRV") == 0) {
            unsigned int prio = 0, weight = 0, port = 0;
            char target[256] = {0};
            if (sscanf(line, "%*s %u %u %u %255s",
                       &prio, &weight, &port, target) != 4) {
                fprintf(stderr, "Warning: Bad SRV line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_srv      = true;
            d->srv_priority = (uint16_t)prio;
            d->srv_weight   = (uint16_t)weight;
            d->srv_port     = (uint16_t)port;
            snprintf(d->srv_target, sizeof(d->srv_target), "%s", target);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> SRV %u %u %u %s\n",
                    current_domain, prio, weight, port, target);
            count++;

        /* --- NXDOMAIN --------------------------------------------------- */
        } else if (strcasecmp(type_kw, "NXDOMAIN") == 0) {
            d->is_blocked = true;
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> BLOCKED (NXDOMAIN)\n",
                    current_domain);
            count++;

        /* --- AAAA ------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "AAAA") == 0) {
            char ip6[64] = {0};
            if (sscanf(line, "%*s %63s", ip6) != 1) {
                fprintf(stderr, "Warning: Bad AAAA line: %s\n", line);
                continue;
            }
            struct in6_addr ia6;
            if (inet_pton(AF_INET6, ip6, &ia6) != 1) {
                fprintf(stderr, "Warning: Invalid IPv6 '%s' for '%s'\n",
                        ip6, current_domain);
                continue;
            }
            d->has_ipv6 = true;
            snprintf(d->ipv6, sizeof(d->ipv6), "%s", ip6);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> %s (AAAA)\n",
                    current_domain, ip6);
            count++;

        /* --- A ---------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "A") == 0) {
            char ip4[20] = {0};
            if (sscanf(line, "%*s %19s", ip4) != 1) {
                fprintf(stderr, "Warning: Bad A line: %s\n", line);
                continue;
            }
            struct in_addr ia;
            if (inet_pton(AF_INET, ip4, &ia) != 1) {
                fprintf(stderr, "Warning: Invalid IPv4 '%s' for '%s'\n",
                        ip4, current_domain);
                continue;
            }
            snprintf(d->ip, sizeof(d->ip), "%s", ip4);
            fprintf(stderr, "  Loaded: %-32s -> %s\n", current_domain, ip4);
            count++;

        } else {
            fprintf(stderr, "Warning: Unknown record type '%s' for [%s]\n",
                    type_kw, current_domain);
            continue;
        }
    }

    fclose(fp);
    return count;
}

/* ---- Public load / reload / lookup ------------------------------------- */

int load_auth_domains(const char *filename)
{
    if (!filename) return -1;

    pthread_rwlock_wrlock(&g_auth_domains_lock);
    auth_domain_count = 0;
    int n = _load_domains_from_file(filename);
    if (n > 0) auth_domain_count = n;
    pthread_rwlock_unlock(&g_auth_domains_lock);

    if (n <= 0) {
        fprintf(stderr,
                "Warning: No valid domains loaded from %s\n", filename);
        return (n == 0) ? 0 : -1;
    }
    fprintf(stderr, "✓ Loaded %d authoritative record(s)\n\n", n);
    return n;
}

void reload_auth_domains(const char *filename)
{
    if (!filename) return;

    pthread_rwlock_wrlock(&g_auth_domains_lock);

    /* Save old SOA serial before overwriting (RFC 1982 — serial must increase). */
    uint32_t old_serial = 0;
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].has_soa) {
            old_serial = auth_domains[i].soa_serial;
            break;
        }
    }

    int old_count = auth_domain_count;
    auth_domain_count = 0;
    int n = _load_domains_from_file(filename);
    if (n > 0) {
        auth_domain_count = n;
        fprintf(stderr,
                "SIGHUP: reloaded %d record(s) (was %d)\n", n, old_count);

        /* Warn if SOA serial did not increase (RFC 1982). */
        if (old_serial > 0) {
            for (int i = 0; i < auth_domain_count; i++) {
                if (auth_domains[i].has_soa) {
                    uint32_t new_serial = auth_domains[i].soa_serial;
                    if (new_serial <= old_serial)
                        fprintf(stderr,
                                "Warning: SOA serial %u <= old serial %u "
                                "— secondaries may not detect the update (RFC 1982)\n",
                                new_serial, old_serial);
                    break;
                }
            }
        }
    } else {
        auth_domain_count = old_count;   /* keep existing data on error */
        fprintf(stderr,
                "SIGHUP: reload failed; keeping %d existing record(s)\n",
                old_count);
    }
    pthread_rwlock_unlock(&g_auth_domains_lock);
}

/*
 * lookup_auth_domain — thread-safe A-record lookup (used by external callers).
 * Returns IP string, "NXDOMAIN" if blocked, NULL if not found.
 */
const char *lookup_auth_domain(const char *full_domain)
{
    if (!full_domain) return NULL;

    pthread_rwlock_rdlock(&g_auth_domains_lock);
    const char *result = NULL;

    for (int i = 0; i < auth_domain_count; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        /* Skip non-A entries */
        if (d->has_mx || d->has_ipv6 || d->has_cname ||
            d->has_ns || d->has_txt || d->has_srv || d->has_soa)
            continue;
        if (strcmp(d->domain, full_domain) != 0) continue;
        result = d->is_blocked ? "NXDOMAIN" : d->ip;
        break;
    }

    pthread_rwlock_unlock(&g_auth_domains_lock);
    return result;
}
