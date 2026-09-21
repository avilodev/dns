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
#include "auth_answer.h"
#include "auth_records.h"
#include "auth_lookup.h"
#include "dns_name.h"

#include <time.h>
#include <ctype.h>

/* =========================================================================
 * Globals
 * ========================================================================= */

/* Defined here, declared extern in main.c.  NULL when DNSSEC signing is off. */
ZoneKey *g_zone_keys = NULL;

/* Reader-writer lock protecting auth_domains[] and auth_domain_count. */
pthread_rwlock_t g_auth_domains_lock = PTHREAD_RWLOCK_INITIALIZER;


/* =========================================================================
 * Response buffer helpers
 * ========================================================================= */

static struct Packet *alloc_response(void)
{
    struct Packet *r = calloc(1, sizeof(struct Packet));
    if (!r) { perror("auth: calloc packet"); return NULL; }
    r->request = calloc(1, DNS_MSG_MAX);
    if (!r->request) { perror("auth: calloc buf"); free(r); return NULL; }
    return r;
}

/* Write 12-byte DNS header (TX ID must already be at buf[0..1]). */
static void write_hdr(char *buf, uint16_t flags,
                      uint16_t qdcount, uint16_t ancount,
                      uint16_t nscount, uint16_t arcount)
{
    wr16(buf + 2, flags);
    wr16(buf + 4, qdcount);
    wr16(buf + 6, ancount);
    wr16(buf + 8, nscount);
    wr16(buf + 10, arcount);
}

/* Standard AA+RA response flags (NOERROR). */
static uint16_t aa_flags(const struct Packet *req)
{
    return (uint16_t)((1u << 15) |           /* QR = response    */
                      (1u << 10) |           /* AA = authoritative */
                      ((unsigned)req->rd << 8) | /* copy RD       */
                      (1u << 7) |             /* RA = available   */
                      ((unsigned)req->cd << 4));  /* copy CD (RFC 4035 §3.2.2) */
}

/* Write the echoed question (QNAME + QTYPE + QCLASS), preserving the client's
 * original QNAME case for 0x20 anti-spoofing (4.8). Advances *pos. */
static void write_question(char *buf, int *pos, const struct Packet *req)
{
    echo_question(buf, pos, req);
}

/*
 * Allocate a response, copy TX ID, write header (AA, ancount), and
 * write the question section.  Returns the Packet with *pos_out pointing
 * just after the question section (start of the answer section).
 */
struct Packet *begin_response(const struct Packet *req,
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
 * Lowercase the ASCII letters of an uncompressed wire-format domain name,
 * label by label (RFC 4034 §6.2 canonical form).  Stops at the root label.
 * Used to canonicalise the owner name and the embedded RDATA names of the
 * pre-RFC-4034 types that require it (NS, MX, SRV, CNAME, SOA, …).
 */
void wire_name_lc(unsigned char *p, int max)
{
    int i = 0;
    while (i < max) {
        uint8_t l = p[i];
        if (l == 0) break;          /* root label — done            */
        if (l & 0xC0) break;        /* compression not expected here */
        i++;
        for (int k = 0; k < l && i < max; k++, i++)
            if (p[i] >= 'A' && p[i] <= 'Z') p[i] = (unsigned char)(p[i] + 32);
    }
}

/*
 * Append one canonical-form RR to out[*out_pos]:
 *   owner_wire (no compression, downcased) || type || class || ttl || rdlen || rdata
 *
 * The owner name is downcased per RFC 4034 §6.2(1).  RDATA is taken as given;
 * callers are responsible for putting any embedded RDATA names into canonical
 * (downcased) form before calling, per the type's §6.2 rules (RFC 6840 §5.1
 * exempts newer types such as HTTPS/SVCB).
 */
void canon_rr_append(unsigned char *out, size_t *out_pos, size_t out_cap,
                             const char *owner_name, uint16_t type, uint32_t ttl,
                             const unsigned char *rdata, size_t rdlen)
{
    char own_wire[280];
    int  own_len = 0;
    write_dns_labels(owner_name, own_wire, &own_len, sizeof(own_wire));
    wire_name_lc((unsigned char *)own_wire, own_len);   /* §6.2(1) */

    size_t need = (size_t)own_len + 2 + 2 + 4 + 2 + rdlen;
    if (*out_pos + need > out_cap) return;

    memcpy(out + *out_pos, own_wire, own_len);        *out_pos += (size_t)own_len;
    wr16(out + *out_pos, type);       *out_pos += 2;
    wr16(out + *out_pos, 1 /* IN */); *out_pos += 2;
    wr32(out + *out_pos, ttl);        *out_pos += 4;
    wr16(out + *out_pos, (uint16_t)rdlen); *out_pos += 2;
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
int append_rrsig(char *buf, int *pos,
                         const char *owner_name,
                         uint16_t type_covered, uint32_t ttl,
                         const unsigned char *canon_rrset, size_t canon_rrset_len,
                         const ZoneKey *zsk,
                         bool is_wildcard,
                         const char *explicit_rr_owner)
{
    if (!buf || !pos || !owner_name || !canon_rrset || !zsk) return 0;

    time_t now = time(NULL);
    uint32_t inception  = (uint32_t)(now - 300);          /* 5 min grace   */
    uint32_t expiration = (uint32_t)(now + 86400UL * 30); /* 30-day window */

    /* Signer name (zone apex) in wire format */
    char signer_wire[280];
    int  signer_wire_len = 0;
    write_dns_labels(zsk->zone, signer_wire, &signer_wire_len, sizeof(signer_wire));

    /* Build RRSIG RDATA header (everything before the signature field):
     *   type_covered(2) + alg(1) + labels(1) + orig_ttl(4)
     *   + sig_expiration(4) + sig_inception(4) + key_tag(2)
     *   + signer_name(var)                                           */
    unsigned char rrsig_hdr[320];
    int hdr_pos = 0;
    wr16(rrsig_hdr + hdr_pos, type_covered);      hdr_pos += 2;
    rrsig_hdr[hdr_pos++] = zsk->algorithm;
    /* RFC 4034 §3.1.3: for wildcard RRsets, labels = label count of owner
     * minus one (the '*' label is not counted in the RRSIG labels field). */
    int lcount = count_labels(owner_name);
    if (is_wildcard && lcount > 0) lcount--;
    rrsig_hdr[hdr_pos++] = (uint8_t)lcount;
    wr32(rrsig_hdr + hdr_pos, ttl);               hdr_pos += 4;
    wr32(rrsig_hdr + hdr_pos, expiration);        hdr_pos += 4;
    wr32(rrsig_hdr + hdr_pos, inception);         hdr_pos += 4;
    wr16(rrsig_hdr + hdr_pos, zsk->key_tag);      hdr_pos += 2;
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

    /* Owner name: a compression pointer for the answer section, full labels
     * for the authority section.  Encode it BEFORE the space check so `need`
     * covers its real length — assuming the 2-byte pointer here let a 255-byte
     * explicit owner push the fixed fields and signature past the end of the
     * DNS_MSG_MAX buffer. */
    uint8_t owner_wire[256];
    int owner_len = 2;                              /* DNS_NAME_PTR */
    if (explicit_rr_owner) {
        owner_len = dname_to_wire(explicit_rr_owner, owner_wire, sizeof(owner_wire));
        if (owner_len < 0) { free(sig); return 0; }
    }

    size_t rrsig_rdlen = (size_t)hdr_pos + sig_len;
    int need = owner_len + 2 + 2 + 4 + 2 + (int)rrsig_rdlen;
    if (*pos + need > DNS_MSG_MAX) { free(sig); return 0; }

    if (explicit_rr_owner) {
        memcpy(buf + *pos, owner_wire, (size_t)owner_len);   *pos += owner_len;
    } else {
        wr16(buf + *pos, DNS_NAME_PTR);                      *pos += 2;
    }
    wr16(buf + *pos, QTYPE_RRSIG);                *pos += 2;
    wr16(buf + *pos, 1 /* IN */);                 *pos += 2;
    wr32(buf + *pos, ttl);                        *pos += 4;
    wr16(buf + *pos, (uint16_t)rrsig_rdlen);      *pos += 2;
    memcpy(buf + *pos, rrsig_hdr, hdr_pos);                       *pos += hdr_pos;
    memcpy(buf + *pos, sig, sig_len);                              *pos += (int)sig_len;
    free(sig);
    return 1;
}

/* =========================================================================
 * RRset assembly with canonical ordering (RFC 4034 §6.3)
 * ========================================================================= */


/*
 * RFC 4034 §6.3 canonical RR ordering: compare the RDATA of two RRs (same
 * owner/class/type) as a left-justified unsigned octet sequence; if one is a
 * prefix of the other, the shorter sorts first ("absence of an octet sorts
 * before a zero octet").
 */
static int rrblob_cmp(const void *a, const void *b)
{
    const RrBlob *x = (const RrBlob *)a;
    const RrBlob *y = (const RrBlob *)b;
    size_t m = (x->len < y->len) ? x->len : y->len;
    int c = memcmp(x->data, y->data, m);
    if (c) return c;
    if (x->len != y->len) return (x->len < y->len) ? -1 : 1;
    return 0;
}

/*
 * Emit one RRset into the answer section and, when DO is set and a signing key
 * is available, append its RRSIG.
 *
 * The RRs are first sorted into RFC 4034 §6.3 canonical order, and that exact
 * order is used both for the answer section and for the signed image — so the
 * signature matches the RRset a validator reconstructs (the fix for the
 * "BOGUS multi-RR RRset" bug).  Each blob's RDATA must already be in §6.2
 * canonical form.  Returns the number of answer RRs written (excluding RRSIG)
 * and updates the ANCOUNT header field.
 */
int emit_signed_rrset(struct Packet *r, int *pos, const char *owner,
                             uint16_t type, uint32_t ttl,
                             RrBlob *blobs, int n,
                             bool do_bit, const ZoneKey *key)
{
    if (n > 1)
        qsort(blobs, (size_t)n, sizeof(RrBlob), rrblob_cmp);   /* §6.3 */

    int written = 0;
    for (int i = 0; i < n; i++) {
        if (*pos + 2 + 2 + 2 + 4 + 2 + (int)blobs[i].len > DNS_MSG_MAX) break;
        wr16(r->request + *pos, DNS_NAME_PTR);   *pos += 2;
        wr16(r->request + *pos, type);           *pos += 2;
        wr16(r->request + *pos, 1 /* IN */);     *pos += 2;
        wr32(r->request + *pos, ttl);            *pos += 4;
        wr16(r->request + *pos, blobs[i].len);   *pos += 2;
        memcpy(r->request + *pos, blobs[i].data, blobs[i].len);  *pos += blobs[i].len;
        written++;
    }
    wr16(r->request + 6, (uint16_t)written);

    if (do_bit && written > 0 && key) {
        /* Sized to the RRset (owner <= 256 wire bytes + 10 fixed per RR), so
         * a large RRset is never signed over a silently truncated image. */
        size_t cap = 0;
        for (int i = 0; i < written; i++) cap += 256 + 10 + blobs[i].len;
        unsigned char *canon = malloc(cap);
        size_t canon_pos = 0;
        if (canon) {
            for (int i = 0; i < written; i++)
                canon_rr_append(canon, &canon_pos, cap,
                                owner, type, ttl, blobs[i].data, blobs[i].len);
            if (canon_pos > 0 &&
                append_rrsig(r->request, pos, owner, type, ttl,
                             canon, canon_pos, key, false, NULL))
                wr16(r->request + 6, (uint16_t)(written + 1));
            free(canon);
        }
    }
    return written;
}

/* =========================================================================
 * NSEC support — RFC 4034 §4
 * ========================================================================= */

/*
 * is_in_zone — true if name is the zone apex or a subdomain of it.
 * "mail.avilo.com" is in "avilo.com"; "avilo.com" is in "avilo.com".
 */
static bool is_in_zone(const char *name, const char *zone)
{
    return name && zone && dname_is_subdomain(name, zone);
}

/*
 * dns_canon_cmp — canonical DNS name order (RFC 4034 §6.1).
 * Names are compared as wire labels from the rightmost label leftwards; each
 * label is compared as a lowercased octet string, and a shorter label (or name)
 * that is a prefix of the other sorts first.  Working on wire labels keeps an
 * escaped dot inside a label from being treated as a separator.
 * Returns <0 if a < b, 0 if equal, >0 if a > b.
 */
static int dns_canon_cmp(const char *a, const char *b)
{
    uint8_t wa[256], wb[256];
    int la = dname_to_wire(a, wa, sizeof(wa));
    int lb = dname_to_wire(b, wb, sizeof(wb));
    if (la < 0 || lb < 0) return strcmp(a, b);        /* malformed: stable fallback */

    /* Offsets of each label, so we can walk them right to left. */
    int oa[128], ob[128], na = 0, nb = 0;
    for (int i = 0; wa[i]; i += 1 + wa[i]) oa[na++] = i;
    for (int i = 0; wb[i]; i += 1 + wb[i]) ob[nb++] = i;

    for (int ia = na - 1, ib = nb - 1; ia >= 0 && ib >= 0; ia--, ib--) {
        const uint8_t *x = wa + oa[ia], *y = wb + ob[ib];
        int lx = x[0], ly = y[0], m = lx < ly ? lx : ly;
        for (int k = 1; k <= m; k++) {
            int cx = tolower(x[k]), cy = tolower(y[k]);
            if (cx != cy) return cx - cy;
        }
        if (lx != ly) return lx - ly;
    }
    return na - nb;                                   /* ancestor sorts first */
}

/*
 * nsec_set_type — set a type bit in a 32-byte window-0 bitmap.
 * Types 0-255 only (window 0).
 */
static void nsec_set_type(unsigned char bm[32], int *max_type, uint16_t t)
{
    if (t < 256) {
        bm[t / 8] |= (uint8_t)(0x80u >> (t % 8));
        if ((int)t > *max_type) *max_type = (int)t;
    }
}

/*
 * build_nsec_type_bitmap — build NSEC type bitmap (RFC 4034 §4.1.2) for owner.
 * Scans auth_domains[] for all record types present at owner.
 * Returns the total length written into out[] (window-block format), 0 on error.
 */
static int build_nsec_type_bitmap(const char *owner,
                                   unsigned char *out, int max_out)
{
    unsigned char bm[32] = {0};
    int max_type = -1;

    /* Every type the store can hold, tested through the one predicate the
     * response builders use — an inline copy of the A-record test here had
     * drifted (it omitted has_https) and could advertise a type we do not
     * actually serve. */
    static const uint16_t kTypes[] = {
        QTYPE_A, QTYPE_NS, QTYPE_SOA, QTYPE_MX, QTYPE_TXT,
        QTYPE_AAAA, QTYPE_SRV, QTYPE_HTTPS, QTYPE_CNAME,
    };

    int st, cnt = auth_records_for(owner, &st);
    for (int i = st; i < st + cnt; i++)
        for (size_t t = 0; t < sizeof(kTypes) / sizeof(kTypes[0]); t++)
            if (rec_has_type(&auth_domains[i], kTypes[t]))
                nsec_set_type(bm, &max_type, kTypes[t]);

    if (max_type < 0) return 0;  /* nothing found at this name */

    /* When the zone is signed, the NSEC bitmap must include RRSIG and NSEC. */
    if (g_zone_keys && find_zsk_for_owner(owner)) {
        nsec_set_type(bm, &max_type, QTYPE_RRSIG);
        nsec_set_type(bm, &max_type, QTYPE_NSEC);
    }

    int bm_bytes = (max_type / 8) + 1;
    if (2 + bm_bytes > max_out) return 0;
    out[0] = 0;                             /* window number (types 0-255) */
    out[1] = (unsigned char)bm_bytes;
    memcpy(out + 2, bm, bm_bytes);
    return 2 + bm_bytes;
}

/*
 * Smallest in-zone name strictly after `after`, wrapping to the zone's first
 * name when `after` is its last (the NSEC chain is circular, RFC 4034 §4.1.1).
 */
static const char *nsec_successor(const char *zone, const char *after)
{
    const char *best = NULL, *first = NULL;
    for (int i = 0; i < auth_domain_count; i++) {
        const char *n = auth_domains[i].domain;
        if (!is_in_zone(n, zone)) continue;
        if (!first || dns_canon_cmp(n, first) < 0) first = n;
        if (dns_canon_cmp(n, after) > 0 && (!best || dns_canon_cmp(n, best) < 0)) best = n;
    }
    return best ? best : first;
}

/*
 * nsec_find_covering — find the NSEC owner and next-name for a denial response.
 *
 * is_nxdomain = true:  qname doesn't exist; owner = its predecessor in
 *                      canonical order (wrapping when qname sorts first).
 * is_nxdomain = false: qname exists but has no data of the queried type
 *                      (NODATA); owner = qname itself.
 * next = the name following the owner, wrapping at the end of the zone.
 *
 * zone: SOA domain (e.g. "avilo.com")
 * Returns 1 on success, 0 if NSEC data is not available.
 *
 * The pair we need is just "the name before" and "the one after", so two
 * linear scans suffice.  Collecting and sorting the zone into a fixed
 * char[256][256] instead cost 64 KB of stack per denial, was O(n^2) twice
 * over, and — worse — silently emitted a WRONG chain for any zone with more
 * than 256 names, because the array simply stopped filling.
 */
static int nsec_find_covering(const char *zone, const char *qname,
                               bool is_nxdomain,
                               char owner_out[256], char next_out[256])
{
    const char *pred = NULL, *last = NULL;
    bool have_qname = false;

    for (int i = 0; i < auth_domain_count; i++) {
        const char *n = auth_domains[i].domain;
        if (!is_in_zone(n, zone)) continue;
        if (!last || dns_canon_cmp(n, last) > 0) last = n;
        if (dns_canon_cmp(n, qname) < 0 && (!pred || dns_canon_cmp(n, pred) > 0)) pred = n;
        if (!have_qname && strcmp(n, qname) == 0) have_qname = true;
    }
    if (!last) return 0;                        /* no names in this zone */

    const char *owner;
    if (is_nxdomain) {
        owner = pred ? pred : last;             /* qname sorts first: wrap */
    } else {
        if (!have_qname) return 0;              /* NODATA needs the name itself */
        owner = qname;
    }

    const char *next = nsec_successor(zone, owner);
    if (!next) return 0;
    snprintf(owner_out, 256, "%s", owner);
    snprintf(next_out,  256, "%s", next);
    return 1;
}

/*
 * append_nsec_authority — append an NSEC RR (+ optional RRSIG) to the
 * authority section of a response already in buf[0..*pos].
 * Updates NSCOUNT at wire offset 8.
 */
static void append_nsec_authority(char *buf, int *pos,
                                   const char *owner_name,
                                   const char *next_name,
                                   const unsigned char *type_bm, int type_bm_len,
                                   const struct Packet *req)
{
    /* NSEC RDATA: next-domain-name (wire, uncompressed) + type bitmap */
    unsigned char rdata[600];
    int rdata_len = 0;
    write_dns_labels(next_name, (char*)rdata, &rdata_len, sizeof(rdata));
    if (rdata_len + type_bm_len > (int)sizeof(rdata)) return;
    memcpy(rdata + rdata_len, type_bm, type_bm_len);
    rdata_len += type_bm_len;

    uint32_t ttl = DEFAULT_RECORD_TTL;
    int need = 300 + rdata_len;
    if (*pos + need > DNS_MSG_MAX) return;

    /* Write NSEC RR: owner (full wire labels) + type + class + ttl + rdlen + rdata */
    write_dns_labels(owner_name, buf, pos, DNS_MSG_MAX);
    wr16(buf + *pos, QTYPE_NSEC);            *pos += 2;
    wr16(buf + *pos, 1 /* IN */);             *pos += 2;
    wr32(buf + *pos, ttl);                   *pos += 4;
    wr16(buf + *pos, (uint16_t)rdata_len);   *pos += 2;
    memcpy(buf + *pos, rdata, rdata_len);                    *pos += rdata_len;

    /* Increment NSCOUNT */
    uint16_t nscount = rd16(buf + 8);
    wr16(buf + 8, nscount + 1);

    /* Append RRSIG(NSEC) when DO=1 */
    if (req->do_bit && g_zone_keys) {
        const ZoneKey *zsk = find_zsk_for_owner(owner_name);
        if (zsk) {
            unsigned char canon[2048];
            size_t canon_pos = 0;
            canon_rr_append(canon, &canon_pos, sizeof(canon),
                            owner_name, QTYPE_NSEC, ttl, rdata, rdata_len);
            if (append_rrsig(buf, pos, owner_name, QTYPE_NSEC, ttl,
                              canon, canon_pos, zsk, false, owner_name)) {
                nscount = rd16(buf + 8);
                wr16(buf + 8, nscount + 1);
            }
        }
    }
}

/* =========================================================================
 * check_internal — main dispatch, called once per query
 * ========================================================================= */

/*
 * Answer `req` from the records owned by `owner` (the query name itself, or
 * the "*.<closest encloser>" wildcard whose records are synthesized for it —
 * every builder writes the answer owner as a pointer to the question name).
 * Caller holds the rdlock.
 */
static struct Packet *answer_from_owner(struct Packet *req, const char *owner,
                                        const struct AuthDomain *soa)
{
    /* RFC 1034 §3.6.2: if the owner is a CNAME alias, return the CNAME RR
     * for any query type except QTYPE_CNAME (direct lookup) and QTYPE_ANY
     * (answered with HINFO per RFC 8482 regardless of record type). */
    if (req->q_type != QTYPE_CNAME && req->q_type != QTYPE_ANY) {
        struct Packet *cr = build_cname_response(req, owner);
        if (cr) return cr;
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

    case QTYPE_HTTPS:
        r = build_https_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_CNAME:
        r = build_cname_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

    case QTYPE_SOA:
        /* Only a zone apex owns an SOA.  Below the apex the answer is NODATA
         * with the zone SOA in the authority section (RFC 2308 §2.2) — not
         * the apex SOA relabelled with the query name. */
        r = build_soa_response(req, owner);
        if (!r) r = build_nodata_response(req, soa);
        break;

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
    return r;
}

struct Packet *check_internal(struct Packet *req)
{
    if (!req || !req->full_domain) return NULL;

    const char *owner = req->full_domain;

    pthread_rwlock_rdlock(&g_auth_domains_lock);

    /* Determine if we are authoritative for this owner.
     * We are if: (a) any record in auth_domains has this exact name, OR
     *            (b) a SOA entry covers this name as a zone suffix.      */
    int rec_start;
    bool has_entry = auth_records_for(owner, &rec_start) > 0;
    const struct AuthDomain *soa = find_zone_soa(owner);

    /* At or below a zone cut (NS below the apex) the data belongs to the child
     * zone: answer with a referral, not with our own NXDOMAIN/NODATA or the
     * NS RRset as authoritative data (RFC 1034 §4.3.2 step 3b).  DS at the cut
     * itself is parent-side data, so it falls through. */
    if (soa) {
        const char *cut = find_zone_cut(owner, soa->domain);
        if (cut && !(req->q_type == QTYPE_DS && strcmp(cut, owner) == 0)) {
            struct Packet *ref = build_referral_response(req, cut);
            pthread_rwlock_unlock(&g_auth_domains_lock);
            return ref;
        }
    }

    /* No exact record for this name.  It is one of: a wildcard match, an empty
     * non-terminal (NODATA), a genuinely non-existent name inside a zone we own
     * (NXDOMAIN, RFC 1034/2308), or a name we are not authoritative for at all
     * (forward upstream). */
    if (!has_entry) {
        /* An empty non-terminal exists, so it is NODATA and never
         * wildcard-synthesized (RFC 4592 §2.2.2). */
        bool ent = is_empty_non_terminal(owner);
        const struct AuthDomain *wc = ent ? NULL : find_wildcard(owner);
        if (!wc) {
            if (soa) {
                /* Inside a zone we own but with no exact record: NODATA only
                 * for an empty non-terminal, otherwise NXDOMAIN. */
                struct Packet *r = ent ? build_nodata_response(req, soa)
                                       : build_nxdomain_response(req, soa);
                if (r && req->do_bit && soa) {
                    int pos = (int)r->recv_len;
                    char nsec_owner[256], nsec_next[256];
                    if (nsec_find_covering(soa->domain, owner, !ent,
                                           nsec_owner, nsec_next)) {
                        unsigned char type_bm[64];
                        int bm_len = build_nsec_type_bitmap(nsec_owner,
                                                            type_bm, sizeof(type_bm));
                        if (bm_len > 0)
                            append_nsec_authority(r->request, &pos, nsec_owner,
                                                  nsec_next, type_bm, bm_len, req);
                        r->recv_len = pos;
                    }
                }
                pthread_rwlock_unlock(&g_auth_domains_lock);
                return r;
            }
            pthread_rwlock_unlock(&g_auth_domains_lock);
            return NULL;   /* not authoritative — forward to upstream */
        }

        /* Wildcard match (RFC 4592): synthesize the answer from the records
         * at the wildcard owner, for any type.  Signing of synthesized
         * answers is not implemented, so they are served unsigned (DO off). */
        uint8_t saved_do = req->do_bit;
        req->do_bit = 0;
        struct Packet *r = answer_from_owner(req, wc->domain, soa);
        req->do_bit = saved_do;

        pthread_rwlock_unlock(&g_auth_domains_lock);
        return r;
    }

    struct Packet *r = answer_from_owner(req, owner, soa);

    /* For NODATA responses when DO=1: append NSEC proof of non-existence
     * (RFC 4034 §3.1.3).  Detect NODATA by RCODE=NOERROR + ANCOUNT=0. */
    if (r && req->do_bit && soa) {
        uint16_t flags   = rd16(r->request + 2);
        uint16_t rcode   = flags & 0x000Fu;
        uint16_t ancount = rd16(r->request + 6);
        if (rcode == 0 && ancount == 0) {
            int pos = (int)r->recv_len;
            char nsec_owner[256], nsec_next[256];
            if (nsec_find_covering(soa->domain, owner, false,
                                   nsec_owner, nsec_next)) {
                unsigned char type_bm[64];
                int bm_len = build_nsec_type_bitmap(nsec_owner,
                                                    type_bm, sizeof(type_bm));
                if (bm_len > 0)
                    append_nsec_authority(r->request, &pos, nsec_owner,
                                          nsec_next, type_bm, bm_len, req);
                r->recv_len = pos;
            }
        }
    }

    pthread_rwlock_unlock(&g_auth_domains_lock);
    return r;
}

