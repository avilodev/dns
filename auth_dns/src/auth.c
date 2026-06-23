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

/*
 * is_empty_non_terminal — true if `owner` is a strict ancestor of some loaded
 * record (e.g. "_tcp.avilo.com" when "_imaps._tcp.avilo.com" exists).  Such a
 * name owns no records itself but DOES exist in the tree, so a query for it is
 * NODATA (NOERROR), not NXDOMAIN (RFC 1034 §4.3.2, empty non-terminal).
 */
static bool is_empty_non_terminal(const char *owner)
{
    if (!owner || !*owner) return false;
    size_t olen = strlen(owner);
    for (int i = 0; i < auth_domain_count; i++) {
        const char *d = auth_domains[i].domain;
        size_t dlen = strlen(d);
        if (dlen > olen + 1 &&
            d[dlen - olen - 1] == '.' &&
            strcmp(d + dlen - olen, owner) == 0)
            return true;
    }
    return false;
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
 * Lowercase the ASCII letters of an uncompressed wire-format domain name,
 * label by label (RFC 4034 §6.2 canonical form).  Stops at the root label.
 * Used to canonicalise the owner name and the embedded RDATA names of the
 * pre-RFC-4034 types that require it (NS, MX, SRV, CNAME, SOA, …).
 */
static void wire_name_lc(unsigned char *p, int max)
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
static void canon_rr_append(unsigned char *out, size_t *out_pos, size_t out_cap,
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

    /* Owner name: use compression ptr for answer section, or full labels for authority. */
    if (explicit_rr_owner) {
        write_dns_labels(explicit_rr_owner, buf, pos, MAXLINE);
    } else {
        *(uint16_t*)(buf + *pos) = htons(DNS_NAME_PTR);             *pos += 2;
    }
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
 * RRset assembly with canonical ordering (RFC 4034 §6.3)
 * ========================================================================= */

/*
 * One resource record's canonical RDATA, used to order and sign an RRset.
 * Sized for the largest RDATA we emit (DNSKEY public keys, SOA, multi-string
 * TXT).  Embedded names must already be in §6.2 canonical form (downcased)
 * where the type requires it; this struct is type-agnostic.
 */
typedef struct { unsigned char data[1024]; uint16_t len; } RrBlob;

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
static int emit_signed_rrset(struct Packet *r, int *pos, const char *owner,
                             uint16_t type, uint32_t ttl,
                             RrBlob *blobs, int n,
                             bool do_bit, const ZoneKey *key)
{
    if (n > 1)
        qsort(blobs, (size_t)n, sizeof(RrBlob), rrblob_cmp);   /* §6.3 */

    int written = 0;
    for (int i = 0; i < n; i++) {
        if (*pos + 2 + 2 + 2 + 4 + 2 + (int)blobs[i].len > MAXLINE) break;
        *(uint16_t*)(r->request + *pos) = htons(DNS_NAME_PTR);   *pos += 2;
        *(uint16_t*)(r->request + *pos) = htons(type);           *pos += 2;
        *(uint16_t*)(r->request + *pos) = htons(1 /* IN */);     *pos += 2;
        *(uint32_t*)(r->request + *pos) = htonl(ttl);            *pos += 4;
        *(uint16_t*)(r->request + *pos) = htons(blobs[i].len);   *pos += 2;
        memcpy(r->request + *pos, blobs[i].data, blobs[i].len);  *pos += blobs[i].len;
        written++;
    }
    *(uint16_t*)(r->request + 6) = htons((uint16_t)written);

    if (do_bit && written > 0 && key) {
        unsigned char canon[16384];
        size_t canon_pos = 0;
        for (int i = 0; i < written; i++)
            canon_rr_append(canon, &canon_pos, sizeof(canon),
                            owner, type, ttl, blobs[i].data, blobs[i].len);
        if (canon_pos > 0 &&
            append_rrsig(r->request, pos, owner, type, ttl,
                         canon, canon_pos, key, false, NULL))
            *(uint16_t*)(r->request + 6) = htons((uint16_t)(written + 1));
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
    if (!name || !zone) return false;
    if (strcmp(name, zone) == 0) return true;
    size_t nlen = strlen(name), zlen = strlen(zone);
    return nlen > zlen &&
           name[nlen - zlen - 1] == '.' &&
           strcmp(name + nlen - zlen, zone) == 0;
}

/*
 * dns_canon_cmp — canonical DNS name order (RFC 4034 §6.1).
 * Labels compared right-to-left, case-insensitive.
 * Returns <0 if a < b, 0 if equal, >0 if a > b.
 */
static int dns_canon_cmp(const char *a, const char *b)
{
    /* Split each name into label pointers by scanning for dots. */
    char abuf[256], bbuf[256];
    strncpy(abuf, a, 255); abuf[255] = '\0';
    strncpy(bbuf, b, 255); bbuf[255] = '\0';

    const char *la[128];  int na = 0;
    const char *lb[128];  int nb = 0;

    /* Split abuf in-place: turn dots into NULs, record label starts. */
    la[na++] = abuf;
    for (char *p = abuf; *p; p++) {
        if (*p == '.' && *(p+1) != '\0') { *p = '\0'; la[na++] = p + 1; }
    }
    lb[nb++] = bbuf;
    for (char *p = bbuf; *p; p++) {
        if (*p == '.' && *(p+1) != '\0') { *p = '\0'; lb[nb++] = p + 1; }
    }

    /* Compare from rightmost label. */
    int ia = na - 1, ib = nb - 1;
    while (ia >= 0 && ib >= 0) {
        int c = strcasecmp(la[ia], lb[ib]);
        if (c != 0) return c;
        ia--; ib--;
    }
    /* All compared labels matched; shorter name sorts first. */
    if (ia < 0 && ib < 0) return 0;
    return (ia < 0) ? -1 : 1;
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

    for (int i = 0; i < auth_domain_count; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        if (strcmp(d->domain, owner) != 0) continue;

        if (d->has_soa)    nsec_set_type(bm, &max_type, QTYPE_SOA);
        if (d->has_ns)     nsec_set_type(bm, &max_type, QTYPE_NS);
        if (d->has_mx)     nsec_set_type(bm, &max_type, QTYPE_MX);
        if (d->has_txt)    nsec_set_type(bm, &max_type, QTYPE_TXT);
        if (d->has_cname)  nsec_set_type(bm, &max_type, QTYPE_CNAME);
        if (d->has_srv)    nsec_set_type(bm, &max_type, QTYPE_SRV);
        if (d->has_https)  nsec_set_type(bm, &max_type, QTYPE_HTTPS);
        if (d->has_ipv6)   nsec_set_type(bm, &max_type, QTYPE_AAAA);
        /* A record: ip set, no typed flags */
        if (!d->has_mx && !d->has_ipv6 && !d->has_cname && !d->has_ns &&
            !d->has_txt && !d->has_srv && !d->has_soa &&
            d->ip[0] != '\0' && strcmp(d->ip, "0.0.0.0") != 0)
            nsec_set_type(bm, &max_type, QTYPE_A);
    }

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
 * nsec_find_covering — find the NSEC owner and next-name for a denial response.
 *
 * is_nxdomain = true:  qname doesn't exist; find predecessor → next existing name.
 * is_nxdomain = false: qname exists but no data of queried type (NODATA);
 *                      owner = qname, next = next name in canonical order.
 *
 * zone: SOA domain (e.g. "avilo.com")
 * Returns 1 on success, 0 if NSEC data not available.
 */
static int nsec_find_covering(const char *zone, const char *qname,
                               bool is_nxdomain,
                               char owner_out[256], char next_out[256])
{
    /* Collect unique names in this zone. */
    char names[256][256];
    int  name_count = 0;

    for (int i = 0; i < auth_domain_count && name_count < 256; i++) {
        const char *n = auth_domains[i].domain;
        if (!is_in_zone(n, zone)) continue;

        bool dup = false;
        for (int j = 0; j < name_count && !dup; j++)
            if (strcmp(names[j], n) == 0) dup = true;
        if (!dup) {
            memcpy(names[name_count], n, 256);
            name_count++;
        }
    }

    if (name_count == 0) return 0;

    /* Insertion-sort by canonical order (zones are tiny). */
    for (int i = 1; i < name_count; i++) {
        char tmp[256];
        memcpy(tmp, names[i], 256);
        int j = i - 1;
        while (j >= 0 && dns_canon_cmp(names[j], tmp) > 0) {
            memcpy(names[j + 1], names[j], 256);
            j--;
        }
        memcpy(names[j + 1], tmp, 256);
    }

    if (is_nxdomain) {
        /*
         * Find the last name < qname (predecessor).
         * If qname < all names, predecessor wraps to the last name in the zone.
         */
        int pred_idx = name_count - 1;  /* default: wrap-around */
        for (int i = 0; i < name_count; i++) {
            if (dns_canon_cmp(names[i], qname) >= 0) break;
            pred_idx = i;
        }
        int next_idx = (pred_idx + 1) % name_count;
        memcpy(owner_out, names[pred_idx], 256);
        memcpy(next_out,  names[next_idx],  256);
    } else {
        /* NODATA: owner is qname itself. */
        int owner_idx = -1;
        for (int i = 0; i < name_count; i++) {
            if (strcmp(names[i], qname) == 0) { owner_idx = i; break; }
        }
        if (owner_idx < 0) return 0;
        int next_idx = (owner_idx + 1) % name_count;
        memcpy(owner_out, names[owner_idx], 256);
        memcpy(next_out,  names[next_idx],  256);
    }
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
    if (*pos + need > MAXLINE) return;

    /* Write NSEC RR: owner (full wire labels) + type + class + ttl + rdlen + rdata */
    write_dns_labels(owner_name, buf, pos, MAXLINE);
    *(uint16_t*)(buf + *pos) = htons(QTYPE_NSEC);            *pos += 2;
    *(uint16_t*)(buf + *pos) = htons(1 /* IN */);             *pos += 2;
    *(uint32_t*)(buf + *pos) = htonl(ttl);                   *pos += 4;
    *(uint16_t*)(buf + *pos) = htons((uint16_t)rdata_len);   *pos += 2;
    memcpy(buf + *pos, rdata, rdata_len);                    *pos += rdata_len;

    /* Increment NSCOUNT */
    uint16_t nscount = ntohs(*(uint16_t*)(buf + 8));
    *(uint16_t*)(buf + 8) = htons(nscount + 1);

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
                nscount = ntohs(*(uint16_t*)(buf + 8));
                *(uint16_t*)(buf + 8) = htons(nscount + 1);
            }
        }
    }
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
static struct Packet *build_https_response(struct Packet *req, const char *owner)
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

    /* No exact record for this name.  It is one of: a wildcard match, an empty
     * non-terminal (NODATA), a genuinely non-existent name inside a zone we own
     * (NXDOMAIN, RFC 1034/2308), or a name we are not authoritative for at all
     * (forward upstream). */
    if (!has_entry) {
        const struct AuthDomain *wc = find_wildcard(owner);
        if (!wc) {
            if (soa) {
                /* Inside a zone we own but with no exact record: NODATA only
                 * for an empty non-terminal, otherwise NXDOMAIN. */
                bool ent = is_empty_non_terminal(owner);
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
            if (r && req->do_bit && soa) {
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

    /* RFC 1034 §3.6.2: if the owner is a CNAME alias, return the CNAME RR
     * for any query type except QTYPE_CNAME (direct lookup) and QTYPE_ANY
     * (answered with HINFO per RFC 8482 regardless of record type). */
    if (req->q_type != QTYPE_CNAME && req->q_type != QTYPE_ANY) {
        struct Packet *cr = build_cname_response(req, owner);
        if (cr) {
            pthread_rwlock_unlock(&g_auth_domains_lock);
            return cr;
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

    case QTYPE_HTTPS:
        r = build_https_response(req, owner);
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

    /* For NODATA responses when DO=1: append NSEC proof of non-existence
     * (RFC 4034 §3.1.3).  Detect NODATA by RCODE=NOERROR + ANCOUNT=0. */
    if (r && req->do_bit && soa) {
        uint16_t flags   = ntohs(*(uint16_t*)(r->request + 2));
        uint16_t rcode   = flags & 0x000Fu;
        uint16_t ancount = ntohs(*(uint16_t*)(r->request + 6));
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

