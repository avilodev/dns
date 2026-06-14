#include "response_handler.h"


/*
 * Check if response contains only CNAME (no final answer)
 */
bool is_cname_only_answer(struct Packet* response, uint16_t original_qtype)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return false;
    }
    
    if (response->ancount == 0) {
        return false;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;
    
    bool has_cname = false;
    bool has_final = false;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4; // QTYPE + QCLASS
    } 

    // Check answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        if (type == QTYPE_CNAME) {
            has_cname = true;
        } else if (type == original_qtype || original_qtype == QTYPE_ANY) {
            /* For QTYPE_ANY any non-CNAME record counts as a final answer. */
            has_final = true;
        }
        
        pos += 10 + rdlength;
    }
    
    return has_cname && !has_final;
}

/*
 * Decide whether a CNAME answer must be re-chased because the answering server
 * attached out-of-bailiwick address records to it (RFC 2181 §5.4.1).
 *
 * Returns true when the response contains a CNAME but has NO record of
 * original_qtype whose owner lies within server_zone — the zone the answering
 * server is authoritative for.  Such "final" records were supplied by a server
 * with no authority over their names (e.g. a parking host stapling its own A
 * record onto a CNAME that points into a different provider's zone), so they
 * must be discarded and the CNAME target re-resolved from its real authority.
 * Trusting them is a cache-poisoning vector: any authoritative server could
 * staple A/AAAA records for arbitrary out-of-zone names onto a CNAME answer.
 *
 * This supersedes is_cname_only_answer(): when no final record is present at
 * all it still returns true (ordinary CNAME chasing); when an in-bailiwick
 * final record IS present it returns false (legitimate same-authority CNAME+A,
 * kept as a complete answer).  server_zone == NULL or "" (the root) makes every
 * owner in-bailiwick, so the function returns false and behaviour is unchanged
 * on the root / non-validating fast paths.
 */
bool cname_answer_needs_rechase(struct Packet* response, uint16_t original_qtype,
                                const char* server_zone)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return false;
    }

    if (response->ancount == 0) {
        return false;
    }

    const char* zone = server_zone ? server_zone : "";

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    bool has_cname = false;
    bool has_inbailiwick_final = false;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4; // QTYPE + QCLASS
    }

    // Check answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        char* owner = parse_dns_name_from_wire(buffer, buffer_len, pos);
        skip_dns_name(buffer, buffer_len, &pos);

        if (pos + 10 > buffer_len) {
            free(owner);
            break;
        }

        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));

        if (type == QTYPE_CNAME) {
            has_cname = true;
        } else if (type == original_qtype || original_qtype == QTYPE_ANY) {
            /* A final record only counts when its owner is within the zone the
             * answering server is authoritative for.  Out-of-bailiwick owners
             * are stapled-on and must not satisfy the query. */
            if (owner && name_in_bailiwick(owner, zone)) {
                has_inbailiwick_final = true;
            }
        }

        free(owner);
        pos += 10 + rdlength;
    }

    return has_cname && !has_inbailiwick_final;
}

/* ==========================================================================
 * DNSSEC stripping for non-DO clients (RFC 4035 §3.2.1, RFC 6840 §5.7)
 * ==========================================================================
 *
 * This resolver fetches DNSSEC records (DO=1) from authoritative servers so it
 * can validate.  But a *client* that did not set the DO bit must be answered
 * exactly like a plain, non-DNSSEC resolver: no RRSIG / NSEC / NSEC3 records,
 * the AD bit cleared, and DO=0 in the OPT — matching what 1.1.1.1 returns.
 * Leaving the DNSSEC machinery in leaks signatures, inflates UDP answers
 * (fragmentation / amplification), and is non-conformant.
 */

#define WIRE_TYPE_OPT 41

/* DNSSEC "meta" RR types — present only to convey signatures / authenticated
 * denial.  Stripped for non-DO clients unless explicitly the queried type. */
static bool is_dnssec_meta_type(uint16_t t)
{
    return t == QTYPE_RRSIG || t == QTYPE_NSEC ||
           t == QTYPE_NSEC3 || t == QTYPE_NSEC3PARAM;
}

/* Walk one wire-format name starting at `off` WITHOUT following pointers.
 * Sets *bad_ptr when a compression pointer targets an offset >= `threshold`
 * (i.e. into or past a region that byte-removal would shift).  Returns the
 * offset just past the name, or -1 on a malformed name. */
static int scan_name_skip(const unsigned char* m, int len, int off,
                          int threshold, bool* bad_ptr)
{
    while (off >= 0 && off < len) {
        uint8_t l = m[off];
        if (l == 0) return off + 1;
        if ((l & 0xC0) == 0xC0) {
            if (off + 2 > len) return -1;
            int target = ((l & 0x3F) << 8) | m[off + 1];
            if (target >= threshold) *bad_ptr = true;
            return off + 2;
        }
        if (l > 63) return -1;
        off += 1 + l;
    }
    return -1;
}

/* Read the name at in[off] (following compression) and append it UNCOMPRESSED
 * to out[*op].  Returns the offset in `in` just past the name *as stored at
 * off* (i.e. not following the pointer), or -1 on a malformed name / overflow.
 * A pointer-chase guard caps following at 128 hops. */
static int copy_name_decompressed(const unsigned char* in, int len, int off,
                                  unsigned char* out, int out_cap, int* op)
{
    int ret = -1;       /* input offset just past the in-place name */
    int cur = off;
    int guard = 0;
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
            if (target >= cur) return -1;            /* must point backward */
            if (ret < 0) ret = cur + 2;
            cur = target;
            if (++guard > 128) return -1;
            continue;
        }
        if (l > 63) return -1;
        if (cur + 1 + l > len) return -1;
        if (*op + 1 + l > out_cap) return -1;
        out[(*op)++] = l;
        memcpy(out + *op, in + cur + 1, l);
        *op += l;
        cur += 1 + l;
    }
    return -1;
}

/* Append one RR's RDATA to out, decompressing any embedded domain names.  Only
 * the legacy compressible types may carry compressed names in RDATA (RFC 3597
 * §4); every other type's RDATA is opaque and copied verbatim.  Returns false
 * on malformed input / overflow. */
static bool emit_rdata_decompressed(const unsigned char* m, int len, uint16_t type,
                                    int rdata, int rdlen, unsigned char* out,
                                    int out_cap, int* op)
{
    switch (type) {
        case QTYPE_NS: case QTYPE_CNAME: case QTYPE_PTR:
            return copy_name_decompressed(m, len, rdata, out, out_cap, op) >= 0;
        case QTYPE_MX: {
            if (rdlen < 3 || *op + 2 > out_cap) return false;
            memcpy(out + *op, m + rdata, 2); *op += 2;          /* preference */
            return copy_name_decompressed(m, len, rdata + 2, out, out_cap, op) >= 0;
        }
        case QTYPE_SOA: {
            int p = copy_name_decompressed(m, len, rdata, out, out_cap, op);   /* MNAME */
            if (p < 0) return false;
            p = copy_name_decompressed(m, len, p, out, out_cap, op);           /* RNAME */
            if (p < 0 || p + 20 > rdata + rdlen || *op + 20 > out_cap) return false;
            memcpy(out + *op, m + p, 20); *op += 20;            /* 5×uint32 */
            return true;
        }
        default:    /* opaque RDATA (A, AAAA, TXT, SRV, DS, DNSKEY, OPT, ...) */
            if (rdlen < 0 || *op + rdlen > out_cap) return false;
            memcpy(out + *op, m + rdata, (size_t)rdlen); *op += rdlen;
            return true;
    }
}

/*
 * Rewrite a finished response for a client that did NOT set DO:
 *   - drop RRSIG / NSEC / NSEC3 / NSEC3PARAM records (unless == qtype),
 *   - clear the AD bit, clear the DO bit in any OPT.
 *
 * The rebuild decompresses every name, so removing interleaved records can never
 * orphan a compression pointer (the failure mode of naive byte-removal: glue
 * whose owner name was first introduced after the first dropped RRSIG).  On any
 * malformed input or buffer overflow the original packet is left untouched
 * (AD/OPT-DO are still cleared in place) rather than risk a corrupt answer.
 */
void strip_dnssec_for_non_do(char** bufp, ssize_t* lenp, uint16_t qtype)
{
    if (!bufp || !*bufp || !lenp || *lenp < HEADER_LEN) return;
    unsigned char* m = (unsigned char*)*bufp;
    int len = (int)*lenp;

    int an = (m[6] << 8) | m[7];
    int ns = (m[8] << 8) | m[9];
    int ar = (m[10] << 8) | m[11];
    int qd = (m[4] << 8) | m[5];
    int total = an + ns + ar;

    /* AD is always cleared for a non-DO client (RFC 6840 §5.7). */
    m[3] &= (unsigned char)~0x20;
    if (total == 0) return;

    /* Pass 1: skip the question, then walk the RRs to clear any OPT DO bit in
     * place and learn whether there is anything to drop at all. */
    int pos = HEADER_LEN;
    for (int i = 0; i < qd; i++) {
        bool d = false;
        pos = scan_name_skip(m, len, pos, len, &d);
        if (pos < 0 || pos + 4 > len) return;   /* malformed -> leave as-is */
        pos += 4;
    }
    int q_end = pos;

    bool any_drop = false;
    int scan = pos;
    for (int i = 0; i < total; i++) {
        bool d = false;
        int name_end = scan_name_skip(m, len, scan, len, &d);
        if (name_end < 0 || name_end + 10 > len) return;
        uint16_t type  = (uint16_t)((m[name_end] << 8) | m[name_end + 1]);
        uint16_t rdlen = (uint16_t)((m[name_end + 8] << 8) | m[name_end + 9]);
        if (type == WIRE_TYPE_OPT) m[name_end + 6] &= (unsigned char)~0x80; /* DO=0 */
        if (is_dnssec_meta_type(type) && type != qtype) any_drop = true;
        scan = name_end + 10 + rdlen;
        if (scan > len) return;
    }
    if (!any_drop) return;   /* AD + OPT-DO already fixed in place */

    /* Pass 2: decompressing rebuild without the dropped records. */
    int out_cap = len * 4 + 2048;        /* generous; abort if a name overflows */
    unsigned char* out = malloc((size_t)out_cap);
    if (!out) return;
    memcpy(out, m, (size_t)q_end);       /* header + question (uncompressed) */
    out[3] &= (unsigned char)~0x20;
    int op = q_end;

    int rd_pos = q_end;
    int kept_an = 0, kept_ns = 0, kept_ar = 0;
    bool ok = true;
    for (int i = 0; i < total && ok; i++) {
        bool d = false;
        int rr_start = rd_pos;
        int name_end = scan_name_skip(m, len, rd_pos, len, &d);
        if (name_end < 0 || name_end + 10 > len) { ok = false; break; }
        uint16_t type  = (uint16_t)((m[name_end] << 8) | m[name_end + 1]);
        uint16_t rdlen = (uint16_t)((m[name_end + 8] << 8) | m[name_end + 9]);
        int rdata = name_end + 10;
        if (rdata + rdlen > len) { ok = false; break; }

        if (!(is_dnssec_meta_type(type) && type != qtype)) {
            /* owner (decompressed) */
            if (copy_name_decompressed(m, len, rr_start, out, out_cap, &op) < 0) {
                ok = false; break;
            }
            /* TYPE + CLASS + TTL (10 bytes minus RDLENGTH); clear OPT DO */
            if (op + 8 > out_cap) { ok = false; break; }
            memcpy(out + op, m + name_end, 8);
            if (type == WIRE_TYPE_OPT) out[op + 6] &= (unsigned char)~0x80;
            op += 8;
            /* RDLENGTH placeholder, then decompressed RDATA, then patch length */
            if (op + 2 > out_cap) { ok = false; break; }
            int rdlen_at = op; op += 2;
            int rdata_out = op;
            if (!emit_rdata_decompressed(m, len, type, rdata, rdlen,
                                         out, out_cap, &op)) { ok = false; break; }
            int new_rdlen = op - rdata_out;
            out[rdlen_at]     = (unsigned char)(new_rdlen >> 8);
            out[rdlen_at + 1] = (unsigned char)(new_rdlen & 0xFF);

            if (i < an)            kept_an++;
            else if (i < an + ns)  kept_ns++;
            else                   kept_ar++;
        }
        rd_pos = rdata + rdlen;
    }

    if (!ok) { free(out); return; }   /* anything odd -> keep original intact */

    out[6]  = (unsigned char)(kept_an >> 8); out[7]  = (unsigned char)(kept_an & 0xFF);
    out[8]  = (unsigned char)(kept_ns >> 8); out[9]  = (unsigned char)(kept_ns & 0xFF);
    out[10] = (unsigned char)(kept_ar >> 8); out[11] = (unsigned char)(kept_ar & 0xFF);

    free(*bufp);
    *bufp = (char*)out;
    *lenp = op;
}

/*
 * Extract CNAME target from answer section
 */
char* extract_cname_target(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }
    
    if (response->ancount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Parse answer section looking for CNAME
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Found CNAME record
        if (type == QTYPE_CNAME && rdlength > 0) {
            int rdata_pos = pos + 10;
            char* cname_target = parse_dns_name_from_wire(buffer, buffer_len, rdata_pos);
            if (cname_target) {
                return cname_target;
            }
        }
        
        pos += 10 + rdlength;
    }

    return NULL;
}

/*
 * Extract IP address (A or AAAA) from answer section
 */
char* extract_ip_from_answer(struct Packet* response, uint16_t qtype)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    if (response->ancount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Parse answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Found A record
        if (type == QTYPE_A && qtype == QTYPE_A && rdlength == 4 && 
            pos + 10 + 4 <= buffer_len) {
            char* ip = malloc(INET_ADDRSTRLEN);
            if (ip) {
                struct in_addr addr;
                memcpy(&addr.s_addr, buffer + pos + 10, 4);
                if (inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN)) {
                    return ip;
                }
                free(ip);
            }
        }
        
        // Found AAAA record
        if (type == QTYPE_AAAA && qtype == QTYPE_AAAA && rdlength == 16 && 
            pos + 10 + 16 <= buffer_len) {
            char* ip = malloc(INET6_ADDRSTRLEN);
            if (ip) {
                struct in6_addr addr;
                memcpy(&addr.s6_addr, buffer + pos + 10, 16);
                if (inet_ntop(AF_INET6, &addr, ip, INET6_ADDRSTRLEN)) {
                    return ip;
                }
                free(ip);
            }
        }
        
        pos += 10 + rdlength;
    }

    return NULL;
}

/*
 * Extract nameserver IP from additional section (glue records)
 * Validates that the glue record matches the NS name
 */
char* extract_ns_server_ip(struct Packet* response, const char* ns_name)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    if (response->arcount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Skip answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    // Skip authority section
    for (int i = 0; i < response->nscount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    /* Parse additional section for A glue records (IPv4 only). */
    for (int i = 0; i < response->arcount && pos < buffer_len; i++) {
        char* record_name = parse_dns_name_from_wire(buffer, buffer_len, pos);
        
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) {
            free(record_name);
            break;
        }
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Check if this glue record is for our NS (if ns_name provided)
        bool name_matches = true;
        if (ns_name && record_name) {
            name_matches = (strcasecmp(record_name, ns_name) == 0);
        }
        
        // Found matching A record
        if (name_matches && type == QTYPE_A && rdlength == 4 && 
            pos + 10 + 4 <= buffer_len) {
            char* ip = malloc(INET_ADDRSTRLEN);
            if (ip) {
                struct in_addr addr;
                memcpy(&addr.s_addr, buffer + pos + 10, 4);
                if (inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN)) {
                    free(record_name);
                    return ip;
                }
                free(ip);
            }
        }
        
        free(record_name);
        pos += 10 + rdlength;
    }

    /* AAAA glue records are not used — outgoing queries are IPv4 only. */
    return NULL;
}


/*
 * Extract first NS name from authority section
 */
char* extract_ns_name(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }
    
    if (response->nscount == 0) {
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Skip answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    // Parse authority section for NS records
    for (int i = 0; i < response->nscount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        // Found NS record
        if (type == QTYPE_NS && rdlength > 0) {
            int rdata_pos = pos + 10;
            char* ns_name = parse_dns_name_from_wire(buffer, buffer_len, rdata_pos);
            if (ns_name) {
                return ns_name;
            }
        }
        
        pos += 10 + rdlength;
    }

    return NULL;
}

/*
 * Extract ALL nameservers with their glue records.
 *
 * Glue A records are only accepted when their owner is in-bailiwick for the
 * delegated zone (4.1): an authoritative server must not be able to supply
 * glue for a name outside the zone it is delegating, which would otherwise let
 * it redirect arbitrary victim names to an attacker-controlled address.
 */
NSCandidateList* extract_all_ns_with_glue(struct Packet* response,
                                          const char* server_zone)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return NULL;
    }

    if (response->nscount == 0) {
        return NULL;
    }

    NSCandidateList* list = calloc(1, sizeof(NSCandidateList));
    if (!list) return NULL;
    
    list->capacity = response->nscount;
    list->candidates = calloc(list->capacity, sizeof(NSCandidate));
    if (!list->candidates) {
        free(list);
        return NULL;
    }

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Skip answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    // Parse authority section - collect ALL NS records
    for (int i = 0; i < response->nscount && pos < buffer_len && list->count < list->capacity; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        if (type == QTYPE_NS && rdlength > 0) {
            int rdata_pos = pos + 10;
            char* ns_name = parse_dns_name_from_wire(buffer, buffer_len, rdata_pos);
            if (ns_name) {
                list->candidates[list->count].ns_name = ns_name;
                list->candidates[list->count].ns_ip = NULL;
                list->count++;
            }
        }
        
        pos += 10 + rdlength;
    }

    // Now match glue records from additional section
    int glue_pos = pos;
    
    for (int i = 0; i < list->count; i++) {
        pos = glue_pos;
        
        for (int j = 0; j < response->arcount && pos < buffer_len; j++) {
            char* record_name = parse_dns_name_from_wire(buffer, buffer_len, pos);
            skip_dns_name(buffer, buffer_len, &pos);
            
            if (pos + 10 > buffer_len) {
                free(record_name);
                break;
            }
            
            uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
            uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
            
            // Found matching A record.  Accept the glue only when its owner is
            // within the bailiwick of the zone the answering server serves (4.1)
            // — drop glue for any out-of-zone name an attacker might inject.
            // The reference is the server's own zone (root contains everything),
            // NOT the delegated child: a TLD's nameservers commonly live in a
            // different TLD (e.g. com -> *.gtld-servers.net), and that glue is
            // legitimately in-bailiwick of the parent that provided it.
            if (record_name && strcasecmp(record_name, list->candidates[i].ns_name) == 0 &&
                name_in_bailiwick(record_name, server_zone) &&
                type == QTYPE_A && rdlength == 4 && pos + 10 + 4 <= buffer_len) {

                char* ip = malloc(INET_ADDRSTRLEN);
                if (ip) {
                    struct in_addr addr;
                    memcpy(&addr.s_addr, buffer + pos + 10, 4);
                    if (inet_ntop(AF_INET, &addr, ip, INET_ADDRSTRLEN)) {
                        list->candidates[i].ns_ip = ip;
                    } else {
                        free(ip);
                    }
                }
            }
            
            free(record_name);
            pos += 10 + rdlength;
        }
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

/*
 * Extract the zone apex from the authority section of a referral.
 * The owner name of the first NS record in the authority section IS the zone
 * that the referral is for (e.g. "example.com" in a delegation to example.com).
 * Caller must free the returned string.
 */
char* extract_zone_apex(struct Packet* response)
{
    if (!response || !response->request || response->recv_len < HEADER_LEN) return NULL;
    if (response->nscount == 0) return NULL;

    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;

    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;
    }

    // Skip answer section
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        pos += 10 + rdlength;
    }

    /* Scan authority section for the first NS record and return its owner.
     * We must filter by type because DNSSEC-signed referrals include NSEC and
     * RRSIG records in the authority section alongside the NS records; if those
     * appear first, returning their owner would yield the wrong zone apex and
     * corrupt the NS cache key. */
    for (int i = 0; i < response->nscount && pos < buffer_len; i++) {
        int owner_pos = pos;
        skip_dns_name(buffer, buffer_len, &pos);
        if (pos + 10 > buffer_len) break;
        uint16_t type     = ntohs(*(uint16_t*)(buffer + pos));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        if (type == QTYPE_NS) {
            return parse_dns_name_from_wire(buffer, buffer_len, owner_pos);
        }
        pos += 10 + rdlength;
    }
    return NULL;
}

extern Hints* g_hints[13];

struct Packet* build_root_hints_response(struct Packet* query)
{
    if (!query) return NULL;
    
    // Create response packet
    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) return NULL;
    
    // Allocate buffer for response
    response->request = malloc(MAXLINE);
    if (!response->request) {
        free(response);
        return NULL;
    }
    
    unsigned char* buf = (unsigned char*)response->request;
    int pos = 0;
    
    // Copy full query (header + question) so skip_dns_name can navigate past QNAME
    if (query->request && query->recv_len >= HEADER_LEN) {
        size_t copy_len = (size_t)query->recv_len < MAXLINE ? (size_t)query->recv_len : MAXLINE;
        memcpy(buf, query->request, copy_len);
    }
    
    // Update header flags
    buf[2] = 0x84;  // QR=1, AA=1, RD=0
    buf[3] = 0x00;  // RA=0, RCODE=0
    
    // Set ANCOUNT to number of root servers
    int root_count = 0;
    for (int i = 0; i < 13; i++) {
        if (g_hints[i] && g_hints[i]->name) {
            root_count++;
        }
    }
    buf[6] = (root_count >> 8) & 0xFF;
    buf[7] = root_count & 0xFF;
    
    pos = HEADER_LEN;
    
    // Skip question section (already in buffer from query)
    skip_dns_name(buf, MAXLINE, &pos);
    pos += 4;  // QTYPE + QCLASS
    
    // Add answer section with root NS records
    for (int i = 0; i < 13; i++) {
        if (!g_hints[i] || !g_hints[i]->name) continue;
        
        // Write name (.) - compression pointer to question
        buf[pos++] = 0xC0;
        buf[pos++] = 0x0C;
        
        // TYPE: NS
        buf[pos++] = 0x00;
        buf[pos++] = 0x02;
        
        // CLASS: IN
        buf[pos++] = 0x00;
        buf[pos++] = 0x01;
        
        // TTL: 518400 (6 days)
        buf[pos++] = 0x00;
        buf[pos++] = 0x07;
        buf[pos++] = 0xE9;
        buf[pos++] = 0x00;
        
        // RDLENGTH: calculate
        int name_len = encode_dns_name(g_hints[i]->name, buf + pos + 2, MAXLINE - pos - 2);
        if (name_len < 0) continue;
        
        buf[pos++] = (name_len >> 8) & 0xFF;
        buf[pos++] = name_len & 0xFF;
        
        pos += name_len;
    }
    
    response->recv_len = pos;
    response->id = query->id;
    response->ancount = root_count;
    response->qdcount = 1;
    response->nscount = 0;
    response->arcount = 0;
    response->rcode = RCODE_NO_ERROR;
    response->aa = 1;
    
    return response;
}