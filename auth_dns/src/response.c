#include "response.h"
#include "auth.h"
#include "utils.h"

/*
 * Append a SOA authority record to a response buffer already containing the
 * question section.  Updates NSCOUNT at wire offset 8 to 1.
 * pos is advanced past the written bytes.
 */
static void append_soa_authority(char* buf, int* pos, const struct AuthDomain* soa)
{
    if (!soa) return;

    // Build SOA RDATA in a temp buffer: MNAME + RNAME + 5×uint32_t
    char rdata[1024];
    int rdata_len = 0;
    write_dns_labels(soa->soa_mname, rdata, &rdata_len);
    write_dns_labels(soa->soa_rname, rdata, &rdata_len);
    *(uint32_t*)(rdata + rdata_len) = htonl(soa->soa_serial);   rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(soa->soa_refresh);  rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(soa->soa_retry);    rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(soa->soa_expire);   rdata_len += 4;
    *(uint32_t*)(rdata + rdata_len) = htonl(soa->soa_minimum);  rdata_len += 4;

    // SOA RR TTL: min(soa_ttl, soa_minimum) per RFC 2308 §5
    uint32_t ttl = (soa->soa_ttl < soa->soa_minimum) ? soa->soa_ttl : soa->soa_minimum;

    // Owner name: zone apex in wire format
    write_dns_labels(soa->domain, buf, pos);
    *(uint16_t*)(buf + *pos) = htons(QTYPE_SOA);   *pos += 2;
    *(uint16_t*)(buf + *pos) = htons(1);            *pos += 2;  // CLASS IN
    *(uint32_t*)(buf + *pos) = htonl(ttl);          *pos += 4;
    *(uint16_t*)(buf + *pos) = htons((uint16_t)rdata_len); *pos += 2;
    memcpy(buf + *pos, rdata, rdata_len);
    *pos += rdata_len;

    // Update NSCOUNT at wire offset 8
    *(uint16_t*)(buf + 8) = htons(1);
}


/**
 * Send DNS response to client over UDP.
 * Works for both IPv4 (sockaddr_in) and IPv6 (sockaddr_in6) clients.
 */
int send_response(int sock, struct Packet* response,
                  const struct sockaddr* client_addr, socklen_t addr_len) {
    if (!response || !response->request || !client_addr) {
        fprintf(stderr, "Error: Invalid parameters for send_response\n");
        return -1;
    }

    ssize_t sent = sendto(sock, response->request, response->recv_len, 0,
                          client_addr, addr_len);

    if (sent < 0) {
        perror("Error: Failed to send response to client");
        return -1;
    }

    if (sent != response->recv_len) {
        fprintf(stderr, "Warning: Partial send to client (%zd/%zd bytes)\n",
                sent, response->recv_len);
        return -1;
    }

    return 0;
}

/**
 * Send DNS response over an established TCP connection.
 * DNS-over-TCP prepends a 2-byte big-endian message length.
 */
int send_tcp_response(int fd, struct Packet* response) {
    if (!response || !response->request || response->recv_len <= 0) {
        return -1;
    }

    uint16_t len_net = htons((uint16_t)response->recv_len);

    // Write length prefix (2 bytes) — loop to handle short writes
    const uint8_t* p = (const uint8_t*)&len_net;
    size_t rem = 2;
    while (rem > 0) {
        ssize_t n = write(fd, p, rem);
        if (n <= 0) {
            perror("Error: Failed to send TCP length prefix");
            return -1;
        }
        p += n; rem -= (size_t)n;
    }

    // Write body — loop to handle short writes
    p = (const uint8_t*)response->request;
    rem = (size_t)response->recv_len;
    while (rem > 0) {
        ssize_t n = write(fd, p, rem);
        if (n <= 0) {
            perror("Error: Failed to send TCP response body");
            return -1;
        }
        p += n; rem -= (size_t)n;
    }

    return 0;
}

/**
 * Build NXDOMAIN response (domain does not exist).
 * soa: if non-NULL, a SOA record is added to the authority section (RFC 2308).
 */
struct Packet* build_nxdomain_response(struct Packet* request,
                                        const struct AuthDomain* soa) {
    if (!request) {
        return NULL;
    }

    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        return NULL;
    }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    // Copy transaction ID from request
    memcpy(response->request + pos, request->request, 2);
    pos += 2;

    // Set response flags with NXDOMAIN
    uint16_t flags = 0;
    flags |= (1 << 15);           // Response
    flags |= (1 << 10);           // Authoritative Answer
    flags |= (request->rd << 8);  // Copy recursion desired
    flags |= (1 << 7);            // Recursion Available
    flags |= RCODE_NAME_ERROR;    // RCODE: NXDOMAIN = 3
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    // Set counts (NSCOUNT updated to 1 by append_soa_authority when soa != NULL)
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // 0 answers
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // 0 authority (updated below)
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // 0 additional
    pos += 2;

    // Write question QNAME using correct label encoding
    if (request->full_domain) {
        write_dns_labels(request->full_domain, response->request, &pos);
    } else {
        response->request[pos++] = 0;
    }

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    // Append SOA in authority section (RFC 2308 §3)
    if (soa) {
        append_soa_authority(response->request, &pos, soa);
    }

    response->recv_len = pos;
    return response;
}

/**
 * Build NODATA response (domain exists, but no records of the requested type).
 * AA=1, RCODE=NOERROR, ancount=0.
 * soa: if non-NULL, a SOA record is added to the authority section (RFC 2308).
 */
struct Packet* build_nodata_response(struct Packet* request,
                                      const struct AuthDomain* soa) {
    if (!request) {
        return NULL;
    }

    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        return NULL;
    }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    memcpy(response->request + pos, request->request, 2);
    pos += 2;

    uint16_t flags = 0;
    flags |= (1 << 15);           // QR: Response
    flags |= (1 << 10);           // AA: Authoritative Answer
    flags |= (request->rd << 8);  // Copy recursion desired
    flags |= (1 << 7);            // RA: Recursion Available
    flags |= RCODE_NO_ERROR;      // RCODE: 0 (no error, but no data)
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    // NSCOUNT updated to 1 by append_soa_authority when soa != NULL
    *(uint16_t*)(response->request + pos) = htons(1);  // 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // 0 answers
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // 0 authority (updated below)
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // 0 additional
    pos += 2;

    // Write question QNAME using correct label encoding
    if (request->full_domain) {
        write_dns_labels(request->full_domain, response->request, &pos);
    } else {
        response->request[pos++] = 0;
    }

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    // Append SOA in authority section (RFC 2308 §3)
    if (soa) {
        append_soa_authority(response->request, &pos, soa);
    }

    response->recv_len = pos;
    return response;
}

/**
 * Build SERVFAIL response (RCODE=2, server failure)
 */
struct Packet* build_servfail_response(struct Packet* request) {
    if (!request) {
        return NULL;
    }

    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) {
        perror("Error: Failed to allocate response packet");
        return NULL;
    }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    memcpy(response->request + pos, request->request, 2);
    pos += 2;

    uint16_t flags = 0;
    flags |= (1 << 15);               // QR: Response
    flags |= (request->rd << 8);      // Copy recursion desired
    flags |= (1 << 7);                // RA: Recursion Available
    flags |= RCODE_SERVER_FAILURE;    // RCODE: 2 (SERVFAIL)
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    *(uint16_t*)(response->request + pos) = htons(1);  // 1 question
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);  // 0 answers
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);
    pos += 2;

    // Write question QNAME using correct label encoding
    if (request->full_domain) {
        write_dns_labels(request->full_domain, response->request, &pos);
    } else {
        response->request[pos++] = 0;
    }

    *(uint16_t*)(response->request + pos) = htons(request->q_type);
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);
    pos += 2;

    response->recv_len = pos;
    return response;
}

/**
 * Build BADVERS response (extended RCODE=16, RFC 6891 §6.1.3).
 * Sent when the client uses an EDNS version > 0 that we don't support.
 * Header RCODE = 0; extended RCODE = 16 lives in the OPT RR TTL high byte.
 */
struct Packet* build_badvers_response(struct Packet* request) {
    if (!request) return NULL;

    struct Packet* response = calloc(1, sizeof(struct Packet));
    if (!response) { perror("Error: Failed to allocate BADVERS response"); return NULL; }

    response->request = calloc(1, MAXLINE);
    if (!response->request) {
        perror("Error: Failed to allocate BADVERS response buffer");
        free(response);
        return NULL;
    }

    int pos = 0;

    memcpy(response->request + pos, request->request, 2);   /* TX ID */
    pos += 2;

    /* Flags: QR=1, RD copy, RA=1, RCODE=0 (extended RCODE in OPT) */
    uint16_t flags = 0;
    flags |= (1u << 15);              /* QR */
    flags |= ((unsigned)request->rd << 8); /* RD */
    flags |= (1u << 7);              /* RA */
    *(uint16_t*)(response->request + pos) = htons(flags);
    pos += 2;

    *(uint16_t*)(response->request + pos) = htons(1);   /* QDCOUNT = 1 */
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);   /* ANCOUNT = 0 */
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(0);   /* NSCOUNT = 0 */
    pos += 2;
    *(uint16_t*)(response->request + pos) = htons(1);   /* ARCOUNT = 1 (OPT) */
    pos += 2;

    /* Question section */
    if (request->full_domain)
        write_dns_labels(request->full_domain, response->request, &pos);
    else
        response->request[pos++] = 0;

    *(uint16_t*)(response->request + pos) = htons(request->q_type);   pos += 2;
    *(uint16_t*)(response->request + pos) = htons(request->q_class);  pos += 2;

    /* OPT RR: root name + type=41 + payload=4096 + TTL=BADVERS_extRCODE + RDLEN=0
     * OPT TTL layout (RFC 6891 §6.1.3):
     *   byte 0 = extended RCODE (16 = BADVERS)
     *   byte 1 = EDNS version (0)
     *   bytes 2-3 = flags (DO bit etc.) */
    if (pos + 11 <= MAXLINE) {
        response->request[pos++] = 0x00;                              /* root name  */
        *(uint16_t*)(response->request + pos) = htons(41);            pos += 2; /* OPT  */
        *(uint16_t*)(response->request + pos) = htons(4096);          pos += 2; /* payload */
        *(uint32_t*)(response->request + pos) = htonl(RCODE_BADVERS << 24); pos += 4; /* TTL */
        *(uint16_t*)(response->request + pos) = htons(0);             pos += 2; /* RDLEN=0 */
    }

    response->recv_len = pos;
    return response;
}

/* ==========================================================================
 * finalize_udp_response — post-processing for all UDP responses.
 *
 * 1. OPT echo (RFC 6891 §6.1.1): if the client sent an OPT record,
 *    we must include one in our reply regardless of RCODE.
 *    We advertise a 4096-byte UDP payload and mirror the DO bit.
 *
 * 2. TC truncation (RFC 1035 §4.1.1 / RFC 6891 §6.2.6): if the built
 *    response exceeds the effective UDP limit (512 without EDNS, or
 *    the client's advertised size with EDNS), set TC=1 and strip
 *    everything after the question section.  The client must retry
 *    over TCP.
 * ========================================================================== */
void finalize_udp_response(struct Packet *response, const struct Packet *request)
{
    if (!response || !response->request || !request) return;

    /* --- 1. Append EDNS0 OPT RR if client sent EDNS --- */
    if (request->edns_present) {
        int pos = (int)response->recv_len;
        if (pos + 11 <= MAXLINE) {
            response->request[pos++] = 0x00;                          /* root name  */
            *(uint16_t*)(response->request + pos) = htons(41);        pos += 2; /* OPT  */
            *(uint16_t*)(response->request + pos) = htons(4096);      pos += 2; /* payload */
            /* TTL: [ext_rcode=0][version=0][flags] — mirror DO bit   */
            uint32_t opt_ttl = request->do_bit ? 0x00008000u : 0u;
            *(uint32_t*)(response->request + pos) = htonl(opt_ttl);   pos += 4;
            *(uint16_t*)(response->request + pos) = htons(0);         pos += 2; /* RDLEN=0 */
            response->recv_len = pos;
            uint16_t arcount = ntohs(*(uint16_t*)(response->request + 10));
            *(uint16_t*)(response->request + 10) = htons(arcount + 1);
        }
    }

    /* --- 2. Truncate if response exceeds UDP payload limit --- */
    int udp_limit = request->edns_present ? (int)request->edns_udp_size : 512;
    if (udp_limit < 512) udp_limit = 512;          /* minimum enforced by RFC */

    if ((int)response->recv_len > udp_limit) {
        /* Walk to end of question section (QNAME labels + QTYPE + QCLASS). */
        int qend = HEADER_LEN;
        const char *buf = response->request;
        while (qend < (int)response->recv_len) {
            uint8_t llen = (uint8_t)buf[qend];
            if (llen == 0)              { qend++; break; }    /* null terminator */
            if ((llen & 0xC0) == 0xC0) { qend += 2; break; } /* compression ptr */
            qend += 1 + llen;
        }
        qend += 4; /* QTYPE (2) + QCLASS (2) */

        /* Set TC=1 (bit 9 of flags word, 0-indexed from MSB). */
        uint16_t flags = ntohs(*(uint16_t*)(response->request + 2));
        flags |= (1u << 9);
        *(uint16_t*)(response->request + 2) = htons(flags);
        *(uint16_t*)(response->request + 6) = 0;   /* ANCOUNT = 0 */
        *(uint16_t*)(response->request + 8) = 0;   /* NSCOUNT = 0 */

        /* RFC 6891 §7: if client sent EDNS, we MUST include an OPT record in
         * every response, including truncated ones.  Re-write a minimal OPT
         * immediately after the question section and keep ARCOUNT = 1.
         * If no EDNS was present, zero ARCOUNT and trim to question only. */
        if (request->edns_present && qend + 11 <= MAXLINE) {
            char *p = response->request + qend;
            p[0] = 0x00;                                          /* root name  */
            *(uint16_t*)(p + 1) = htons(41);                      /* OPT        */
            *(uint16_t*)(p + 3) = htons(4096);                    /* payload    */
            uint32_t opt_ttl = request->do_bit ? 0x00008000u : 0u;
            *(uint32_t*)(p + 5) = htonl(opt_ttl);                 /* TTL/flags  */
            *(uint16_t*)(p + 9) = htons(0);                       /* RDLEN = 0  */
            *(uint16_t*)(response->request + 10) = htons(1);      /* ARCOUNT = 1 */
            response->recv_len = qend + 11;
        } else {
            *(uint16_t*)(response->request + 10) = 0;             /* ARCOUNT = 0 */
            response->recv_len = qend;
        }
    }
}
