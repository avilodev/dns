#include "request.h"
#include "dns_name.h"

/*
 * Parse DNS request headers and question section
 * @param buffer Raw DNS packet buffer
 * @param recv_len Length of received data
 * @return Parsed packet structure or NULL on error
 */ 
struct Packet* parse_request_headers(char* buffer, ssize_t recv_len) {
    if (!buffer) {
        fprintf(stderr, "Error: NULL buffer provided\n");
        return NULL;
    }

    if (recv_len < HEADER_LEN) {
        fprintf(stderr, "Error: Buffer too short for DNS header (%zd bytes)\n", recv_len);
        return NULL;
    }

    struct Packet* pkt = calloc(1, sizeof(struct Packet));
    if (!pkt) {
        perror("Error: Memory allocation failed for packet");
        return NULL;
    }

    // Parse DNS header (12 bytes, all fields in network byte order)
    pkt->id = rd16(buffer + 0);
    pkt->flags = rd16(buffer + 2);
    pkt->qdcount = rd16(buffer + 4);
    pkt->ancount = rd16(buffer + 6);
    pkt->nscount = rd16(buffer + 8);
    pkt->arcount = rd16(buffer + 10);

    // Extract individual flag bits
    pkt->qr = (pkt->flags >> 15) & 0x1;
    pkt->opcode = (pkt->flags >> 11) & 0xF;
    pkt->aa = (pkt->flags >> 10) & 0x1;
    pkt->tc = (pkt->flags >> 9) & 0x1;
    pkt->rd = (pkt->flags >> 8) & 0x1;
    pkt->ra = (pkt->flags >> 7) & 0x1;
    pkt->z = (pkt->flags >> 6) & 0x1;
    pkt->ad = (pkt->flags >> 5) & 0x1;
    pkt->cd = (pkt->flags >> 4) & 0x1;
    pkt->rcode = pkt->flags & 0xF;

    // Drop response packets — a QR=1 packet arriving as a query is invalid
    if (pkt->qr == 1) {
        free_packet(pkt);
        return NULL;
    }

    // Only standard queries (opcode=0) supported; flag others for NOTIMP reply
    if (pkt->opcode != 0) {
        pkt->rcode = RCODE_NOTIMP;
        return pkt;
    }

    // Validate question count — exactly one question (RFC 1035).  The EDNS OPT
    // scan below assumes a single question, so reject anything else with FORMERR.
    if (pkt->qdcount != 1) {
        fprintf(stderr, "Error: qdcount=%u (expected 1) — FORMERR\n", pkt->qdcount);
        pkt->rcode = RCODE_FORMAT_ERROR;
        return pkt;
    }

    /* Question name: literal labels only (a compression pointer in a
     * question is malformed), decoded to escaped lowercase text (dns_name.h)
     * so a label containing '.', '\\' or binary bytes survives intact.
     * The root decodes to ".", which the root-query branch and cache key on. */
    int question_start = HEADER_LEN;
    for (int p = HEADER_LEN; ; ) {
        if (p >= recv_len) {
            fprintf(stderr, "Error: Question name runs past the packet\n");
            free_packet(pkt);
            return NULL;
        }
        uint8_t l = (uint8_t)buffer[p];
        if (l == 0) break;
        if (l & 0xC0) {
            fprintf(stderr, "Error: Unexpected compression in question section\n");
            free_packet(pkt);
            return NULL;
        }
        p += 1 + l;
    }
    char domain[DNAME_TEXT_MAX];
    int pos = dname_from_wire((const uint8_t*)buffer, (int)recv_len, HEADER_LEN, true,
                              domain, sizeof(domain));
    if (pos < 0) {
        fprintf(stderr, "Error: Malformed question name\n");
        free_packet(pkt);
        return NULL;
    }
    pkt->full_domain = strdup(domain);
    if (!pkt->full_domain) {
        perror("Error: Failed to allocate domain string");
        free_packet(pkt);
        return NULL;
    }


    // Parse question type and class
    if (pos + 4 > recv_len) {
        fprintf(stderr, "Error: Buffer too short for question type/class\n");
        free_packet(pkt);
        return NULL;
    }
    
    pkt->q_type = rd16(buffer + pos);
    pkt->q_class = rd16(buffer + pos + 2);
    pos += 4;

    // Validate QCLASS — only IN (1) and ANY/QCLASS_ANY (255) are valid (RFC 1035)
    if (pkt->q_class != 1 && pkt->q_class != 255) {
        fprintf(stderr, "Warning: Unsupported QCLASS %u — returning FORMERR\n", pkt->q_class);
        pkt->rcode = RCODE_FORMAT_ERROR;
        return pkt;
    }

    int question_end = pos;  // End of question section

    // Scan additional section for EDNS OPT record (type=41, RFC 6891).
    // We do this before rebuilding the clean buffer so we can capture the
    // client's UDP payload size, EDNS version, and DO bit.
    {
        int scan = question_end;
        int rr_idx = 0;
        int total_rrs = (int)pkt->ancount + (int)pkt->nscount + (int)pkt->arcount;
        while (scan < recv_len - 10 && rr_idx < total_rrs) {
            // Skip owner name (may be 0x00 for root, or label sequence)
            if ((uint8_t)buffer[scan] == 0x00) {
                scan++;  // root label
            } else if (((uint8_t)buffer[scan] & 0xC0) == 0xC0) {
                scan += 2;  // compression pointer
            } else {
                // Walk labels
                while (scan < recv_len) {
                    uint8_t ll = (uint8_t)buffer[scan];
                    if (ll == 0) { scan++; break; }
                    if ((ll & 0xC0) == 0xC0) { scan += 2; break; }
                    scan += 1 + ll;
                }
            }
            if (scan + 10 > recv_len) break;
            uint16_t rr_type  = rd16(buffer + scan);
            uint16_t rr_class = rd16(buffer + scan + 2);
            uint32_t rr_ttl   = rd32(buffer + scan + 4);
            uint16_t rr_rdlen = rd16(buffer + scan + 8);
            scan += 10;
            if (rr_type == 41) {  // OPT
                pkt->edns_present  = true;
                pkt->edns_udp_size = rr_class;  // CLASS field = UDP payload size
                pkt->edns_version  = (uint8_t)((rr_ttl >> 16) & 0xFF);
                pkt->do_bit        = (rr_ttl & 0x00008000) ? true : false;
            }
            if (scan + rr_rdlen > recv_len) break;
            scan += rr_rdlen;
            rr_idx++;
        }
    }

    // Copy ONLY header + question section, zero out AN/NS/AR counts
    if (pkt->ancount > 0 || pkt->nscount > 0 || pkt->arcount > 0) {
        // Calculate question section length
        int question_len = question_end - question_start;
        int new_packet_len = HEADER_LEN + question_len;
        
        // Allocate new clean buffer
        char* clean_buffer = malloc(new_packet_len);
        if (!clean_buffer) {
            perror("Error: Failed to allocate clean buffer");
            free_packet(pkt);
            return NULL;
        }
        
        // Copy header
        memcpy(clean_buffer, buffer, HEADER_LEN);
        
        // Zero out AN/NS/AR counts in new buffer
        clean_buffer[6] = 0;   // ANCOUNT high byte
        clean_buffer[7] = 0;   // ANCOUNT low byte
        clean_buffer[8] = 0;   // NSCOUNT high byte
        clean_buffer[9] = 0;   // NSCOUNT low byte
        clean_buffer[10] = 0;  // ARCOUNT high byte
        clean_buffer[11] = 0;  // ARCOUNT low byte
        
        // Copy question section
        memcpy(clean_buffer + HEADER_LEN, buffer + question_start, question_len);
        
        // Replace packet buffer with clean version
        pkt->request = clean_buffer;
        pkt->recv_len = new_packet_len;

        // Update counts
        pkt->ancount = 0;
        pkt->nscount = 0;
        pkt->arcount = 0;
    } else {
        // Normal query without EDNS0 - copy as-is
        pkt->request = malloc(recv_len);
        if (!pkt->request) {
            perror("Error: Memory allocation failed for request buffer");
            free_packet(pkt);
            return NULL;
        }
        memcpy(pkt->request, buffer, recv_len);
        pkt->recv_len = recv_len;
    }

    return pkt;
}

/*
 * Parse DNS response
 * Handles responses from upstream DNS servers
 * It does NOT strip EDNS0 because responses can legitimately have NS/AR records
 */
struct Packet* parse_response(char* buffer, ssize_t recv_len) {
    if (!buffer) {
        fprintf(stderr, "Error: NULL buffer provided\n");
        return NULL;
    }

    if (recv_len < HEADER_LEN) {
        fprintf(stderr, "Error: Buffer too short for DNS header (%zd bytes)\n", recv_len);
        return NULL;
    }

    struct Packet* pkt = calloc(1, sizeof(struct Packet));
    if (!pkt) {
        perror("Error: Memory allocation failed for packet");
        return NULL;
    }

    // Copy raw response as is
    pkt->request = malloc(recv_len);
    if (!pkt->request) {
        perror("Error: Memory allocation failed for response buffer");
        free(pkt);
        return NULL;
    }
    memcpy(pkt->request, buffer, recv_len);
    pkt->recv_len = recv_len;

    // Parse DNS header
    pkt->id = rd16(buffer + 0);
    pkt->flags = rd16(buffer + 2);
    pkt->qdcount = rd16(buffer + 4);
    pkt->ancount = rd16(buffer + 6);
    pkt->nscount = rd16(buffer + 8);
    pkt->arcount = rd16(buffer + 10);

    // Extract individual flag bits
    pkt->qr = (pkt->flags >> 15) & 0x1;
    pkt->opcode = (pkt->flags >> 11) & 0xF;
    pkt->aa = (pkt->flags >> 10) & 0x1;
    pkt->tc = (pkt->flags >> 9) & 0x1;
    pkt->rd = (pkt->flags >> 8) & 0x1;
    pkt->ra = (pkt->flags >> 7) & 0x1;
    pkt->z = (pkt->flags >> 6) & 0x1;
    pkt->ad = (pkt->flags >> 5) & 0x1;
    pkt->cd = (pkt->flags >> 4) & 0x1;
    pkt->rcode = pkt->flags & 0xF;

    // Question section: name (case preserved, escaped text) + type/class,
    // used for the RFC 5452 question match against what we asked.
    if (pkt->qdcount > 0) {
        char domain[DNAME_TEXT_MAX];
        int pos = dname_from_wire((const uint8_t*)buffer, (int)recv_len, HEADER_LEN,
                                  false, domain, sizeof(domain));
        if (pos >= 0) {
            pkt->full_domain = strdup(domain);
            if (pos + 4 <= recv_len) {
                pkt->q_type  = rd16(buffer + pos);
                pkt->q_class = rd16(buffer + pos + 2);
            }
        }
    }

    return pkt;
}