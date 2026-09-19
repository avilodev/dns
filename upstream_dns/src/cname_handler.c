#include "cname_handler.h"
#include "dns_name.h"
#include <ctype.h>

/*
 * Check if domain is already in CNAME chain (loop detection)
 */
bool check_cname_loop(CnameChain* chain, const char* domain)
{
    if (!chain || !domain) return false;
    
    for (int i = 0; i < chain->count; i++) {
        if (chain->domains[i] && strcasecmp(chain->domains[i], domain) == 0) {
            return true;
        }
    }
    return false;
}

/*
 * Does the name stored at buf[off] (following compression pointers, reading
 * only buf[0..len)) equal the uncompressed wire name `want`, ignoring ASCII
 * case?  Comparing wire labels — never text — keeps a label that contains a
 * dot from matching two labels.
 */
static bool wire_name_equals(const unsigned char* buf, size_t len, size_t off,
                             const uint8_t* want)
{
    size_t cur = off;
    int w = 0, hops = 0;
    while (cur < len) {
        uint8_t l = buf[cur];
        if ((l & 0xC0) == 0xC0) {
            if (cur + 1 >= len || ++hops > 64) return false;
            cur = ((size_t)(l & 0x3F) << 8) | buf[cur + 1];
            continue;
        }
        if (l > 63 || l != want[w]) return false;
        if (l == 0) return true;
        if (cur + 1 + l > len) return false;
        for (int k = 1; k <= l; k++)
            if (tolower(buf[cur + k]) != tolower(want[w + k])) return false;
        cur += 1 + l;
        w += 1 + l;
    }
    return false;
}

/*
 * Write `name` at buffer[pos], replacing its longest suffix that already
 * appears in buffer[HEADER_LEN .. search_end) with a compression pointer
 * (RFC 1035 §4.1.4).  Returns bytes written or -1.
 */
static int write_dns_name_compressed(const char* name, unsigned char* buffer,
                                     size_t buffer_size, size_t pos,
                                     unsigned char* full_buffer, size_t search_end)
{
    (void)full_buffer;   /* == buffer: pointers refer into the message itself */
    if (!name || !buffer || pos >= buffer_size) return -1;

    uint8_t wire[256];
    int wlen = dname_to_wire(name, wire, sizeof(wire));
    if (wlen < 0) return -1;

    /* Bounded scan: every offset is tried as a candidate, so an unbounded
     * search is quadratic on large (TCP-sized) answers.  The useful targets —
     * question and early owners — sit near the start. */
    size_t limit = search_end < pos ? search_end : pos;
    if (limit > 2048) limit = 2048;

    for (int off = 0; wire[off] != 0; off += 1 + wire[off]) {
        for (size_t i = HEADER_LEN; i < limit; i++) {
            if (!wire_name_equals(buffer, pos, i, wire + off)) continue;
            if (pos + (size_t)off + 2 > buffer_size) return -1;
            memcpy(buffer + pos, wire, (size_t)off);        /* leading labels */
            buffer[pos + off]     = (unsigned char)(0xC0 | (i >> 8));
            buffer[pos + off + 1] = (unsigned char)(i & 0xFF);
            return off + 2;
        }
    }
    if (pos + (size_t)wlen > buffer_size) return -1;
    memcpy(buffer + pos, wire, (size_t)wlen);
    return wlen;
}

/*
 * Reconstruct complete DNS response with CNAME chain
 * Uses DNS compression to keep packet size under 512 bytes
 */
struct Packet* reconstruct_cname_response(
    struct Packet* original_query,
    CnameChainData* chain_data,
    struct Packet* final_answer)
{
    if (!original_query || !final_answer) {
        return final_answer;
    }
    
    // If no CNAME chain, return final answer directly
    if (!chain_data || chain_data->count == 0) {
        return final_answer;
    }
    
    // If final_answer has no request buffer, can't reconstruct
    if (!final_answer->request || final_answer->recv_len < HEADER_LEN) {
        return final_answer;
    }
    
    // Allocate new response packet
    struct Packet* reconstructed = calloc(1, sizeof(struct Packet));
    if (!reconstructed) {
        return final_answer;
    }
    
    // Copy metadata from final answer
    reconstructed->id = original_query->id;
    reconstructed->qr = 1;  // Response
    reconstructed->opcode = final_answer->opcode;
    reconstructed->aa = final_answer->aa;
    reconstructed->tc = 0;
    reconstructed->rd = final_answer->rd;
    reconstructed->ra = final_answer->ra;
    reconstructed->z = 0;
    reconstructed->ad = final_answer->ad;
    reconstructed->cd = final_answer->cd;
    reconstructed->rcode = final_answer->rcode;
    reconstructed->qdcount = 1;
    reconstructed->nscount = (final_answer->ancount == 0) ? final_answer->nscount : 0;
    reconstructed->arcount = 0;
    reconstructed->q_type = original_query->q_type;
    reconstructed->q_class = original_query->q_class;
    
    // Copy domain name
    if (original_query->full_domain) {
        reconstructed->full_domain = strdup(original_query->full_domain);
    }
    
    // Allocate buffer for complete response.  Size it from the final answer
    // (a TCP answer may exceed MAXLINE) plus room for name decompression and
    // the CNAME chain; UDP size limits are applied later by the transport.
    size_t buffer_size = (size_t)final_answer->recv_len * 2 + 2048;
    if (buffer_size < MAXLINE) buffer_size = MAXLINE;
    reconstructed->request = calloc(1, buffer_size);
    if (!reconstructed->request) {
        free(reconstructed->full_domain);
        free(reconstructed);
        return final_answer;
    }
    
    unsigned char* buffer = (unsigned char*)reconstructed->request;
    size_t pos = 0;
    
    // Header
    buffer[pos++] = (original_query->id >> 8) & 0xFF;
    buffer[pos++] = original_query->id & 0xFF;
    
    // Flags
    uint16_t flags = 0;
    flags |= (1 << 15);  // QR = 1
    flags |= (final_answer->aa & 0x01) << 10;
    flags |= (final_answer->rd & 0x01) << 8;
    flags |= (final_answer->ra & 0x01) << 7;
    flags |= (final_answer->rcode & 0x0F);
    
    uint16_t flags_net = htons(flags);
    memcpy(buffer + pos, &flags_net, 2);
    pos += 2;
    
    // Counts
    uint16_t qdcount = htons(1);
    memcpy(buffer + pos, &qdcount, 2);
    pos += 2;
    
    // Answer count = CNAME chain + final answers
    uint16_t total_answers = chain_data->count + final_answer->ancount;
    uint16_t ancount_net = htons(total_answers);
    memcpy(buffer + pos, &ancount_net, 2);
    pos += 2;
    
    // NS count - preserve authority section for NODATA responses
    uint16_t nscount = (final_answer->ancount == 0) ? final_answer->nscount : 0;
    uint16_t nscount_net = htons(nscount);
    memcpy(buffer + pos, &nscount_net, 2);
    pos += 2;
    
    // AR count = 0
    uint16_t zero = 0;
    memcpy(buffer + pos, &zero, 2);
    pos += 2;
    
    // Question
    int qname_pos = pos;  // Remember position for compression
    int name_len = write_dns_name(original_query->full_domain, buffer, 
                                  buffer_size, pos);
    if (name_len < 0) {
        fprintf(stderr, "Failed to write question name\n");
        free(reconstructed->request);
        free(reconstructed->full_domain);
        free(reconstructed);
        free_packet(final_answer);
        return NULL;
    }
    pos += name_len;

    uint16_t qtype_net = htons(original_query->q_type);
    memcpy(buffer + pos, &qtype_net, 2);
    pos += 2;

    uint16_t qclass_net = htons(original_query->q_class);
    memcpy(buffer + pos, &qclass_net, 2);
    pos += 2;

    int question_end_pos = (int)pos;  /* used to truncate TC=1 responses */

    // Header counts are rewritten at the end from what was actually emitted,
    // so an RR skipped below can never leave ANCOUNT/NSCOUNT overstated.
    int written_an = 0, written_ns = 0;

    // Answer with CNAME compression
    for (int i = 0; i < chain_data->count; i++) {
        if (!chain_data->entries[i].name || !chain_data->entries[i].target) {
            continue;
        }
        
        // Owner name - use compression to point back to question if it matches
        int owner_pos = pos;
        if (i == 0 && strcasecmp(chain_data->entries[i].name, original_query->full_domain) == 0) {
            // First CNAME owner matches question - use compression pointer
            buffer[pos++] = 0xC0 | ((qname_pos >> 8) & 0x3F);
            buffer[pos++] = qname_pos & 0xFF;
        } else {
            // Try to compress against existing names
            name_len = write_dns_name_compressed(chain_data->entries[i].name, buffer, 
                                               buffer_size, pos, buffer, owner_pos);
            if (name_len < 0) {
                // Fall back to uncompressed
                name_len = write_dns_name(chain_data->entries[i].name, buffer, 
                                        buffer_size, pos);
                if (name_len < 0) break;
            }
            pos += name_len;
        }
        
        // TYPE = CNAME (5)
        uint16_t type_net = htons(QTYPE_CNAME);
        memcpy(buffer + pos, &type_net, 2);
        pos += 2;
        
        // CLASS = IN (1)
        uint16_t class_net = htons(1);
        memcpy(buffer + pos, &class_net, 2);
        pos += 2;
        
        // TTL
        uint32_t ttl = chain_data->entries[i].ttl;
        uint32_t ttl_net = htonl(ttl);
        memcpy(buffer + pos, &ttl_net, 4);
        pos += 4;
        
        // RDLENGTH - placeholder
        int rdlength_pos = pos;
        pos += 2;
        
        // RDATA - target name with compression
        int rdata_start = pos;
        name_len = write_dns_name_compressed(chain_data->entries[i].target, buffer,
                                           buffer_size, pos, buffer, rdata_start);
        if (name_len < 0) {
            // Fall back to uncompressed
            name_len = write_dns_name(chain_data->entries[i].target, buffer,
                                    buffer_size, pos);
            if (name_len < 0) break;
        }
        pos += name_len;
        
        // Fill in RDLENGTH
        uint16_t rdlength = pos - rdata_start;
        uint16_t rdlength_net = htons(rdlength);
        memcpy(buffer + rdlength_pos, &rdlength_net, 2);
        written_an++;
    }
    
    if (final_answer->ancount > 0 && final_answer->request) {
        unsigned char* final_buffer = (unsigned char*)final_answer->request;
        int final_pos = HEADER_LEN;
        
        // Skip question section in final answer
        for (int i = 0; i < final_answer->qdcount && 
             final_pos < final_answer->recv_len; i++) {
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            final_pos += 4;
        }
        
        // Copy answer RRs with compression
        for (int i = 0; i < final_answer->ancount && 
             final_pos < final_answer->recv_len; i++) {
            
            // Parse owner name (handles compression)
            char* owner_name = parse_dns_name_from_wire(final_buffer, 
                                                        final_answer->recv_len, 
                                                        final_pos);
            if (!owner_name) {
                fprintf(stderr, "Failed to parse owner name for answer RR %d\n", i);
                break;
            }
            
            // Skip name in source buffer
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            
            if (final_pos + 10 > final_answer->recv_len) {
                free(owner_name);
                break;
            }
            
            // Read TYPE, CLASS, TTL, RDLENGTH
            uint16_t rr_type = rd16(final_buffer + final_pos);
            uint16_t rr_class = rd16(final_buffer + final_pos + 2);
            uint32_t rr_ttl = rd32(final_buffer + final_pos + 4);
            uint16_t rdlength = rd16(final_buffer + final_pos + 8);
            final_pos += 10;
            
            if (final_pos + rdlength > final_answer->recv_len) {
                free(owner_name);
                break;
            }
            
            // Write owner name WITH compression
            int owner_start = pos;
            name_len = write_dns_name_compressed(owner_name, buffer, buffer_size, 
                                               pos, buffer, owner_start);
            if (name_len < 0) {
                // Fall back to uncompressed
                name_len = write_dns_name(owner_name, buffer, buffer_size, pos);
            }
            free(owner_name);
            
            if (name_len < 0) {
                fprintf(stderr, "Failed to write owner name\n");
                break;
            }
            pos += name_len;
            
            if (pos + 10 + rdlength > buffer_size) {
                fprintf(stderr, "Buffer overflow prevented\n");
                break;
            }
            
            // Write TYPE
            uint16_t type_net = htons(rr_type);
            memcpy(buffer + pos, &type_net, 2);
            pos += 2;
            
            // Write CLASS
            uint16_t class_net = htons(rr_class);
            memcpy(buffer + pos, &class_net, 2);
            pos += 2;
            
            // Write TTL
            uint32_t ttl_net = htonl(rr_ttl);
            memcpy(buffer + pos, &ttl_net, 4);
            pos += 4;
            
            // RDLENGTH placeholder
            int rdata_len_pos = pos;
            pos += 2;
            
            // Write RDATA
            int rdata_start = pos;
            if (rr_type == QTYPE_A || rr_type == QTYPE_AAAA) {
                // Raw IP address
                memcpy(buffer + pos, final_buffer + final_pos, rdlength);
                pos += rdlength;
            } else if (rr_type == QTYPE_NS || rr_type == QTYPE_CNAME || 
                       rr_type == QTYPE_PTR) {
                // RDATA contains domain name - decompress and recompress
                char* rdata_name = parse_dns_name_from_wire(final_buffer, 
                                                            final_answer->recv_len,
                                                            final_pos);
                if (rdata_name) {
                    int rdata_name_len = write_dns_name_compressed(rdata_name, buffer, 
                                                                  buffer_size, pos,
                                                                  buffer, rdata_start);
                    if (rdata_name_len < 0) {
                        rdata_name_len = write_dns_name(rdata_name, buffer, buffer_size, pos);
                    }
                    free(rdata_name);
                    
                    if (rdata_name_len < 0) {
                        fprintf(stderr, "Failed to write RDATA name\n");
                        break;
                    }
                    pos += rdata_name_len;
                } else {
                    // Fallback
                    memcpy(buffer + pos, final_buffer + final_pos, rdlength);
                    pos += rdlength;
                }
            } else {
                // Other types - copy raw RDATA
                memcpy(buffer + pos, final_buffer + final_pos, rdlength);
                pos += rdlength;
            }
            
            // Fill in actual RDLENGTH
            uint16_t actual_rdlength = pos - rdata_start;
            uint16_t rdlength_net = htons(actual_rdlength);
            memcpy(buffer + rdata_len_pos, &rdlength_net, 2);
            
            final_pos += rdlength;
            written_an++;
        }
    }

    // Authority
    if (final_answer->ancount == 0 && final_answer->nscount > 0 && final_answer->request) {
        unsigned char* final_buffer = (unsigned char*)final_answer->request;
        int final_pos = HEADER_LEN;
        
        // Skip question section
        for (int i = 0; i < final_answer->qdcount && final_pos < final_answer->recv_len; i++) {
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            final_pos += 4;
        }
        
        // Skip answer section (should be empty)
        for (int i = 0; i < final_answer->ancount && final_pos < final_answer->recv_len; i++) {
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            if (final_pos + 10 > final_answer->recv_len) break;
            uint16_t rdlength = rd16(final_buffer + final_pos + 8);
            final_pos += 10 + rdlength;
        }
        
        // Copy authority section (SOA records)
        for (int i = 0; i < final_answer->nscount && final_pos < final_answer->recv_len; i++) {
            // Parse owner name
            char* owner_name = parse_dns_name_from_wire(final_buffer, 
                                                        final_answer->recv_len, 
                                                        final_pos);
            if (!owner_name) {
                fprintf(stderr, "Failed to parse authority RR owner name\n");
                break;
            }
            
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            
            if (final_pos + 10 > final_answer->recv_len) {
                free(owner_name);
                break;
            }
            
            uint16_t rr_type = rd16(final_buffer + final_pos);
            uint16_t rr_class = rd16(final_buffer + final_pos + 2);
            uint32_t rr_ttl = rd32(final_buffer + final_pos + 4);
            uint16_t rdlength = rd16(final_buffer + final_pos + 8);
            final_pos += 10;
            
            if (final_pos + rdlength > final_answer->recv_len) {
                free(owner_name);
                break;
            }
            
            // Write owner name
            int owner_start = pos;
            name_len = write_dns_name_compressed(owner_name, buffer, buffer_size,
                                               pos, buffer, owner_start);
            if (name_len < 0) {
                name_len = write_dns_name(owner_name, buffer, buffer_size, pos);
            }
            free(owner_name);
            
            if (name_len < 0) break;
            pos += name_len;
            
            if (pos + 10 + rdlength > buffer_size) break;
            
            // Write TYPE, CLASS, TTL
            uint16_t type_net = htons(rr_type);
            memcpy(buffer + pos, &type_net, 2);
            pos += 2;
            
            uint16_t class_net = htons(rr_class);
            memcpy(buffer + pos, &class_net, 2);
            pos += 2;
            
            uint32_t ttl_net = htonl(rr_ttl);
            memcpy(buffer + pos, &ttl_net, 4);
            pos += 4;
            
            // RDLENGTH placeholder
            int rdata_len_pos = pos;
            pos += 2;
            
            int rdata_start = pos;
            
            // Handle SOA RDATA
            if (rr_type == QTYPE_SOA) {
                // Parse MNAME
                char* mname = parse_dns_name_from_wire(final_buffer, final_answer->recv_len, final_pos);
                if (mname) {
                    int mname_len = write_dns_name_compressed(mname, buffer, buffer_size,
                                                            pos, buffer, rdata_start);
                    if (mname_len < 0) {
                        mname_len = write_dns_name(mname, buffer, buffer_size, pos);
                    }
                    if (mname_len > 0) {
                        pos += mname_len;
                        
                        // Skip MNAME in source
                        int temp_pos = final_pos;
                        skip_dns_name(final_buffer, final_answer->recv_len, &temp_pos);
                        
                        // Parse RNAME
                        char* rname = parse_dns_name_from_wire(final_buffer, final_answer->recv_len, temp_pos);
                        if (rname) {
                            int rname_len = write_dns_name_compressed(rname, buffer, buffer_size,
                                                                    pos, buffer, rdata_start);
                            if (rname_len < 0) {
                                rname_len = write_dns_name(rname, buffer, buffer_size, pos);
                            }
                            if (rname_len > 0) {
                                pos += rname_len;
                                
                                // Skip RNAME in source
                                skip_dns_name(final_buffer, final_answer->recv_len, &temp_pos);
                                
                                // Copy the 5 uint32_t values
                                int soa_data_len = rdlength - (temp_pos - final_pos);
                                if (soa_data_len == 20 && temp_pos + 20 <= final_answer->recv_len) {
                                    memcpy(buffer + pos, final_buffer + temp_pos, 20);
                                    pos += 20;
                                }
                            }
                            free(rname);
                        }
                    }
                    free(mname);
                }
            } else {
                // Other authority types
                memcpy(buffer + pos, final_buffer + final_pos, rdlength);
                pos += rdlength;
            }
            
            // Fill in actual RDLENGTH
            uint16_t actual_rdlength = pos - rdata_start;
            uint16_t rdlength_net = htons(actual_rdlength);
            memcpy(buffer + rdata_len_pos, &rdlength_net, 2);
            
            final_pos += rdlength;
            written_ns++;
        }
    }

    total_answers = (uint16_t)written_an;
    nscount = (uint16_t)written_ns;
    buffer[6] = (uint8_t)(total_answers >> 8); buffer[7] = (uint8_t)(total_answers & 0xFF);
    buffer[8] = (uint8_t)(nscount >> 8);       buffer[9] = (uint8_t)(nscount & 0xFF);

    reconstructed->recv_len = pos;
    reconstructed->ancount = total_answers;
    reconstructed->nscount = nscount;

    /* No truncation here: this function does not know the client's transport.
     * UDP replies are trimmed (TC=1) per the client's EDNS size by
     * finalize_udp_truncation(); TCP clients get the full answer.  (A 512-byte
     * cut here used to be cached and made large CNAME answers unresolvable.) */
    (void)question_end_pos;

    // Free final_answer
    free_packet(final_answer);
    
    return reconstructed;
}

/*
 * Free CNAME chain memory
 */
void free_cname_chain(CnameChain* chain)
{
    if (!chain) return;
    
    for (int i = 0; i < chain->count; i++) {
        free(chain->domains[i]);
        chain->domains[i] = NULL;
    }
    chain->count = 0;
}

/*
 * Free CnameChainData
 */
void free_cname_chain_data(CnameChainData* chain_data)
{
    if (!chain_data) return;
    
    for (int i = 0; i < chain_data->count; i++) {
        free(chain_data->entries[i].name);
        free(chain_data->entries[i].target);
        free(chain_data->entries[i].rdata);
        chain_data->entries[i].name = NULL;
        chain_data->entries[i].target = NULL;
        chain_data->entries[i].rdata = NULL;
    }
    chain_data->count = 0;
}