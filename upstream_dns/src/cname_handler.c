#include "cname_handler.h"

/**
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

/**
 * Write DNS name with compression support
 * Searches for existing labels in buffer and creates compression pointers when possible
 */
static int write_dns_name_compressed(const char* name, unsigned char* buffer, 
                                     size_t buffer_size, size_t pos,
                                     unsigned char* full_buffer, size_t search_end)
{
    if (!name || !buffer || pos >= buffer_size) {
        return -1;
    }
    
    size_t start_pos = pos;
    char name_copy[256];
    strncpy(name_copy, name, sizeof(name_copy) - 1);
    name_copy[sizeof(name_copy) - 1] = '\0';
    
    char* saveptr = NULL;
    char* label = strtok_r(name_copy, ".", &saveptr);
    
    // Build the remaining domain for each label
    char remaining[256];
    strncpy(remaining, name, sizeof(remaining) - 1);
    remaining[sizeof(remaining) - 1] = '\0';
    
    while (label) {
        size_t label_len = strlen(label);
        
        // Try to find this suffix in the buffer (look for compression opportunity)
        // Only search up to search_end to avoid false matches
        bool compressed = false;
        if (search_end > HEADER_LEN) {
            for (size_t i = HEADER_LEN; i < search_end && i < pos; i++) {
                // Check if there's a domain name at this position that matches our remaining domain
                char* existing = parse_dns_name_from_wire(full_buffer, buffer_size, i);
                if (existing && strcasecmp(existing, remaining) == 0) {
                    // Found a match! Use compression pointer
                    if (pos + 2 > buffer_size) {
                        free(existing);
                        return -1;
                    }
                    
                    uint16_t offset = i;
                    if (offset < 0x3FFF) {  // Max offset for compression
                        buffer[pos++] = 0xC0 | ((offset >> 8) & 0x3F);
                        buffer[pos++] = offset & 0xFF;
                        compressed = true;
                        free(existing);
                        break;
                    }
                }
                free(existing);
            }
        }
        
        if (compressed) {
            break;  // Rest of name is compressed
        }
        
        // No compression - write label normally
        if (label_len > 63 || pos + label_len + 1 >= buffer_size) {
            return -1;
        }
        
        buffer[pos++] = (unsigned char)label_len;
        memcpy(buffer + pos, label, label_len);
        pos += label_len;
        
        // Move to next label in remaining domain
        char* dot = strchr(remaining, '.');
        if (dot) {
            memmove(remaining, dot + 1, strlen(dot));
        } else {
            remaining[0] = '\0';
        }
        
        label = strtok_r(NULL, ".", &saveptr);
    }
    
    // If didn't use compression for the whole name, add null terminator
    if (pos == start_pos || buffer[pos - 2] < 0xC0) {
        if (pos >= buffer_size) {
            return -1;
        }
        buffer[pos++] = 0;
    }
    
    return pos - start_pos;
}

/**
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
    
    printf("→ Reconstructing CNAME chain (%d hops) with compression\n", chain_data->count);
    
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
    
    // Allocate buffer for complete response
    size_t buffer_size = MAXLINE;
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
        fprintf(stderr, "✗ Failed to write question name\n");
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
    
    // Answer with CNAME compression
    for (int i = 0; i < chain_data->count; i++) {
        printf("  Adding CNAME #%d: %s -> %s\n", 
               i + 1, 
               chain_data->entries[i].name ? chain_data->entries[i].name : "?",
               chain_data->entries[i].target ? chain_data->entries[i].target : "?");
        
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
        if (ttl == 0) ttl = 300;
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
    }
    
    // Answer section 
    // Note: Even if ancount=0 (NODATA), still need to preserve the response flags
    if (final_answer->request) {
        // For NODATA (ancount=0), we just show the CNAME chain
        // The AA and RCODE flags are already set in the header
        if (final_answer->ancount == 0) {
            printf("  Final answer is NODATA (ancount=0), will include authority section\n");
        }
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
                fprintf(stderr, "✗ Failed to parse owner name for answer RR %d\n", i);
                break;
            }
            
            // Skip name in source buffer
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            
            if (final_pos + 10 > final_answer->recv_len) {
                free(owner_name);
                break;
            }
            
            // Read TYPE, CLASS, TTL, RDLENGTH
            uint16_t rr_type = ntohs(*(uint16_t*)(final_buffer + final_pos));
            uint16_t rr_class = ntohs(*(uint16_t*)(final_buffer + final_pos + 2));
            uint32_t rr_ttl = ntohl(*(uint32_t*)(final_buffer + final_pos + 4));
            uint16_t rdlength = ntohs(*(uint16_t*)(final_buffer + final_pos + 8));
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
                fprintf(stderr, "✗ Failed to write owner name\n");
                break;
            }
            pos += name_len;
            
            if (pos + 10 + rdlength > buffer_size) {
                fprintf(stderr, "✗ Buffer overflow prevented\n");
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
                        fprintf(stderr, "✗ Failed to write RDATA name\n");
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
        }
        
        printf("  Added %u final answer record(s)\n", final_answer->ancount);
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
            uint16_t rdlength = ntohs(*(uint16_t*)(final_buffer + final_pos + 8));
            final_pos += 10 + rdlength;
        }
        
        // Copy authority section (SOA records)
        for (int i = 0; i < final_answer->nscount && final_pos < final_answer->recv_len; i++) {
            // Parse owner name
            char* owner_name = parse_dns_name_from_wire(final_buffer, 
                                                        final_answer->recv_len, 
                                                        final_pos);
            if (!owner_name) {
                fprintf(stderr, "✗ Failed to parse authority RR owner name\n");
                break;
            }
            
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            
            if (final_pos + 10 > final_answer->recv_len) {
                free(owner_name);
                break;
            }
            
            uint16_t rr_type = ntohs(*(uint16_t*)(final_buffer + final_pos));
            uint16_t rr_class = ntohs(*(uint16_t*)(final_buffer + final_pos + 2));
            uint32_t rr_ttl = ntohl(*(uint32_t*)(final_buffer + final_pos + 4));
            uint16_t rdlength = ntohs(*(uint16_t*)(final_buffer + final_pos + 8));
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
        }
        
        printf("  Added %u authority record(s) (SOA for NODATA)\n", final_answer->nscount);
    }
    
    reconstructed->recv_len = pos;
    reconstructed->ancount = total_answers;
    reconstructed->nscount = nscount;
    
    printf("✓ Reconstructed response: %ld bytes, %u answers + %u authority\n",
           pos, total_answers, nscount);
    
    // Check if response exceeds UDP limit
    if (pos > 512) {
        printf("⚠ Warning: Response size %ld bytes exceeds UDP limit (512 bytes)\n", pos);
        reconstructed->tc = 1;  // Set truncation bit
        // Update TC bit in buffer
        buffer[2] |= 0x02;
    }
    
    // Free final_answer
    free_packet(final_answer);
    
    return reconstructed;
}

/**
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

/**
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