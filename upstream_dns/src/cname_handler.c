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
 * Reconstruct complete DNS response with CNAME chain
 * 
 * IMPORTANT: This function takes ownership of final_answer and will free it
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
    
    printf("→ Reconstructing CNAME chain (%d hops)\n", chain_data->count);
    
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
    reconstructed->nscount = 0;  // Don't copy NS/AR sections for simplicity
    reconstructed->arcount = 0;
    reconstructed->q_type = original_query->q_type;
    reconstructed->q_class = original_query->q_class;
    
    // Copy domain name
    if (original_query->full_domain) {
        reconstructed->full_domain = strdup(original_query->full_domain);
    }
    
    // Allocate NEW buffer for complete response
    size_t buffer_size = MAXLINE;
    reconstructed->request = calloc(1, buffer_size);
    if (!reconstructed->request) {
        free(reconstructed->full_domain);
        free(reconstructed);
        return final_answer;
    }
    
    unsigned char* buffer = (unsigned char*)reconstructed->request;
    int pos = 0;
    
    //Header section
    buffer[pos++] = (original_query->id >> 8) & 0xFF;
    buffer[pos++] = original_query->id & 0xFF;
    
    // Flags
    uint16_t flags = 0;
    flags |= (1 << 15);  // QR = 1 (response)
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
    
    // NS and AR counts = 0
    uint16_t zero = 0;
    memcpy(buffer + pos, &zero, 2);
    pos += 2;
    memcpy(buffer + pos, &zero, 2);
    pos += 2;
    
    //Question section
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
    
    //Answer Section
    for (int i = 0; i < chain_data->count; i++) {
        printf("  Adding CNAME #%d: %s -> %s\n", 
               i + 1, 
               chain_data->entries[i].name ? chain_data->entries[i].name : "?",
               chain_data->entries[i].target ? chain_data->entries[i].target : "?");
        
        if (!chain_data->entries[i].name || !chain_data->entries[i].target) {
            continue;
        }
        
        // Owner name
        name_len = write_dns_name(chain_data->entries[i].name, buffer, 
                                 buffer_size, pos);
        if (name_len < 0) break;
        pos += name_len;
        
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
        
        // RDATA - target name
        int rdata_start = pos;
        name_len = write_dns_name(chain_data->entries[i].target, buffer,
                                 buffer_size, pos);
        if (name_len < 0) break;
        pos += name_len;
        
        // Fill in RDLENGTH
        uint16_t rdlength = pos - rdata_start;
        uint16_t rdlength_net = htons(rdlength);
        memcpy(buffer + rdlength_pos, &rdlength_net, 2);
    }
    
    //Answer Section
    if (final_answer->ancount > 0 && final_answer->request) {
        unsigned char* final_buffer = (unsigned char*)final_answer->request;
        int final_pos = HEADER_LEN;
        
        // Skip question section in final answer
        for (int i = 0; i < final_answer->qdcount && 
             final_pos < final_answer->recv_len; i++) {
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            final_pos += 4;
        }
        
        // Copy all answer RRs from final answer
        for (int i = 0; i < final_answer->ancount && 
             final_pos < final_answer->recv_len; i++) {
            int rr_start = final_pos;
            
            skip_dns_name(final_buffer, final_answer->recv_len, &final_pos);
            
            if (final_pos + 10 > final_answer->recv_len) break;
            
            uint16_t rdlength = ntohs(*(uint16_t*)(final_buffer + final_pos + 8));
            int rr_end = final_pos + 10 + rdlength;
            
            if (rr_end > final_answer->recv_len) break;
            
            size_t rr_len = rr_end - rr_start;
            if (pos + rr_len < buffer_size) {
                memcpy(buffer + pos, final_buffer + rr_start, rr_len);
                pos += rr_len;
            } else {
                fprintf(stderr, "✗ Buffer overflow prevented\n");
                break;
            }
            
            final_pos = rr_end;
        }
        
        printf("  Added %u final answer record(s)\n", final_answer->ancount);
    }
    
    reconstructed->recv_len = pos;
    reconstructed->ancount = total_answers;
    
    printf("✓ Reconstructed response: %d bytes, %u total answers (%d CNAMEs + %u final)\n",
           pos, total_answers, chain_data->count, final_answer->ancount);
    
    // Free final_answer - we've extracted what we need
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