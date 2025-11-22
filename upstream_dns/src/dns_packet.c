#include "dns_packet.h"

struct Packet* copy_packet(struct Packet* pkt)
{ 
    if(!pkt)
        return NULL;

    struct Packet* copy = calloc(1, sizeof(struct Packet));
    if (!copy) 
        return NULL;

    //Malloc for binary data
    if (pkt->request && pkt->recv_len > 0) {
        copy->request = malloc(pkt->recv_len);
        if (!copy->request) {
            free(copy);
            return NULL;
        }
        memcpy(copy->request, pkt->request, pkt->recv_len);
        copy->recv_len = pkt->recv_len;
    } else {
        copy->request = NULL;
        copy->recv_len = 0;
    }

    copy->id = pkt->id;
    copy->flags = pkt->flags;
    copy->qr = pkt->qr;
    copy->opcode = pkt->opcode;
    copy->aa = pkt->aa;      
    copy->tc = pkt->tc;   
    copy->rd = pkt->rd;    
    copy->ra = pkt->ra;      
    copy->z = pkt->z;     
    copy->ad = pkt->ad;    
    copy->cd = pkt->cd;   
    copy->rcode = pkt->rcode;  

   
    copy->qdcount = pkt->qdcount;
    copy->ancount = pkt->ancount;
    copy->nscount = pkt->nscount;
    copy->arcount = pkt->arcount;


    copy->full_domain = pkt->full_domain ? strdup(pkt->full_domain) : NULL;
    copy->authoritative_domain = pkt->authoritative_domain ? strdup(pkt->authoritative_domain) : NULL;
    copy->domain = pkt->domain ? strdup(pkt->domain) : NULL;
    copy->top_level_domain = pkt->top_level_domain ? strdup(pkt->top_level_domain) : NULL;

    copy->q_type = pkt->q_type; 
    copy->q_class = pkt->q_class;

    return copy;
}


// Construct DNS packet into pkt->request buffer, returns bytes written or -1 on error
int construct_dns_packet(struct Packet* pkt)
{
    if (!pkt || !pkt->request) {
        return -1;
    }
    
    // Assume standard DNS buffer size if recv_len is 0 or negative
    size_t buffer_size = (pkt->recv_len > 0) ? (size_t)pkt->recv_len : 512;
    
    if (buffer_size < 12) {
        return -1;  // Need at least header size
    }
    
    unsigned char* ptr = (unsigned char*)pkt->request;
    size_t remaining = buffer_size;
    
    // Transaction ID (2 bytes)
    *ptr++ = (pkt->id >> 8) & 0xFF;
    *ptr++ = pkt->id & 0xFF;
    
    // Flags (2 bytes)
    // Build flags from individual bits
    uint16_t flags = 0;
    flags |= (pkt->qr & 0x01) << 15;      // QR bit
    flags |= (pkt->opcode & 0x0F) << 11;  // Opcode (4 bits)
    flags |= (pkt->aa & 0x01) << 10;      // AA bit
    flags |= (pkt->tc & 0x01) << 9;       // TC bit
    flags |= (pkt->rd & 0x01) << 8;       // RD bit
    flags |= (pkt->ra & 0x01) << 7;       // RA bit
    flags |= (pkt->z & 0x01) << 6;        // Z bit
    flags |= (pkt->ad & 0x01) << 5;       // AD bit
    flags |= (pkt->cd & 0x01) << 4;       // CD bit
    flags |= (pkt->rcode & 0x0F);         // RCODE (4 bits)
    
    *ptr++ = (flags >> 8) & 0xFF;
    *ptr++ = flags & 0xFF;
    
    // Question count (2 bytes)
    *ptr++ = (pkt->qdcount >> 8) & 0xFF;
    *ptr++ = pkt->qdcount & 0xFF;
    
    // Answer count (2 bytes)
    *ptr++ = (pkt->ancount >> 8) & 0xFF;
    *ptr++ = pkt->ancount & 0xFF;
    
    // Authority count (2 bytes)
    *ptr++ = (pkt->nscount >> 8) & 0xFF;
    *ptr++ = pkt->nscount & 0xFF;
    
    // Additional count (2 bytes)
    *ptr++ = (pkt->arcount >> 8) & 0xFF;
    *ptr++ = pkt->arcount & 0xFF;
    
    remaining = buffer_size - (ptr - (unsigned char*)pkt->request);
    
    // === QUESTION SECTION ===
    if (pkt->qdcount > 0 && pkt->full_domain) {
        // Encode domain name in DNS format
        int qname_len = encode_dns_name(pkt->full_domain, ptr, remaining);
        if (qname_len < 0) {
            return -1;  // Buffer too small
        }
        ptr += qname_len;
        remaining -= qname_len;
        
        if (remaining < 4) {
            return -1;  // Not enough space for QTYPE and QCLASS
        }
        
        // QTYPE (2 bytes)
        *ptr++ = (pkt->q_type >> 8) & 0xFF;
        *ptr++ = pkt->q_type & 0xFF;
        
        // QCLASS (2 bytes)
        *ptr++ = (pkt->q_class >> 8) & 0xFF;
        *ptr++ = pkt->q_class & 0xFF;
        
        remaining -= 4;
    }
    
    // Total bytes written
    return ptr - (unsigned char*)pkt->request;
}

/**
 * Free packet structure and all allocated memory
 */
int free_packet(struct Packet* pkt) {
    if (!pkt) {
        return -1;
    }

    if(pkt->request)
        free(pkt->request);

    if(pkt->full_domain)
        free(pkt->full_domain);

    if(pkt->authoritative_domain)
        free(pkt->authoritative_domain);

    if(pkt->domain)
        free(pkt->domain);

    if(pkt->top_level_domain)
        free(pkt->top_level_domain);

    if(pkt)
        free(pkt);

    return 0;
}


/**
 * Format a DNS query packet for iterative resolution
 * Sets RD=0 (no recursion desired) for iterative queries
 */
struct Packet* format_resolver(struct Packet* pkt)
{
    if (!pkt) {
        fprintf(stderr, "Error: NULL packet provided to format_resolver\n");
        return NULL;
    }

    struct Packet* copy_pkt = copy_packet(pkt);
    if (!copy_pkt) {
        fprintf(stderr, "Error: Failed to copy packet\n");
        return NULL;
    }

    set_packet_fields(copy_pkt);

    int ret = construct_dns_packet(copy_pkt);
    if (ret < 0) {
        fprintf(stderr, "Error: Failed to construct DNS packet\n");
        free_packet(copy_pkt);
        return NULL;
    }

    copy_pkt->recv_len = ret;
    return copy_pkt;
}


/**
 * Set packet fields for iterative DNS query (non-recursive)
 */
void set_packet_fields(struct Packet* pkt)
{
    if (!pkt) return;

    pkt->id = get_random_id();
    pkt->qr = 0;       // Query
    pkt->opcode = 0;   // Standard query
    pkt->rd = 0;       // No recursion desired (iterative)
    pkt->ra = 0;
    pkt->aa = 0;
    pkt->tc = 0;
    pkt->ad = 0;
    pkt->cd = 0;
    pkt->z = 0;
    pkt->rcode = 0;
    
    // Rebuild flags field
    pkt->flags = 0;
    pkt->flags |= (pkt->qr & 0x01) << 15;
    pkt->flags |= (pkt->opcode & 0x0F) << 11;
    pkt->flags |= (pkt->aa & 0x01) << 10;
    pkt->flags |= (pkt->tc & 0x01) << 9;
    pkt->flags |= (pkt->rd & 0x01) << 8;
    pkt->flags |= (pkt->ra & 0x01) << 7;
    pkt->flags |= (pkt->z & 0x01) << 6;
    pkt->flags |= (pkt->ad & 0x01) << 5;
    pkt->flags |= (pkt->cd & 0x01) << 4;
    pkt->flags |= (pkt->rcode & 0x0F);
    
    pkt->qdcount = 1;
    pkt->ancount = 0;
    pkt->nscount = 0;
    pkt->arcount = 0;
}