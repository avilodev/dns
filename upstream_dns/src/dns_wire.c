#include "dns_wire.h"

/*
 * Skip over a DNS name in wire format
 * Handles both labels and compression pointers
 */
void skip_dns_name(unsigned char* buffer, int buffer_len, int* pos)
{
    if (!buffer || !pos || *pos >= buffer_len) return;
    
    while (*pos < buffer_len && buffer[*pos] != 0) {
        // Compression pointer
        if ((buffer[*pos] & 0xC0) == 0xC0) {
            *pos += 2;
            return;
        }
        
        // Regular label
        int label_len = buffer[*pos];
        if (label_len > 63) {
            // Invalid label length
            *pos = buffer_len;
            return;
        }
        
        *pos += label_len + 1;
    }
    
    // Skip final null byte
    if (*pos < buffer_len && buffer[*pos] == 0) {
        (*pos)++;
    }
}

/*
 * Parse a DNS name from wire format into a readable string
 * Handles compression pointers with loop detection
 */
char* parse_dns_name_from_wire(unsigned char* buffer, int buffer_len, int pos)
{
    if (!buffer || pos >= buffer_len) return NULL;
    
    char name[256] = {0};
    int name_len = 0;
    int jumps = 0;
    
    while (pos < buffer_len && jumps < MAX_NAME_JUMPS) {
        uint8_t len = buffer[pos];
        
        // End of name
        if (len == 0) {
            break;
        }
        
        // Compression pointer
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= buffer_len) return NULL;
            
            uint16_t offset = ((len & 0x3F) << 8) | buffer[pos + 1];
            if (offset >= buffer_len) return NULL;
            
            pos = offset;
            jumps++;
            continue;
        }
        
        // Regular label
        if (len > 63) return NULL;
        
        pos++;
        if (pos + len > buffer_len) return NULL;
        
        // Add dot separator
        if (name_len > 0 && name_len < 255) {
            name[name_len++] = '.';
        }
        
        // Check space
        if (name_len + len >= 255) return NULL;
        
        // Copy label
        memcpy(name + name_len, buffer + pos, len);
        name_len += len;
        pos += len;
    }
    
    if (jumps >= MAX_NAME_JUMPS) {
        fprintf(stderr, "  Warning: Too many compression pointer jumps\n");
        return NULL;
    }
    
    name[name_len] = '\0';
    return name_len > 0 ? strdup(name) : NULL;
}

/*
 * Write DNS name in wire format to buffer
 */
int write_dns_name(const char* name, unsigned char* buffer, 
                         size_t buffer_size, size_t pos)
{
    if (!name || !buffer) {
        return -1;
    }
    
    int start_pos = pos;
    char name_copy[256];
    strncpy(name_copy, name, sizeof(name_copy) - 1);
    name_copy[sizeof(name_copy) - 1] = '\0';
    
    char* saveptr = NULL;
    char* label = strtok_r(name_copy, ".", &saveptr);
    
    while (label) {
        size_t label_len = strlen(label);
        if (label_len > 63 || pos + label_len + 1 >= buffer_size) {
            return -1;
        }
        
        buffer[pos++] = (unsigned char)label_len;
        memcpy(buffer + pos, label, label_len);
        pos += label_len;
        
        label = strtok_r(NULL, ".", &saveptr);
    }
    
    // Null terminator
    if (pos >= buffer_size) {
        return -1;
    }
    buffer[pos++] = 0;
    
    return pos - start_pos;
}

// Encodes domain name into DNS wire format
int encode_dns_name(const char* domain, unsigned char* buffer, size_t buf_size)
{
    if (!domain || !buffer || buf_size == 0) {
        return -1;
    }
    
    unsigned char* ptr = buffer;
    const char* start = domain;
    const char* end;
    size_t remaining = buf_size;
    
    // Handle empty domain or root (.)
    if (domain[0] == '\0' || (domain[0] == '.' && domain[1] == '\0')) {
        if (remaining < 1) return -1;
        *ptr++ = 0;
        return 1;
    }
    
    while (*start) {
        // Skip leading dots
        if (*start == '.') {
            start++;
            continue;
        }
        
        // Find end of label
        end = start;
        while (*end && *end != '.') {
            end++;
        }
        
        size_t label_len = end - start;
        
        // Check label length (max 63)
        if (label_len > 63) {
            return -1;
        }
        
        // Check buffer space (length byte + label)
        if (remaining < label_len + 1) {
            return -1;
        }
        
        // Write length byte
        *ptr++ = (unsigned char)label_len;
        remaining--;
        
        // Write label
        memcpy(ptr, start, label_len);
        ptr += label_len;
        remaining -= label_len;
        
        start = end;
    }
    
    // Write terminating zero
    if (remaining < 1) {
        return -1;
    }
    *ptr++ = 0;

    return ptr - buffer;
}

/* -------------------------------------------------------------------------
 * DNSSEC wire-format parsers
 * ------------------------------------------------------------------------- */

/* parse_dnskey_rdata — RFC 4034 §2.1
 * rdata[0..1] = flags, rdata[2] = protocol, rdata[3] = algorithm,
 * rdata[4..rdlength-1] = public key bytes. */
int parse_dnskey_rdata(const unsigned char* rdata, int rdlength,
                       DnskeyRdata* out)
{
    if (!rdata || !out || rdlength < 4) return -1;

    out->flags     = ((uint16_t)rdata[0] << 8) | rdata[1];
    out->protocol  = rdata[2];
    out->algorithm = rdata[3];
    out->pubkey_len = (uint16_t)(rdlength - 4);

    if (out->pubkey_len > 0) {
        out->pubkey = malloc(out->pubkey_len);
        if (!out->pubkey) return -1;
        memcpy(out->pubkey, rdata + 4, out->pubkey_len);
    } else {
        out->pubkey = NULL;
    }
    return 0;
}

/* parse_rrsig_rdata — RFC 4034 §3.1
 * buf/buf_len: full DNS message (for name decompression).
 * rdata_offset: byte offset in buf where the RRSIG RDATA begins.
 * rdlength: length of the RRSIG RDATA. */
int parse_rrsig_rdata(const unsigned char* buf, int buf_len,
                      int rdata_offset, int rdlength,
                      RrsigRdata* out)
{
    if (!buf || !out || rdlength < 18) return -1;
    const unsigned char* r = buf + rdata_offset;
    int end = rdata_offset + rdlength;

    out->type_covered    = ((uint16_t)r[0]  << 8) | r[1];
    out->algorithm       = r[2];
    out->labels          = r[3];
    out->orig_ttl        = ((uint32_t)r[4]  << 24) | ((uint32_t)r[5]  << 16)
                         | ((uint32_t)r[6]  <<  8) |  (uint32_t)r[7];
    out->sig_expiration  = ((uint32_t)r[8]  << 24) | ((uint32_t)r[9]  << 16)
                         | ((uint32_t)r[10] <<  8) |  (uint32_t)r[11];
    out->sig_inception   = ((uint32_t)r[12] << 24) | ((uint32_t)r[13] << 16)
                         | ((uint32_t)r[14] <<  8) |  (uint32_t)r[15];
    out->key_tag         = ((uint16_t)r[16] << 8) | r[17];

    /* Signer's name at rdata_offset+18 (may be compressed) */
    int name_pos = rdata_offset + 18;
    char* sname = parse_dns_name_from_wire((unsigned char*)buf, buf_len, name_pos);
    if (!sname) return -1;
    strncpy(out->signer_name, sname, sizeof(out->signer_name) - 1);
    out->signer_name[sizeof(out->signer_name) - 1] = '\0';
    free(sname);

    /* Advance past the wire-encoded signer name */
    skip_dns_name((unsigned char*)buf, buf_len, &name_pos);
    int sig_start = name_pos;
    int sig_len = end - sig_start;
    if (sig_len < 0) return -1;

    out->sig_len = (uint16_t)sig_len;
    if (sig_len > 0) {
        out->signature = malloc((size_t)sig_len);
        if (!out->signature) return -1;
        memcpy(out->signature, buf + sig_start, (size_t)sig_len);
    } else {
        out->signature = NULL;
    }
    return 0;
}

/* parse_ds_rdata — RFC 4034 §5.1 */
int parse_ds_rdata(const unsigned char* rdata, int rdlength,
                   DsRdata* out)
{
    if (!rdata || !out || rdlength < 4) return -1;

    out->key_tag     = ((uint16_t)rdata[0] << 8) | rdata[1];
    out->algorithm   = rdata[2];
    out->digest_type = rdata[3];
    out->digest_len  = (uint16_t)(rdlength - 4);

    if (out->digest_len > 0) {
        out->digest = malloc(out->digest_len);
        if (!out->digest) return -1;
        memcpy(out->digest, rdata + 4, out->digest_len);
    } else {
        out->digest = NULL;
    }
    return 0;
}

/* parse_nsec3_rdata — RFC 5155 §3.2 */
int parse_nsec3_rdata(const unsigned char* rdata, int rdlength,
                      Nsec3Rdata* out)
{
    if (!rdata || !out || rdlength < 5) return -1;
    int pos = 0;

    out->hash_alg   = rdata[pos++];
    out->flags      = rdata[pos++];
    out->iterations = ((uint16_t)rdata[pos] << 8) | rdata[pos + 1]; pos += 2;

    uint8_t salt_len = rdata[pos++];
    out->salt_len = salt_len;
    if (pos + salt_len > rdlength) return -1;
    if (salt_len > 0) {
        out->salt = malloc(salt_len);
        if (!out->salt) return -1;
        memcpy(out->salt, rdata + pos, salt_len);
    } else {
        out->salt = NULL;
    }
    pos += salt_len;

    if (pos >= rdlength) return -1;
    uint8_t hash_len = rdata[pos++];
    out->next_hashed_len = hash_len;
    if (pos + hash_len > rdlength) { free(out->salt); return -1; }
    if (hash_len > 0) {
        out->next_hashed = malloc(hash_len);
        if (!out->next_hashed) { free(out->salt); return -1; }
        memcpy(out->next_hashed, rdata + pos, hash_len);
    } else {
        out->next_hashed = NULL;
    }
    pos += hash_len;

    int bitmaps_len = rdlength - pos;
    out->bitmaps_len = (uint16_t)(bitmaps_len > 0 ? bitmaps_len : 0);
    if (out->bitmaps_len > 0) {
        out->type_bitmaps = malloc(out->bitmaps_len);
        if (!out->type_bitmaps) { free(out->salt); free(out->next_hashed); return -1; }
        memcpy(out->type_bitmaps, rdata + pos, out->bitmaps_len);
    } else {
        out->type_bitmaps = NULL;
    }
    return 0;
}

/* compute_key_tag — RFC 4034 Appendix B */
uint16_t compute_key_tag(uint16_t flags, uint8_t protocol, uint8_t algorithm,
                         const uint8_t* pubkey, uint16_t pubkey_len)
{
    unsigned long ac = 0;
    /* First 4 bytes of DNSKEY RDATA in wire order */
    unsigned char hdr[4] = {
        (unsigned char)(flags >> 8), (unsigned char)(flags & 0xFF),
        protocol, algorithm
    };
    for (int i = 0; i < 4; i++) {
        if (i & 1) ac +=  hdr[i];
        else        ac += (unsigned long)hdr[i] << 8;
    }
    for (int i = 0; i < pubkey_len; i++) {
        if ((i + 4) & 1) ac +=  pubkey[i];
        else              ac += (unsigned long)pubkey[i] << 8;
    }
    ac += (ac >> 16) & 0xFFFF;
    return (uint16_t)(ac & 0xFFFF);
}