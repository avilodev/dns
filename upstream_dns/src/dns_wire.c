#include "dns_wire.h"

/**
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

/**
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

/**
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

// Helper function to encode domain name into DNS wire format
// "www.example.com" -> 3www7example3com0
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