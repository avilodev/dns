#include "cache.h"
#include "request.h"
#include "dns_wire.h"
#include <string.h>
#include <stdlib.h>

/*
 * Walk all RRs in a wire-format DNS response and clamp every TTL to max_ttl.
 * OPT records (type 41) carry extended-RCODE/EDNS flags in their TTL field —
 * skip them so EDNS negotiation is not corrupted.
 */
static void patch_response_ttls(unsigned char* buf, int len, uint32_t max_ttl)
{
    if (!buf || len < HEADER_LEN || max_ttl == 0) return;

    uint16_t qdcount = ntohs(*(uint16_t*)(buf + 4));
    uint16_t ancount = ntohs(*(uint16_t*)(buf + 6));
    uint16_t nscount = ntohs(*(uint16_t*)(buf + 8));
    uint16_t arcount = ntohs(*(uint16_t*)(buf + 10));
    int pos = HEADER_LEN;

    /* Skip question section */
    for (int i = 0; i < qdcount && pos < len; i++) {
        skip_dns_name(buf, len, &pos);
        pos += 4; /* QTYPE + QCLASS */
    }

    int total_rrs = (int)ancount + nscount + arcount;
    for (int i = 0; i < total_rrs && pos < len; i++) {
        skip_dns_name(buf, len, &pos);
        if (pos + 10 > len) break;

        uint16_t rr_type = ntohs(*(uint16_t*)(buf + pos));
        if (rr_type != 41) { /* skip OPT pseudo-RR */
            uint32_t rr_ttl = ntohl(*(uint32_t*)(buf + pos + 4));
            if (rr_ttl > max_ttl) {
                uint32_t clamped = htonl(max_ttl);
                memcpy(buf + pos + 4, &clamped, 4);
            }
        }

        uint16_t rdlen = ntohs(*(uint16_t*)(buf + pos + 8));
        pos += 10 + rdlen;
    }
}

// Simple hash function
static unsigned long hash_string(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static unsigned long hash_domain_type(const char* domain, uint16_t qtype) {
    unsigned long hash = 5381;
    int c;
    while ((c = *domain++))
        hash = ((hash << 5) + hash) + c;
    hash = ((hash << 5) + hash) + qtype;
    return hash;
}

NSCache* ns_cache_create(size_t size) {
    NSCache* cache = malloc(sizeof(NSCache));
    if (!cache) return NULL;
    
    cache->buckets = calloc(size, sizeof(NSCacheEntry*));
    if (!cache->buckets) {
        free(cache);
        return NULL;
    }
     
    cache->size = size;
    pthread_mutex_init(&cache->lock, NULL);
    return cache;
}

void ns_cache_destroy(NSCache* cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        NSCacheEntry* entry = cache->buckets[i];
        while (entry) {
            NSCacheEntry* next = entry->next;
            free(entry->domain);
            free(entry->ns_ip);
            free(entry);
            entry = next;
        }
    }
    
    free(cache->buckets);
    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

int ns_cache_put(NSCache* cache, const char* domain, const char* ns_ip, uint32_t ttl) {
    if (!cache || !domain || !ns_ip) return -1;
    
    // TTL limits
    if (ttl < MIN_CACHE_TTL) ttl = MIN_CACHE_TTL;
    if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;
    
    unsigned long hash = hash_string(domain);
    size_t index = hash % cache->size;
    
    pthread_mutex_lock(&cache->lock);
    
    // Check if entry already exists and updates it
    NSCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0) {
            char* new_ip = strdup(ns_ip);
            if (!new_ip) {
                pthread_mutex_unlock(&cache->lock);
                return -1;
            }
            free(entry->ns_ip);
            entry->ns_ip = new_ip;
            entry->expiry = time(NULL) + ttl;
            pthread_mutex_unlock(&cache->lock);
            return 0;
        }
        entry = entry->next;
    }
    
    // Create new entry
    NSCacheEntry* new_entry = malloc(sizeof(NSCacheEntry));
    if (!new_entry) {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }

    new_entry->domain = strdup(domain);
    new_entry->ns_ip  = strdup(ns_ip);
    if (!new_entry->domain || !new_entry->ns_ip) {
        free(new_entry->domain);
        free(new_entry->ns_ip);
        free(new_entry);
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }
    new_entry->expiry = time(NULL) + ttl;
    new_entry->next = cache->buckets[index];
    cache->buckets[index] = new_entry;

    pthread_mutex_unlock(&cache->lock);
    return 0;
}

char* ns_cache_get(NSCache* cache, const char* domain) {
    if (!cache || !domain) return NULL;
    
    unsigned long hash = hash_string(domain);
    size_t index = hash % cache->size;
    time_t now = time(NULL);
    
    pthread_mutex_lock(&cache->lock);
    
    NSCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0) {
            if (entry->expiry > now) {
                char* result = strdup(entry->ns_ip);
                pthread_mutex_unlock(&cache->lock);
                return result;
            } else {
                pthread_mutex_unlock(&cache->lock);
                return NULL;
            }
        }
        entry = entry->next;
    }
    
    pthread_mutex_unlock(&cache->lock);
    return NULL;
}

void ns_cache_cleanup_expired(NSCache* cache) {
    if (!cache) return;
    
    time_t now = time(NULL);
    int removed = 0;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        NSCacheEntry** entry_ptr = &cache->buckets[i];
        while (*entry_ptr) {
            NSCacheEntry* entry = *entry_ptr;
            if (entry->expiry <= now) {
                *entry_ptr = entry->next;
                free(entry->domain);
                free(entry->ns_ip);
                free(entry);
                removed++;
            } else {
                entry_ptr = &entry->next;
            }
        }
    }
    
    pthread_mutex_unlock(&cache->lock);
}

AnswerCache* answer_cache_create(size_t size) {
    AnswerCache* cache = malloc(sizeof(AnswerCache));
    if (!cache) return NULL;
    
    cache->buckets = calloc(size, sizeof(AnswerCacheEntry*));
    if (!cache->buckets) {
        free(cache);
        return NULL;
    }
    
    cache->size = size;
    pthread_mutex_init(&cache->lock, NULL);
    return cache;
}

void answer_cache_destroy(AnswerCache* cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        AnswerCacheEntry* entry = cache->buckets[i];
        while (entry) {
            AnswerCacheEntry* next = entry->next;
            free(entry->domain);
            free(entry->response_data);
            free(entry);
            entry = next;
        }
    }
    
    free(cache->buckets);
    pthread_mutex_unlock(&cache->lock);
    pthread_mutex_destroy(&cache->lock);
    free(cache);
}

int answer_cache_put(AnswerCache* cache, const char* domain, uint16_t qtype,
                     const char* response_data, ssize_t response_len, uint32_t ttl) {
    if (!cache || !domain || !response_data || response_len <= 0) return -1;
    
    // Enforce TTL limits
    if (ttl < MIN_CACHE_TTL) ttl = MIN_CACHE_TTL;
    if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;
    
    unsigned long hash = hash_domain_type(domain, qtype);
    size_t index = hash % cache->size;
    
    pthread_mutex_lock(&cache->lock);
    
    // Check if entry exists and updates it
    AnswerCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0 && entry->qtype == qtype) {
            char* new_data = malloc(response_len);
            if (!new_data) {
                pthread_mutex_unlock(&cache->lock);
                return -1;
            }
            free(entry->response_data);
            entry->response_data = new_data;
            memcpy(entry->response_data, response_data, response_len);
            entry->response_len = response_len;
            entry->stored_at = time(NULL);
            entry->expiry = entry->stored_at + ttl;
            pthread_mutex_unlock(&cache->lock);
            return 0;
        }
        entry = entry->next;
    }
    
    // Create new entry
    AnswerCacheEntry* new_entry = malloc(sizeof(AnswerCacheEntry));
    if (!new_entry) {
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }
    
    new_entry->domain = strdup(domain);
    new_entry->qtype = qtype;
    new_entry->response_data = malloc(response_len);
    if (!new_entry->response_data) {
        free(new_entry->domain);
        free(new_entry);
        pthread_mutex_unlock(&cache->lock);
        return -1;
    }
    
    memcpy(new_entry->response_data, response_data, response_len);
    new_entry->response_len = response_len;
    new_entry->stored_at = time(NULL);
    new_entry->expiry = new_entry->stored_at + ttl;
    new_entry->next = cache->buckets[index];
    cache->buckets[index] = new_entry;
    
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

struct Packet* answer_cache_get(AnswerCache* cache, const char* domain, uint16_t qtype) {
    if (!cache || !domain) return NULL;
    
    unsigned long hash = hash_domain_type(domain, qtype);
    size_t index = hash % cache->size;
    time_t now = time(NULL);
    
    pthread_mutex_lock(&cache->lock);
    
    AnswerCacheEntry* entry = cache->buckets[index];
    while (entry) {
        if (strcmp(entry->domain, domain) == 0 && entry->qtype == qtype) {
            if (entry->expiry > now) {
                // Copy raw response data under the lock, then patch outside
                // the critical section to avoid holding mutex during allocation.
                ssize_t data_len = entry->response_len;
                char* data_copy = malloc(data_len);
                if (!data_copy) {
                    pthread_mutex_unlock(&cache->lock);
                    return NULL;
                }
                memcpy(data_copy, entry->response_data, data_len);
                /* Compute remaining TTL: how many seconds until expiry. */
                uint32_t remaining = (entry->expiry > now)
                    ? (uint32_t)(entry->expiry - now) : 0;
                pthread_mutex_unlock(&cache->lock);

                /* RFC 1034 §4.1.3: decrement all RR TTLs by elapsed time
                 * before returning the cached response to the client. */
                patch_response_ttls((unsigned char*)data_copy, (int)data_len,
                                    remaining);

                struct Packet* pkt = parse_response(data_copy, data_len);
                free(data_copy);
                return pkt;
            } else {
                pthread_mutex_unlock(&cache->lock);
                return NULL;
            }
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&cache->lock);
    return NULL;
}

void answer_cache_cleanup_expired(AnswerCache* cache) {
    if (!cache) return;
    
    time_t now = time(NULL);
    int removed = 0;
    
    pthread_mutex_lock(&cache->lock);
    
    for (size_t i = 0; i < cache->size; i++) {
        AnswerCacheEntry** entry_ptr = &cache->buckets[i];
        while (*entry_ptr) {
            AnswerCacheEntry* entry = *entry_ptr;
            if (entry->expiry <= now) {
                *entry_ptr = entry->next;
                free(entry->domain);
                free(entry->response_data);
                free(entry);
                removed++;
            } else {
                entry_ptr = &entry->next;
            }
        }
    }
    
    pthread_mutex_unlock(&cache->lock);
}

uint32_t extract_min_ttl_from_response(struct Packet* response) {
    if (!response || !response->request || response->recv_len < HEADER_LEN) {
        return DEFAULT_NS_TTL;
    }
    
    unsigned char* buffer = (unsigned char*)response->request;
    int pos = HEADER_LEN;
    int buffer_len = response->recv_len;
    uint32_t min_ttl = DEFAULT_NS_TTL;
    bool found_ttl = false;
    
    // Skip question section
    for (int i = 0; i < response->qdcount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        pos += 4;  // QTYPE + QCLASS
    }
    
    // Check answer section for TTLs
    for (int i = 0; i < response->ancount && pos < buffer_len; i++) {
        skip_dns_name(buffer, buffer_len, &pos);
        
        if (pos + 10 > buffer_len) break;
        
        uint32_t ttl = ntohl(*(uint32_t*)(buffer + pos + 4));
        uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
        
        if (!found_ttl || ttl < min_ttl) {
            min_ttl = ttl;
            found_ttl = true;
        }
        
        pos += 10 + rdlength;
    }
    
    // For NXDOMAIN, check authority section for SOA minimum TTL
    if (response->rcode == RCODE_NAME_ERROR && response->nscount > 0) {
        for (int i = 0; i < response->nscount && pos < buffer_len; i++) {
            skip_dns_name(buffer, buffer_len, &pos);
            
            if (pos + 10 > buffer_len) break;
            
            uint16_t type = ntohs(*(uint16_t*)(buffer + pos));
            uint32_t ttl = ntohl(*(uint32_t*)(buffer + pos + 4));
            uint16_t rdlength = ntohs(*(uint16_t*)(buffer + pos + 8));
            
            // Found authoritative NXDOMAIN (SOA)
            if (type == QTYPE_SOA && rdlength > 20) {
                int rdata_pos = pos + 10;
                
                // Skip primary nameserver
                skip_dns_name(buffer, buffer_len, &rdata_pos);
                
                // Skip RNAME
                skip_dns_name(buffer, buffer_len, &rdata_pos);
                
                // Skip serial, refresh, retry, expire (4 uint32_t = 16 bytes)
                rdata_pos += 16;
                
                // Read MINIMUM (the negative caching TTL)
                if (rdata_pos + 4 <= buffer_len) {
                    uint32_t soa_minimum = ntohl(*(uint32_t*)(buffer + rdata_pos));
                    
                    // Use the smaller of SOA TTL or SOA minimum
                    uint32_t negative_ttl = (ttl < soa_minimum) ? ttl : soa_minimum;
                    return negative_ttl;
                }
            }
            
            pos += 10 + rdlength;
        }
    }
    
    // Enforce reasonable limits
    if (min_ttl < 60) min_ttl = MIN_CACHE_TTL;
    if (min_ttl > 86400) min_ttl = MAX_CACHE_TTL;
    
    return found_ttl ? min_ttl : DEFAULT_NS_TTL;
}

/*
 * Return the TTL of the first NS record in the authority section of a referral
 * response (rcode=NOERROR, ancount=0, nscount>0), clamped to [MIN_CACHE_TTL,
 * MAX_CACHE_TTL].  Falls back to DEFAULT_NS_TTL if no NS record is found.
 */
uint32_t extract_referral_ns_ttl(struct Packet* response) {
    if (!response || !response->request || response->recv_len < HEADER_LEN)
        return DEFAULT_NS_TTL;

    unsigned char* buf = (unsigned char*)response->request;
    int blen = (int)response->recv_len;
    int pos = HEADER_LEN;

    /* Skip question section */
    for (int i = 0; i < (int)response->qdcount && pos < blen; i++) {
        skip_dns_name(buf, blen, &pos);
        pos += 4; /* QTYPE + QCLASS */
    }

    /* Skip answer section (should be empty for a referral) */
    for (int i = 0; i < (int)response->ancount && pos < blen; i++) {
        skip_dns_name(buf, blen, &pos);
        if (pos + 10 > blen) break;
        uint16_t rdlen = ntohs(*(uint16_t*)(buf + pos + 8));
        pos += 10 + rdlen;
    }

    /* Read TTL of the first NS record in the authority section */
    for (int i = 0; i < (int)response->nscount && pos < blen; i++) {
        skip_dns_name(buf, blen, &pos);
        if (pos + 10 > blen) break;
        uint16_t type  = ntohs(*(uint16_t*)(buf + pos));
        uint32_t ttl   = ntohl(*(uint32_t*)(buf + pos + 4));
        uint16_t rdlen = ntohs(*(uint16_t*)(buf + pos + 8));
        if (type == QTYPE_NS) {
            if (ttl < MIN_CACHE_TTL) ttl = MIN_CACHE_TTL;
            if (ttl > MAX_CACHE_TTL) ttl = MAX_CACHE_TTL;
            return ttl;
        }
        pos += 10 + rdlen;
    }

    return DEFAULT_NS_TTL;
}

void print_cache_stats(NSCache* ns_cache, AnswerCache* answer_cache) {
    if (!ns_cache || !answer_cache) return;
    
    int ns_count = 0, answer_count = 0;
    time_t now = time(NULL);
    
    // Count NS cache entries
    pthread_mutex_lock(&ns_cache->lock);
    for (size_t i = 0; i < ns_cache->size; i++) {
        NSCacheEntry* entry = ns_cache->buckets[i];
        while (entry) {
            if (entry->expiry > now) ns_count++;
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&ns_cache->lock);
    
    // Count Answer cache entries
    pthread_mutex_lock(&answer_cache->lock);
    for (size_t i = 0; i < answer_cache->size; i++) {
        AnswerCacheEntry* entry = answer_cache->buckets[i];
        while (entry) {
            if (entry->expiry > now) answer_count++;
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&answer_cache->lock);
    
    printf("\n╔════════════════════════════════════════════╗\n");
    printf("║            CACHE STATISTICS                ║\n");
    printf("╠════════════════════════════════════════════╣\n");
    printf("║ NS Cache:     %6d entries             ║\n", ns_count);
    printf("║ Answer Cache: %6d entries             ║\n", answer_count);
    printf("╚════════════════════════════════════════════╝\n\n");
}