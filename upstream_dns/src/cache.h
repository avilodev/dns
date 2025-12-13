#ifndef CACHE_H
#define CACHE_H

#include "types.h"
#include <time.h>
#include <pthread.h>

// Cache entry for nameserver mappings
typedef struct NSCacheEntry {
    char* domain;              // Domain name 
    char* ns_ip;               // Nameserver IP address
    time_t expiry;             // Expiration timestamp
    struct NSCacheEntry* next; // Linked list for hash collision
} NSCacheEntry;

// Cache entry for DNS answers (domain+type -> answer data)
typedef struct AnswerCacheEntry {
    char* domain;              // Full domain name
    uint16_t qtype;            // Query type (A, AAAA, MX, etc.)
    char* response_data;       // Raw DNS response packet
    ssize_t response_len;      // Length of response
    time_t expiry;             // Expiration timestamp
    struct AnswerCacheEntry* next;
} AnswerCacheEntry;

// Hash table for NS cache
typedef struct NSCache {
    NSCacheEntry** buckets;
    size_t size;
    pthread_mutex_t lock;
} NSCache;

// Hash table for Answer cache
typedef struct AnswerCache {
    AnswerCacheEntry** buckets;
    size_t size;
    pthread_mutex_t lock;
} AnswerCache;

// Cache configuration
#define NS_CACHE_SIZE 10007
#define ANSWER_CACHE_SIZE 100003
#define DEFAULT_NS_TTL 3600      // 1 hour for NS records
#define MIN_CACHE_TTL 60         // Minimum 60 seconds
#define MAX_CACHE_TTL 86400      // Maximum 24 hours

// NS Cache functions
NSCache* ns_cache_create(size_t size);
void ns_cache_destroy(NSCache* cache);
int ns_cache_put(NSCache* cache, const char* domain, const char* ns_ip, uint32_t ttl);
char* ns_cache_get(NSCache* cache, const char* domain);
void ns_cache_cleanup_expired(NSCache* cache);

// Answer Cache functions
AnswerCache* answer_cache_create(size_t size);
void answer_cache_destroy(AnswerCache* cache);
int answer_cache_put(AnswerCache* cache, const char* domain, uint16_t qtype, 
                     const char* response_data, ssize_t response_len, uint32_t ttl);
struct Packet* answer_cache_get(AnswerCache* cache, const char* domain, uint16_t qtype);
void answer_cache_cleanup_expired(AnswerCache* cache);

// Utility functions
uint32_t extract_min_ttl_from_response(struct Packet* response);
void print_cache_stats(NSCache* ns_cache, AnswerCache* answer_cache);

#endif /* CACHE_H */