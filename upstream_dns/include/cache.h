#ifndef CACHE_H
#define CACHE_H

#include "types.h"
#include <time.h>
#include <pthread.h>

/* ---- NS cache: zone apex -> the delegation's nameserver addresses ---------- */

/* Addresses kept per zone.  Real delegations use 2-13 nameservers (the root
 * exactly 13); a hard cap keeps a hostile referral listing thousands of NS
 * from costing memory or a query flood (NXNSAttack, CVE-2020-12662). */
#define NS_SET_MAX 13

typedef struct NSCacheEntry {
    char* domain;                  // zone apex (lowercased)
    char* ips[NS_SET_MAX];         // nameserver addresses for the zone
    int   nips;
    time_t expiry;                 // monotonic seconds
    struct NSCacheEntry* next;     // hash chain
    struct NSCacheEntry* lru_prev; // intrusive LRU (most recent at head)
    struct NSCacheEntry* lru_next;
} NSCacheEntry;

typedef struct NSCache {
    NSCacheEntry** buckets;
    size_t size;                   // bucket count
    size_t count;                  // live entries
    size_t max_entries;            // LRU-evicted past this
    NSCacheEntry* lru_head;
    NSCacheEntry* lru_tail;
    pthread_mutex_t lock;
} NSCache;

/* ---- Answer cache: (name, type) -> raw response, sharded for concurrency ---- */

typedef struct AnswerCacheEntry {
    char* domain;              // Full domain name
    uint16_t qtype;            // Query type; ANSWER_QTYPE_ANY_NXDOMAIN = name-wide
    char* response_data;       // Raw DNS response packet
    ssize_t response_len;      // Length of response
    time_t expiry;             // Expiration (monotonic seconds)
    struct AnswerCacheEntry* next;
    struct AnswerCacheEntry* lru_prev;
    struct AnswerCacheEntry* lru_next;
} AnswerCacheEntry;

/* One independently locked slice of the answer cache.  Each has its own
 * buckets, LRU and budgets, so concurrent hits on different names never
 * contend on a single mutex. */
typedef struct AnswerShard {
    AnswerCacheEntry** buckets;
    size_t size;               // bucket count
    size_t count;              // live entries
    size_t max_entries;        // LRU-evicted past this
    size_t bytes;              // sum of response_len
    size_t max_bytes;          // LRU-evicted past this
    AnswerCacheEntry* lru_head;
    AnswerCacheEntry* lru_tail;
    pthread_mutex_t lock;
} AnswerShard;

#define ANSWER_CACHE_SHARDS 64

typedef struct AnswerCache {
    AnswerShard shards[ANSWER_CACHE_SHARDS];
} AnswerCache;

/* RFC 8020: an NXDOMAIN (with no answer records) means the name does not
 * exist for ANY type, so it is stored once per name under this key and served
 * for every qtype.  Type 0 is reserved and never a real cached type. */
#define ANSWER_QTYPE_ANY_NXDOMAIN 0

/* Sizes (answer-cache totals are split evenly across shards) */
#define NS_CACHE_SIZE 10007
#define ANSWER_CACHE_SIZE 100003
#define NS_CACHE_MAX_ENTRIES     8192
#define ANSWER_CACHE_MAX_ENTRIES 262144
/* Byte budget: a TCP answer can be ~64 KB, so entry count alone won't bound memory. */
#define ANSWER_CACHE_MAX_BYTES   (64u * 1024 * 1024)
/* Larger answers are served but not cached. */
#define ANSWER_CACHE_MAX_ENTRY   (16u * 1024)
#define DEFAULT_NS_TTL 3600
#define MIN_CACHE_TTL  60
#define MAX_CACHE_TTL  86400

/* Process-wide caches (created in main). */
extern NSCache*     g_ns_cache;
extern AnswerCache* g_answer_cache;

/* NS cache */
NSCache* ns_cache_create(size_t size);
void ns_cache_destroy(NSCache* cache);
/* Store (replace) the address set for `zone`; at most NS_SET_MAX are kept. */
int  ns_cache_put_set(NSCache* cache, const char* zone,
                      char* const* ips, int nips, uint32_t ttl);
/* Copy the zone's addresses into ips_out (strdup'd; caller frees), ordered
 * best-first by infra_score().  Returns the count, 0 on miss/expiry. */
int  ns_cache_get_set(NSCache* cache, const char* zone, char* ips_out[NS_SET_MAX]);
void ns_cache_cleanup_expired(NSCache* cache);
void ns_cache_flush(NSCache* cache);

/* Answer cache */
AnswerCache* answer_cache_create(size_t size);
void answer_cache_destroy(AnswerCache* cache);
int answer_cache_put(AnswerCache* cache, const char* domain, uint16_t qtype,
                     const char* response_data, ssize_t response_len, uint32_t ttl);
struct Packet* answer_cache_get(AnswerCache* cache, const char* domain, uint16_t qtype);
/* Raw, TTL-adjusted copy of the cached bytes (caller frees), or NULL. */
char* answer_cache_get_raw(AnswerCache* cache, const char* domain, uint16_t qtype,
                           ssize_t* out_len);
void answer_cache_cleanup_expired(AnswerCache* cache);

/* Response helpers */
bool wire_is_signed(const unsigned char* buf, int len);
bool response_is_signed(struct Packet* response);
uint32_t extract_min_ttl_from_response(struct Packet* response);
uint32_t extract_referral_ns_ttl(struct Packet* response);
void clamp_negative_soa_ttl(struct Packet* response);
void print_cache_stats(NSCache* ns_cache, AnswerCache* answer_cache);

#endif /* CACHE_H */
