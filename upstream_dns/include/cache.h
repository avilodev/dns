#ifndef CACHE_H
#define CACHE_H

#include "types.h"
#include <time.h>
#include <pthread.h>

// NS cache: zone apex -> the delegation's nameserver addresses

// Addresses kept per zone.
#define NS_SET_MAX 13

typedef struct ns_cache_entry {
	char* domain;                  // zone apex (lowercased)
	char* ips[NS_SET_MAX];         // nameserver addresses for the zone
	int   nips;
	time_t expiry;                 // monotonic seconds
	struct ns_cache_entry* next;     // hash chain
	struct ns_cache_entry* lru_prev; // intrusive LRU (most recent at head)
	struct ns_cache_entry* lru_next;
} ns_cache_entry;

typedef struct ns_cache {
	ns_cache_entry** buckets;
	size_t size;                   // bucket count
	size_t count;                  // live entries
	size_t max_entries;            // LRU-evicted past this
	ns_cache_entry* lru_head;
	ns_cache_entry* lru_tail;
	pthread_mutex_t lock;
} ns_cache;

// Answer cache: (name, type) -> raw response, sharded for concurrency

typedef struct answer_cache_entry {
	char* domain;              // Full domain name
	uint16_t qtype;            // Query type; ANSWER_QTYPE_ANY_NXDOMAIN = name-wide
	char* response_data;       // Raw DNS response packet
	ssize_t response_len;      // Length of response
	time_t expiry;             // Expiration (monotonic seconds)
	struct answer_cache_entry* next;
	struct answer_cache_entry* lru_prev;
	struct answer_cache_entry* lru_next;
} answer_cache_entry;

// One independently locked slice of the answer cache.
typedef struct answer_shard {
	answer_cache_entry** buckets;
	size_t size;               // bucket count
	size_t count;              // live entries
	size_t max_entries;        // LRU-evicted past this
	size_t bytes;              // sum of response_len
	size_t max_bytes;          // LRU-evicted past this
	answer_cache_entry* lru_head;
	answer_cache_entry* lru_tail;
	pthread_mutex_t lock;
} answer_shard;

#define ANSWER_CACHE_SHARDS 64

typedef struct answer_cache {
	answer_shard shards[ANSWER_CACHE_SHARDS];
} answer_cache;

// RFC 8020: an NXDOMAIN means the name does not exist for ANY type
#define ANSWER_QTYPE_ANY_NXDOMAIN 0

// Sizes (answer-cache totals are split evenly across shards)
#define NS_CACHE_SIZE 10007
#define ANSWER_CACHE_SIZE 100003
#define NS_CACHE_MAX_ENTRIES     8192
#define ANSWER_CACHE_MAX_ENTRIES 262144
// Byte budget: a TCP answer can be ~64 KB
#define ANSWER_CACHE_MAX_BYTES   (64u * 1024 * 1024)
// Larger answers are served but not cached.
#define ANSWER_CACHE_MAX_ENTRY   (16u * 1024)
#define DEFAULT_NS_TTL 3600
#define MIN_CACHE_TTL  60
#define MAX_CACHE_TTL  86400

// Process-wide caches (created in main).
extern ns_cache*     g_ns_cache;
extern answer_cache* g_answer_cache;

// NS cache
ns_cache* ns_cache_create(size_t size);
void ns_cache_destroy(ns_cache* cache);
// Store (replace) the address set for `zone`; at most NS_SET_MAX are kept.
int  ns_cache_put_set(ns_cache* cache, const char* zone,
					  char* const* ips, int nips, uint32_t ttl);
// Copy the zone's addresses into ips_out, ordered best-first by infra_score.
int  ns_cache_get_set(ns_cache* cache, const char* zone, char* ips_out[NS_SET_MAX]);
void ns_cache_cleanup_expired(ns_cache* cache);
void ns_cache_flush(ns_cache* cache);

// Answer cache
answer_cache* answer_cache_create(size_t size);
void answer_cache_destroy(answer_cache* cache);
int answer_cache_put(answer_cache* cache, const char* domain, uint16_t qtype,
					 const char* response_data, ssize_t response_len, uint32_t ttl);
struct packet* answer_cache_get(answer_cache* cache, const char* domain, uint16_t qtype);
// Raw, TTL-adjusted copy of the cached bytes (caller frees), or NULL.
char* answer_cache_get_raw(answer_cache* cache, const char* domain, uint16_t qtype,
						   ssize_t* out_len);
void answer_cache_cleanup_expired(answer_cache* cache);

// Response helpers
bool wire_is_signed(const unsigned char* buf, int len);
bool response_is_signed(struct packet* response);
uint32_t extract_min_ttl_from_response(struct packet* response);
uint32_t extract_referral_ns_ttl(struct packet* response);
void clamp_negative_soa_ttl(struct packet* response);
void print_cache_stats(ns_cache* ns_store, answer_cache* answer_store);

#endif /* CACHE_H */
