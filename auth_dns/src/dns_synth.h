#ifndef DNS_SYNTH_H
#define DNS_SYNTH_H

#include <stdint.h>
#include <stddef.h>     // size_t
#include <sys/types.h>  // ssize_t

// Synthesized DNS responses.

// One answer RR to emit.
typedef struct {
	uint16_t qtype;       // 1 = A, 28 = AAAA, 5 = CNAME
	uint8_t  addr[16];    // network-order address; first addrlen bytes used
	int      addrlen;     // 4 for A, 16 for AAAA, 0 for CNAME
	char     cname[256];  // presentation-form target when qtype == CNAME
	uint32_t ttl;         // RR TTL in seconds
} synth_answer;

// Build a response to `query` (a well-formed query, `qlen` bytes) into `out`.
ssize_t dns_synth_response(const unsigned char* query, ssize_t qlen,
						   int rcode,
						   const synth_answer* answers, int nanswers,
						   unsigned char* out, size_t out_max);

#endif /* DNS_SYNTH_H */
