#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>
#include <stddef.h>
#include "dns_synth.h"   // SynthAnswer

// Local query policy for the auth server: a blocklist.

typedef enum { POLICY_PASS = 0, POLICY_BLOCK } policy_action;

// Load blocked domains from the shared config file into a fresh table
int policy_load(const char* config_path);

// Select how a blocked name is answered (future lookups only)
int policy_set_block_mode(const char* mode);   // -1: unrecognised mode (NXDOMAIN used)

// RCODE for a BLOCK result: 3 (NXDOMAIN) or 0 (sinkhole modes).
int policy_block_mode_rcode(void);

// Classify a query; `out` is zeroed, then filled with an answer RR if due
policy_action policy_lookup(const char* qname, uint16_t qtype, synth_answer* out,
						   char* zone_out, size_t zone_cap);

// Number of queries blocked since startup (for SIGUSR1 stats).
uint64_t policy_blocked_count(void);

#endif /* POLICY_H */
