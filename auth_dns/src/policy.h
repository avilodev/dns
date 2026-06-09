#ifndef POLICY_H
#define POLICY_H

#include <stdint.h>
#include "dns_synth.h"   /* SynthAnswer */

/*
 * Local query policy for the auth server: a blocklist (ad/tracker/malware
 * suppression).  Consulted after the authoritative zones and before forwarding
 * to the upstream resolver, so auth owns all "local knowledge" and upstream
 * stays a clean recursor.
 *
 * Pure decision logic — no sockets.  The table is built at load and swapped
 * atomically behind an internal rwlock, so policy_lookup() is safe to call
 * concurrently and across a SIGHUP reload.
 */

typedef enum { POLICY_PASS = 0, POLICY_BLOCK } PolicyAction;

/*
 * Load blocked domains from the shared config file into a fresh table and
 * atomically swap it in.  Only the file's "[blocklist]" section is read; the
 * authoritative-zone sections are ignored here (auth.c parses those).  Accepted
 * line formats inside that section:
 *   - bare domain:   "ads.example.com"
 *   - hosts-format:  "0.0.0.0 ads.example.com"   (the leading IP is ignored)
 * '#' starts a comment; blank lines are skipped; names are lowercased.
 * A NULL path or unreadable file leaves an empty (pass-everything) table.
 * Returns the number of entries loaded (>= 0), or -1 on allocation failure
 * (in which case the active table is left unchanged).
 */
int policy_load(const char* config_path);

/*
 * Select how a blocked name is answered (affects future lookups only):
 *   NULL / "nxdomain"  -> NXDOMAIN, no answer record            [default]
 *   "zero"             -> sinkhole A=0.0.0.0 / AAAA=::
 *   "<ipv4|ipv6>"      -> sinkhole to that address
 */
void policy_set_block_mode(const char* mode);

/* RCODE for a BLOCK result: 3 (NXDOMAIN) or 0 (sinkhole modes). */
int policy_block_mode_rcode(void);

/*
 * Classify a query.  `out` is zeroed first, then filled with an answer RR when
 * one should be emitted (a sinkhole block of a matching qtype).
 * out->addrlen == 0 && out->qtype == 0 means "emit no answer" (NXDOMAIN, or
 * NODATA for a sinkhole that has no record for this qtype).
 * Match is a subtree test against the blocklist; otherwise PASS.
 */
PolicyAction policy_lookup(const char* qname, uint16_t qtype, SynthAnswer* out);

/* Number of queries blocked since startup (for SIGUSR2 stats). */
uint64_t policy_blocked_count(void);

#endif /* POLICY_H */
