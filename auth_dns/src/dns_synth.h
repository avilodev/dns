#ifndef DNS_SYNTH_H
#define DNS_SYNTH_H

#include <stdint.h>
#include <stddef.h>     /* size_t  */
#include <sys/types.h>  /* ssize_t */

/*
 * Synthesized DNS responses (locally-generated answers: blocklist refusals and
 * local-zone overrides).  Pure wire construction — no allocation, no sockets,
 * and no dependency on any other module (self-contained name encoder), so it
 * drops unchanged into any server.
 *
 * The owner of every synthesized answer RR is the query's own QNAME, emitted as
 * a compression pointer to offset 12 (0xC00C), so only the type/rdata/ttl vary.
 */

/* One answer RR to emit. */
typedef struct {
    uint16_t qtype;       /* 1 = A, 28 = AAAA, 5 = CNAME                         */
    uint8_t  addr[16];    /* network-order address; first addrlen bytes used     */
    int      addrlen;     /* 4 for A, 16 for AAAA, 0 for CNAME                    */
    char     cname[256];  /* presentation-form target when qtype == CNAME        */
    uint32_t ttl;         /* RR TTL in seconds                                   */
} SynthAnswer;

/*
 * Build a response to `query` (a well-formed query, `qlen` bytes) into `out`.
 *
 * The question section is echoed verbatim; the header is rewritten to:
 *   QR=1, AA=0, TC=0, RA=1, opcode + RD echoed from the query, RCODE = `rcode`.
 * QDCOUNT stays 1, ANCOUNT = `nanswers`, NSCOUNT = ARCOUNT = 0 (any OPT/EDNS in
 * the query's additional section is intentionally not echoed).
 *
 * Returns the response length in bytes, or -1 on bad input or insufficient room.
 */
ssize_t dns_synth_response(const unsigned char* query, ssize_t qlen,
                           int rcode,
                           const SynthAnswer* answers, int nanswers,
                           unsigned char* out, size_t out_max);

#endif /* DNS_SYNTH_H */
