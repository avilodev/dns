#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include <stdbool.h>
#include <stdint.h>

/* Low-level walking of DNS wire messages. */

/* Offset just past the name at msg[pos] (pointers not followed), or -1. */
int dns_name_end(const uint8_t* msg, int len, int pos);

/* malloc'd presentation text of the name at msg[pos] (case kept), or NULL. */
char* dns_name_text(const uint8_t* msg, int len, int pos);

/* Offset just past the question section, or -1 if malformed. */
int dns_question_end(const uint8_t* msg, int len);

/* ---- Resource-record iterator ---------------------------------------- */

enum { SEC_ANSWER, SEC_AUTHORITY, SEC_ADDITIONAL };

typedef struct {
    int      owner;     /* offset of the owner name */
    uint16_t type, rclass;
    uint32_t ttl;
    uint16_t rdlen;
    int      rdata;     /* offset of the RDATA */
    int      section;   /* SEC_* */
} DnsRR;

typedef struct {
    const uint8_t* msg;
    int len, pos, idx, an, ns, total;
} RRIter;

/* Iterate every RR after the question, in order, using the header counts.
 *   RRIter it; DnsRR rr;
 *   for (rr_iter_init(&it, buf, len); rr_next(&it, &rr); ) ...
 * Stops at the first malformed or truncated record. */
bool rr_iter_init(RRIter* it, const void* msg, int len);
bool rr_next(RRIter* it, DnsRR* rr);

/* ---- EDNS OPT pseudo-RR ---------------------------------------------- */

#define OPT_RR_LEN 11

/* Write a bare OPT (root owner, our UDP size, DO mirrored, no options). */
void write_opt_rr(uint8_t* out, bool do_bit, uint8_t ext_rcode);

/* True if the message carries an OPT; *do_bit gets its DO flag. */
bool find_opt_rr(const uint8_t* msg, int len, bool* do_bit);

#endif /* DNS_WIRE_H */
