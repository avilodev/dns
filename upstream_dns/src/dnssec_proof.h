#ifndef DNSSEC_PROOF_H
#define DNSSEC_PROOF_H

#include <stdint.h>

/* One validated (owner, type) pair recorded during the RRSIG loop. */
typedef struct {
    uint8_t  owner[256];
    int      owner_len;       /* uncompressed, lowercased wire length */
    uint16_t type;            /* the RRSIG's type_covered */
} ValidatedRR;

/* NSEC / NSEC3 denial-of-existence proof verification (RFC 4034 §4, RFC 5155). */
int verify_nsec_denial(const uint8_t *buf, int buf_len,
                       const uint8_t *qname_wire, int qname_len,
                       uint16_t qtype, int is_nxdomain,
                       int ns_start, int nscount);

/* Answer-coverage helpers (RFC 4035 §5.3.2): the AD bit may be set only when
 * the RRset that answers the question is itself covered by a verified RRSIG. */
int wire_name_is_suffix(const uint8_t *owner, int owner_len,
                        const uint8_t *signer, int signer_len);
int dns_skip_questions(const uint8_t *buf, int buf_len, int qdcount);
int dns_skip_rrs(const uint8_t *buf, int buf_len, int pos, int count);
int section_has_type(const uint8_t *buf, int buf_len, int pos,
                     int count, uint16_t want_type);
uint16_t question_qtype(const uint8_t *buf, int buf_len);
int answer_is_validated(const uint8_t *buf, int buf_len,
                        int qdcount, int ancount, uint16_t qtype,
                        const ValidatedRR *set, int set_n);

#endif /* DNSSEC_PROOF_H */
