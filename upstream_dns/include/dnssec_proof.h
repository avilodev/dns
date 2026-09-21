#ifndef DNSSEC_PROOF_H
#define DNSSEC_PROOF_H

#include <stdint.h>

/* An (owner, type) RRset covered by a verified, in-bailiwick RRSIG. */
typedef struct {
    uint8_t  owner[256];      /* uncompressed, lowercased wire */
    int      owner_len;
    uint16_t type;
} ValidatedRR;

/* NSEC denial of existence (RFC 4034 §4) for (qname, qtype) from the
 * authority section: 1 proven, 0 contradicted, -1 no usable NSEC (NSEC3
 * hashing is not implemented). */
int verify_nsec_denial(const uint8_t *buf, int buf_len,
                       const uint8_t *qname_wire, int qname_len,
                       uint16_t qtype, int is_nxdomain);

/* 1 if `signer` is `owner` or a parent of it (label-aligned wire names). */
int wire_name_is_suffix(const uint8_t *owner, int owner_len,
                        const uint8_t *signer, int signer_len);

/* 1 if the RRset answering the question — following an in-packet CNAME
 * chain whose every hop is itself validated — is in `set` (RFC 4035 §5.3.2). */
int answer_is_validated(const uint8_t *buf, int buf_len, uint16_t qtype,
                        const ValidatedRR *set, int set_n);

#endif /* DNSSEC_PROOF_H */
