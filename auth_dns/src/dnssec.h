#ifndef DNSSEC_H
#define DNSSEC_H

/*
 * DNSSEC online signing for auth_dns.
 *
 * Loads KSK and ZSK private keys from auth_dns/config/dnssec.conf and
 * signs RRsets on the fly using EVP_DigestSign per RFC 4034 §6.2.
 * RRSIG records are appended to responses only when the client sends
 * an EDNS OPT record with the DO bit set (RFC 4035 §3.2.1).
 *
 * Supported algorithms:
 *   8  = RSASHA256        (RFC 5702)
 *   13 = ECDSAP256SHA256  (RFC 6605)
 *   14 = ECDSAP384SHA384  (RFC 6605)
 *   15 = Ed25519          (RFC 8080)
 */

#include "types.h"
#include "dnssec_types.h"

#include <openssl/evp.h>

/* One zone signing key (KSK or ZSK). */
typedef struct ZoneKey {
    uint16_t  flags;       /* 257 = KSK, 256 = ZSK */
    uint8_t   algorithm;
    EVP_PKEY* pkey;        /* OpenSSL private key handle */
    uint16_t  key_tag;     /* RFC 4034 Appendix B key tag */
    char      zone[256];   /* zone apex this key belongs to, e.g. "avilo.com" */
    struct ZoneKey* next;
} ZoneKey;

/*
 * Load zone signing keys listed in config_dir/dnssec.conf.
 * Returns linked list (caller frees with free_zone_keys), or NULL.
 */
ZoneKey* load_zone_keys(const char* config_dir);
void free_zone_keys(ZoneKey* keys);

/*
 * Sign an RRset wire image with the given key.
 * On success, *sig_out is malloc'd and *sig_len is set.
 * Returns 0 on success, -1 on error.
 */
int dnssec_sign_rrset(const ZoneKey* key,
                      const unsigned char* rrset, size_t rrset_len,
                      unsigned char** sig_out, size_t* sig_len);

/*
 * Extract the public key bytes in DNSKEY wire format (the portion after
 * flags/protocol/algorithm, i.e. just the raw public key material).
 * out must be at least 600 bytes.  Returns byte count on success, -1 on error.
 */
int dnssec_pubkey_rdata(const ZoneKey* key, unsigned char* out, size_t out_size);

#endif /* DNSSEC_H */
