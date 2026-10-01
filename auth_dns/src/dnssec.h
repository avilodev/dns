#ifndef DNSSEC_H
#define DNSSEC_H

// DNSSEC online signing for auth_dns.

#include "types.h"
#include "dnssec_types.h"

#include <openssl/evp.h>

// One zone signing key (KSK or ZSK).
typedef struct zone_key {
	uint16_t  flags;       // 257 = KSK, 256 = ZSK
	uint8_t   algorithm;
	EVP_PKEY* pkey;        // OpenSSL private key handle
	uint16_t  key_tag;     // RFC 4034 Appendix B key tag
	char      zone[256];   // zone apex this key belongs to, e.g. "example.com"
	struct zone_key* next;
} zone_key;

// Load zone signing keys listed in config_dir/dnssec.conf.
zone_key* load_zone_keys(const char* config_dir);
void free_zone_keys(zone_key* keys);

// Sign an RRset wire image with the given key.
int dnssec_sign_rrset(const zone_key* key,
					  const unsigned char* rrset, size_t rrset_len,
					  unsigned char** sig_out, size_t* sig_len);

// Extract the public key bytes in DNSKEY wire format
int dnssec_pubkey_rdata(const zone_key* key, unsigned char* out, size_t out_size);

#endif /* DNSSEC_H */
