#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include "types.h"
#include "dnssec_types.h"

#define MAX_NAME_JUMPS 10

void skip_dns_name(unsigned char* buffer, int buffer_len, int* pos);
char* parse_dns_name_from_wire(unsigned char* buffer, int buffer_len, int pos);
int write_dns_name(const char* name, unsigned char* buffer, size_t buffer_size, size_t pos);
int encode_dns_name(const char* domain, unsigned char* buffer, size_t buf_size);

/*
 * DNSSEC wire-format parsers (RFC 4034, RFC 5155).
 * Each parser returns 0 on success, -1 on malformed input.
 * Caller must call the corresponding free_*_rdata() on success.
 */
int parse_dnskey_rdata(const unsigned char* rdata, int rdlength,
                       DnskeyRdata* out);
int parse_rrsig_rdata(const unsigned char* buf, int buf_len,
                      int rdata_offset, int rdlength,
                      RrsigRdata* out);
int parse_ds_rdata(const unsigned char* rdata, int rdlength,
                   DsRdata* out);
int parse_nsec3_rdata(const unsigned char* rdata, int rdlength,
                      Nsec3Rdata* out);

/*
 * Compute the key tag for a DNSKEY RR (RFC 4034 Appendix B).
 */
uint16_t compute_key_tag(uint16_t flags, uint8_t protocol, uint8_t algorithm,
                         const uint8_t* pubkey, uint16_t pubkey_len);

#endif /* DNS_WIRE_H */