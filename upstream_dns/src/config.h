#ifndef CONFIG_H
#define CONFIG_H

#include "types.h"
#include "dnssec_types.h"

#include <ctype.h>

int load_config(int argc, char** argv);

/* Create an IPv4 UDP socket bound to port (exits on failure). */
int create_server_socket(int port);

/* Create an IPv6 UDP socket bound to port.  Returns -1 if IPv6 unavailable. */
int create_server_socket_v6(int port);

/* Create an IPv4 TCP listener bound to port.  Returns -1 on failure. */
int create_tcp_socket_v4(int port);

/* Create an IPv6 TCP listener bound to port.  Returns -1 if unavailable. */
int create_tcp_socket_v6(int port);

int load_hints(const char* filename);
int load_hints_builtin(void);
void free_hints(void);

/*
 * Trust anchor (DNSSEC root key) loaded from root-trust-anchor.key.
 * Each entry represents one DNSKEY record (typically the root KSK).
 */
typedef struct TrustAnchor {
    char     owner[256];     /* zone apex, e.g. "." */
    uint16_t flags;          /* DNSKEY flags (257 = KSK) */
    uint8_t  protocol;       /* always 3 */
    uint8_t  algorithm;      /* 8 = RSASHA256, etc. */
    uint8_t* pubkey;         /* DER-decoded public key bytes — malloc'd */
    uint16_t pubkey_len;
    uint16_t key_tag;        /* computed per RFC 4034 Appendix B */
    struct TrustAnchor* next;
} TrustAnchor;

/*
 * Load trust anchors from file (format: zone TTL IN DNSKEY flags proto algo b64key).
 * Returns a malloc'd linked list on success, NULL if file missing or no valid keys.
 * Caller frees with free_trust_anchors().
 */
TrustAnchor* load_trust_anchors(const char* filename);
void free_trust_anchors(TrustAnchor* anchors);

#endif /* CONFIG_H */
