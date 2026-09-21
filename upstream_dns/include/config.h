#ifndef CONFIG_H
#define CONFIG_H

#include "types.h"

extern Config g_config;

/* Parse CLI flags into g_config.  Returns -1 on a bad flag. */
int load_config(int argc, char** argv);

/* ---- Listeners ------------------------------------------------------- */

/* Bound (and for TCP, listening) socket on -b or the wildcard.  Returns -1
 * when -b is the other family, or on failure (fatal=true exits instead). */
int create_listener(int family, int type, int port, bool fatal);

/* ---- Root hints (swapped atomically on SIGHUP) ------------------------ */

#define ROOT_SERVERS 13

int   load_hints(const char* filename);   /* count loaded, or -1 (kept old) */
int   load_hints_builtin(void);
char* hints_random_root_ip(void);         /* best-scored root IPv4, strdup'd */
int   hints_copy_names(char names[ROOT_SERVERS][256]);

/* ---- DNSSEC trust anchors -------------------------------------------- */

/* One root DNSKEY from root-trust-anchor.key. */
typedef struct TrustAnchor {
    char     owner[256];
    uint16_t flags;
    uint8_t  protocol;
    uint8_t  algorithm;
    uint8_t* pubkey;
    uint16_t pubkey_len;
    uint16_t key_tag;
    struct TrustAnchor* next;
} TrustAnchor;

extern TrustAnchor* g_trust_anchors;   /* NULL = validation disabled */

/* Parse "owner TTL IN DNSKEY flags proto alg base64" lines.  NULL if none. */
TrustAnchor* load_trust_anchors(const char* filename);
void free_trust_anchors(TrustAnchor* anchors);

#endif /* CONFIG_H */
