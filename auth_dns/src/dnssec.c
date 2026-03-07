#include "dnssec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#  include <openssl/core_names.h>
#  include <openssl/param_build.h>
#else
#  include <openssl/rsa.h>
#  include <openssl/ec.h>
#endif

/* ==========================================================================
 * dnssec_pubkey_rdata
 *
 * Extracts the raw public key material portion of DNSKEY RDATA (the bytes
 * after flags/protocol/algorithm) for the given ZoneKey.  This is needed to:
 *   - Build DNSKEY answer RRs
 *   - Compute the key tag (RFC 4034 Appendix B)
 *
 * Algorithm-specific encoding:
 *   8/10 (RSA):   RFC 3110 — [exp_len(1 or 3)][exponent][modulus]
 *   13 (ECDSA P-256): X||Y (64 bytes, raw big-endian coordinates)
 *   14 (ECDSA P-384): X||Y (96 bytes)
 *   15 (Ed25519):  32 raw bytes
 *
 * Returns number of bytes written on success, -1 on error.
 * ========================================================================== */
int dnssec_pubkey_rdata(const ZoneKey *key, unsigned char *out, size_t out_size)
{
    if (!key || !key->pkey || !out || out_size < 4) return -1;

    switch (key->algorithm) {

    /* ---- Ed25519 ---- */
    case 15: {
        size_t pub_len = 32;
        if (out_size < 32) return -1;
        if (EVP_PKEY_get_raw_public_key(key->pkey, out, &pub_len) != 1) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        return (int)pub_len;
    }

    /* ---- ECDSA P-256 / P-384 ---- */
    case 13:
    case 14: {
        int coord_len = (key->algorithm == 13) ? 32 : 48;
        if (out_size < (size_t)(2 * coord_len)) return -1;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        size_t pt_len = 0;
        /* EVP_PKEY_get_octet_string_param returns uncompressed point: 0x04||X||Y */
        if (EVP_PKEY_get_octet_string_param(key->pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                            NULL, 0, &pt_len) != 1)
            return -1;
        unsigned char *pt = malloc(pt_len);
        if (!pt) return -1;
        if (EVP_PKEY_get_octet_string_param(key->pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                            pt, pt_len, &pt_len) != 1) {
            free(pt); return -1;
        }
        /* Strip leading 0x04 uncompressed-point marker */
        if (pt_len < 1 || pt[0] != 0x04) { free(pt); return -1; }
        memcpy(out, pt + 1, (size_t)(2 * coord_len));
        free(pt);
#else
        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key->pkey);
        if (!ec) return -1;
        const EC_GROUP *grp = EC_KEY_get0_group(ec);
        const EC_POINT *pub = EC_KEY_get0_public_key(ec);
        size_t pt_len = EC_POINT_point2oct(grp, pub,
                                           POINT_CONVERSION_UNCOMPRESSED,
                                           NULL, 0, NULL);
        unsigned char *pt = malloc(pt_len);
        if (!pt) return -1;
        EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                           pt, pt_len, NULL);
        if (pt_len < 1 || pt[0] != 0x04) { free(pt); return -1; }
        memcpy(out, pt + 1, (size_t)(2 * coord_len));
        free(pt);
#endif
        return 2 * coord_len;
    }

    /* ---- RSA (alg 8 = RSASHA256, 10 = RSASHA512) ---- */
    case 8:
    case 10: {
        BIGNUM *n = NULL, *e = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
            EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
            BN_free(n); BN_free(e); return -1;
        }
#else
        RSA *rsa = EVP_PKEY_get0_RSA(key->pkey);
        if (!rsa) return -1;
        const BIGNUM *cn, *ce;
        RSA_get0_key(rsa, &cn, &ce, NULL);
        n = BN_dup(cn);
        e = BN_dup(ce);
        if (!n || !e) { BN_free(n); BN_free(e); return -1; }
#endif
        int exp_len = BN_num_bytes(e);
        int mod_len = BN_num_bytes(n);
        int need = (exp_len < 256 ? 1 : 3) + exp_len + mod_len;
        if (need < 0 || (size_t)need > out_size) {
            BN_free(n); BN_free(e); return -1;
        }
        int pos = 0;
        if (exp_len < 256) {
            out[pos++] = (unsigned char)exp_len;
        } else {
            out[pos++] = 0;
            out[pos++] = (unsigned char)(exp_len >> 8);
            out[pos++] = (unsigned char)(exp_len & 0xFF);
        }
        BN_bn2bin(e, out + pos); pos += exp_len;
        BN_bn2bin(n, out + pos); pos += mod_len;
        BN_free(n); BN_free(e);
        return pos;
    }

    default:
        return -1;
    }
}

/* ==========================================================================
 * keytag_compute — RFC 4034 Appendix B
 * Input: full DNSKEY RDATA wire bytes (flags + protocol + alg + pubkey).
 * ========================================================================== */
static uint16_t keytag_compute(const unsigned char *rdata, size_t rdlen)
{
    unsigned long ac = 0;
    for (size_t i = 0; i < rdlen; i++)
        ac += (i & 1) ? rdata[i] : (unsigned long)rdata[i] << 8;
    ac += (ac >> 16) & 0xFFFFUL;
    return (uint16_t)(ac & 0xFFFFUL);
}

/* ==========================================================================
 * load_zone_keys
 *
 * Parses config_dir/dnssec.conf (INI format):
 *
 *   [zone.name]
 *   ksk_algorithm = <n>
 *   ksk_file      = /path/to/ksk.pem
 *   zsk_algorithm = <n>
 *   zsk_file      = /path/to/zsk.pem
 *
 * For each key file found, loads the PEM private key, computes the key tag,
 * and appends a ZoneKey to the returned linked list.
 * Returns NULL if no keys could be loaded.
 * ========================================================================== */

static void flush_key(const char *path, const char *config_dir,
                      uint8_t algorithm, uint16_t flags,
                      const char *zone,
                      ZoneKey **head, ZoneKey **tail)
{
    if (!path || path[0] == '\0' || algorithm == 0) return;

    /* Support relative paths: resolve them against config_dir. */
    char resolved[512];
    if (path[0] != '/' && config_dir) {
        snprintf(resolved, sizeof(resolved), "%s/%s", config_dir, path);
        path = resolved;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "DNSSEC: cannot open key file %s: ", path);
        perror("");
        return;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "DNSSEC: failed to load private key from %s\n", path);
        ERR_print_errors_fp(stderr);
        return;
    }

    ZoneKey *zk = calloc(1, sizeof(ZoneKey));
    if (!zk) {
        EVP_PKEY_free(pkey);
        return;
    }
    zk->flags     = flags;
    zk->algorithm = algorithm;
    zk->pkey      = pkey;
    if (zone) snprintf(zk->zone, sizeof(zk->zone), "%s", zone);

    /* Compute RFC 4034 Appendix B key tag from DNSKEY RDATA */
    {
        unsigned char rdata[600];
        size_t rdata_pos = 0;
        *(uint16_t*)(rdata + rdata_pos) = htons(flags);   rdata_pos += 2;
        rdata[rdata_pos++] = 3;           /* protocol = 3 */
        rdata[rdata_pos++] = algorithm;
        int pub_len = dnssec_pubkey_rdata(zk, rdata + rdata_pos,
                                          sizeof(rdata) - rdata_pos);
        if (pub_len > 0) {
            rdata_pos += (size_t)pub_len;
            zk->key_tag = keytag_compute(rdata, rdata_pos);
        }
    }

    if (!*head) {
        *head = *tail = zk;
    } else {
        (*tail)->next = zk;
        *tail = zk;
    }
    printf("DNSSEC: loaded %s for zone '%s' from %s (alg=%u tag=%u)\n",
           flags == 257 ? "KSK" : "ZSK",
           zone ? zone : "?", path, algorithm, zk->key_tag);
}

ZoneKey *load_zone_keys(const char *config_dir)
{
    if (!config_dir) return NULL;

    char conf_path[512];
    snprintf(conf_path, sizeof(conf_path), "%s/dnssec.conf", config_dir);

    FILE *fp = fopen(conf_path, "r");
    if (!fp) {
        fprintf(stderr, "DNSSEC: no dnssec.conf in %s"
                " — online signing disabled\n", config_dir);
        return NULL;
    }

    ZoneKey *head = NULL, *tail = NULL;
    char    line[512];
    uint8_t cur_ksk_alg = 0, cur_zsk_alg = 0;
    char    cur_ksk_file[256] = {0};
    char    cur_zsk_file[256] = {0};
    char    cur_zone[256]     = {0};

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        int len = (int)strlen(p);
        while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r'
                           || p[len-1] == ' '))
            p[--len] = '\0';

        if (*p == '\0' || *p == '#' || *p == ';') continue;

        if (*p == '[') {
            /* Flush accumulated keys for the previous zone */
            flush_key(cur_ksk_file, config_dir, cur_ksk_alg, 257, cur_zone, &head, &tail);
            flush_key(cur_zsk_file, config_dir, cur_zsk_alg, 256, cur_zone, &head, &tail);
            cur_ksk_alg = cur_zsk_alg = 0;
            cur_ksk_file[0] = cur_zsk_file[0] = '\0';
            /* Extract zone name between '[' and ']' */
            char *close = strchr(p, ']');
            if (close && close > p + 1) {
                size_t zlen = (size_t)(close - p - 1);
                if (zlen >= sizeof(cur_zone)) zlen = sizeof(cur_zone) - 1;
                memcpy(cur_zone, p + 1, zlen);
                cur_zone[zlen] = '\0';
            } else {
                cur_zone[0] = '\0';
            }
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) continue;

        int klen = (int)(eq - p);
        while (klen > 0 && (p[klen-1] == ' ' || p[klen-1] == '\t')) klen--;
        if (klen <= 0 || klen >= 64) continue;

        char key[64];
        memcpy(key, p, (size_t)klen);
        key[klen] = '\0';

        char *v = eq + 1;
        while (*v == ' ' || *v == '\t') v++;
        char val[256];
        snprintf(val, sizeof(val), "%s", v);

        if (strcmp(key, "ksk_algorithm") == 0) {
            cur_ksk_alg = (uint8_t)atoi(val);
        } else if (strcmp(key, "zsk_algorithm") == 0) {
            cur_zsk_alg = (uint8_t)atoi(val);
        } else if (strcmp(key, "ksk_file") == 0) {
            snprintf(cur_ksk_file, sizeof(cur_ksk_file), "%s", val);
        } else if (strcmp(key, "zsk_file") == 0) {
            snprintf(cur_zsk_file, sizeof(cur_zsk_file), "%s", val);
        }
    }
    fclose(fp);

    /* Flush the last zone's keys */
    flush_key(cur_ksk_file, config_dir, cur_ksk_alg, 257, cur_zone, &head, &tail);
    flush_key(cur_zsk_file, config_dir, cur_zsk_alg, 256, cur_zone, &head, &tail);

    if (!head)
        fprintf(stderr, "DNSSEC: no signing keys loaded from %s\n", conf_path);

    return head;
}

void free_zone_keys(ZoneKey *keys)
{
    while (keys) {
        ZoneKey *next = keys->next;
        if (keys->pkey) EVP_PKEY_free(keys->pkey);
        free(keys);
        keys = next;
    }
}

/* ==========================================================================
 * dnssec_sign_rrset
 *
 * Signs the pre-built canonical signed-data buffer (RRSIG header ||
 * canonical sorted RRset, per RFC 4034 §6.2) with the given private key.
 *
 * For ECDSA algorithms (13/14), OpenSSL produces DER-encoded (r,s); the
 * function converts this to the raw (r || s) wire format required by DNS.
 *
 * On success: *sig_out is malloc'd, *sig_len is set, returns 0.
 * On failure: returns -1.
 * ========================================================================== */

int dnssec_sign_rrset(const ZoneKey *key,
                      const unsigned char *rrset, size_t rrset_len,
                      unsigned char **sig_out, size_t *sig_len)
{
    if (!key || !key->pkey || !rrset || rrset_len == 0
            || !sig_out || !sig_len)
        return -1;

    const EVP_MD *md = NULL;
    switch (key->algorithm) {
    case 8:  md = EVP_sha256(); break;
    case 10: md = EVP_sha512(); break;
    case 13: md = EVP_sha256(); break;
    case 14: md = EVP_sha384(); break;
    case 15: md = NULL;         break;   /* Ed25519: implicit digest */
    default:
        fprintf(stderr, "DNSSEC: unsupported signing algorithm %u\n",
                key->algorithm);
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key->pkey) != 1 ||
        EVP_DigestSignUpdate(ctx, rrset, rrset_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    size_t raw_len = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &raw_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned char *raw = malloc(raw_len);
    if (!raw) { EVP_MD_CTX_free(ctx); return -1; }

    if (EVP_DigestSignFinal(ctx, raw, &raw_len) != 1) {
        ERR_print_errors_fp(stderr);
        free(raw); EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    /* ECDSA (alg 13/14): OpenSSL returns DER (r,s); DNS wire wants raw r||s */
    if (key->algorithm == 13 || key->algorithm == 14) {
        int coord_len = (key->algorithm == 13) ? 32 : 48;
        const unsigned char *der_p = raw;
        ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &der_p, (long)raw_len);
        free(raw);
        if (!esig) return -1;

        const BIGNUM *r, *s;
        ECDSA_SIG_get0(esig, &r, &s);

        unsigned char *wire = calloc(1, (size_t)(2 * coord_len));
        if (!wire) { ECDSA_SIG_free(esig); return -1; }
        BN_bn2binpad(r, wire,             coord_len);
        BN_bn2binpad(s, wire + coord_len, coord_len);
        ECDSA_SIG_free(esig);

        *sig_out = wire;
        *sig_len = (size_t)(2 * coord_len);
        return 0;
    }

    *sig_out = raw;
    *sig_len = raw_len;
    return 0;
}
