#include "auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>

#include "types.h"   /* MAX_INTERNAL_HOSTS, DEFAULT_RECORD_TTL */

/* The authoritative record store. Defined here (loading owns it); the serving
 * path (check_internal in auth.c) reads it via the extern decls in auth.h.
 * Both sides synchronize on g_auth_domains_lock. */
struct AuthDomain auth_domains[MAX_INTERNAL_HOSTS];
int auth_domain_count = 0;

/* =========================================================================
 * Domain file loader
 * ========================================================================= */

/* Lowercase a NUL-terminated string in place. */
static void strlower(char *s)
{
    if (!s) return;
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/*
 * _load_domains_from_file — parse the [domain] sections of config.txt under
 * wrlock.  The [blocklist] section is skipped here (policy.c owns it).
 *
 * Supported record types (second token determines type):
 *   SOA    — domain SOA mname rname serial refresh retry expire minimum
 *   NS     — domain NS nameserver
 *   MX     — domain MX priority hostname
 *   CNAME  — domain CNAME target
 *   TXT    — domain TXT rest-of-line  (quoted or unquoted)
 *   SRV    — domain SRV priority weight port target
 *   IPv6   — domain 2001:db8::1   (detected by ':' in token)
 *   IPv4   — domain 192.168.1.1   (default, validated)
 *
 * Wildcard: if the domain starts with '*' it is stored verbatim
 *           (e.g. "*.avilo.com") and marked is_wildcard = true.
 *
 * Returns number of records loaded, or -1 on I/O error.
 */
static int _load_domains_from_file(const char *filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n",
                filename, strerror(errno));
        return -1;
    }

    int  count               = 0;
    char line[1024];
    char current_domain[256] = {0};  /* set by [domain] section headers */

    while (fgets(line, sizeof(line), fp)) {
        /* Strip trailing whitespace / newline. */
        int llen = (int)strlen(line);
        while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r' ||
                            line[llen-1] == ' '  || line[llen-1] == '\t'))
            line[--llen] = '\0';

        if (llen == 0 || line[0] == '#') continue;

        /* --- Section header: [domain.name] -------------------------------- */
        if (line[0] == '[') {
            char *close = strchr(line, ']');
            if (close && close > line + 1) {
                size_t dlen = (size_t)(close - line - 1);
                if (dlen >= sizeof(current_domain))
                    dlen = sizeof(current_domain) - 1;
                memcpy(current_domain, line + 1, dlen);
                current_domain[dlen] = '\0';
                strlower(current_domain);
            }
            continue;
        }

        /* Ignore record lines that appear before any [domain] header. */
        if (current_domain[0] == '\0') continue;

        /* The [blocklist] section is owned by policy.c, not the zone loader. */
        if (strcasecmp(current_domain, "blocklist") == 0) continue;

        if (count >= MAX_INTERNAL_HOSTS) {
            fprintf(stderr,
                    "Warning: auth_domains limit (%d) reached; skipping rest\n",
                    MAX_INTERNAL_HOSTS);
            break;
        }

        char type_kw[64] = {0};
        if (sscanf(line, "%63s", type_kw) < 1) continue;

        bool is_wc = (current_domain[0] == '*');

        struct AuthDomain *d = &auth_domains[count];
        memset(d, 0, sizeof(*d));
        snprintf(d->domain, sizeof(d->domain), "%s", current_domain);
        d->is_wildcard = is_wc;

        /* --- SOA -------------------------------------------------------- */
        if (strcasecmp(type_kw, "SOA") == 0) {
            char mname[256] = {0}, rname[256] = {0};
            unsigned int serial = 0, refresh = 0, retry = 0,
                         expire = 0, minimum = 0;
            if (sscanf(line, "%*s %255s %255s %u %u %u %u %u",
                       mname, rname,
                       &serial, &refresh, &retry, &expire, &minimum) != 7) {
                fprintf(stderr, "Warning: Bad SOA line: %s\n", line);
                continue;
            }
            strlower(mname); strlower(rname);
            d->has_soa     = true;
            snprintf(d->soa_mname, sizeof(d->soa_mname), "%s", mname);
            snprintf(d->soa_rname, sizeof(d->soa_rname), "%s", rname);
            d->soa_serial  = serial;
            d->soa_refresh = refresh;
            d->soa_retry   = retry;
            d->soa_expire  = expire;
            d->soa_minimum = minimum;
            d->soa_ttl     = refresh;   /* default TTL = refresh interval */
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> SOA serial=%u\n",
                    current_domain, serial);
            count++;

        /* --- NS --------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "NS") == 0) {
            char ns[256] = {0};
            if (sscanf(line, "%*s %255s", ns) != 1) {
                fprintf(stderr, "Warning: Bad NS line: %s\n", line);
                continue;
            }
            strlower(ns);
            d->has_ns = true;
            snprintf(d->ns_name, sizeof(d->ns_name), "%s", ns);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> NS %s\n", current_domain, ns);
            count++;

        /* --- MX --------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "MX") == 0) {
            unsigned int prio = 0;
            char mx_host[256] = {0};
            if (sscanf(line, "%*s %u %255s", &prio, mx_host) != 2) {
                fprintf(stderr, "Warning: Bad MX line: %s\n", line);
                continue;
            }
            strlower(mx_host);
            d->has_mx      = true;
            d->mx_priority = (uint16_t)prio;
            snprintf(d->mx_hostname, sizeof(d->mx_hostname), "%s", mx_host);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> MX %u %s\n",
                    current_domain, prio, mx_host);
            count++;

        /* --- CNAME ------------------------------------------------------ */
        } else if (strcasecmp(type_kw, "CNAME") == 0) {
            char target[256] = {0};
            if (sscanf(line, "%*s %255s", target) != 1) {
                fprintf(stderr, "Warning: Bad CNAME line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_cname = true;
            snprintf(d->cname_target, sizeof(d->cname_target), "%s", target);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> CNAME %s\n",
                    current_domain, target);
            count++;

        /* --- TXT -------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "TXT") == 0) {
            /* Advance past the "TXT" keyword to the text content. */
            const char *p = line;
            while (*p && !isspace((unsigned char)*p)) p++;
            while (*p &&  isspace((unsigned char)*p)) p++;
            /* p now points to the text data (possibly quoted) */
            if (*p == '"') p++;
            char txt[512];
            snprintf(txt, sizeof(txt), "%s", p);
            int tlen = (int)strlen(txt);
            if (tlen > 0 && txt[tlen - 1] == '"') txt[--tlen] = '\0';
            d->has_txt = true;
            snprintf(d->txt_data, sizeof(d->txt_data), "%s", txt);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> TXT \"%s\"\n",
                    current_domain, txt);
            count++;

        /* --- SRV -------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "SRV") == 0) {
            unsigned int prio = 0, weight = 0, port = 0;
            char target[256] = {0};
            if (sscanf(line, "%*s %u %u %u %255s",
                       &prio, &weight, &port, target) != 4) {
                fprintf(stderr, "Warning: Bad SRV line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_srv      = true;
            d->srv_priority = (uint16_t)prio;
            d->srv_weight   = (uint16_t)weight;
            d->srv_port     = (uint16_t)port;
            snprintf(d->srv_target, sizeof(d->srv_target), "%s", target);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> SRV %u %u %u %s\n",
                    current_domain, prio, weight, port, target);
            count++;

        /* --- HTTPS (RFC 9460) ------------------------------------------- */
        } else if (strcasecmp(type_kw, "HTTPS") == 0) {
            unsigned int prio = 0;
            char target[256] = {0};
            if (sscanf(line, "%*s %u %255s", &prio, target) != 2) {
                fprintf(stderr, "Warning: Bad HTTPS line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_https      = true;
            d->https_priority = (uint16_t)prio;
            snprintf(d->https_target, sizeof(d->https_target), "%s", target);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> HTTPS %u %s\n",
                    current_domain, prio, target);
            count++;

        /* --- AAAA ------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "AAAA") == 0) {
            char ip6[64] = {0};
            if (sscanf(line, "%*s %63s", ip6) != 1) {
                fprintf(stderr, "Warning: Bad AAAA line: %s\n", line);
                continue;
            }
            struct in6_addr ia6;
            if (inet_pton(AF_INET6, ip6, &ia6) != 1) {
                fprintf(stderr, "Warning: Invalid IPv6 '%s' for '%s'\n",
                        ip6, current_domain);
                continue;
            }
            d->has_ipv6 = true;
            snprintf(d->ipv6, sizeof(d->ipv6), "%s", ip6);
            strcpy(d->ip, "0.0.0.0");
            fprintf(stderr, "  Loaded: %-32s -> %s (AAAA)\n",
                    current_domain, ip6);
            count++;

        /* --- A ---------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "A") == 0) {
            char ip4[20] = {0};
            if (sscanf(line, "%*s %19s", ip4) != 1) {
                fprintf(stderr, "Warning: Bad A line: %s\n", line);
                continue;
            }
            struct in_addr ia;
            if (inet_pton(AF_INET, ip4, &ia) != 1) {
                fprintf(stderr, "Warning: Invalid IPv4 '%s' for '%s'\n",
                        ip4, current_domain);
                continue;
            }
            snprintf(d->ip, sizeof(d->ip), "%s", ip4);
            fprintf(stderr, "  Loaded: %-32s -> %s\n", current_domain, ip4);
            count++;

        } else {
            fprintf(stderr, "Warning: Unknown record type '%s' for [%s]\n",
                    type_kw, current_domain);
            continue;
        }
    }

    fclose(fp);
    return count;
}

/* ---- Public load / reload / lookup ------------------------------------- */

int load_auth_domains(const char *filename)
{
    if (!filename) return -1;

    pthread_rwlock_wrlock(&g_auth_domains_lock);
    auth_domain_count = 0;
    int n = _load_domains_from_file(filename);
    if (n > 0) auth_domain_count = n;
    pthread_rwlock_unlock(&g_auth_domains_lock);

    if (n <= 0) {
        fprintf(stderr,
                "Warning: No valid domains loaded from %s\n", filename);
        return (n == 0) ? 0 : -1;
    }
    fprintf(stderr, "Loaded %d authoritative record(s)\n\n", n);
    return n;
}

void reload_auth_domains(const char *filename)
{
    if (!filename) return;

    pthread_rwlock_wrlock(&g_auth_domains_lock);

    /* Save old SOA serial before overwriting (RFC 1982 — serial must increase). */
    uint32_t old_serial = 0;
    for (int i = 0; i < auth_domain_count; i++) {
        if (auth_domains[i].has_soa) {
            old_serial = auth_domains[i].soa_serial;
            break;
        }
    }

    int old_count = auth_domain_count;
    auth_domain_count = 0;
    int n = _load_domains_from_file(filename);
    if (n > 0) {
        auth_domain_count = n;
        fprintf(stderr,
                "SIGHUP: reloaded %d record(s) (was %d)\n", n, old_count);

        /* Warn if SOA serial did not increase (RFC 1982). */
        if (old_serial > 0) {
            for (int i = 0; i < auth_domain_count; i++) {
                if (auth_domains[i].has_soa) {
                    uint32_t new_serial = auth_domains[i].soa_serial;
                    if (new_serial <= old_serial)
                        fprintf(stderr,
                                "Warning: SOA serial %u <= old serial %u "
                                "— secondaries may not detect the update (RFC 1982)\n",
                                new_serial, old_serial);
                    break;
                }
            }
        }
    } else {
        auth_domain_count = old_count;   /* keep existing data on error */
        fprintf(stderr,
                "SIGHUP: reload failed; keeping %d existing record(s)\n",
                old_count);
    }
    pthread_rwlock_unlock(&g_auth_domains_lock);
}

/*
 * lookup_auth_domain — thread-safe A-record lookup (used by external callers).
 * Returns IP string, or NULL if not found.
 */
const char *lookup_auth_domain(const char *full_domain)
{
    if (!full_domain) return NULL;

    pthread_rwlock_rdlock(&g_auth_domains_lock);
    const char *result = NULL;

    for (int i = 0; i < auth_domain_count; i++) {
        const struct AuthDomain *d = &auth_domains[i];
        /* Skip non-A entries */
        if (d->has_mx || d->has_ipv6 || d->has_cname ||
            d->has_ns || d->has_txt || d->has_srv || d->has_soa)
            continue;
        if (strcmp(d->domain, full_domain) != 0) continue;
        result = d->ip;
        break;
    }

    pthread_rwlock_unlock(&g_auth_domains_lock);
    return result;
}
