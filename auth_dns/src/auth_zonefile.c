#include "auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>

#include "types.h"   /* MAX_INTERNAL_HOSTS, DEFAULT_RECORD_TTL */
#include "utils.h"   /* path_fopen */
#include "dns_name.h" /* dname_to_wire (name validation) */
#include "auth_lookup.h" /* auth_index_build */

/* The authoritative record store. Defined here (loading owns it); the serving
 * path (check_internal in auth.c) reads it via the extern decls in auth.h.
 * Both sides synchronize on g_auth_domains_lock. */
struct AuthDomain *auth_domains = NULL;
int auth_domain_count = 0;

/* =========================================================================
 * Domain file loader
 * ========================================================================= */

/* True if `name` is a well-formed domain name (escapes allowed). */
static bool valid_name(const char *name)
{
    uint8_t wire[256];
    return name && *name && dname_to_wire(name, wire, sizeof(wire)) > 0;
}

/* Lowercase a NUL-terminated string in place. */
static void strlower(char *s)
{
    if (!s) return;
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/*
 * Parse TXT presentation data into RDATA (RFC 1035 §3.3.14, §5.1).
 *
 *   "v=spf1 mx -all"             -> one character-string
 *   "v=DKIM1; k=rsa; " "p=MIIB"  -> two character-strings (DKIM style)
 *   bare words                   -> the rest of the line as one string
 *
 * Inside quotes, \" and \\ escape a quote / backslash.  Any string longer than
 * 255 bytes is split into consecutive 255-byte character-strings.  Returns 0 on
 * success, -1 on an unterminated quote or overflow.
 */
static int append_charstrings(const char *txt, size_t n,
                              unsigned char *out, size_t cap, uint16_t *len)
{
    do {
        size_t chunk = n > 255 ? 255 : n;
        if (*len + 1 + chunk > cap) return -1;
        out[(*len)++] = (unsigned char)chunk;
        memcpy(out + *len, txt, chunk);
        *len += (uint16_t)chunk;
        txt += chunk; n -= chunk;
    } while (n > 0);
    return 0;
}

static int parse_txt_rdata(const char *p, unsigned char *out, size_t cap,
                           uint16_t *out_len)
{
    *out_len = 0;
    if (*p != '"') {                               /* unquoted: whole rest of line */
        return append_charstrings(p, strlen(p), out, cap, out_len);
    }
    while (*p) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p != '"') return -1;                  /* junk between strings */
        p++;
        char buf[512];
        size_t n = 0;
        while (*p && *p != '"') {
            if (*p == '\\' && (p[1] == '"' || p[1] == '\\')) p++;
            if (n >= sizeof(buf)) return -1;
            buf[n++] = *p++;
        }
        if (*p != '"') return -1;                  /* unterminated */
        p++;
        if (append_charstrings(buf, n, out, cap, out_len) != 0) return -1;
    }
    return *out_len ? 0 : -1;
}

/* Cut a '#' comment that starts a line or follows whitespace, ignoring any
 * '#' inside a quoted TXT string ("\"" escapes a quote). */
static void strip_inline_comment(char *line)
{
    bool quoted = false;
    for (char *p = line; *p; p++) {
        if (quoted && *p == '\\' && p[1]) { p++; continue; }
        if (*p == '"') quoted = !quoted;
        else if (*p == '#' && !quoted &&
                 (p == line || isspace((unsigned char)p[-1]))) { *p = '\0'; return; }
    }
}

/*
 * _load_domains_from_file — parse the [domain] sections of config.txt into a
 * heap array that grows as needed (*out, *cap; caller frees).  No lock is taken: callers parse into a private table and only
 * swap it in (under the wrlock) once the whole file has been read.  The
 * [blocklist] section is skipped here (policy.c owns it).
 *
 * Record lines under a [name] header, with an optional leading TTL
 * (e.g. "300 A 192.168.1.2"; default DEFAULT_RECORD_TTL):
 *   SOA    — SOA mname rname serial refresh retry expire minimum
 *   NS     — NS nameserver
 *   MX     — MX priority hostname
 *   CNAME  — CNAME target
 *   TXT    — TXT rest-of-line  (quoted or unquoted)
 *   SRV    — SRV priority weight port target
 *   HTTPS  — HTTPS priority target
 *   AAAA   — AAAA 2001:db8::1
 *   A      — A 192.168.1.1
 * Names are validated; 16-bit fields out of range reject the line; a CNAME
 * that shares its owner with other data is dropped (RFC 1034 §3.6.2).
 *
 * Wildcard: if the domain starts with '*' it is stored verbatim
 *           (e.g. "*.avilo.com") and marked is_wildcard = true.
 *
 * Returns number of records loaded, or -1 on I/O error.
 */
static int _load_domains_from_file(const char *filename,
                                  struct AuthDomain **outp, int *capp)
{
    FILE *fp = path_fopen(filename);
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s: %s\n",
                filename, strerror(errno));
        return -1;
    }

    int  count               = 0;
    char line[1024];
    char current_domain[256] = {0};  /* set by [domain] section headers (AuthDomain.domain size) */

    while (fgets(line, sizeof(line), fp)) {
        /* A line longer than the buffer arrives in pieces; parsing the tail as
         * a record of its own would attribute garbage to the current section.
         * Drop the remainder, and if the over-long line was a [section] header
         * we never saw its ']' — so stop trusting current_domain too. */
        size_t raw = strlen(line);
        if (raw > 0 && line[raw - 1] != '\n' && !feof(fp)) {
            fprintf(stderr, "Warning: over-long line, skipping: %.40s...\n", line);
            int c;
            while ((c = fgetc(fp)) != EOF && c != '\n') { }
            if (line[0] == '[') current_domain[0] = '\0';
            continue;
        }

        strip_inline_comment(line);

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
                uint8_t wire[256];
                if (dlen >= sizeof(current_domain)) {
                    fprintf(stderr, "Warning: section name too long, skipping: %.40s...\n",
                            line + 1);
                    current_domain[0] = '\0';          /* skip its records */
                    continue;
                }
                memcpy(current_domain, line + 1, dlen);
                current_domain[dlen] = '\0';
                if (strcasecmp(current_domain, "blocklist") != 0 &&
                    dname_to_wire(current_domain, wire, sizeof(wire)) < 0) {
                    fprintf(stderr, "Warning: invalid name [%s], skipping its records\n",
                            current_domain);
                    current_domain[0] = '\0';
                    continue;
                }
                strlower(current_domain);
            } else {
                /* "[]", or a '[' line with no ']': we do not know what section
                 * we are in, so skip its records instead of silently filing
                 * them under whatever section came before. */
                fprintf(stderr, "Warning: malformed section header, "
                                "skipping its records: %.40s\n", line);
                current_domain[0] = '\0';
            }
            continue;
        }

        /* Ignore record lines that appear before any [domain] header. */
        if (current_domain[0] == '\0') continue;

        /* The [blocklist] section is owned by policy.c, not the zone loader. */
        if (strcasecmp(current_domain, "blocklist") == 0) continue;

        if (count >= *capp) {                          /* grow geometrically */
            int ncap = *capp ? *capp * 2 : 256;
            struct AuthDomain *grown = realloc(*outp, (size_t)ncap * sizeof(**outp));
            if (!grown) {
                fprintf(stderr, "Error: out of memory loading %s\n", filename);
                fclose(fp);
                return -1;
            }
            *outp = grown;
            *capp = ncap;
        }
        struct AuthDomain *out = *outp;

        /* Optional leading TTL: "300 A 1.2.3.4". */
        char *rec = line;
        while (*rec == ' ' || *rec == '\t') rec++;
        uint32_t rr_ttl = 0;
        if (isdigit((unsigned char)*rec)) {
            char *end;
            unsigned long t = strtoul(rec, &end, 10);
            if ((*end != ' ' && *end != '\t') || t > 0x7FFFFFFFul) {
                fprintf(stderr, "Warning: Bad TTL in line: %s\n", line);
                continue;
            }
            rr_ttl = (uint32_t)t;
            rec = end;
            while (*rec == ' ' || *rec == '\t') rec++;
        }

        char type_kw[64] = {0};
        if (sscanf(rec, "%63s", type_kw) < 1) continue;

        bool is_wc = (current_domain[0] == '*');

        struct AuthDomain *d = &out[count];
        memset(d, 0, sizeof(*d));
        snprintf(d->domain, sizeof(d->domain), "%s", current_domain);
        d->is_wildcard = is_wc;
        d->ttl = rr_ttl;

        /* --- SOA -------------------------------------------------------- */
        if (strcasecmp(type_kw, "SOA") == 0) {
            char mname[256] = {0}, rname[256] = {0};
            unsigned int serial = 0, refresh = 0, retry = 0,
                         expire = 0, minimum = 0;
            if (sscanf(rec, "%*s %255s %255s %u %u %u %u %u",
                       mname, rname,
                       &serial, &refresh, &retry, &expire, &minimum) != 7) {
                fprintf(stderr, "Warning: Bad SOA line: %s\n", line);
                continue;
            }
            if (!valid_name(mname) || !valid_name(rname)) {
                fprintf(stderr, "Warning: Bad SOA name in line: %s\n", line);
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
            d->soa_ttl     = rr_ttl ? rr_ttl : DEFAULT_RECORD_TTL;
            fprintf(stderr, "  Loaded: %-32s -> SOA serial=%u\n",
                    current_domain, serial);
            count++;

        /* --- NS --------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "NS") == 0) {
            char ns[256] = {0};
            if (sscanf(rec, "%*s %255s", ns) != 1) {
                fprintf(stderr, "Warning: Bad NS line: %s\n", line);
                continue;
            }
            if (!valid_name(ns)) {
                fprintf(stderr, "Warning: Bad NS target in line: %s\n", line);
                continue;
            }
            strlower(ns);
            d->has_ns = true;
            snprintf(d->ns_name, sizeof(d->ns_name), "%s", ns);
            fprintf(stderr, "  Loaded: %-32s -> NS %s\n", current_domain, ns);
            count++;

        /* --- MX --------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "MX") == 0) {
            unsigned int prio = 0;
            char mx_host[256] = {0};
            if (sscanf(rec, "%*s %u %255s", &prio, mx_host) != 2) {
                fprintf(stderr, "Warning: Bad MX line: %s\n", line);
                continue;
            }
            if (prio > 65535 || !valid_name(mx_host)) {
                fprintf(stderr, "Warning: Bad MX line: %s\n", line);
                continue;
            }
            strlower(mx_host);
            d->has_mx      = true;
            d->mx_priority = (uint16_t)prio;
            snprintf(d->mx_hostname, sizeof(d->mx_hostname), "%s", mx_host);
            fprintf(stderr, "  Loaded: %-32s -> MX %u %s\n",
                    current_domain, prio, mx_host);
            count++;

        /* --- CNAME ------------------------------------------------------ */
        } else if (strcasecmp(type_kw, "CNAME") == 0) {
            char target[256] = {0};
            if (sscanf(rec, "%*s %255s", target) != 1) {
                fprintf(stderr, "Warning: Bad CNAME line: %s\n", line);
                continue;
            }
            if (!valid_name(target)) {
                fprintf(stderr, "Warning: Bad CNAME target in line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_cname = true;
            snprintf(d->cname_target, sizeof(d->cname_target), "%s", target);
            fprintf(stderr, "  Loaded: %-32s -> CNAME %s\n",
                    current_domain, target);
            count++;

        /* --- TXT -------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "TXT") == 0) {
            /* Advance past the "TXT" keyword to the text content. */
            const char *p = rec;
            while (*p && !isspace((unsigned char)*p)) p++;
            while (*p &&  isspace((unsigned char)*p)) p++;
            if (parse_txt_rdata(p, d->txt_wire, sizeof(d->txt_wire),
                                &d->txt_wire_len) != 0) {
                fprintf(stderr, "Warning: Bad TXT line: %s\n", line);
                continue;
            }
            d->has_txt = true;
            fprintf(stderr, "  Loaded: %-32s -> TXT %s\n", current_domain, p);
            count++;

        /* --- SRV -------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "SRV") == 0) {
            unsigned int prio = 0, weight = 0, port = 0;
            char target[256] = {0};
            if (sscanf(rec, "%*s %u %u %u %255s",
                       &prio, &weight, &port, target) != 4) {
                fprintf(stderr, "Warning: Bad SRV line: %s\n", line);
                continue;
            }
            if (prio > 65535 || weight > 65535 || port > 65535 || !valid_name(target)) {
                fprintf(stderr, "Warning: Bad SRV line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_srv      = true;
            d->srv_priority = (uint16_t)prio;
            d->srv_weight   = (uint16_t)weight;
            d->srv_port     = (uint16_t)port;
            snprintf(d->srv_target, sizeof(d->srv_target), "%s", target);
            fprintf(stderr, "  Loaded: %-32s -> SRV %u %u %u %s\n",
                    current_domain, prio, weight, port, target);
            count++;

        /* --- HTTPS (RFC 9460) ------------------------------------------- */
        } else if (strcasecmp(type_kw, "HTTPS") == 0) {
            unsigned int prio = 0;
            char target[256] = {0};
            if (sscanf(rec, "%*s %u %255s", &prio, target) != 2) {
                fprintf(stderr, "Warning: Bad HTTPS line: %s\n", line);
                continue;
            }
            if (prio > 65535 || !valid_name(target)) {
                fprintf(stderr, "Warning: Bad HTTPS line: %s\n", line);
                continue;
            }
            strlower(target);
            d->has_https      = true;
            d->https_priority = (uint16_t)prio;
            snprintf(d->https_target, sizeof(d->https_target), "%s", target);
            fprintf(stderr, "  Loaded: %-32s -> HTTPS %u %s\n",
                    current_domain, prio, target);
            count++;

        /* --- AAAA ------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "AAAA") == 0) {
            char ip6[INET6_ADDRSTRLEN] = {0};      /* 46: longest valid form */
            if (sscanf(rec, "%*s %45s", ip6) != 1) {
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
            fprintf(stderr, "  Loaded: %-32s -> %s (AAAA)\n",
                    current_domain, ip6);
            count++;

        /* --- A ---------------------------------------------------------- */
        } else if (strcasecmp(type_kw, "A") == 0) {
            char ip4[INET_ADDRSTRLEN] = {0};       /* 16: "255.255.255.255" */
            if (sscanf(rec, "%*s %15s", ip4) != 1) {
                fprintf(stderr, "Warning: Bad A line: %s\n", line);
                continue;
            }
            struct in_addr ia;
            if (inet_pton(AF_INET, ip4, &ia) != 1) {
                fprintf(stderr, "Warning: Invalid IPv4 '%s' for '%s'\n",
                        ip4, current_domain);
                continue;
            }
            d->has_a = true;
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
    struct AuthDomain *out = *outp;

    /* RFC 1034 §3.6.2 / RFC 2181 §10.1: a CNAME owner may hold no other data
     * (which also rules out a CNAME at a zone apex, where the SOA/NS live).
     * Keep the other data and drop the conflicting CNAME. */
    int kept = 0;
    for (int i = 0; i < count; i++) {
        bool drop = false;
        if (out[i].has_cname) {
            for (int j = 0; j < count && !drop; j++) {
                if (j == i || strcmp(out[j].domain, out[i].domain) != 0) continue;
                if (!out[j].has_cname) {
                    fprintf(stderr, "Warning: [%s] has a CNAME and other data; "
                                    "ignoring the CNAME\n", out[i].domain);
                    drop = true;
                } else if (j < i) {
                    /* A second CNAME at one owner is equally illegal
                     * (RFC 1034 §3.6.2); keep the first one in file order. */
                    fprintf(stderr, "Warning: [%s] has more than one CNAME; "
                                    "ignoring all but the first\n", out[i].domain);
                    drop = true;
                }
            }
        }
        if (!drop) {
            if (kept != i) out[kept] = out[i];
            kept++;
        }
    }
    return kept;
}

/* ---- Public load / reload -------------------------------------------- */

/* Parse `filename` into a private table; on success swap it in under the
 * wrlock.  Readers are never blocked on file I/O, and a failed or empty parse
 * leaves the live table untouched.  Returns the record count, 0 if the file
 * held none, or -1 on I/O / allocation error. */
static int load_and_swap(const char *filename, int *old_count_out,
                         uint32_t *old_serial_out)
{
    struct AuthDomain *tmp = NULL;
    int cap = 0;
    int n = _load_domains_from_file(filename, &tmp, &cap);
    AuthIndex *idx = (n > 0) ? auth_index_build(tmp, n) : NULL;
    if (n > 0 && !idx) {
        perror("auth: zone index");
        n = -1;
    }

    struct AuthDomain *old_table = NULL;
    AuthIndex *old_idx = NULL;
    pthread_rwlock_wrlock(&g_auth_domains_lock);
    if (old_count_out) *old_count_out = auth_domain_count;
    if (old_serial_out) {
        *old_serial_out = 0;
        for (int i = 0; i < auth_domain_count; i++)
            if (auth_domains[i].has_soa) { *old_serial_out = auth_domains[i].soa_serial; break; }
    }
    if (n > 0) {
        old_table = auth_domains;   old_idx = g_auth_index;
        auth_domains = tmp;         g_auth_index = idx;
        auth_domain_count = n;
        tmp = NULL;                 idx = NULL;
    }
    pthread_rwlock_unlock(&g_auth_domains_lock);

    /* No reader can hold the old table once the wrlock was granted. */
    free(old_table);
    auth_index_free(old_idx);
    free(tmp);
    auth_index_free(idx);
    return n;
}

int load_auth_domains(const char *filename)
{
    if (!filename) return -1;

    int n = load_and_swap(filename, NULL, NULL);
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

    int old_count = 0;
    uint32_t old_serial = 0;
    int n = load_and_swap(filename, &old_count, &old_serial);
    if (n <= 0) {
        fprintf(stderr,
                "SIGHUP: reload failed; keeping %d existing record(s)\n", old_count);
        return;
    }
    fprintf(stderr, "SIGHUP: reloaded %d record(s) (was %d)\n", n, old_count);

    /* Warn if the SOA serial did not increase (RFC 1982 serial arithmetic). */
    if (old_serial > 0) {
        pthread_rwlock_rdlock(&g_auth_domains_lock);
        for (int i = 0; i < auth_domain_count; i++) {
            if (!auth_domains[i].has_soa) continue;
            uint32_t new_serial = auth_domains[i].soa_serial;
            if ((int32_t)(new_serial - old_serial) <= 0)
                fprintf(stderr,
                        "Warning: SOA serial %u is not newer than %u "
                        "— secondaries may not detect the update (RFC 1982)\n",
                        new_serial, old_serial);
            break;
        }
        pthread_rwlock_unlock(&g_auth_domains_lock);
    }
}
