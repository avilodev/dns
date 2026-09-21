#include "dns_name.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>   /* strncasecmp */

static bool is_root(const char *s)
{
    return !s || s[0] == '\0' || (s[0] == '.' && s[1] == '\0');
}

/* Append one label's bytes to out[*o] in escaped text form. */
static bool put_label(const uint8_t *lbl, int len, bool lower,
                      char *out, size_t cap, size_t *o)
{
    for (int i = 0; i < len; i++) {
        uint8_t c = lbl[i];
        if (lower && c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        char esc[5];
        int n;
        if (c == '.' || c == '\\')      n = snprintf(esc, sizeof(esc), "\\%c", c);
        else if (c <= 0x20 || c >= 0x7F) n = snprintf(esc, sizeof(esc), "\\%03u", c);
        else { esc[0] = (char)c; n = 1; }
        if (*o + (size_t)n + 1 > cap) return false;
        memcpy(out + *o, esc, (size_t)n);
        *o += (size_t)n;
    }
    return true;
}

int dname_from_wire(const uint8_t *msg, int msg_len, int off, bool lower,
                    char *out, size_t cap)
{
    if (!msg || !out || cap < 2 || off < 0) return -1;
    int ret = -1, cur = off, hops = 0, wire_len = 0;
    size_t o = 0;

    while (cur < msg_len) {
        uint8_t l = msg[cur];
        if (l == 0) {
            if (ret < 0) ret = cur + 1;
            if (o == 0) out[o++] = '.';                 /* the root */
            out[o] = '\0';
            return ret;
        }
        if ((l & 0xC0) == 0xC0) {
            if (cur + 2 > msg_len || ++hops > 127) return -1;
            if (ret < 0) ret = cur + 2;
            cur = ((l & 0x3F) << 8) | msg[cur + 1];
            continue;
        }
        if (l > 63 || cur + 1 + l > msg_len) return -1;
        wire_len += 1 + l;
        if (wire_len + 1 > 255) return -1;
        if (o > 0) {
            if (o + 2 > cap) return -1;
            out[o++] = '.';
        }
        if (!put_label(msg + cur + 1, l, lower, out, cap, &o)) return -1;
        cur += 1 + l;
    }
    return -1;
}

int dname_to_wire(const char *text, uint8_t *out, int cap)
{
    if (!out || cap < 1) return -1;
    if (is_root(text)) { out[0] = 0; return 1; }

    int pos = 0;
    const char *p = text;
    while (*p) {
        int len_at = pos++;
        int len = 0;
        if (pos > cap) return -1;
        while (*p && *p != '.') {
            uint8_t c;
            if (*p == '\\') {
                if (isdigit((unsigned char)p[1]) && isdigit((unsigned char)p[2]) &&
                    isdigit((unsigned char)p[3])) {
                    int v = (p[1] - '0') * 100 + (p[2] - '0') * 10 + (p[3] - '0');
                    if (v > 255) return -1;
                    c = (uint8_t)v;
                    p += 4;
                } else if (p[1]) {
                    c = (uint8_t)p[1];
                    p += 2;
                } else {
                    return -1;                          /* dangling backslash */
                }
            } else {
                c = (uint8_t)*p++;
            }
            if (++len > 63 || pos + 1 > cap) return -1;
            out[pos++] = c;
        }
        if (len == 0) return -1;                        /* empty label: "a..b" */
        out[len_at] = (uint8_t)len;
        if (*p == '.') {
            p++;
            if (*p == '\0') break;                      /* trailing dot */
        }
    }
    if (pos + 1 > cap || pos + 1 > 255) return -1;
    out[pos++] = 0;
    return pos;
}

/* Is the character at name[i] a label separator (a dot not escaped by an odd
 * run of backslashes)?  "\\." is an escaped backslash followed by a real dot. */
static bool is_separator(const char *name, size_t i)
{
    if (name[i] != '.') return false;
    size_t bs = 0;
    while (i > bs && name[i - bs - 1] == '\\') bs++;
    return (bs % 2) == 0;
}

const char *dname_parent(const char *name)
{
    if (is_root(name)) return NULL;
    for (size_t i = 0; name[i]; i++) {
        if (name[i] == '\\') {                          /* skip the escape */
            if (isdigit((unsigned char)name[i + 1]) && isdigit((unsigned char)name[i + 2]) &&
                isdigit((unsigned char)name[i + 3])) i += 3;
            else if (name[i + 1]) i += 1;
            continue;
        }
        if (name[i] == '.')
            return name[i + 1] ? name + i + 1 : NULL;
    }
    return NULL;
}

bool dname_is_subdomain(const char *name, const char *zone)
{
    if (!name || !zone) return false;
    if (is_root(zone)) return true;
    size_t nlen = strlen(name), zlen = strlen(zone);
    /* Ignore one trailing (unescaped) dot, as in "example.com." */
    if (nlen > 1 && is_separator(name, nlen - 1)) nlen--;
    if (zlen > 1 && is_separator(zone, zlen - 1)) zlen--;
    if (nlen < zlen) return false;
    if (strncasecmp(name + (nlen - zlen), zone, zlen) != 0) return false;
    if (nlen == zlen) return true;
    return is_separator(name, nlen - zlen - 1);
}
