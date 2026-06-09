#include "utils.h"
#include <sys/random.h>
#include <strings.h>   /* strncasecmp */

int get_random_id()
{
    uint16_t id;
    if (getrandom(&id, sizeof(id), 0) == sizeof(id)) {
        return id;
    }
    // fallback if getrandom fails
    return rand() & 0xFFFF;
}

int get_random_server()
{
    uint8_t r;
    if (getrandom(&r, sizeof(r), 0) == sizeof(r)) {
        return r % 13;
    }
    return rand() % 13;
}

/*
 * Convert QTYPE to name string.  Returns NULL for unrecognised types so
 * callers can fall back to a "TYPE%u" numeric format.
 */
const char* qtype_to_string(uint16_t qtype)
{
    switch (qtype) {
        case QTYPE_A:          return "A";
        case QTYPE_NS:         return "NS";
        case QTYPE_CNAME:      return "CNAME";
        case QTYPE_SOA:        return "SOA";
        case QTYPE_PTR:        return "PTR";
        case QTYPE_MX:         return "MX";
        case QTYPE_TXT:        return "TXT";
        case QTYPE_AAAA:       return "AAAA";
        case 33:               return "SRV";
        case QTYPE_DS:         return "DS";
        case QTYPE_RRSIG:      return "RRSIG";
        case QTYPE_NSEC:       return "NSEC";
        case QTYPE_DNSKEY:     return "DNSKEY";
        case QTYPE_NSEC3:      return "NSEC3";
        case QTYPE_NSEC3PARAM: return "NSEC3PARAM";
        case 255:              return "ANY";
        default:               return NULL;
    }
}

/*
 * Bailiwick test (cache-poisoning defence, RFC 2181 §5.4.1).
 *
 * Return true when `name` is at or below `zone` in the DNS hierarchy — i.e.
 * name == zone, or name is a proper subdomain of zone — comparing
 * label-by-label and case-insensitively (DNS names are case-insensitive,
 * RFC 1035 §3.1).
 *
 * Both arguments are presentation-form names with no trailing dot
 * (e.g. "www.example.com", "example.com"); a single trailing dot is tolerated.
 * The root zone, represented by "" or ".", is the bailiwick of every name.
 *
 *   name_in_bailiwick("www.example.com", "example.com") == true
 *   name_in_bailiwick("example.com",     "example.com") == true   (equal)
 *   name_in_bailiwick("evil.com",        "paypal.com")  == false
 *   name_in_bailiwick("notexample.com",  "example.com") == false  (label boundary)
 *   name_in_bailiwick("anything.com",    "")            == true   (root)
 */
bool name_in_bailiwick(const char* name, const char* zone)
{
    if (!name || !zone) return false;

    size_t nlen = strlen(name);
    size_t zlen = strlen(zone);

    /* Ignore a single trailing dot so "example.com." == "example.com",
     * but keep the lone root dot ("."). */
    if (nlen > 1 && name[nlen - 1] == '.') nlen--;
    if (zlen > 1 && zone[zlen - 1] == '.') zlen--;

    /* The root zone ("" or ".") contains every name. */
    if (zlen == 0 || (zlen == 1 && zone[0] == '.')) return true;

    /* A name shorter than the zone cannot be at or below it. */
    if (nlen < zlen) return false;

    /* Exact match. */
    if (nlen == zlen) return strncasecmp(name, zone, zlen) == 0;

    /* Proper subdomain: the zone must align on a label boundary, so the byte
     * in `name` immediately preceding the zone suffix must be a dot. */
    if (name[nlen - zlen - 1] != '.') return false;
    return strncasecmp(name + (nlen - zlen), zone, zlen) == 0;
}
