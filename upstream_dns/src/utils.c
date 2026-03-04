#include "utils.h"
#include <sys/random.h>

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
