#include "utils.h"

int get_random_id()
{
    return (uint16_t)((rand() << 8) | (rand() & 0xFF));
}

int get_random_server()
{
    return rand() % 13;
}

/**
 * Convert query type to string for logging
 */
const char* qtype_to_string(uint16_t qtype)
{
    switch(qtype) {
        case QTYPE_A:     return "A";
        case QTYPE_AAAA:  return "AAAA";
        case QTYPE_NS:    return "NS";
        case QTYPE_CNAME: return "CNAME";
        case QTYPE_MX:    return "MX";
        case QTYPE_TXT:   return "TXT";
        case QTYPE_SOA:   return "SOA";
        case QTYPE_PTR:   return "PTR";
        default:          return "UNKNOWN";
    }
}