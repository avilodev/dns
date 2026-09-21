#ifndef WIRE_IO_H
#define WIRE_IO_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/* Alignment-safe big-endian field access (wire fields sit at odd offsets). */
static inline uint16_t rd16(const void *p) { uint16_t v; memcpy(&v, p, 2); return ntohs(v); }
static inline uint32_t rd32(const void *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }
static inline void wr16(void *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }
static inline void wr32(void *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }

#endif /* WIRE_IO_H */
