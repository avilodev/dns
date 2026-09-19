#ifndef WIRE_IO_H
#define WIRE_IO_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * Alignment-safe access to big-endian (network order) fields inside a DNS
 * message.  Fields in a DNS packet sit at arbitrary byte offsets, so casting
 * `buf + off` to uint16_t* / uint32_t* is undefined behaviour (and a fault on
 * strict-alignment CPUs).  memcpy() of a fixed size compiles to a plain load or
 * store on every target that allows it.
 *
 *   rd16/rd32  read a network-order field, return host order
 *   wr16/wr32  write a host-order value as network order
 */
static inline uint16_t rd16(const void *p) { uint16_t v; memcpy(&v, p, 2); return ntohs(v); }
static inline uint32_t rd32(const void *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }
static inline void wr16(void *p, uint16_t v) { v = htons(v); memcpy(p, &v, 2); }
static inline void wr32(void *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }

#endif /* WIRE_IO_H */
