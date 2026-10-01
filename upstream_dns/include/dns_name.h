#ifndef DNS_NAME_H
#define DNS_NAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Name codec: the only place names cross between wire format and text.

// Longest text form of a legal name (every byte as "\DDD").
#define DNAME_TEXT_MAX 1024

// Decode the (possibly compressed) name at msg[off].
int dname_from_wire(const uint8_t *msg, int msg_len, int off, bool lower,
					char *out, size_t cap);

// Encode text to uncompressed wire.
int dname_to_wire(const char *text, uint8_t *out, int cap);

// "www.example.com" -> "example.com" (pointer into name); NULL at the top.
const char *dname_parent(const char *name);

// name == zone or below it (case-insensitive, label-aligned); root holds all.
bool dname_is_subdomain(const char *name, const char *zone);

#endif /* DNS_NAME_H */
