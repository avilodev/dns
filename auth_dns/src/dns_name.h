#ifndef DNS_NAME_H
#define DNS_NAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Domain-name codec: the ONLY place names cross between DNS wire format

// Longest text form of a legal name: 255 wire octets, each label byte as "\DDD"
#define DNAME_TEXT_MAX 1024

// Decode the (possibly compressed) name at msg[off] into text.
int dname_from_wire(const uint8_t *msg, int msg_len, int off, bool lower,
					char *out, size_t cap);

// Encode text into uncompressed wire format.
int dname_to_wire(const char *text, uint8_t *out, int cap);

// Parent of `name`, as a pointer into `name`
const char *dname_parent(const char *name);

// True if `name` is `zone` or below it (case-insensitive, label-aligned).
bool dname_is_subdomain(const char *name, const char *zone);

// Number of labels ("a.b.c" -> 3, root -> 0).
int dname_label_count(const char *name);

#endif /* DNS_NAME_H */
