#ifndef DNS_NAME_H
#define DNS_NAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Domain-name codec: the ONLY place names cross between DNS wire format and
 * text.  Every other module handles names as text produced here.
 *
 * Text form is RFC 1035 §5.1 presentation format without the trailing dot:
 * labels joined by '.', and inside a label a literal '.' or '\' is escaped as
 * "\." / "\\", and any byte outside printable ASCII as "\DDD" (decimal).  A
 * label is therefore never split or merged by a byte it happens to contain,
 * and wire -> text -> wire round-trips exactly.  The root is ".".
 *
 * Label arithmetic (parent, subdomain, label count) must go through the
 * helpers below: a bare strchr(name, '.') would split an escaped dot.
 */

/* Longest text form of a legal name: 255 wire octets, each label byte as
 * "\DDD", plus separators and the NUL. */
#define DNAME_TEXT_MAX 1024

/* Decode the (possibly compressed) name at msg[off] into text.  `lower`
 * folds ASCII letters to lowercase.  Returns the offset just past the name as
 * stored at `off` (i.e. not following pointers), or -1 if malformed,
 * over-long, looping, or `cap` is too small. */
int dname_from_wire(const uint8_t *msg, int msg_len, int off, bool lower,
                    char *out, size_t cap);

/* Encode text (escapes honoured, optional trailing dot, "." = root) into
 * uncompressed wire format.  Returns bytes written including the root label,
 * or -1 on a malformed name (empty label, label > 63, name > 255) or when
 * `cap` is too small. */
int dname_to_wire(const char *text, uint8_t *out, int cap);

/* Parent of `name` ("www.example.com" -> "example.com"), as a pointer into
 * `name`; NULL for a single-label name or the root. */
const char *dname_parent(const char *name);

/* True if `name` is `zone` or below it (case-insensitive, label-aligned).
 * The root ("" or ".") contains every name. */
bool dname_is_subdomain(const char *name, const char *zone);

/* Number of labels ("a.b.c" -> 3, root -> 0). */
int dname_label_count(const char *name);

#endif /* DNS_NAME_H */
