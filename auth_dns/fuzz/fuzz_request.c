/* libFuzzer harness for the auth_dns wire-format query parser.
 *
 * Target: parse_request_headers() — the function that turns raw, untrusted
 * network bytes from a client into a Packet. This is the primary attack
 * surface of the authoritative server, so we feed it arbitrary input under
 * AddressSanitizer + UndefinedBehaviorSanitizer to surface memory/UB bugs.
 *
 * Build & run:
 *   make -C auth_dns fuzz
 *   auth_dns/obj/fuzz_request -max_total_time=30
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "request.h"
#include "utils.h"

/* parse_request_headers() links against utils.c, which references the global
 * server config. The parser itself never reads it, but the symbol must resolve,
 * so we provide a zero-initialized definition here. */
Config g_config;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* The parser takes a mutable char* and copies the buffer internally, so a
     * heap copy sized exactly to the input lets ASan catch any over-read. */
    char *buf = malloc(size ? size : 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);

    struct Packet *pkt = parse_request_headers(buf, (ssize_t)size);
    if (pkt)
        free_packet(pkt);

    free(buf);
    return 0;
}
