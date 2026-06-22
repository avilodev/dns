/* libFuzzer harness for the upstream_dns wire-format query parser.
 *
 * Target: parse_request_headers() — turns raw, untrusted client bytes into a
 * Packet. This is the recursive resolver's front-door parser (the one whose
 * root-zone name normalization was just fixed), so we feed it arbitrary input
 * under AddressSanitizer + UndefinedBehaviorSanitizer to surface memory/UB bugs.
 *
 * Build & run:
 *   make -C upstream_dns fuzz
 *   upstream_dns/obj/fuzz_request -max_total_time=30
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "request.h"

/* A linked unit (utils.c) references the global server config. The parser never
 * reads it, but the symbol must resolve, so provide a zero-initialized one. */
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
