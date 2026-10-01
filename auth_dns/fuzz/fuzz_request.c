// libFuzzer harness for the auth_dns wire-format query parser.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "request.h"
#include "utils.h"

// parse_request_headers links against utils.c
Config g_config;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	// The parser takes a mutable char* and copies the buffer internally
	char *buf = malloc(size ? size : 1);

	if(!buf)
		return 0;
	memcpy(buf, data, size);

	struct packet *pkt = parse_request_headers(buf, (ssize_t)size);
	if(pkt)
		free_packet(pkt);

	free(buf);

	return 0;
}
