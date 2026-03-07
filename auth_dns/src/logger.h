#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>

#include "types.h"

/* Log a DNS query result. Format: [timestamp] client_ip:port QTYPE domain RCODE [-> info] */
int log_entry(const char* client_ip, uint16_t port, uint16_t qtype,
              const char* domain, uint8_t rcode, const char* info);

/* Close persistent log fd. Call once on shutdown. */
void log_close(void);

/* Convert QTYPE to name string; returns NULL for unknown types. */
const char* qtype_name(uint16_t qtype);

#endif
