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

int log_entry(const char* client_ip, uint16_t port, const char* domain, const char* resolved_ip);

#endif