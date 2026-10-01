#ifndef DIAG_H
#define DIAG_H

#include <stdio.h>

// Severity gate for the server's human-readable diagnostics.
typedef enum {
	DIAG_ERROR = 0,   // the server cannot do what was asked
	DIAG_WARN  = 1,   // degraded, but still serving
	DIAG_INFO  = 2,   // lifecycle: startup, reloads, stats
	DIAG_DEBUG = 3    // per-query detail; scales with traffic
} diag_level;

extern int g_diag_level;

// "error"|"warn"|"info"|"debug" -> DiagLevel, or -1 if unrecognised.
int diag_level_from_name(const char* name);
const char* diag_level_name(int level);

// Errors and warnings go to stderr, info/debug to stdout, so `docker logs`
#define DIAG(level, ...)                                                       \
    do {                                                                       \
        if ((int)(level) <= g_diag_level)                                       \
            fprintf((int)(level) <= DIAG_WARN ? stderr : stdout, __VA_ARGS__);  \
    } while (0)

#endif /* DIAG_H */
