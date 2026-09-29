#ifndef DIAG_H
#define DIAG_H

#include <stdio.h>

/*
 * Severity gate for the server's human-readable diagnostics.
 *
 * This is NOT the CSV query log (query_log.c), which is always written — it
 * is the running commentary that the launcher captures into the per-server .err files.
 * The distinction that matters: a few messages are emitted once per process
 * (config, listeners, reloads), but most scale with QUERY VOLUME — every
 * resolution failure, every upstream timeout, every stray packet. Ungated,
 * that per-query chatter grew faster than either query log and never
 * rotated. Those sites are DIAG_DEBUG and are off by default.
 *
 * Set once from -L during startup, before any worker thread exists, and
 * only read afterwards — so no locking.
 */
typedef enum {
    DIAG_ERROR = 0,   /* the server cannot do what was asked */
    DIAG_WARN  = 1,   /* degraded, but still serving */
    DIAG_INFO  = 2,   /* lifecycle: startup, reloads, stats */
    DIAG_DEBUG = 3    /* per-query detail; scales with traffic */
} DiagLevel;

extern int g_diag_level;

/* "error"|"warn"|"info"|"debug" -> DiagLevel, or -1 if unrecognised. */
int diag_level_from_name(const char* name);
const char* diag_level_name(int level);

/*
 * Errors and warnings go to stderr, info/debug to stdout, so `docker logs`
 * and the .err files keep the same split the code already used.
 * `level` is always a constant here, so evaluating it twice is harmless.
 */
#define diag(level, ...)                                                       \
    do {                                                                       \
        if ((int)(level) <= g_diag_level)                                       \
            fprintf((int)(level) <= DIAG_WARN ? stderr : stdout, __VA_ARGS__);  \
    } while (0)

#endif /* DIAG_H */
