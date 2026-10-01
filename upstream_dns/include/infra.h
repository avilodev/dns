#ifndef INFRA_H
#define INFRA_H

#include <stdbool.h>

// Per-nameserver speed and health: smoothed RTT on success

// Record a successful exchange with `ip` that took `rtt_ms`.
void infra_report_rtt(const char* ip, int rtt_ms);

// Record a failed exchange with `ip` (timeout, unreachable, bad reply).
void infra_report_failure(const char* ip);

// Lower is better; unknown servers get a middling score
int infra_score(const char* ip);

#endif /* INFRA_H */
