#ifndef QUERY_LOG_H
#define QUERY_LOG_H

#include <stdint.h>

// CSV query logger for upstream_dns.

void log_query(const char* client_ip, uint16_t port,
			   uint16_t qtype_val, const char* domain,
			   uint8_t rcode, const char* info);
void log_close_upstream(void);
void log_reopen_upstream(void);   // also opens it early, before a privilege drop

// Pin the log AND its rotation slot while still root.
void log_pin_paths(void);

// Per-QTYPE counters (lock-free), printed on SIGUSR1.
void count_query(uint16_t qtype);
void print_query_stats(void);

#endif /* QUERY_LOG_H */
