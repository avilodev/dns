#ifndef QUERY_LOG_H
#define QUERY_LOG_H

#include <stdint.h>

/* CSV query logger for upstream_dns.
 * Format: timestamp,client_ip,port,qtype,domain,rcode,info
 * The info column is empty when there is no answer detail. */

void log_query(const char* client_ip, uint16_t port,
               uint16_t qtype_val, const char* domain,
               uint8_t rcode, const char* info);
void log_close_upstream(void);
void log_reopen_upstream(void);   /* also opens it early, before a privilege drop */

/* Per-QTYPE counters (lock-free), printed on SIGUSR1. */
void count_query(uint16_t qtype);
void print_query_stats(void);

#endif /* QUERY_LOG_H */
