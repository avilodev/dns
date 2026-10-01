#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Client access control for the DNS servers (known_issues 4.3).

// Install the default allow-list
void acl_init_defaults(void);

// REPLACE the active allow-list with a comma-separated CIDR list
int acl_set_list(const char *cidr_csv);

// True if src is permitted by the active allow-list.
bool acl_allows(const struct sockaddr_storage *src);

// Configure per-source rate limiting (qps and burst)
void rl_configure(int qps, int burst);

// Charge one query against src's bucket.
bool rl_allow(const struct sockaddr_storage *src);

// Per-source cap on concurrent TCP connections
#define TCP_MAX_CONNS_PER_SOURCE 8
bool tcp_conn_acquire(const struct sockaddr_storage *src);
void tcp_conn_release(const struct sockaddr_storage *src);

#endif /* ACCESS_CONTROL_H */
