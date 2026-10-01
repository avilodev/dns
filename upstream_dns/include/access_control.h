#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Client access control: a CIDR allow-list

// Default allow-list: loopback, RFC1918, link-local, IPv6 ULA.
void acl_init_defaults(void);

// Replace the allow-list with "cidr,cidr,..." — a bare address is a host route.
int acl_set_list(const char *cidr_csv);

// True if src is permitted by the active allow-list.
bool acl_allows(const struct sockaddr_storage *src);

// qps <= 0 disables; burst <= 0 means 2*qps.
void rl_configure(int qps, int burst);

// Charge one query. false = over rate: drop silently (a reply still amplifies).
bool rl_allow(const struct sockaddr_storage *src);

// Each TCP connection holds a worker: at most this many per source.
#define TCP_MAX_CONNS_PER_SOURCE 8
bool tcp_conn_acquire(const struct sockaddr_storage *src);
void tcp_conn_release(const struct sockaddr_storage *src);

#endif /* ACCESS_CONTROL_H */
