#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * Client access control: a CIDR allow-list (no open resolver), per-source
 * token-bucket rate limiting (IPv4 address / IPv6 /64), and a per-source cap
 * on concurrent TCP connections.  The allow-list is set once at startup and
 * read lock-free; the limiter is mutex-guarded.
 */

/* Default allow-list: loopback, RFC1918, link-local, IPv6 ULA. */
void acl_init_defaults(void);

/* Replace (not extend) the allow-list with "cidr,cidr,..." — a bare address
 * is a host route.  Include loopback yourself.  -1 on a parse error (the old
 * list stays). */
int acl_set_list(const char *cidr_csv);

/* True if src is permitted by the active allow-list. */
bool acl_allows(const struct sockaddr_storage *src);

/* qps <= 0 disables; burst <= 0 means 2*qps. */
void rl_configure(int qps, int burst);

/* Charge one query.  false = over rate: drop silently (a reply still amplifies). */
bool rl_allow(const struct sockaddr_storage *src);

/* Each TCP connection holds a worker: at most this many per source.  Pair
 * every successful acquire() with a release(). */
#define TCP_MAX_CONNS_PER_SOURCE 8
bool tcp_conn_acquire(const struct sockaddr_storage *src);
void tcp_conn_release(const struct sockaddr_storage *src);

#endif /* ACCESS_CONTROL_H */
