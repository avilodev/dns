#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * Client access control for the DNS servers (known_issues 4.3).
 *
 *   - CIDR allow-list: refuse recursion/forwarding for sources outside the
 *     trusted network, closing the open-resolver amplification vector.
 *   - Per-source-IP token-bucket rate limiting: bound the query rate any one
 *     client can drive, regardless of allow-list membership.
 *
 * The allow-list is configured once at startup (before worker threads start)
 * and is read-only thereafter, so allow-list lookups are lock-free.  The rate
 * limiter is mutex-guarded because it mutates per-source state on every query.
 */

/*
 * Install the default allow-list: loopback + RFC1918 private ranges +
 * link-local (IPv4 169.254/16, IPv6 fe80::/10) + IPv6 ULA (fc00::/7).
 * Call once at startup.
 */
void acl_init_defaults(void);

/*
 * REPLACE the active allow-list with a comma-separated CIDR list, e.g.
 * "10.0.0.0/8,192.168.0.0/16,::1/128".  A bare address implies a host route
 * (/32 for IPv4, /128 for IPv6).  Returns 0 on success; on any parse error the
 * existing list is left unchanged and -1 is returned.
 *
 * NOTE: a custom list fully replaces the defaults, so include loopback / your
 * own LAN range explicitly or you will lock yourself out.
 */
int acl_set_list(const char *cidr_csv);

/* True if src is permitted by the active allow-list. */
bool acl_allows(const struct sockaddr_storage *src);

/*
 * Configure per-source rate limiting.  qps = sustained queries/sec per source
 * IP; burst = bucket capacity (max instantaneous burst).  qps <= 0 disables
 * rate limiting.  If burst <= 0 it defaults to 2*qps (min 1).
 */
void rl_configure(int qps, int burst);

/*
 * Charge one query against src's bucket.  Returns true if the query may
 * proceed, false if src has exceeded its rate (caller should DROP silently —
 * responding would still amplify).  Always true when rate limiting is disabled.
 */
bool rl_allow(const struct sockaddr_storage *src);

#endif /* ACCESS_CONTROL_H */
