# dns-args.sh — single source of truth for assembling each server's CLI flags
# from the dns.conf variables. The caller MUST have already sourced dns.conf so
# the AUTH_*/UPSTREAM_* variables are in the environment.
#
# Sourced by BOTH cron_scripts/dns-startup (native boot) and the Makefile
# (Docker), so the two deployments always pass identical flags. Each function
# prints the space-separated argv on stdout; dns.conf values never contain
# spaces (enforced by its format rules), so callers can word-split safely.

# build_auth_args <bundled_upstream_ip>
#   <bundled_upstream_ip> is auth's -u target when AUTH_UPSTREAM_IP is blank
#   (127.0.0.1 native, 172.28.0.2 on the docker bridge). A set AUTH_UPSTREAM_IP
#   is an external resolver and defaults its port to 53.
build_auth_args() {
    _bundled_ip="$1"
    _ip="${AUTH_UPSTREAM_IP:-}"
    _port="${AUTH_UPSTREAM_PORT:-}"
    if [ -n "$_ip" ]; then
        [ -n "$_port" ] || _port=53
    else
        _ip="$_bundled_ip"
        [ -n "$_port" ] || _port="${UPSTREAM_PORT:-5335}"
    fi
    set -- -u "$_ip" -p "$_port" -t "${AUTH_THREADS:-20}" -q "${AUTH_QUEUE:-512}"
    [ "${AUTH_DROP_ENABLED:-true}" = true ]       && set -- "$@" -U "${AUTH_DROP_USER:-nobody}"
    [ "${AUTH_RATELIMIT_ENABLED:-false}" = true ] && set -- "$@" -r "${AUTH_RATELIMIT_QPS:-0}"
    [ "${AUTH_ACL_ENABLED:-false}" = true ]       && set -- "$@" -a "${AUTH_ACL_CIDRS}"
    [ "${AUTH_BIND_ENABLED:-false}" = true ]      && set -- "$@" -b "${AUTH_BIND_ADDR}"
    [ "${AUTH_BLOCK_ENABLED:-false}" = true ]     && set -- "$@" -S "${AUTH_BLOCK_MODE}"
    echo "$@"
}

# build_upstream_args
build_upstream_args() {
    set -- -p "${UPSTREAM_PORT:-5335}" -t "${UPSTREAM_THREADS:-20}" -q "${UPSTREAM_QUEUE:-512}"
    [ "${UPSTREAM_DROP_ENABLED:-true}" = true ]       && set -- "$@" -U "${UPSTREAM_DROP_USER:-nobody}"
    [ "${UPSTREAM_RATELIMIT_ENABLED:-false}" = true ] && set -- "$@" -r "${UPSTREAM_RATELIMIT_QPS:-0}"
    [ "${UPSTREAM_ACL_ENABLED:-false}" = true ]       && set -- "$@" -a "${UPSTREAM_ACL_CIDRS}"
    [ "${UPSTREAM_BIND_ENABLED:-false}" = true ]      && set -- "$@" -b "${UPSTREAM_BIND_ADDR}"
    echo "$@"
}
