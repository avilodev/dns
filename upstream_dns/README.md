# upstream_dns

A recursive, iterative DNS resolver written in C. Listens on port 5335 by default and resolves queries by walking the DNS delegation tree from the root.

## Features

- **Iterative resolution**: walks the delegation tree from root hints or a cached NS entry, following referrals to authoritative nameservers
- **DNSSEC validation**: full chain-of-trust from the root KSK through DS → DNSKEY → RRSIG at each delegation level; supports algorithms 8 (RSA-SHA256), 13 (ECDSA-P256), 14 (ECDSA-P384), 15 (Ed25519)
- **NSEC denial-of-existence verification**: validates NSEC records in NXDOMAIN/NODATA responses; NSEC3-signed zones pass RRSIG verification and defer content checks
- **Dual-stack**: IPv4 and IPv6 sockets, UDP and TCP
- **Answer cache**: stores full DNS responses with TTL decrement on retrieval (RFC 1034 §4.1.3); OPT RR TTL skipped during patch
- **NS cache**: keyed on zone apex, TTL taken from actual NS records in referrals; flushed on SIGHUP
- **CNAME following**: recursively resolves CNAME chains; TC=1 UDP answers retried over TCP
- **EDNS0**: advertises 4096-byte UDP payload and DO=1 (requests DNSSEC records); echoes client OPT RR back; BADVERS response for EDNS version > 0
- **AD bit**: set in responses when DNSSEC validation succeeds (RFC 4035 §3.2.3)
- **CD bit**: validation skipped when client sets CD=1 (RFC 4035 §3.1.6)
- **Thread pool**: configurable worker threads; each query handled independently
- **QCLASS validation**: FORMERR returned for non-IN/ANY queries (RFC 1035 §3.2.4)
- **Transaction ID randomisation**: outgoing query IDs randomised via `getrandom()`
- **Source IP validation**: responses from unexpected addresses are discarded
- **Structured response validation**: rejects QR=0, wrong opcode, or implausibly short packets
- **Atomic per-QTYPE counters**: SIGUSR1/SIGUSR2 dump statistics to stderr
- **Persistent log fd**: queries written to `upstream.log` via a mutex-protected fd opened once at startup; reopened on SIGHUP (compatible with logrotate)
- **PID file**: written to `/run/upstream_dns.pid` at startup; removed on clean shutdown
- **Graceful shutdown**: SIGTERM/SIGINT drain the thread pool and join the cleanup thread

## Building

```sh
cd upstream_dns
make           # build
make rebuild   # clean + build
```

To install and run both servers at boot, use the **top-level** `sudo make install`
(see the repo root README) — it installs the cron jobs, including the `@reboot`
launcher that starts this resolver.

Requires: `gcc`, `libssl-dev` (OpenSSL ≥ 1.1 or 3.x), `libatomic`.

## Running

```sh
sudo ./bin/upstream_dns [options]
```

| Option | Default | Description |
|--------|---------|-------------|
| `-p PORT` | `5335` | UDP/TCP listen port |
| `-t THREADS` | `4` | Worker thread count |
| `-q QUEUE` | `256` | Thread pool queue depth |

For system use, run `sudo make install` from the repo root and reboot — the
`@reboot` cron launcher (`cron_scripts/dns-startup`) starts this resolver
automatically. Edit that launcher to choose which servers run.

## Configuration

### Root hints (`misc/root_hints.txt`)

Standard IANA root hints file. If missing at startup, a built-in fallback with hardcoded A/AAAA addresses for all 13 root servers is used. Refreshed daily by `/etc/cron.daily/refresh-root-hints`.

### Trust anchor (`config/root-trust-anchor.key`)

DNSKEY record for the DNS root zone (KSK-2017, key tag 20326). Used as the starting point for DNSSEC chain-of-trust validation. Format:

```
. 172800 IN DNSKEY 257 3 8 <base64-public-key>
```

### Log size cap (in-process)

`upstream.log` is capped in-process: once it exceeds `LOG_MAX_BYTES` the server truncates it in place (`ftruncate` to 0) — there is no rotation, no `upstream.log.1`, and no logrotate config to install.

## Signal handling

| Signal | Effect |
|--------|--------|
| `SIGUSR1` / `SIGUSR2` | Print per-QTYPE query counters to stderr |
| `SIGHUP` | Flush NS cache, reopen log file |
| `SIGTERM` / `SIGINT` | Graceful shutdown (drain pool, join threads) |

## Source layout

| File | Description |
|------|-------------|
| `main.c` | Entry point, signal handling, poll loop, thread pool, logging |
| `config.c/h` | Argument parsing, root hints loading, trust anchor loading |
| `resolve.c/h` | Core iterative resolver — NS lookup, query dispatch, DNSSEC chain integration |
| `cache.c/h` | Answer cache (hash table, TTL patching) and NS cache |
| `dns_packet.c/h` | Outgoing query wire builder (sets DO bit, EDNS0) |
| `dns_wire.c/h` | Wire-format parsers: DNSKEY, RRSIG, DS, NSEC3 RDATA; `compute_key_tag` |
| `dnssec.c/h` | RRSIG verification (all supported algorithms), canonical RR form, NSEC denial verification |
| `dnssec_chain.c/h` | Per-resolution chain-of-trust context: DS digest verification, DNSKEY promotion |
| `dnssec_types.h` | Structs for DNSKEY, RRSIG, DS, NSEC3 RDATA |
| `request.c/h` | Incoming packet parser: QNAME, QTYPE, QCLASS, EDNS OPT, DO/CD/RD bits |
| `response_handler.c/h` | Response classifier: final answer vs referral vs CNAME-only |
| `cname_handler.c/h` | CNAME chain reconstruction |
| `ns_resolver.c/h` | Glue IP extraction, NS candidate management |
| `ns_resolution_context.c/h` | Per-iteration resolution state machine |
| `udp_client.c/h` | UDP query sender (source IP validation), TCP fallback for TC=1 |
| `utils.c/h` | QTYPE name lookup, DNS label writer |
| `thread_pool.c/h` | Work queue with mutex/condvar, graceful drain |
| `types.h` | Packet struct, constants (MAXLINE, timeouts, RCODE values) |
