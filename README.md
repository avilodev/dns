# DNS Server

A custom DNS server written in C, running on a Raspberry Pi. It's split into two separate programs that work together: an **authoritative server** that answers for your own domains, and an **upstream resolver** that handles everything else by walking the DNS tree from the root down.

---

## How it works

```
Client query
     |
     v
auth_dns (port 53)
     |-- Your domains? --> answer directly
     |-- Everything else? --> forward to upstream_dns (port 5335)
                                     |
                                     v
                              upstream_dns
                              iterative resolver:
                              root hints -> TLD -> zone -> answer
```

**auth_dns** is what your network points at. It serves authoritative records for your zones (avilo.com, avilo.priv, adoliva.com, etc.) and forwards anything it doesn't own to the upstream resolver.

**upstream_dns** is a full recursive/iterative resolver. It doesn't forward to Google or Cloudflare — it starts from the DNS root and walks the delegation chain itself, following NS referrals until it reaches the authoritative server for the queried domain.

Both servers are multithreaded, support UDP and TCP, and speak IPv4 and IPv6.

---

## Building

You need `gcc`, `make`, OpenSSL development headers (`libssl-dev`), and `libatomic`.

```bash
make                 # build both servers
make rebuild         # clean + build both servers
sudo make install    # build + install all cron jobs (daily + @reboot startup)
sudo make uninstall  # remove the installed cron jobs
```

Binaries end up at `auth_dns/bin/auth_dns` and `upstream_dns/bin/upstream_dns`.

`make install` installs three cron jobs, all rendered from generic templates in `cron_scripts/` with install-time paths substituted in — no hardcoded paths in the source tree:

- `dns_log` (daily) — archives and truncates the auth `server.log`.
- `refresh-root-hints` (daily) — refreshes the upstream resolver's root hints.
- `dns-startup` (`@reboot`) — starts the servers at boot. This is a one-line `/etc/cron.d` entry that points back at the launcher in `cron_scripts/dns-startup`, which is the file you edit to choose what runs.

## Auto-start at boot

After `sudo make install`, the servers start automatically on every boot. To choose **which** servers run, edit `cron_scripts/dns-startup` and comment out a line at the bottom:

```bash
start_upstream    # comment out to disable the recursive resolver
start_auth        # comment out to disable the authoritative server
```

Leave both for the full setup. Edits take effect on the next boot — no reinstall needed. Tunables (threads, ports, optional `-U` privilege drop) live at the top of that file.

---

## Docker deployment

The images are **self-contained and multi-arch**: each `Dockerfile` compiles its
binary inside a build stage with fixed container paths baked in (`/opt/<svc>`,
`/var/log/dns`), so there is no host build step and no `.env`/`DNS_ROOT` to
manage. Networking is bridge: `auth_dns` publishes `:53`, while `upstream_dns`
stays private on the `dnsnet` network at a static IP (`172.28.0.2`) that auth
forwards to.

```bash
sudo make docker        # build images, start the servers in dns.conf + daily cron
sudo make docker-down   # stop containers, remove images + daily cron
```

### Configuration: `dns.conf`

**One file** drives both the Docker deployment *and* the native build
(`cron_scripts/dns-startup` reads the same file). Edit `dns.conf`, then re-run
`sudo make docker`. Each server is independent, with its own flags and an
enable/disable toggle:

```sh
AUTH_ENABLED=true          # run the authoritative front door (:53)?
UPSTREAM_ENABLED=true      # run the recursive resolver?
AUTH_THREADS=20            # per-server flags: threads, queue, drop-user,
UPSTREAM_THREADS=20        #   rate limit, ACL CIDRs, bind addr, block mode ...
```

- **Just auth:** `AUTH_ENABLED=true`, `UPSTREAM_ENABLED=false`, and set
  `AUTH_UPSTREAM_IP` to an external resolver (e.g. `1.1.1.1`).
- **Just upstream:** `UPSTREAM_ENABLED=true`, `AUTH_ENABLED=false`.
- **Both (default):** leave `AUTH_UPSTREAM_IP` blank — auth auto-targets the
  bundled upstream.

`make docker` reads `dns.conf`, builds each server's flags
(`cron_scripts/dns-args.sh` — the same builder the native launcher uses), and
starts only the enabled servers via Compose profiles. The compose file itself
holds no config and reads no env file.

### Required host-daemon setting (client source IP)

`auth_dns` rate-limits and applies ACLs per **client source IP**. Under the
default Docker bridge, published-port traffic is SNAT'd and every query appears
to come from the gateway — which collapses rate limiting and breaks ACLs/logs.
Set this once per host in `/etc/docker/daemon.json`, then restart Docker:

```json
{ "userland-proxy": false }
```

This makes DNAT preserve the real client IP. (For maximum fidelity a `macvlan`
network — giving the container its own LAN IP — is an alternative.)

### Multi-arch release to GHCR

```bash
docker login ghcr.io
docker run --privileged tonistiigi/binfmt          # once, for cross-arch builds
make release VERSION=1.0 GHCR_OWNER=<your-gh-user>  # builds arm64+amd64, pushes
```

### Deploy on another host

DNSSEC keys (`config/*.pem|*.key`) are gitignored — provision them into the
`config/` dirs out-of-band first. Then pull the pre-built images and start the
servers selected in `dns.conf` (no local build):

```bash
git clone <repo> && cd dns          # provides compose + dns.conf + misc/ + config.txt
docker login ghcr.io
export GHCR_OWNER=<your-gh-user> DNS_TAG=1.0
make deploy                         # pulls from GHCR, starts per dns.conf
```

---

## Running

Start the upstream resolver first, then the authoritative server.

```bash
# Upstream resolver (port 5335, 20 threads)
./upstream_dns/bin/upstream_dns -p 5335 -t 20 -q 100

# Authoritative server (always listens on port 53; forwards to upstream at 127.0.0.1:5335)
sudo ./auth_dns/bin/auth_dns -u 127.0.0.1 -p 5335 -t 20 -q 100
```

Port 53 requires root (or `CAP_NET_BIND_SERVICE`).

---

## auth_dns flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u HOST` | Upstream resolver IPv4 address (bare IP — no port) | 1.1.1.1 |
| `-p PORT` | Upstream resolver **port** | 53 |
| `-t N` | Number of worker threads | 20 |
| `-q N` | Thread pool queue depth | 100 |
| `-b ADDR` | Listen address to bind (IPv4 or IPv6) | `0.0.0.0` / `::` |
| `-a CIDRS` | **Recursion** allow-list, comma-separated CIDRs (replaces defaults) | loopback + RFC1918 + link-local |
| `-r N` | Per-source rate limit for recursion, queries/sec (`0` = off) | `0` |

> **Note:** the authoritative server always listens on **port 53** (a compile-time
> constant); there is no flag to change its listen port. `-p` sets the *upstream*
> port and `-u` takes a bare IPv4 address — pass them separately
> (`-u 127.0.0.1 -p 5335`), not as `host:port`.

> **Access control:** `-a`/`-r` gate only the **recursive/forwarding** path —
> authoritative answers for your own zones are served to every source. See
> [Access control](#access-control) below.

### What it serves

- **A, AAAA, MX, NS, SOA, TXT, CNAME, SRV** — from the `[domain]` sections of `auth_dns/misc/config.txt`
- **DNSKEY** — if DNSSEC signing keys are configured
- **ANY** — returns an RFC 8482 HINFO response (minimal, not a full dump)
- **NXDOMAIN** — domains in the `[blocklist]` section return NXDOMAIN immediately, no forwarding
- **Everything else** — forwarded to the upstream resolver

Responses include a **SOA record in the authority section** for NXDOMAIN and NODATA answers (RFC 2308).

---

## upstream_dns flags

| Flag | Description | Default |
|------|-------------|---------|
| `-p PORT` | Port to listen on | 5335 |
| `-t N` | Number of worker threads | 20 |
| `-q N` | Thread pool queue depth | 100 |
| `-b ADDR` | Listen address to bind (IPv4 or IPv6) | `0.0.0.0` / `::` |
| `-a CIDRS` | Client allow-list, comma-separated CIDRs (replaces defaults) | loopback + RFC1918 + link-local |
| `-r N` | Per-source rate limit, queries/sec (`0` = off) | `0` |

> **Access control:** every query to the upstream resolver is checked against
> the allow-list (it is a pure recursive resolver). See
> [Access control](#access-control) below.

### How it resolves

1. Checks the **answer cache** first — serves cached responses with TTLs decremented to reflect time already elapsed (RFC 1034 §4.1.3).
2. Checks the **NS cache** — if it knows a nameserver for the target zone, starts from there instead of root.
3. Falls back to **root hints** (`upstream_dns/misc/root_hints.txt`) and walks the full delegation chain. If the hints file is missing, hardcoded IPs for all 13 root servers are used.
4. When a CNAME is encountered mid-chain, the resolver automatically follows it and reconstructs the response.
5. When a UDP answer arrives truncated (TC=1), the resolver automatically retries over TCP.

The NS cache is keyed on zone apex (e.g. `example.com`, not `www.example.com`) so all names in a zone share one cache entry. Expired entries are pruned every 60 seconds by a background thread.

---

## Config file format

Authoritative records and the blocklist share one file, `auth_dns/misc/config.txt`:
records go in `[domain]` sections, blocked names in the `[blocklist]` section.
Lines starting with `#` are comments.

```
# Record types:
#   A:        domain ip_address
#   AAAA:     domain ipv6_address
#   NXDOMAIN: domain NXDOMAIN
#   MX:       domain MX priority hostname
#   NS:       domain NS nameserver-hostname
#   CNAME:    domain CNAME canonical-name
#   TXT:      domain TXT "text data"
#   SRV:      domain SRV priority weight port target
#   SOA:      domain SOA primary-ns admin-email serial refresh retry expire minimum
```

**Bare A/AAAA records** (no type keyword) default to A:

```
avilo.com 192.168.1.2
avilo.com 2001:db8::1
```

**Full zone example:**

```
avilo.com SOA ns1.avilo.com hostmaster.avilo.com 2026022802 3600 900 604800 300
avilo.com NS ns1.avilo.com
avilo.com NS ns2.avilo.com
avilo.com 192.168.1.2
avilo.com MX 10 mail.avilo.com
avilo.com TXT "v=spf1 mx -all"
www.avilo.com CNAME avilo.com
mail.avilo.com 192.168.1.4
ns1.avilo.com 192.168.1.2
_imaps._tcp.avilo.com SRV 10 1 993 mail.avilo.com

# Block a domain
ads.google.com NXDOMAIN
```

**SOA fields:** `serial refresh retry expire minimum` — all in seconds except serial (use YYYYMMDDNN format). Negative caching TTL comes from `minimum`.

Wildcards are supported for A and AAAA using `*.zone` syntax.

Reload zone data without restarting:

```bash
kill -HUP $(pidof auth_dns)   # auth_dns only
```

---

## Access control

Both servers are intended for a **trusted LAN**. To prevent abuse as an open
recursive resolver (DNS-amplification DDoS) and to limit remote attack surface,
client access is controlled in two layers:

**Allow-list (`-a`)** — a list of CIDRs permitted to use recursion. The default
covers loopback, RFC1918 private ranges, and link-local addresses:

```
127.0.0.0/8  10.0.0.0/8  172.16.0.0/12  192.168.0.0/16  169.254.0.0/16
::1/128  fc00::/7  fe80::/10
```

Passing `-a` **replaces** the defaults, so include loopback / your own LAN range
explicitly:

```bash
./upstream_dns/bin/upstream_dns -a 127.0.0.1/32,192.168.1.0/24
```

- On the **upstream resolver**, the allow-list gates *every* query (it is a pure
  recursive resolver). Non-allowed sources receive **REFUSED**.
- On the **authoritative server**, the allow-list gates only the
  **recursive/forwarding** path. Authoritative answers for your own zones are
  served to any source; only forwarded queries from non-allowed sources are
  **REFUSED**.

**Rate limiting (`-r`)** — a per-source-IP token bucket. `-r 50` allows ~50
queries/sec per client (burst 100). Over-limit UDP queries are dropped silently
(responding would still amplify); `0` (default) disables it.

**Bind address (`-b`)** — for defense in depth, bind the listener to a specific
LAN interface instead of all interfaces. The port is then not even open on
untrusted networks:

```bash
./upstream_dns/bin/upstream_dns -b 192.168.1.10
sudo ./auth_dns/bin/auth_dns -b 192.168.1.10 -u 127.0.0.1 -p 5335
```

A bare IPv4 address binds the IPv4 sockets only; an IPv6 address binds the IPv6
sockets only. With no `-b`, both families listen on the wildcard address.

---

## DNSSEC

### Upstream — validation

The upstream resolver validates DNSSEC signatures on answers when the client sends a query with the DO bit set (EDNS). It walks the full **chain of trust**:

```
Root KSK (trust anchor) -> Root ZSK signs DS(com) -> com KSK <- DS(com)
-> com ZSK signs DS(example.com) -> example.com KSK <- DS(example.com) -> ...
```

At each delegation hop, the referral's DS records are verified against the parent's already-validated DNSKEY before being trusted. Validated intermediate keys are carried through the resolution walk so the final answer can be verified against them.

When validation succeeds, the response is returned to the client with the **AD bit set**. When validation fails, the resolver returns **SERVFAIL**. When a zone is unsigned (no RRSIG/DS), the response passes through as-is.

The AD bit is set **only** when the RRset that actually answers the question (or the terminal RRset of an in-packet CNAME chain) is covered by a verified RRSIG whose signer is in-bailiwick for the owner — a validated-but-irrelevant signature (e.g. a signed SOA alongside a forged answer) is not sufficient. Any AD bit present on the upstream response is cleared before our own validation runs, so a downstream client can trust AD as reflecting *this* resolver's validation.

The **root trust anchor** lives at `upstream_dns/config/root-trust-anchor.key` (KSK-2017, key tag 20326, algorithm 8 / RSA-SHA256).

Clients can set the **CD (Checking Disabled)** bit to bypass validation and receive raw responses.

Supported signature algorithms: RSA-SHA1 (alg 5), RSA-SHA256 (alg 8), RSA-SHA512 (alg 10), ECDSA-P256 (alg 13), ECDSA-P384 (alg 14), Ed25519 (alg 15).

### Auth — signing

If DNSSEC signing keys are present in `auth_dns/config/`, the server signs responses on the fly when clients request it (DO=1). Responses include RRSIG records. DNSKEY records are served on request.

Keys are configured in `auth_dns/config/dnssec.conf` (INI format, PEM key files). If the config is absent, signing is silently disabled — normal DNS still works.

---

## Signals

Both servers handle the same signals:

| Signal | Effect |
|--------|--------|
| `SIGINT`, `SIGTERM`, `SIGQUIT` | Graceful shutdown |
| `SIGHUP` | auth_dns: reload zone file. upstream_dns: reload root hints. |
| `SIGUSR1` or `SIGUSR2` | Print per-QTYPE query statistics to stdout |

```bash
kill -USR1 $(pidof auth_dns)    # dump stats (auth_dns)
kill -USR1 $(pidof upstream_dns) # dump stats (upstream_dns)
kill -HUP  $(pidof auth_dns)    # reload zone file
kill -HUP  $(pidof upstream_dns) # flush NS cache / reload hints
```

---

## Logs

Both servers write to the `logs/` directory (at the root of the repository):

- `auth_dns` logs go to `auth.log`
- `upstream_dns` logs go to `upstream.log`

Log format — CSV, one row per query:
`timestamp,client_ip,port,qtype,domain,rcode,info`

```
2026-03-07 14:23:01,192.168.1.10,54321,A,www.google.com,NOERROR,142.250.80.36
2026-03-07 14:23:02,192.168.1.10,54322,A,ads.google.com,NXDOMAIN,
```

The `info` column is empty when there is no answer detail; multiple answer IPs
are space-separated within that single column so the CSV stays well-formed.

---

## File layout

```
dns/
├── auth_dns/
│   ├── bin/auth_dns               # compiled binary
│   ├── src/                       # source code
│   ├── misc/
│   │   └── config.txt            # zone records + blocklist
│   └── config/
│       ├── dnssec.conf            # DNSSEC signing key config (optional)
│       └── *.pem                  # zone signing keys (optional)
│
├── upstream_dns/
│   ├── bin/upstream_dns           # compiled binary
│   ├── src/                       # source code
│   ├── misc/
│   │   └── root_hints.txt         # root server IPs (falls back to built-in)
│   └── config/
│       └── root-trust-anchor.key  # DNSSEC root trust anchor
│
└── logs/
    ├── auth.log
    └── upstream.log
```

---

## EDNS

Both servers speak EDNS0 (RFC 6891). The upstream resolver sets the DO bit on all outgoing queries so it receives DNSSEC records from nameservers. Auth responses respect the client's advertised UDP payload size and set TC=1 with truncation when a response would exceed it.

EDNS version 1+ is rejected with BADVERS per RFC 6891.
