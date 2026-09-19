# DNS scan — fix status (2026-09-18)

Legend: ✅ done & verified on ASAN/UBSAN test builds · 🟡 partly done · ⏸ not done (see note)

Deploy: `make` rebuilt both binaries in place; the RUNNING servers still run the old code
until restarted (sudo).

## Round 2 (all ✅)
- ✅ All 250 unaligned `*(uint16_t*)` / `*(uint32_t*)` wire accesses replaced by alignment-safe
  rd16/rd32/wr16/wr32 (wire_io.h). UBSan: 0 reports.
- ✅ Warnings: 0 under -Wall -Wextra plus -Wshadow -Wformat=2 -Wstrict-prototypes
  -Wmissing-prototypes -Wcast-qual -Wlogical-op -Wnull-dereference …; 0 from gcc -fanalyzer.
- ✅ Dead `domain`/`top_level_domain`/`authoritative_domain` fields removed (never read; dot-split).
- ✅ Zone loader: inline `# comments` (quote-aware); invalid/over-long section names rejected with a warning.
- ✅ TCP idle limit (2 s) now applies from connection start in both servers (was 5 s before first query).
- ✅ README config section rewritten to the real `[name]` format; dnssec.conf / docker healthcheck
  no longer reference removed zones.
- ✅ Fuzz harness source lists include dns_name.c (verified with a gcc-built random driver, 200k inputs).

 1. The resolver has had no root hints since 06:25, so every uncached lookup returns SERVFAIL (L). This morning's refresh-root-hints cron job downloaded new hints and sent a reload signal (SIGHUP). The resolver now
  runs as nobody, and nobody can't get into /home/avilo, which is locked down to your user only (0700). The log shows Failed to open hints file: Permission denied. The reload code frees the old hints before loading the
  new ones and doesn't fall back to the built-in list, so none are left (upstream_dns/src/main.c:344). The resolver's query log also stopped at 06:25 for the same reason. Restart upstream_dns now, then either run
  chmod 711 /home/avilo or move the install out of your home directory.
      → ✅ DONE — hints load into a private table and swap in under a lock only if usable; a failed reload keeps the current hints. Hints file + log are opened via a directory fd pinned before the privilege drop, so reloads work despite the 0700 home. (Live resolver still needs a restart to pick this up.)

  🔴 Critical

  2. The same permission problem breaks a reload of auth (T). The reload step config.txt documents is kill -HUP. When that happens, the zones are kept, but policy_load swaps in an empty blocklist
     (auth_dns/src/policy.c:187-213) and the log fails to reopen, so logging stops.
      → ✅ DONE — config/log pinned the same way; a failed blocklist load keeps the current blocklist; a failed log reopen keeps the old fd.
  3. Heap overflow in auth when forwarding over TCP (T, caught by ASAN). The resolver's TCP replies carry no EDNS record (upstream_dns/src/workers.c:334). Auth then appends 11 bytes to a buffer sized exactly to the
     reply (auth_dns/src/response.c:440, buffer allocated at resolve.c:132). Any +tcp query, or a client retrying over TCP, for a name that has a CNAME corrupts auth's heap.
      → ✅ DONE — auth sizes TCP answer buffers to at least MAXLINE; the resolver now adds an OPT to TCP replies for EDNS clients. ASAN clean.
  4. CNAME answers over 512 bytes get stuck as empty truncated replies (T). upstream_dns/src/cname_handler.c:574 cuts every rebuilt CNAME answer at 512 bytes, even over TCP and for clients that support larger replies.
     That empty reply is then cached (resolve.c:688), with no answers so it gets the default 3600 s. www.gov.uk became unresolvable for every client, over UDP and TCP.
      → ✅ DONE — 512-byte cut removed (transport truncates per client EDNS size); TC=1 answers are never cached; header counts track RRs actually written. www.gov.uk resolves over UDP and TCP.
  5. CNAMEs in your own zones aren't followed (L). www.avilo.com A returns only the CNAME, and getent ahosts www.avilo.com fails, so real clients can't reach it (auth_dns/src/auth.c:656). A server your clients query
     directly has to return the target's records as well. This is most likely the "authoritative domains" problem you've seen.
      → ✅ DONE — auth follows CNAME chains: in-zone targets inline, external targets via upstream (recursion-gated), merged into one answer (RFC 6604 RCODE).

  🟠 High

  6. Every resolver failure costs clients 5 seconds (L). The resolver sends SERVFAIL with no question section (udp_helpers.c:14). Auth rejects that as a mismatched reply (auth_dns/src/resolve.c:317) and waits out its
     timeout: 5145 ms through auth versus 18 ms direct.
      → ✅ DONE — error replies from both servers echo the question; auth also fails fast on a question-less error reply. 5145 ms → 15 ms.
  7. Local answers can wait behind slow forwards (T). Each auth UDP worker handles recursion synchronously, so a local zone answer can sit behind a 5 s forward from the same client socket. Measured: avilo.com took 5.17
     s. The TXT timeout I hit earlier on the live server matches this.
      → ✅ DONE — UDP receive threads only answer locally; forwarding runs in a separate forwarder pool. Local answer now 0.22 s behind a stalled forward.
  8. Four idle TCP connections stall all TCP in auth for about 5 s (T). The TCP pool is capped at 4 threads (main.c:652). The resolver shares one pool for TCP and UDP, so 20 idle TCP connections block all uncached
     resolution there.
      → ✅ DONE — auth TCP pool = thread count (min 4) with a 2 s idle timeout between pipelined queries; resolver TCP has its own pool.
  9. Negative "no such record type" answers are cached for 3600 s regardless of the zone's SOA (cache.c:564, RFC 2308). A newly added record can stay invisible for up to an hour.
      → ✅ DONE — negative answers use min(SOA TTL, SOA MINIMUM); negatives without an SOA are not cached.
  10. One misbehaving nameserver can fail the whole lookup. An upward or lame referral, or a response with no answer and no AA flag, is a hard SERVFAIL (resolve.c:788, :967), and the remaining nameservers are never
      tried.
      → ✅ DONE — lame/upward referrals and malformed replies fall through to sibling nameservers (shared next_ns_candidate helper).
  11. SOA queries for names below the zone apex return a fake SOA (L). For example, mail.avilo.com SOA comes back with that name as the owner (auth.c:709). It should be NODATA with the SOA in the authority section.
      → ✅ DONE — non-apex SOA queries return NODATA with the zone SOA in authority.

  🟡 Medium

  12. False "referral loop" detection: loops are tracked by server IP, so a nameserver IP that appears again fails the lookup outright (resolve.c:311).
      → ✅ DONE — loop detection keys on (server IP, zone).
  13. The nameserver cache is only checked for the exact query name or the TLD (resolve.c:216), so zone-level entries are almost never reused.
      → ✅ DONE — NS cache walks every suffix of the name, deepest first (DS queries start at the parent).
  14. Use-after-free race: free_hints() runs while worker threads are reading g_hints without a lock.
      → ✅ DONE — all g_hints access goes through a rwlock (hints_random_root_ip / hints_copy_names).
  15. TCP fallback rejects answers over 4096 bytes (udp_client.c:394). Truncated replies with empty sections hit the "Unexpected response format" error.
      → ✅ DONE — TCP fallback accepts up to 65535 bytes; any non-referral TC reply (incl. empty sections) retries over TCP.
  16. The resolver advertises a 4096-byte EDNS buffer to other servers (dns_packet.c:151). DNS Flag Day 2020 recommends 1232 to avoid dropped fragments.
      → ✅ DONE — EDNS_UDP_PAYLOAD = 1232 outbound; replies to clients are also capped at 1232.
  17. -u accepts an IPv6 upstream address, but forwarding only works over IPv4, so every forward would fail.
      → ✅ DONE — auth forwards to IPv4 or IPv6 upstreams (tested with -u ::1).
  18. TXT records written as several quoted strings ("a" "b", common for DKIM) are parsed as one string with the quotes inside it (auth_zonefile.c:186).
      → ✅ DONE — TXT parsed into proper character-strings ("a" "b", escapes, >255 split).
  19. Config: avilo.com AAAA 2001:db8::1 is a documentation-only address and isn't routable, so IPv6 clients stall before falling back to IPv4.
      → ✅ DONE (config) — per your note that only pi5.priv / pi3.priv are used, the avilo.com, avilo.priv and adoliva.com zones were removed from config.txt (the bogus AAAA went with them).
  20. Config: the .priv hosts have no SOA. Names under them, and private reverse (PTR) lookups, are sent out to the internet instead of being answered locally (RFC 6303; consider using .internal).
      → ✅ DONE — config.txt now has a [priv] zone (SOA + NS) so any unlisted .priv name gets a local NXDOMAIN instead of leaking to the internet; RFC 6303 private reverse zones answered locally.

  🟢 Low

  21. Wildcards only match one label deep, and they override empty non-terminals (RFC 4592).
      → ✅ DONE — wildcards use the closest encloser (any depth) and never override empty non-terminals.
  22. SERVFAIL, REFUSED and NOTIMP replies carry no question section. Strict stub resolvers such as glibc ignore these and wait until they time out.
      → ✅ DONE — SERVFAIL/REFUSED/NOTIMP/FORMERR echo the question in both servers (UDP and TCP).
  23. Queries that can't be parsed get SERVFAIL instead of FORMERR.
      → ✅ DONE — unparseable queries get FORMERR; QR=1 packets are dropped instead of answered.
  24. The resolver's cache fast path doesn't check the opcode.
      → ✅ DONE — cache fast path only serves opcode QUERY.
  25. A 60 s minimum is applied to all cached TTLs.
      → ✅ DONE — no 60 s floor on answer TTLs; TTL 0 is not cached; CNAME TTLs are kept as published.
  26. Log lines that get truncated lose their trailing newline, so entries run together.
      → ✅ DONE — truncated log lines keep their trailing newline (both loggers).
  27. The log labels "no such record type" answers as "NXDOMAIN".
      → ✅ DONE — empty NOERROR answers are logged as NODATA.
  28. quick_parse_query and similar code assume names have no dots inside a label, which is rare in practice.
      → ✅ DONE — new dns_name.c codec (one per server): RFC 1035 §5.1 escapes (\. \\ \DDD); every wire<->text conversion, suffix walk, bailiwick check, NSEC ordering and CNAME compression now goes through it. Question echoed byte-for-byte for labels containing dots/binary; results match 1.1.1.1.