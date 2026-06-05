"""Signal handling: SIGUSR1 stats dump, SIGHUP zone/hints reload.

The production daemons are owned by root, so we use `sudo -n kill` (requires
passwordless sudo — the suite skips otherwise). These tests are deliberately
minimal: they verify the server doesn't crash on each signal and continues
serving afterwards. Verifying that stats were actually printed would require
attaching to the screen session.
"""
from __future__ import annotations

import os
import signal
import subprocess
import time

import dns.rcode
import pytest

from helpers.dns_client import udp_query


pytestmark = pytest.mark.needs_sudo

# Opt-in flag for tests that demonstrate the stats-pipe wedge bug by actually
# wedging the daemon. Off by default — turning it on requires manually
# restarting the affected daemon afterwards.
_DANGEROUS = os.environ.get("DNS_TESTS_DANGEROUS") == "1"


def _kill(pid: int, sig: int) -> None:
    """Send a signal to a root-owned process via sudo."""
    subprocess.run(
        ["sudo", "-n", "kill", f"-{sig}", str(pid)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def _still_alive(auth_addr) -> bool:
    """Smoke probe — does the auth server still answer?"""
    try:
        r = udp_query("avilo.com.", "SOA", *auth_addr, timeout=1.5)
        return dns.rcode.to_text(r.rcode()) == "NOERROR"
    except Exception:  # noqa: BLE001
        return False


def test_sigusr1_stats_does_not_crash_auth(auth_addr, auth_pid):
    """SIGUSR1 / SIGUSR2 print stats — server must keep serving on UDP.

    NOTE: this passes only because auth uses SO_REUSEPORT UDP workers — the
    main thread's pipe-drain loop blocks forever (same bug as upstream), but
    the workers are independent and keep serving UDP. The TCP listener and
    SIGHUP reload, which both go through main, ARE broken after SIGUSR1 —
    see test_tcp_after_sigusr1_is_wedged below.
    """
    _kill(auth_pid, signal.SIGUSR1)
    time.sleep(0.2)
    assert _still_alive(auth_addr), "auth_dns died after SIGUSR1"


def test_sigusr2_stats_does_not_crash_auth(auth_addr, auth_pid):
    _kill(auth_pid, signal.SIGUSR2)
    time.sleep(0.2)
    assert _still_alive(auth_addr), "auth_dns died after SIGUSR2"


def test_sighup_reload_does_not_crash_auth(auth_addr, auth_pid):
    """SIGHUP reloads zone file + DNSSEC keys + reopens log fd. We're not
    modifying the zone file, so the reload is a no-op data-wise — but it
    exercises the reload code path.

    SIGHUP is processed at the top of the main loop, BEFORE the pipe drain,
    so SIGHUP alone (without a prior SIGUSR1) still works."""
    _kill(auth_pid, signal.SIGHUP)
    time.sleep(0.4)  # give the main loop a chance to process the flag
    assert _still_alive(auth_addr), "auth_dns died after SIGHUP"
    # And the same record should still answer correctly after the reload
    r = udp_query("avilo.com.", "A", *auth_addr)
    addrs = {rr.address for rs in r.answer for rr in rs}
    assert "192.168.1.2" in addrs, "post-SIGHUP record content changed unexpectedly"


@pytest.mark.skipif(
    not _DANGEROUS,
    reason="Sends SIGUSR1 then probes TCP — demonstrates the pipe-drain bug. "
           "Opt in with DNS_TESTS_DANGEROUS=1.",
)
@pytest.mark.xfail(strict=True,
    reason="Same root cause as the upstream signal bug: after SIGUSR1, the "
           "main thread's stats-pipe drain loop blocks on the second read() "
           "because the read end isn't O_NONBLOCK. UDP workers keep going "
           "but the TCP listener (which uses poll() in main) wedges.",
)
def test_tcp_after_sigusr1_is_wedged(auth_addr, auth_pid):
    """After SIGUSR1, the main thread's poll loop is stuck inside the pipe
    drain — so the TCP accept loop never runs. New TCP connections hang."""
    _kill(auth_pid, signal.SIGUSR1)
    time.sleep(0.5)
    # Probe TCP — this should hang/fail if the main thread is wedged
    import socket
    import struct
    from dns.message import make_query
    q = make_query("avilo.com.", "SOA")
    payload = q.to_wire()
    with socket.create_connection((auth_addr[0], auth_addr[1]), timeout=2.0) as s:
        s.settimeout(2.0)
        s.sendall(struct.pack("!H", len(payload)) + payload)
        s.recv(2)  # length prefix — will time out if main is wedged


@pytest.mark.skipif(
    not _DANGEROUS,
    reason="SIGUSR1 to upstream_dns wedges the daemon (see test docstring). "
           "Opt in with DNS_TESTS_DANGEROUS=1 (will require restarting upstream).",
)
@pytest.mark.xfail(strict=True,
    reason="KNOWN BUG: in main.c the stats-pipe drain loop "
           "`while (read(stats_pipe[0], buf, sizeof(buf)) > 0) {}` blocks forever "
           "after the first read because stats_pipe[0] is NOT set O_NONBLOCK "
           "(only stats_pipe[1] is). Auth survives this same bug because its "
           "UDP workers are SO_REUSEPORT-independent of the main thread; "
           "upstream_dns's main thread serves UDP itself, so the whole server "
           "wedges. Fix: set O_NONBLOCK on stats_pipe[0] at pipe setup, or "
           "change the drain to use ioctl FIONREAD or a single recv.",
)
def test_sigusr1_wedges_upstream(upstream_addr, upstream_pid):
    _kill(upstream_pid, signal.SIGUSR1)
    time.sleep(1.0)
    from dns.message import make_query
    from dns.query import udp as dns_udp
    q = make_query("probe.invalid.test.", "A")
    last = None
    for _ in range(4):
        try:
            r = dns_udp(q, upstream_addr[0], port=upstream_addr[1], timeout=2.0)
            assert r is not None
            return
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(0.5)
    raise AssertionError(f"upstream did not respond after SIGUSR1: {last!r}")


@pytest.mark.skipif(
    not _DANGEROUS,
    reason="SIGHUP to wedged upstream_dns also can't recover (see SIGUSR1 test). "
           "Opt in with DNS_TESTS_DANGEROUS=1.",
)
def test_sighup_reload_does_not_crash_upstream(upstream_addr, upstream_pid):
    """SIGHUP on a wedged upstream — does not exercise the reload path because
    the main loop never reaches the SIGHUP check. Only run after fixing the
    pipe-drain bug above."""
    _kill(upstream_pid, signal.SIGHUP)
    time.sleep(1.0)
    from dns.message import make_query
    from dns.query import udp as dns_udp
    q = make_query("probe.invalid.test.", "A")
    r = dns_udp(q, upstream_addr[0], port=upstream_addr[1], timeout=3.0)
    assert r is not None
