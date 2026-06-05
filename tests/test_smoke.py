"""Smoke tests — if these fail, nothing downstream matters."""
from __future__ import annotations

import dns.flags
import dns.rcode

from helpers.dns_client import udp_query


def test_auth_server_alive(auth_addr):
    """auth_dns answers SOA for an owned zone."""
    r = udp_query("avilo.com.", "SOA", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    assert r.flags & dns.flags.AA, "auth response should have AA bit"
    assert len(r.answer) >= 1


def test_upstream_server_alive(upstream_addr):
    """upstream_dns answers (even REFUSED is fine — we only care it's not dead)."""
    r = udp_query("probe.invalid.test.", "A", *upstream_addr)
    # Any response is acceptable — we just want to prove the process is responsive
    assert r is not None
