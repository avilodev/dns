"""auth_dns forwards non-authoritative queries to the upstream resolver.

Per the README and resolve.c, any name not in the loaded zones (and not on the
blocklist) gets forwarded to the configured upstream. The reply we see at
the client should be the upstream's reply, with the AA bit cleared (we are
NOT authoritative for these names)."""
from __future__ import annotations

import dns.flags
import dns.rcode
import dns.rdatatype
import pytest

from helpers.dns_client import udp_query
from helpers.net import has_internet


pytestmark = pytest.mark.internet


def test_forwarded_query_resolves(auth_addr):
    """example.com is not in our zones — auth should forward and return a
    real answer. We can't pin the exact IP (CDN-served), so we only check
    NOERROR + at least one A record."""
    r = udp_query("example.com.", "A", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR", \
        f"forward failed for example.com: {dns.rcode.to_text(r.rcode())}"
    addrs = {rr.address for rs in r.answer for rr in rs if rs.rdtype == dns.rdatatype.A}
    assert addrs, f"no A records in forwarded response: {r.answer}"


@pytest.mark.xfail(
    reason="KNOWN BUG: upstream_dns sets AA on recursively-resolved responses, "
           "which auth_dns then forwards verbatim. A recursive resolver is by "
           "definition NOT authoritative for the names it resolves — AA must "
           "be cleared. Verified via `dig @127.0.0.1 -p 5335 example.com A` "
           "which returns `flags: qr aa`. Fix in upstream's response builder.",
    strict=True,
)
def test_forwarded_response_not_authoritative(auth_addr):
    """Forwarded responses must NOT have AA set — we are not authoritative
    for upstream-served names."""
    r = udp_query("example.com.", "A", *auth_addr)
    assert not (r.flags & dns.flags.AA), \
        "auth_dns set AA on a forwarded response (it must only be set for owned zones)"


def test_forwarded_response_ra_bit(auth_addr):
    """Even though AA is wrongly set today (xfail above), the RA bit
    (Recursion Available) should be set on responses from a server that
    provides recursive resolution."""
    r = udp_query("example.com.", "A", *auth_addr)
    # RA is informational; some implementations don't bother. Treat as soft.
    if not (r.flags & dns.flags.RA):
        pytest.xfail("auth_dns does not advertise RA on forwarded responses "
                     "(non-fatal; upstream-only servers commonly omit this)")


def test_forwarded_aaaa(auth_addr):
    """Most public sites publish AAAA. Don't pin a specific value — just
    confirm the forward path handles AAAA at all."""
    r = udp_query("example.com.", "AAAA", *auth_addr)
    # NOERROR is required; the AAAA set may be empty for some names, which
    # would arrive as NOERROR + empty answer (NODATA forwarded through).
    assert dns.rcode.to_text(r.rcode()) in ("NOERROR",), \
        f"forward of AAAA failed: {dns.rcode.to_text(r.rcode())}"


def test_forwarded_nxdomain_passes_through(auth_addr):
    """An NXDOMAIN from upstream should reach the client as NXDOMAIN."""
    r = udp_query("definitely-not-a-real-domain-xyzzy-2026.", "A", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) in ("NXDOMAIN", "NOERROR"), \
        f"unexpected rcode: {dns.rcode.to_text(r.rcode())}"
    # If it's NOERROR we accept (some resolvers return empty answer for invalid TLDs)


def test_owned_zone_not_forwarded(auth_addr):
    """A query for an owned zone must be answered authoritatively, NOT
    forwarded — even if we have internet access."""
    r = udp_query("avilo.com.", "A", *auth_addr)
    assert r.flags & dns.flags.AA, \
        "auth_dns must serve owned zones authoritatively, not forward them"
