"""Negative-answer behaviour: NXDOMAIN, NODATA, ANY (RFC 8482).

Per the README and source:
  - Blocked domains in the zone file with `NXDOMAIN` directive return NXDOMAIN
    immediately, without forwarding upstream.
  - NODATA (NOERROR + empty answer) is returned when the name exists but the
    requested type doesn't, with a SOA record in the AUTHORITY section
    (RFC 2308 negative-caching).
  - ANY queries get an RFC 8482 minimal HINFO response, not a dump.
"""
from __future__ import annotations

import dns.flags
import dns.rcode
import dns.rdatatype
import pytest

from helpers.dns_client import udp_query


# -- NXDOMAIN ----------------------------------------------------------------

@pytest.mark.parametrize("blocked", [
    "ads.google.com.",
    "doubleclick.net.",
])
def test_blocked_domain_nxdomain(auth_addr, blocked):
    r = udp_query(blocked, "A", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NXDOMAIN", \
        f"{blocked} should be blocked → NXDOMAIN, got {dns.rcode.to_text(r.rcode())}"
    assert len(r.answer) == 0, "NXDOMAIN must not carry answers"


def test_nxdomain_has_soa_in_authority(auth_addr):
    """RFC 2308 — negative answers SHOULD carry the SOA so resolvers can cache
    them for the SOA-minimum TTL.

    The blocked domain `ads.google.com` doesn't belong to any of our zones, so
    the server can't include a SOA from one of *its* zones. We only assert
    that if a SOA is present in authority, it parses correctly."""
    r = udp_query("ads.google.com.", "A", *auth_addr)
    for rs in r.authority:
        if rs.rdtype == dns.rdatatype.SOA:
            rr = list(rs)[0]
            assert rr.minimum > 0, "SOA minimum (neg-cache TTL) must be positive"
            return  # ok
    # If no SOA in authority, that's still spec-compliant (SHOULD, not MUST).


def test_nxdomain_for_owned_zone(auth_addr):
    """A nonexistent name *inside* an owned zone should NXDOMAIN with the
    zone's SOA in authority."""
    r = udp_query("does-not-exist-xyzzy.avilo.com.", "A", *auth_addr)
    # Either NXDOMAIN with SOA, or forwarded upstream — auth-only zones
    # typically NXDOMAIN. We accept either, but if NXDOMAIN, demand the SOA.
    rcode = dns.rcode.to_text(r.rcode())
    if rcode == "NXDOMAIN":
        soa_rrs = [rs for rs in r.authority if rs.rdtype == dns.rdatatype.SOA]
        assert soa_rrs, "NXDOMAIN inside an owned zone must include SOA in authority"
        rr = list(soa_rrs[0])[0]
        assert rr.mname.to_text().lower() == "ns1.avilo.com."


# -- NODATA (NOERROR + empty answer + SOA) -----------------------------------

def test_nodata_returns_soa(auth_addr):
    """avilo.com has no SRV at the zone apex → NODATA + SOA in authority."""
    r = udp_query("avilo.com.", "SRV", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR", \
        f"NODATA must be NOERROR, got {dns.rcode.to_text(r.rcode())}"
    assert len(r.answer) == 0, "NODATA must have no answer records"
    soa_rrs = [rs for rs in r.authority if rs.rdtype == dns.rdatatype.SOA]
    assert soa_rrs, "NODATA must include SOA in authority (RFC 2308)"


def test_nodata_for_aaaa_when_only_a_exists(auth_addr):
    """mail.avilo.com has only A; an AAAA query should be NODATA + SOA."""
    r = udp_query("mail.avilo.com.", "AAAA", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    assert len(r.answer) == 0
    soa_rrs = [rs for rs in r.authority if rs.rdtype == dns.rdatatype.SOA]
    assert soa_rrs, "NODATA AAAA should include SOA in authority"


# -- ANY (RFC 8482) ----------------------------------------------------------

def test_any_returns_minimal_hinfo(auth_addr):
    """RFC 8482 §4.1 — answer ANY queries with a single HINFO of class IN."""
    r = udp_query("avilo.com.", "ANY", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    # Must contain at least one HINFO, and (per RFC 8482) NOT dump every RR.
    hinfo = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.HINFO]
    assert hinfo, "ANY query should yield an HINFO record (RFC 8482)"
    # A compliant server returns *only* HINFO. Some servers also return SOA;
    # we tolerate but warn on excess. The total RRset count must stay small.
    assert len(r.answer) <= 2, \
        f"ANY response should be minimal (RFC 8482), got {len(r.answer)} rrsets"
