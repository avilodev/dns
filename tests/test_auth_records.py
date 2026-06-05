"""Authoritative record-type coverage.

The auth_dns daemon ships with three zones on disk:
  - avilo.com   (A 192.168.1.2, AAAA 2001:db8::1, MX, TXT, NS, SOA)
  - avilo.priv  (A 192.168.1.2, MX, NS, SOA)
  - adoliva.com (A 192.168.1.2, MX, NS, SOA)
plus per-host entries (www.avilo.com CNAME, mail.avilo.com A, etc).

Tests below pin the wire-format expectations so a regression in any RR encoder
fails loudly.
"""
from __future__ import annotations

import ipaddress

import dns.flags
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import pytest

from helpers.dns_client import udp_query


# -- A / AAAA ----------------------------------------------------------------

@pytest.mark.parametrize("name,expected_ip", [
    ("avilo.com.",        "192.168.1.2"),
    ("mail.avilo.com.",   "192.168.1.4"),
    ("ns1.avilo.com.",    "192.168.1.2"),
    ("ns2.avilo.com.",    "192.168.1.2"),
    ("mail.avilo.priv.",  "192.168.1.3"),
    ("ns1.avilo.priv.",   "192.168.1.2"),
    ("avilo.priv.",       "192.168.1.2"),
    ("adoliva.com.",      "192.168.1.2"),
    ("mail.adoliva.com.", "192.168.1.3"),
    ("pi5.priv.",         "192.168.1.2"),
    ("pi3.priv.",         "192.168.1.3"),
])
def test_a_records(auth_addr, name, expected_ip):
    r = udp_query(name, "A", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    assert r.flags & dns.flags.AA, f"missing AA flag for {name}"
    a_records = [rr for rs in r.answer for rr in rs if rs.rdtype == dns.rdatatype.A]
    addrs = {rr.address for rr in a_records}
    assert expected_ip in addrs, f"{name} A: expected {expected_ip}, got {addrs}"


def test_aaaa_record(auth_addr):
    r = udp_query("avilo.com.", "AAAA", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    addrs = {rr.address for rs in r.answer for rr in rs}
    assert any(ipaddress.ip_address(a) == ipaddress.ip_address("2001:db8::1") for a in addrs), \
        f"avilo.com AAAA expected 2001:db8::1, got {addrs}"


# -- MX / NS / TXT / SRV -----------------------------------------------------

@pytest.mark.parametrize("zone,priority,host", [
    ("avilo.com.",   10, "mail.avilo.com."),
    ("avilo.priv.",  10, "mail.avilo.priv."),
    ("adoliva.com.", 10, "mail.adoliva.com."),
])
def test_mx_records(auth_addr, zone, priority, host):
    r = udp_query(zone, "MX", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    mx_set = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.MX]
    assert mx_set, f"no MX rrset for {zone}"
    pairs = {(rr.preference, rr.exchange.to_text().lower()) for rr in mx_set[0]}
    assert (priority, host) in pairs, f"{zone} MX: expected {priority} {host}, got {pairs}"


def test_ns_records(auth_addr):
    r = udp_query("avilo.com.", "NS", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    ns_set = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.NS][0]
    names = {rr.target.to_text().lower() for rr in ns_set}
    assert {"ns1.avilo.com.", "ns2.avilo.com."}.issubset(names), \
        f"avilo.com NS expected ns1+ns2, got {names}"


def test_txt_record(auth_addr):
    r = udp_query("avilo.com.", "TXT", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    texts = []
    for rs in r.answer:
        if rs.rdtype != dns.rdatatype.TXT:
            continue
        for rr in rs:
            texts.extend(b"".join(rr.strings).decode("ascii", "replace") for _ in [0])
    assert any("v=spf1" in t for t in texts), f"expected SPF TXT, got {texts}"


def test_srv_record(auth_addr):
    r = udp_query("_imaps._tcp.avilo.com.", "SRV", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    srv = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.SRV][0]
    rr = list(srv)[0]
    assert rr.priority == 10
    assert rr.weight == 1
    assert rr.port == 993
    assert rr.target.to_text().lower() == "mail.avilo.com."


# -- SOA ---------------------------------------------------------------------

@pytest.mark.parametrize("zone,mname,rname", [
    ("avilo.com.",   "ns1.avilo.com.",   "hostmaster.avilo.com."),
    ("avilo.priv.",  "ns1.avilo.priv.",  "hostmaster.avilo.priv."),
    ("adoliva.com.", "ns1.adoliva.com.", "hostmaster.adoliva.com."),
])
def test_soa_record(auth_addr, zone, mname, rname):
    r = udp_query(zone, "SOA", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    soa = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.SOA][0]
    rr = list(soa)[0]
    assert rr.mname.to_text().lower() == mname
    assert rr.rname.to_text().lower() == rname
    # Per zone file: refresh=3600, retry=900, expire=604800, minimum=300
    assert rr.refresh == 3600
    assert rr.retry == 900
    assert rr.expire == 604800
    assert rr.minimum == 300
    # serial format is YYYYMMDDNN — at least 10 digits, plausible year
    assert 2020_00_00_00 <= rr.serial <= 2099_99_99_99, f"weird serial {rr.serial}"


# -- CNAME -------------------------------------------------------------------

def test_cname_record(auth_addr):
    """www.avilo.com is CNAME → avilo.com. Server should either return just the
    CNAME or follow it and return the A record too (auth servers commonly do
    both for in-zone CNAMEs)."""
    r = udp_query("www.avilo.com.", "A", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    cname_set = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.CNAME]
    assert cname_set, "no CNAME rrset for www.avilo.com"
    target = list(cname_set[0])[0].target.to_text().lower()
    assert target == "avilo.com."


def test_cname_target_resolved(auth_addr):
    """When the CNAME target is in-zone, a well-behaved auth server includes
    the chased A record in the same answer (RFC 1034 §3.6.2 recommendation)."""
    r = udp_query("www.avilo.com.", "A", *auth_addr)
    a_records = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.A]
    if a_records:  # implementation may or may not chase — only assert if it did
        addrs = {rr.address for rs in a_records for rr in rs}
        assert "192.168.1.2" in addrs


# -- TTL sanity --------------------------------------------------------------

def test_ttls_are_positive(auth_addr):
    """Every returned RR must have a sane (>0, <= 1 week) TTL."""
    r = udp_query("avilo.com.", "A", *auth_addr)
    assert r.answer, "expected answers"
    for rs in r.answer:
        assert 0 < rs.ttl <= 7 * 24 * 3600, f"weird TTL {rs.ttl} for {rs.name}"


def test_question_section_echoed(auth_addr):
    """The question must appear in the response, byte-identical (case folded)."""
    r = udp_query("avilo.com.", "MX", *auth_addr)
    assert len(r.question) == 1
    q = r.question[0]
    assert q.name.to_text().lower() == "avilo.com."
    assert q.rdtype == dns.rdatatype.MX
    assert q.rdclass == dns.rdataclass.IN


def test_response_id_matches_query(auth_addr):
    """RFC 1035 §4.1.1 — response ID must equal request ID."""
    import dns.message
    import dns.query
    q = dns.message.make_query("avilo.com.", "A")
    q.id = 0xBEEF
    host, port = auth_addr
    r = dns.query.udp(q, host, port=port, timeout=2.0)
    assert r.id == 0xBEEF, f"server returned id 0x{r.id:04x}, expected 0xBEEF"
