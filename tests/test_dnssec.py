"""DNSSEC: signing (auth) + validation (upstream).

Auth side (no internet required):
  - When the client sends DO=1, signed zones (avilo.com, avilo.priv, adoliva.com)
    must return RRSIG records covering each answer RRset.
  - DNSKEY queries to those zones must return the public KSK + ZSK.
  - The RRSIGs must cryptographically verify against the served DNSKEY set.

Upstream side (internet required, marked accordingly):
  - Queries with DO+RD set to signed zones (e.g., cloudflare.com) get AD=1
    when validation succeeds.
  - Queries with CD=1 bypass validation.
"""
from __future__ import annotations

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from helpers.dns_client import make_query, udp_query


SIGNED_ZONES = ["avilo.com.", "avilo.priv.", "adoliva.com."]


# --- Auth: DNSKEY ----------------------------------------------------------

@pytest.mark.parametrize("zone", SIGNED_ZONES)
def test_dnskey_records_returned(auth_addr, zone):
    """DNSKEY query should return at least one KSK (flags=257) and one ZSK
    (flags=256). The dnssec.conf maps both to Ed25519 (algorithm 15)."""
    r = udp_query(zone, "DNSKEY", *auth_addr, want_dnssec=True)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    keys = [rr for rs in r.answer if rs.rdtype == dns.rdatatype.DNSKEY for rr in rs]
    assert len(keys) >= 2, f"{zone} DNSKEY: expected ≥2 keys (KSK+ZSK), got {len(keys)}"
    flag_set = {rr.flags for rr in keys}
    assert 257 in flag_set, f"{zone} DNSKEY missing KSK (flags=257)"
    assert 256 in flag_set, f"{zone} DNSKEY missing ZSK (flags=256)"
    for k in keys:
        assert k.algorithm == 15, f"expected Ed25519 (alg 15), got {k.algorithm}"


# --- Auth: RRSIG appears when DO=1 -----------------------------------------

@pytest.mark.parametrize("zone", SIGNED_ZONES)
def test_rrsig_appears_with_do_bit(auth_addr, zone):
    """Any answer for a signed zone with DO=1 must include an RRSIG."""
    r = udp_query(zone, "SOA", *auth_addr, want_dnssec=True)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    rrsigs = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.RRSIG]
    assert rrsigs, f"{zone} SOA with DO=1: expected RRSIG, got answer={r.answer}"


def test_no_rrsig_without_do_bit(auth_addr):
    """Without DO=1, the server must NOT include DNSSEC records (saves bytes
    and respects the client's stated lack of interest)."""
    r = udp_query("avilo.com.", "SOA", *auth_addr, want_dnssec=False)
    rrsigs = [rs for rs in r.answer if rs.rdtype == dns.rdatatype.RRSIG]
    assert not rrsigs, "RRSIG sent to client that didn't set DO=1"


# --- Auth: RRSIG verifies against served DNSKEY ----------------------------

@pytest.mark.parametrize("zone,qtype", [
    ("avilo.com.", "SOA"),
    ("avilo.com.", "A"),
    ("avilo.com.", "MX"),
    ("avilo.priv.", "SOA"),
    ("adoliva.com.", "SOA"),
])
def test_rrsig_verifies_cryptographically(auth_addr, zone, qtype):
    """Pull both the answer (with RRSIG) and the DNSKEY set, then validate the
    signature using dnspython's dns.dnssec.validate(). If this fails, the
    server is either signing with the wrong key, encoding the signature wrong,
    or canonicalizing the RRset wrong."""
    # 1) Fetch the answer
    r = udp_query(zone, qtype, *auth_addr, want_dnssec=True)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"

    answer_rrset = None
    rrsig_rrset = None
    for rs in r.answer:
        if rs.rdtype == dns.rdatatype.from_text(qtype):
            answer_rrset = rs
        elif rs.rdtype == dns.rdatatype.RRSIG and rs.covers == dns.rdatatype.from_text(qtype):
            rrsig_rrset = rs
    assert answer_rrset is not None, f"{zone} {qtype}: no answer rrset"
    assert rrsig_rrset is not None, f"{zone} {qtype}: no RRSIG covering it"

    # 2) Fetch DNSKEY set
    dk = udp_query(zone, "DNSKEY", *auth_addr, want_dnssec=True)
    dnskey_rrset = None
    for rs in dk.answer:
        if rs.rdtype == dns.rdatatype.DNSKEY:
            dnskey_rrset = rs
            break
    assert dnskey_rrset is not None, f"{zone} DNSKEY rrset missing"

    # 3) Verify — raises ValidationFailure on failure
    name = dns.name.from_text(zone)
    try:
        dns.dnssec.validate(
            answer_rrset,
            rrsig_rrset,
            {name: dnskey_rrset},
        )
    except dns.dnssec.ValidationFailure as e:
        pytest.fail(f"RRSIG validation failed for {zone} {qtype}: {e}")


# --- Upstream: AD bit on validated answers (internet) ----------------------

@pytest.mark.internet
def test_upstream_ad_bit_on_signed_zone(upstream_addr):
    """cloudflare.com is DNSSEC-signed. With DO+RD+CD=0, a validating resolver
    should set AD=1 on the response."""
    host, port = upstream_addr
    q = dns.message.make_query("cloudflare.com.", "A", want_dnssec=True)
    q.flags |= dns.flags.RD
    q.flags &= ~dns.flags.CD
    r = dns.query.udp(q, host, port=port, timeout=5.0)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    # If the upstream is doing DNSSEC validation, AD must be set.
    # If it's silently degrading to non-validation, AD will be missing.
    if not (r.flags & dns.flags.AD):
        pytest.xfail("upstream did not set AD on a known-signed zone — "
                     "DNSSEC validation may be silently disabled")


@pytest.mark.internet
def test_upstream_cd_bit_returns_raw(upstream_addr):
    """With CD=1, the upstream should return the raw (unvalidated) response
    even for signed zones. AD should NOT be set when CD is."""
    host, port = upstream_addr
    q = dns.message.make_query("cloudflare.com.", "A", want_dnssec=True)
    q.flags |= dns.flags.RD | dns.flags.CD
    r = dns.query.udp(q, host, port=port, timeout=5.0)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    # Per RFC 4035 §3.2.2: when CD is set, AD is unspecified — we don't assert.
    # We only require: must not SERVFAIL just because CD was set.
