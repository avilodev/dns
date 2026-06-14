"""
Conformance comparison — local auth_dns (port 53) vs Cloudflare 1.1.1.1.

This is a *self-contained* suite (no dependency on the project's own tests/ or
conftest). It probes the live auth_dns front door on port 53 and a public
reference resolver (1.1.1.1) and compares them across:

  * header flag correctness  (QR / AA / RA / RD / opcode / Z / RCODE)
  * EDNS + DNSSEC signalling  (the DO bit, RRSIG leakage, the AD bit)
  * domain correctness        (deterministic anchors: TLD NS sets, SOA, PTR)
  * NXDOMAIN behaviour        (RCODE + SOA-in-authority per RFC 2308)
  * blocklist behaviour       (operator policy diverges from public on purpose)
  * DNSSEC validation         (signed → AD; bogus → SERVFAIL)

Run it on its own:

    python3 -m pytest compare_tests/ -v

Overrides via env: DNS_AUTH_HOST, DNS_AUTH_PORT, DNS_REF_HOST.

------------------------------------------------------------------------------
EXPECTED FAILURES — these encode functional bugs found while writing the suite.
A failing assertion here IS the bug report; fix the server, the test goes green.

  [BUG-1] DO-bit / RRSIG / AD leak to non-DO clients
      When the client does NOT set the EDNS DO bit, the recursive path still
      returns DO=1 in the OPT record and staples RRSIG records (and sometimes
      AD=1) into the answer. 1.1.1.1 correctly suppresses all DNSSEC machinery
      for DO=0 clients (RFC 4035 §3.2.1, RFC 6840 §5.7). Reproduced on both the
      upstream (5335) and the auth front door (53), so the auth front door is
      passing the upstream's OPT/RRSIG through unfiltered.
      -> test_do_bit_absent_when_not_requested
      -> test_no_rrsig_leaked_to_non_do_client

  [BUG-2] Blocklist missing example.org / example.net
      Operator states example.com/.org/.net are all blocked; only example.com
      actually returns NXDOMAIN. .org and .net resolve normally.
      -> test_blocked_domains_return_nxdomain[example.org]
      -> test_blocked_domains_return_nxdomain[example.net]

  [BUG-3] Incomplete DNSSEC validation of bogus zones
      dnssec-failed.org is correctly SERVFAILed, but other deliberately-broken
      signed zones (e.g. rhybar.cz) are returned as NOERROR with DO=1, where
      1.1.1.1 returns SERVFAIL. Marked xfail (third-party test zones move).
      -> test_bogus_dnssec_servfails[rhybar.cz]
"""
from __future__ import annotations

import os
import random
import string

import pytest

import dns.message
import dns.query
import dns.flags
import dns.rcode
import dns.rdatatype
import dns.rdataclass


# --------------------------------------------------------------------------- #
# Configuration                                                               #
# --------------------------------------------------------------------------- #

AUTH_HOST = os.environ.get("DNS_AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("DNS_AUTH_PORT", "53"))
REF_HOST = os.environ.get("DNS_REF_HOST", "1.1.1.1")
REF_PORT = int(os.environ.get("DNS_REF_PORT", "53"))

TIMEOUT = 6.0

# Stable, always-resolvable public domains (used for structural comparison —
# never compared by literal IP, which varies with CDN/geo).
RESOLVABLE = ["google.com", "cloudflare.com", "wikipedia.org", "github.com"]

# DNSSEC-signed zones that should validate (AD bit + RRSIG).
SIGNED = ["cloudflare.com", "nlnetlabs.nl"]

# Per the operator, these are all blocklisted (NXDOMAIN locally).
BLOCKED = ["example.com", "example.org", "example.net"]


# --------------------------------------------------------------------------- #
# Query helpers                                                               #
# --------------------------------------------------------------------------- #

def _query(host, port, qname, qtype, *, do=False, rd=True, timeout=TIMEOUT, tries=2):
    """Send one UDP query and return the parsed response (retries on timeout)."""
    last = None
    for _ in range(tries):
        q = dns.message.make_query(qname, qtype, use_edns=0, want_dnssec=do)
        if not rd:
            q.flags &= ~dns.flags.RD
        try:
            return dns.query.udp(q, host, port=port, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — surfaced via the raise below
            last = exc
    raise last


def local(qname, qtype, **kw):
    return _query(AUTH_HOST, AUTH_PORT, qname, qtype, **kw)


def reference(qname, qtype, **kw):
    return _query(REF_HOST, REF_PORT, qname, qtype, **kw)


def flag_set(msg, flag):
    return bool(msg.flags & flag)


def do_bit(msg):
    return bool(msg.ednsflags & dns.flags.DO) if msg.edns >= 0 else False


def has_rrsig(section):
    return any(rr.rdtype == dns.rdatatype.RRSIG for rr in section)


def rrtypes(section):
    return {dns.rdatatype.to_text(rr.rdtype) for rr in section}


def count_type(section, rdtype):
    return sum(len(rr) for rr in section if rr.rdtype == rdtype)


def names_of(section, rdtype):
    return {
        item.to_text().lower().rstrip(".")
        for rr in section if rr.rdtype == rdtype for item in rr
    }


def random_nxdomain():
    label = "nx-" + "".join(random.choices(string.ascii_lowercase, k=14))
    return f"{label}.com"


# --------------------------------------------------------------------------- #
# Availability guard (skip, not fail, when infra is down)                     #
# --------------------------------------------------------------------------- #

_AVAIL = {}


def _probe(host, port, qname, qtype):
    try:
        _query(host, port, qname, qtype, timeout=3.0, tries=1)
        return True
    except Exception:  # noqa: BLE001
        return False


def require_both():
    """Skip the test if either daemon / the reference resolver is unreachable."""
    if "local" not in _AVAIL:
        # example.com is blocklisted -> answered locally, no internet needed.
        _AVAIL["local"] = _probe(AUTH_HOST, AUTH_PORT, "example.com", "A")
    if "ref" not in _AVAIL:
        _AVAIL["ref"] = _probe(REF_HOST, REF_PORT, "cloudflare.com", "A")
    if not _AVAIL["local"]:
        pytest.skip(f"local auth_dns {AUTH_HOST}:{AUTH_PORT} not responding")
    if not _AVAIL["ref"]:
        pytest.skip(f"reference {REF_HOST}:{REF_PORT} unreachable (no internet?)")


@pytest.fixture(autouse=True)
def _guard():
    require_both()


# =========================================================================== #
# 1. Header flag correctness (forwarded / recursive path)                     #
# =========================================================================== #

@pytest.mark.parametrize("name", RESOLVABLE)
def test_qr_and_ra_set(name):
    """A recursive answer must have QR=1 and RA=1, matching 1.1.1.1."""
    l = local(name, "A")
    assert flag_set(l, dns.flags.QR), f"{name}: local response missing QR"
    assert flag_set(l, dns.flags.RA), f"{name}: local response missing RA (recursion available)"


@pytest.mark.parametrize("name", RESOLVABLE)
def test_aa_clear_on_forwarded(name):
    """We are not authoritative for forwarded names: AA must be 0 (like 1.1.1.1)."""
    l = local(name, "A")
    r = reference(name, "A")
    assert not flag_set(l, dns.flags.AA), f"{name}: local set AA=1 on a forwarded answer"
    assert flag_set(l, dns.flags.AA) == flag_set(r, dns.flags.AA), (
        f"{name}: AA differs (local={flag_set(l, dns.flags.AA)}, ref={flag_set(r, dns.flags.AA)})"
    )


@pytest.mark.parametrize("name", RESOLVABLE)
def test_rd_echoed(name):
    """RD set in the query must be echoed in the response (RFC 1035 §4.1.1)."""
    l = local(name, "A")
    assert flag_set(l, dns.flags.RD), f"{name}: RD not echoed back"


@pytest.mark.parametrize("name", RESOLVABLE)
def test_rcode_matches_reference(name):
    """RCODE for a resolvable name must agree with the reference resolver."""
    l = local(name, "A")
    r = reference(name, "A")
    assert l.rcode() == r.rcode(), (
        f"{name}: RCODE local={dns.rcode.to_text(l.rcode())} "
        f"ref={dns.rcode.to_text(r.rcode())}"
    )


@pytest.mark.parametrize("name", RESOLVABLE)
def test_opcode_and_reserved_bits(name):
    """opcode must be QUERY(0) and the reserved Z bit must be 0."""
    l = local(name, "A")
    assert l.opcode() == dns.opcode.QUERY, f"{name}: opcode != QUERY"
    Z = 0x0040  # reserved bit, must be zero
    assert (l.flags & Z) == 0, f"{name}: reserved Z bit set"


def test_transaction_id_and_question_echoed():
    """The response must keep the client's TXID and echo the exact question."""
    q = dns.message.make_query("google.com", "A", use_edns=0)
    r = dns.query.udp(q, AUTH_HOST, port=AUTH_PORT, timeout=TIMEOUT)
    assert r.id == q.id, "transaction ID not preserved"
    assert r.question[0].name == q.question[0].name, "QNAME not echoed"
    assert r.question[0].rdtype == q.question[0].rdtype, "QTYPE not echoed"


# =========================================================================== #
# 2. EDNS / DNSSEC signalling to NON-DO clients   [BUG-1]                      #
# =========================================================================== #

@pytest.mark.parametrize("name", RESOLVABLE)
def test_do_bit_absent_when_not_requested(name):
    """
    [BUG-1] With the client DO bit clear, the response OPT must also have DO=0.
    1.1.1.1 honours this; the local server leaks DO=1 on the forwarded path.
    """
    l = local(name, "A", do=False)
    r = reference(name, "A", do=False)
    assert do_bit(r) is False  # sanity: reference behaves
    assert do_bit(l) is False, (
        f"{name}: local set DO=1 in OPT for a client that did not request DNSSEC"
    )


@pytest.mark.parametrize("name", SIGNED)
def test_no_rrsig_leaked_to_non_do_client(name):
    """
    [BUG-1] A DO=0 client MUST NOT receive RRSIG records (RFC 4035 §3.2.1).
    1.1.1.1 strips them; the local server staples them in for signed zones.
    """
    l = local(name, "A", do=False)
    r = reference(name, "A", do=False)
    assert not has_rrsig(r.answer)  # sanity: reference behaves
    assert not has_rrsig(l.answer), (
        f"{name}: local leaked RRSIG to a non-DO client "
        f"(answer types: {sorted(rrtypes(l.answer))})"
    )


# =========================================================================== #
# 3. Domain correctness — deterministic anchors                               #
# =========================================================================== #

@pytest.mark.parametrize("tld", ["com", "net", "org"])
def test_tld_ns_set_matches(tld):
    """The delegation NS set for a TLD is fixed and must match 1.1.1.1 exactly."""
    l = local(tld, "NS")
    r = reference(tld, "NS")
    ln = names_of(l.answer, dns.rdatatype.NS)
    rn = names_of(r.answer, dns.rdatatype.NS)
    assert ln and rn, f"{tld}: empty NS set (local={ln}, ref={rn})"
    assert ln == rn, f"{tld}: NS set differs\n local={sorted(ln)}\n ref  ={sorted(rn)}"


def test_soa_mname_matches_for_com():
    """The com zone SOA MNAME/RNAME are stable identifiers (serial excluded)."""
    l = local("com", "SOA")
    r = reference("com", "SOA")
    def soa(msg):
        for rr in msg.answer:
            if rr.rdtype == dns.rdatatype.SOA:
                s = rr[0]
                return (s.mname.to_text().lower().rstrip("."),
                        s.rname.to_text().lower().rstrip("."))
        return None
    assert soa(l) == soa(r), f"com SOA mname/rname differ: local={soa(l)} ref={soa(r)}"


def test_ptr_of_known_address():
    """1.1.1.1 -> one.one.one.one is a fixed reverse record."""
    qn = "1.1.1.1.in-addr.arpa"
    l = names_of(local(qn, "PTR").answer, dns.rdatatype.PTR)
    r = names_of(reference(qn, "PTR").answer, dns.rdatatype.PTR)
    assert l == r and l, f"PTR mismatch: local={l} ref={r}"


@pytest.mark.parametrize("name,qtype", [
    ("google.com", "A"),
    ("google.com", "AAAA"),
    ("cloudflare.com", "A"),
    ("cloudflare.com", "MX"),
    ("wikipedia.org", "A"),
])
def test_answer_has_expected_rrtype(name, qtype):
    """
    Structural correctness: same RCODE and at least one record of the queried
    type on both sides (IP *values* deliberately not compared — CDN/geo vary).
    """
    l = local(name, qtype)
    r = reference(name, qtype)
    assert l.rcode() == r.rcode() == dns.rcode.NOERROR, (
        f"{name}/{qtype}: rcode local={dns.rcode.to_text(l.rcode())} "
        f"ref={dns.rcode.to_text(r.rcode())}"
    )
    want = dns.rdatatype.from_text(qtype)
    assert count_type(l.answer, want) >= 1, (
        f"{name}/{qtype}: local returned no {qtype} record "
        f"(types: {sorted(rrtypes(l.answer))})"
    )
    assert count_type(r.answer, want) >= 1, f"{name}/{qtype}: reference returned no {qtype}"


# =========================================================================== #
# 4. NXDOMAIN correctness                                                      #
# =========================================================================== #

def test_nxdomain_rcode_and_soa_authority():
    """A non-existent name: NXDOMAIN on both, with a SOA in authority (RFC 2308)."""
    qn = random_nxdomain()
    l = local(qn, "A")
    r = reference(qn, "A")
    assert l.rcode() == dns.rcode.NXDOMAIN, (
        f"{qn}: local rcode={dns.rcode.to_text(l.rcode())} (expected NXDOMAIN)")
    assert r.rcode() == dns.rcode.NXDOMAIN, f"{qn}: reference not NXDOMAIN (got a wildcard?)"
    assert has_soa(l.authority), f"{qn}: local NXDOMAIN missing SOA in authority section"
    assert not flag_set(l, dns.flags.AA), f"{qn}: AA set on a forwarded NXDOMAIN"


def has_soa(section):
    return any(rr.rdtype == dns.rdatatype.SOA for rr in section)


# =========================================================================== #
# 5. Blocklist behaviour (intentional divergence from public)   [BUG-2]       #
# =========================================================================== #

@pytest.mark.parametrize("name", BLOCKED)
def test_blocked_domains_return_nxdomain(name):
    """
    Operator policy: BLOCKED names return NXDOMAIN locally while the public
    resolver returns NOERROR with addresses. example.org/.net currently FAIL —
    they are absent from the blocklist (BUG-2).
    """
    l = local(name, "A")
    r = reference(name, "A")
    assert r.rcode() == dns.rcode.NOERROR, f"{name}: reference unexpectedly not NOERROR"
    assert l.rcode() == dns.rcode.NXDOMAIN, (
        f"{name}: expected local NXDOMAIN (blocklisted) but got "
        f"{dns.rcode.to_text(l.rcode())} — name is not actually blocked"
    )


# =========================================================================== #
# 6. DNSSEC validation                                                         #
# =========================================================================== #

@pytest.mark.parametrize("name", SIGNED)
def test_signed_zone_sets_ad_with_do(name):
    """A correctly-signed zone queried with DO=1 must set AD and carry RRSIG."""
    l = local(name, "A", do=True)
    r = reference(name, "A", do=True)
    assert flag_set(r, dns.flags.AD), f"{name}: reference did not set AD (zone unsigned?)"
    assert flag_set(l, dns.flags.AD), f"{name}: local failed to set AD for a signed zone"
    assert has_rrsig(l.answer), f"{name}: local DO=1 answer carried no RRSIG"


def test_bogus_dnssec_servfails_canonical():
    """dnssec-failed.org has bad signatures: a validating resolver returns SERVFAIL."""
    name = "dnssec-failed.org"
    r = reference(name, "A", do=True)
    if r.rcode() != dns.rcode.SERVFAIL:
        pytest.skip(f"reference no longer SERVFAILs {name}; test zone changed")
    l = local(name, "A", do=True)
    assert l.rcode() == dns.rcode.SERVFAIL, (
        f"{name}: local rcode={dns.rcode.to_text(l.rcode())} — bogus signatures not rejected"
    )


@pytest.mark.xfail(reason="[BUG-3] some bogus zones validate as NOERROR; third-party zone may change")
@pytest.mark.parametrize("name", ["rhybar.cz"])
def test_bogus_dnssec_servfails(name):
    """Other deliberately-broken zones should also SERVFAIL under DO=1."""
    r = reference(name, "A", do=True)
    if r.rcode() != dns.rcode.SERVFAIL:
        pytest.skip(f"reference no longer SERVFAILs {name}; test zone changed")
    l = local(name, "A", do=True)
    assert l.rcode() == dns.rcode.SERVFAIL, (
        f"{name}: local rcode={dns.rcode.to_text(l.rcode())} — bogus signatures not rejected"
    )
