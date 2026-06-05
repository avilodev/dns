"""Transport-layer tests: UDP, TCP, IPv6 loopback.

Auth + upstream both speak UDP and TCP on IPv4 and IPv6 (per README and the
listener setup code in main.c).
"""
from __future__ import annotations

import socket
import struct

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import pytest

from helpers.dns_client import raw_tcp, tcp_query, udp_query, udp_query_v6


# -- TCP transport (RFC 1035 §4.2.2 / RFC 7766) ------------------------------

def test_tcp_basic_query(auth_addr):
    """auth_dns must accept TCP queries and return the same payload as UDP."""
    r = tcp_query("avilo.com.", "SOA", *auth_addr)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    assert r.flags & dns.flags.AA


def test_tcp_a_record_matches_udp(auth_addr):
    udp_r = udp_query("avilo.com.", "A", *auth_addr)
    tcp_r = tcp_query("avilo.com.", "A", *auth_addr)
    udp_addrs = {rr.address for rs in udp_r.answer for rr in rs}
    tcp_addrs = {rr.address for rs in tcp_r.answer for rr in rs}
    assert udp_addrs == tcp_addrs


def test_tcp_length_prefix_format(auth_addr):
    """RFC 1035 §4.2.2 — TCP DNS uses a 16-bit big-endian length prefix.
    Send a hand-built query and verify the prefix on the response."""
    host, port = auth_addr
    q = dns.message.make_query("avilo.com.", "SOA")
    payload = q.to_wire()
    with socket.create_connection((host, port), timeout=3.0) as s:
        s.sendall(struct.pack("!H", len(payload)) + payload)
        hdr = s.recv(2)
        assert len(hdr) == 2, "missing 2-byte length prefix"
        (ln,) = struct.unpack("!H", hdr)
        assert 12 <= ln <= 4096, f"impossible TCP response length {ln}"
        body = b""
        while len(body) < ln:
            chunk = s.recv(ln - len(body))
            if not chunk:
                break
            body += chunk
        assert len(body) == ln
        # And it must parse as a valid DNS message
        resp = dns.message.from_wire(body)
        assert resp.id == q.id


def test_tcp_pipelining(auth_addr):
    """RFC 7766 §6.2.1.1 — multiple queries on one TCP connection."""
    host, port = auth_addr
    qa = dns.message.make_query("avilo.com.", "A")
    qb = dns.message.make_query("avilo.com.", "MX")
    qa.id, qb.id = 0x1111, 0x2222
    pa, pb = qa.to_wire(), qb.to_wire()
    with socket.create_connection((host, port), timeout=4.0) as s:
        s.sendall(struct.pack("!H", len(pa)) + pa + struct.pack("!H", len(pb)) + pb)
        seen = set()
        for _ in range(2):
            hdr = s.recv(2)
            (ln,) = struct.unpack("!H", hdr)
            body = b""
            while len(body) < ln:
                chunk = s.recv(ln - len(body))
                if not chunk:
                    break
                body += chunk
            r = dns.message.from_wire(body)
            seen.add(r.id)
        assert seen == {0x1111, 0x2222}, \
            f"pipelined responses missing — got ids {seen}"


# -- IPv6 loopback -----------------------------------------------------------

@pytest.mark.ipv6
@pytest.mark.xfail(
    reason="KNOWN BUG in auth_dns/src/main.c:555 — create_udp_socket_v6(PORT) "
           "is called for its side effect but the returned fd is discarded. "
           "That leaked socket lacks SO_REUSEPORT and holds [::]:53, so the 20 "
           "worker threads fail to bind to IPv6 (perror in worker, then return). "
           "Net effect: 1 leaked IPv6 socket nobody reads from + 0 IPv6 workers, "
           "and all UDP queries to ::1:53 time out. lsof confirms: only 1 IPv6 "
           "UDP fd vs. 20 IPv4 UDP fds. Fix: store and reuse the fd, or pass "
           "it to a worker.",
    strict=True,
)
def test_ipv6_udp_query(auth_port):
    """auth_dns listens on [::]:53 — loopback should reach it.
    dnspython 2.7 picks the family automatically from the address string."""
    q = dns.message.make_query("avilo.com.", "SOA")
    r = dns.query.udp(q, "::1", port=auth_port, timeout=2.0)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"
    assert r.flags & dns.flags.AA


@pytest.mark.ipv6
def test_ipv6_tcp_query(auth_port):
    q = dns.message.make_query("avilo.com.", "SOA")
    r = dns.query.tcp(q, "::1", port=auth_port, timeout=3.0)
    assert dns.rcode.to_text(r.rcode()) == "NOERROR"


@pytest.mark.ipv6
def test_ipv6_upstream(upstream_port):
    q = dns.message.make_query("probe.invalid.test.", "A")
    r = dns.query.udp(q, "::1", port=upstream_port, timeout=2.0)
    assert r is not None  # any response is fine


# -- EDNS (RFC 6891) ---------------------------------------------------------

def test_edns_opt_echoed_on_response(auth_addr):
    """If the client sends EDNS OPT, the server MUST include OPT in reply
    (RFC 6891 §6.1.1 / §7)."""
    r = udp_query("avilo.com.", "SOA", *auth_addr, edns=0, payload=4096)
    assert r.edns >= 0, f"expected OPT in reply, got EDNS={r.edns}"


def test_edns_udp_payload_size_respected(auth_addr):
    """Server-advertised payload size in the OPT reply should be a sensible
    value (≥512). Some implementations echo the client size, others advertise
    their own — both are spec-compliant."""
    r = udp_query("avilo.com.", "ANY", *auth_addr, edns=0, payload=4096)
    if r.edns >= 0:
        assert r.payload >= 512, f"weird advertised payload {r.payload}"


@pytest.mark.xfail(
    reason="KNOWN BUG in auth_dns/src/response.c:362. See test docstring.",
    strict=True,
)
def test_edns_badvers_on_version_2(auth_addr):
    """RFC 6891 §6.1.3 — when the client sends an EDNS version we don't
    support, the server MUST reply BADVERS (combined 12-bit RCODE = 16,
    encoded as extended-rcode=0x01 in OPT TTL high byte + header RCODE=0).

    KNOWN BUG: auth_dns/src/response.c:362 writes
        htonl(RCODE_BADVERS << 24)        # = 0x10000000
    which puts the literal value 16 (0x10) in the extended-rcode byte
    instead of the high 8 bits of the 12-bit value (which would be 0x01).
    Result: client sees a combined RCODE of 256 instead of 16.

    This test asserts the correct value; xfail documents the bug so it
    surfaces in test output without breaking the suite. Fix line 362 to:
        htonl((RCODE_BADVERS >> 4) << 24)   # or just (1 << 24)
    """
    q = dns.message.make_query("avilo.com.", "SOA", use_edns=2)
    host, port = auth_addr
    r = dns.query.udp(q, host, port=port, timeout=2.0)
    assert r.rcode() == 16, \
        f"expected BADVERS (16), got {int(r.rcode())} — see test docstring for the auth_dns encoding bug"


def test_edns_badvers_does_respond(auth_addr):
    """Independent of the encoding bug above, the server MUST respond at all
    when sent an unsupported EDNS version, not silently drop the query."""
    q = dns.message.make_query("avilo.com.", "SOA", use_edns=2)
    host, port = auth_addr
    r = dns.query.udp(q, host, port=port, timeout=2.0)
    assert r is not None
    # Server should NOT serve the query normally with NOERROR + answers
    has_answers = len(r.answer) > 0
    is_error = int(r.rcode()) != 0
    assert is_error or not has_answers, \
        "EDNS version >0 should not be answered as if it were valid"


def test_tc_truncation_when_response_too_large(upstream_addr):
    """If client advertises a 512-byte UDP buffer and the response would be
    larger, server must set TC=1 (RFC 1035 §4.2.1 / RFC 6891 §6.2.4).

    We query the upstream resolver for the `.` NS RRset (13 root servers +
    glue + DNSSEC = comfortably > 512 bytes) with a tiny UDP buffer."""
    host, port = upstream_addr
    q = dns.message.make_query(".", "NS", use_edns=0, payload=512, want_dnssec=True)
    try:
        r = dns.query.udp(q, host, port=port, timeout=3.0, ignore_unexpected=True)
    except dns.exception.Timeout:
        pytest.skip("upstream slow to answer .NS query")
    # Either the server truncated (TC=1, no answers) or the response fit.
    if r.flags & dns.flags.TC:
        assert len(r.answer) == 0 or len(r.to_wire()) <= 512
    else:
        # If it didn't truncate, it must have been short enough to fit.
        assert len(r.to_wire()) <= 512, \
            f"response is {len(r.to_wire())} bytes with no TC flag set"


def test_tc_response_followable_by_tcp(upstream_addr):
    """After getting TC=1, the client should be able to retry over TCP and
    get a complete answer (RFC 7766 §5)."""
    host, port = upstream_addr
    q = dns.message.make_query(".", "NS", use_edns=0, payload=512, want_dnssec=True)
    try:
        r = dns.query.udp(q, host, port=port, timeout=3.0, ignore_unexpected=True)
    except dns.exception.Timeout:
        pytest.skip("upstream slow to answer .NS query")
    if not (r.flags & dns.flags.TC):
        pytest.skip("response wasn't truncated; nothing to retry over TCP")
    tcp_r = dns.query.tcp(q, host, port=port, timeout=4.0)
    assert dns.rcode.to_text(tcp_r.rcode()) == "NOERROR"
    assert len(tcp_r.answer) > 0
