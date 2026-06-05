"""DNS protocol error handling: bad QCLASS, weird opcodes, malformed bits.

The source explicitly handles:
  - FORMERR on invalid QCLASS (request.c)
  - NOTIMP / NOTIFY (opcode 4) special case (main.c)
"""
from __future__ import annotations

import struct

import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import pytest

from helpers.dns_client import raw_udp


def _build_query(qname: bytes, qtype: int, qclass: int, opcode: int = 0,
                  xid: int = 0xABCD, qdcount: int = 1) -> bytes:
    """Hand-build a DNS query so we can poke at QCLASS / opcode independently
    of what dnspython will let us encode."""
    flags = (opcode & 0xF) << 11 | 0x0100  # RD=1
    header = struct.pack("!HHHHHH", xid, flags, qdcount, 0, 0, 0)
    return header + qname + struct.pack("!HH", qtype, qclass)


def _encode_name(name: str) -> bytes:
    out = b""
    for lbl in name.rstrip(".").split("."):
        out += bytes([len(lbl)]) + lbl.encode("ascii")
    return out + b"\x00"


# -- FORMERR on invalid QCLASS -----------------------------------------------

def test_formerr_on_garbage_qclass(auth_addr):
    """QCLASS values outside IN/CHAOS/HESIOD/ANY should produce FORMERR."""
    q = _build_query(_encode_name("avilo.com"), qtype=1, qclass=42)  # bogus class
    host, port = auth_addr
    raw = raw_udp(q, host, port)
    assert raw is not None, "no response to bogus-class query"
    rcode = raw[3] & 0x0F
    assert rcode == 1, f"expected FORMERR (1) for bogus QCLASS, got rcode {rcode}"


# -- NOTIMP / NOTIFY ---------------------------------------------------------

def test_notify_opcode(auth_addr):
    """Opcode 4 (NOTIFY, RFC 1996) gets a special-cased reply: QR=1, opcode=4,
    RCODE=0. Without authentication / zone match this is the safest response."""
    q = _build_query(_encode_name("avilo.com"), qtype=6, qclass=1, opcode=4)
    host, port = auth_addr
    raw = raw_udp(q, host, port)
    assert raw is not None
    qr = (raw[2] & 0x80) >> 7
    opcode_bits = (raw[2] >> 3) & 0x0F
    rcode = raw[3] & 0x0F
    assert qr == 1, "NOTIFY response missing QR bit"
    assert opcode_bits == 4, f"NOTIFY response should carry opcode 4, got {opcode_bits}"
    assert rcode == 0, f"NOTIFY response should be NOERROR, got rcode {rcode}"


def test_unknown_opcode_returns_notimp(auth_addr):
    """Opcode 5+ (unassigned) → NOTIMP per the code path."""
    q = _build_query(_encode_name("avilo.com"), qtype=1, qclass=1, opcode=7)
    host, port = auth_addr
    raw = raw_udp(q, host, port)
    assert raw is not None
    rcode = raw[3] & 0x0F
    assert rcode == 4, f"expected NOTIMP (4) for unknown opcode, got {rcode}"


# -- Question-section integrity ---------------------------------------------

def test_query_with_too_short_header_is_dropped(auth_addr):
    """A buffer shorter than the 12-byte DNS header should not crash the server.
    The server may drop it silently (no response) or reply FORMERR."""
    host, port = auth_addr
    raw = raw_udp(b"\xab\xcd\x01", host, port, timeout=1.0)
    # No response (server dropped it) is fine — we just want it to not crash.
    # If it did respond, the rcode should be FORMERR or SERVFAIL.
    if raw is not None:
        rcode = raw[3] & 0x0F
        assert rcode in (1, 2), f"unexpected rcode {rcode} for truncated query"
    # Follow up with a normal query to make sure the server is still alive.
    follow = raw_udp(_build_query(_encode_name("avilo.com"), 6, 1), host, port)
    assert follow is not None, "server stopped responding after truncated query"


def test_qdcount_zero_handled(auth_addr):
    """A header-only query with QDCOUNT=0 must not crash the server."""
    q = _build_query(b"", qtype=0, qclass=0, qdcount=0)
    # strip the trailing QTYPE+QCLASS we just wrote (no qname before it either)
    q = q[:12]
    host, port = auth_addr
    raw = raw_udp(q, host, port, timeout=1.0)
    # Server response not required — just no crash. Verify with a follow-up.
    follow = raw_udp(_build_query(_encode_name("avilo.com"), 6, 1), host, port)
    assert follow is not None
