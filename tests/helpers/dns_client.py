"""Thin wrappers over dnspython for the common query shapes used by tests.

These give us a single place to set timeouts, EDNS defaults, and IPv6
addressing so individual test files stay focused on assertions.
"""
from __future__ import annotations

import socket
import struct
from typing import Optional

import dns.edns
import dns.flags
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype


DEFAULT_TIMEOUT = 4.0


def make_query(name: str, rdtype: str | int, *,
               want_dnssec: bool = False,
               edns: int = 0,
               payload: int = 1232,
               flags: Optional[int] = None) -> dns.message.Message:
    """Build a query with sane EDNS defaults."""
    q = dns.message.make_query(
        name,
        rdtype,
        use_edns=edns,
        payload=payload,
        want_dnssec=want_dnssec,
    )
    if flags is not None:
        q.flags = flags
    return q


def udp_query(name: str, rdtype: str | int, host: str = "127.0.0.1",
              port: int = 53, *, timeout: float = DEFAULT_TIMEOUT,
              **kwargs) -> dns.message.Message:
    q = make_query(name, rdtype, **kwargs)
    return dns.query.udp(q, host, port=port, timeout=timeout)


def tcp_query(name: str, rdtype: str | int, host: str = "127.0.0.1",
              port: int = 53, *, timeout: float = DEFAULT_TIMEOUT,
              **kwargs) -> dns.message.Message:
    q = make_query(name, rdtype, **kwargs)
    return dns.query.tcp(q, host, port=port, timeout=timeout)


def udp_query_v6(name: str, rdtype: str | int, host: str = "::1",
                 port: int = 53, *, timeout: float = DEFAULT_TIMEOUT,
                 **kwargs) -> dns.message.Message:
    q = make_query(name, rdtype, **kwargs)
    return dns.query.udp(q, host, port=port, timeout=timeout, af=socket.AF_INET6)


def raw_udp(payload: bytes, host: str = "127.0.0.1", port: int = 53,
            timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
    """Send arbitrary bytes over UDP and return the raw reply (or None on timeout).

    Used by malformed/adversarial tests where we want to bypass dnspython's
    own packet builder.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        try:
            data, _ = s.recvfrom(4096)
            return data
        except socket.timeout:
            return None
    finally:
        s.close()


def raw_tcp(payload: bytes, host: str = "127.0.0.1", port: int = 53,
            timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
    """Send length-prefixed DNS payload over TCP, return the response payload."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(struct.pack("!H", len(payload)) + payload)
        hdr = _recv_all(s, 2)
        if hdr is None or len(hdr) < 2:
            return None
        (ln,) = struct.unpack("!H", hdr)
        body = _recv_all(s, ln)
        return body


def _recv_all(s: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
