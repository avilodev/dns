"""Tiny network helpers used by the test harness."""
from __future__ import annotations

import socket
from contextlib import closing


def find_free_udp_port(host: str = "127.0.0.1") -> int:
    """Bind a UDP socket to port 0 to ask the kernel for a free port, return it.

    Note: this is racy in theory (kernel could re-hand the port to another
    process before our binary binds) but in practice the window is tiny and
    we only have ourselves to compete with on a test host.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def has_internet(host: str = "1.1.1.1", port: int = 53, timeout: float = 2.0) -> bool:
    """Quick reachability probe — used to auto-skip internet-dependent tests."""
    try:
        with closing(socket.create_connection((host, port), timeout=timeout)):
            return True
    except OSError:
        return False


def has_ipv6_loopback() -> bool:
    """True if the kernel has IPv6 enabled at the loopback level."""
    try:
        with closing(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)) as s:
            s.bind(("::1", 0))
            return True
    except OSError:
        return False
