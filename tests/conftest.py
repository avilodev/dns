"""Pytest fixtures for the DNS server test suite.

Mode: tests run against the *already-running* production daemons.
  - auth_dns at 127.0.0.1:53 (or override via DNS_AUTH_HOST / DNS_AUTH_PORT)
  - upstream_dns at 127.0.0.1:5335 (or DNS_UPSTREAM_HOST / DNS_UPSTREAM_PORT)

A session-scoped autouse fixture probes both daemons before any test runs;
if they're not answering, the whole suite aborts with a clear message instead
of every test failing with a useless timeout.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

# Make `helpers` importable without an install step.
sys.path.insert(0, str(Path(__file__).parent))

import dns.message  # noqa: E402
import dns.query  # noqa: E402

from helpers.net import has_internet, has_ipv6_loopback  # noqa: E402


AUTH_HOST = os.environ.get("DNS_AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("DNS_AUTH_PORT", "53"))
UPSTREAM_HOST = os.environ.get("DNS_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT = int(os.environ.get("DNS_UPSTREAM_PORT", "5335"))


# --- pytest markers ---------------------------------------------------------

def pytest_configure(config):
    config.addinivalue_line("markers", "internet: requires outbound DNS to the real internet")
    config.addinivalue_line("markers", "ipv6: requires loopback IPv6 support")
    config.addinivalue_line("markers", "stress: long-running / load-test")
    config.addinivalue_line("markers", "needs_sudo: needs passwordless sudo (signals to root-owned daemons)")


def pytest_collection_modifyitems(config, items):
    skip_inet = pytest.mark.skip(reason="no internet (set DNS_TESTS_INTERNET=1 to force)")
    skip_v6 = pytest.mark.skip(reason="no loopback IPv6")
    skip_sudo = pytest.mark.skip(reason="needs passwordless sudo")

    inet_ok = has_internet() or os.environ.get("DNS_TESTS_INTERNET") == "1"
    v6_ok = has_ipv6_loopback()
    sudo_ok = subprocess.run(
        ["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0

    for item in items:
        if "internet" in item.keywords and not inet_ok:
            item.add_marker(skip_inet)
        if "ipv6" in item.keywords and not v6_ok:
            item.add_marker(skip_v6)
        if "needs_sudo" in item.keywords and not sudo_ok:
            item.add_marker(skip_sudo)


# --- daemon-up probe (autouse, session-scoped) ------------------------------

def _probe(host: str, port: int, name: str, rdtype: str) -> str | None:
    """Return None on success, error string on failure."""
    try:
        q = dns.message.make_query(name, rdtype)
        dns.query.udp(q, host, port=port, timeout=1.5)
        return None
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


@pytest.fixture(scope="session", autouse=True)
def _check_daemons_running():
    auth_err = _probe(AUTH_HOST, AUTH_PORT, "avilo.com.", "SOA")
    upstream_err = _probe(UPSTREAM_HOST, UPSTREAM_PORT, "probe.invalid.test.", "A")
    msgs = []
    if auth_err:
        msgs.append(f"  auth_dns at {AUTH_HOST}:{AUTH_PORT} not responding ({auth_err})")
    if upstream_err:
        msgs.append(f"  upstream_dns at {UPSTREAM_HOST}:{UPSTREAM_PORT} not responding ({upstream_err})")
    if msgs:
        pytest.exit(
            "DNS test suite requires both daemons to be running:\n"
            + "\n".join(msgs)
            + "\n\nOverride hosts/ports with DNS_AUTH_HOST/PORT and DNS_UPSTREAM_HOST/PORT.\n",
            returncode=2,
        )


# --- address fixtures -------------------------------------------------------

@pytest.fixture(scope="session")
def auth_host() -> str:
    return AUTH_HOST


@pytest.fixture(scope="session")
def auth_port() -> int:
    return AUTH_PORT


@pytest.fixture(scope="session")
def auth_addr() -> tuple[str, int]:
    return (AUTH_HOST, AUTH_PORT)


@pytest.fixture(scope="session")
def upstream_host() -> str:
    return UPSTREAM_HOST


@pytest.fixture(scope="session")
def upstream_port() -> int:
    return UPSTREAM_PORT


@pytest.fixture(scope="session")
def upstream_addr() -> tuple[str, int]:
    return (UPSTREAM_HOST, UPSTREAM_PORT)


# --- pid fixtures for signal tests ------------------------------------------

def _find_pid(name: str) -> int | None:
    """pgrep for a binary basename and return the youngest PID."""
    try:
        out = subprocess.check_output(["pgrep", "-x", name], text=True).strip()
    except subprocess.CalledProcessError:
        return None
    pids = [int(x) for x in out.splitlines() if x.strip()]
    return max(pids) if pids else None


@pytest.fixture(scope="session")
def auth_pid() -> int:
    pid = _find_pid("auth_dns")
    if pid is None:
        pytest.skip("auth_dns process not found via pgrep")
    return pid


@pytest.fixture(scope="session")
def upstream_pid() -> int:
    pid = _find_pid("upstream_dns")
    if pid is None:
        pytest.skip("upstream_dns process not found via pgrep")
    return pid
