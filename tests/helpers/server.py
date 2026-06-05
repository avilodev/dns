"""Server process lifecycle helper.

Spawns auth_dns / upstream_dns binaries on a chosen port, waits until the
server actually answers (not just "process is up"), and tears it down cleanly
at the end. Used by both module-scoped and function-scoped fixtures.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import dns.flags
import dns.message
import dns.query
import dns.rcode


REPO_ROOT = Path(__file__).resolve().parents[2]
AUTH_BIN = REPO_ROOT / "auth_dns" / "bin" / "auth_dns"
UPSTREAM_BIN = REPO_ROOT / "upstream_dns" / "bin" / "upstream_dns"


@dataclass
class ServerProc:
    """Wraps a running DNS server subprocess."""

    name: str
    port: int
    host: str = "127.0.0.1"
    proc: Optional[subprocess.Popen] = None
    log_lines: List[str] = field(default_factory=list)

    @property
    def pid(self) -> int:
        assert self.proc is not None, "process not started"
        return self.proc.pid

    def stop(self, timeout: float = 5.0) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2.0)
        # Drain remaining stderr (for diagnostics on failure)
        if self.proc.stderr is not None:
            try:
                rest = self.proc.stderr.read()
                if rest:
                    self.log_lines.extend(rest.splitlines())
            except Exception:
                pass

    def send_signal(self, sig: int) -> None:
        assert self.proc is not None
        self.proc.send_signal(sig)


def _wait_for_ready(host: str, port: int, probe_name: str, timeout: float = 8.0) -> None:
    """Poll the server with a SOA query until it answers or we give up.

    A successful TCP/UDP connect isn't enough — the server may have bound
    the socket but not yet entered the recv loop. We require a real DNS
    response.
    """
    deadline = time.monotonic() + timeout
    last_err: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            q = dns.message.make_query(probe_name, "SOA")
            r = dns.query.udp(q, host, port=port, timeout=0.5)
            # any response — even REFUSED or SERVFAIL — proves the server is alive
            if r is not None:
                return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.1)
    raise TimeoutError(f"server {host}:{port} did not become ready in {timeout}s (last: {last_err!r})")


def start_upstream(port: int, threads: int = 4, queue: int = 100) -> ServerProc:
    if not UPSTREAM_BIN.exists():
        raise FileNotFoundError(f"missing binary: {UPSTREAM_BIN} — run `make` in repo root first")
    proc = subprocess.Popen(
        [str(UPSTREAM_BIN), "-p", str(port), "-t", str(threads), "-q", str(queue)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        # Don't share the parent's signal handlers
        preexec_fn=os.setsid,
    )
    sp = ServerProc(name="upstream_dns", port=port, proc=proc)
    try:
        # Probe with a name the server won't recognize — we just want any answer
        _wait_for_ready("127.0.0.1", port, probe_name="probe.invalid.test.")
    except TimeoutError:
        sp.stop()
        raise
    return sp


def start_auth(port: int, upstream_host: str, upstream_port: int,
               threads: int = 4, queue: int = 100) -> ServerProc:
    if not AUTH_BIN.exists():
        raise FileNotFoundError(f"missing binary: {AUTH_BIN} — run `make` in repo root first")
    proc = subprocess.Popen(
        [
            str(AUTH_BIN),
            "-p", str(port),
            "-t", str(threads),
            "-u", f"{upstream_host}:{upstream_port}",
            "-q", str(queue),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=os.setsid,
    )
    sp = ServerProc(name="auth_dns", port=port, proc=proc)
    try:
        # avilo.com is in the production zone file and always answers SOA
        _wait_for_ready("127.0.0.1", port, probe_name="avilo.com.")
    except TimeoutError:
        sp.stop()
        raise
    return sp
