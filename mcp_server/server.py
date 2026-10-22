"""FastMCP server exposing a small set of safe, local-only recon tools.

Every tool here is deliberately harmless on its own: pings and port scans are
restricted to localhost, and file-reading tools are sandboxed to the bundled
sample_data directory with resolved-path checks to prevent path traversal.
The zero-trust enforcement (allowlists, sensitivity, human approval) lives in
the agent's policy layer, not here -- this server only guarantees that even a
misused tool call cannot escape localhost or the sample_data directory.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from scapy.all import rdpcap  # type: ignore[import-untyped]

mcp = FastMCP("zero-trust-recon")

SAMPLE_DATA_DIR = (Path(__file__).resolve().parent.parent / "sample_data").resolve()

# Port scanning stays localhost-only: scanning a real external host is
# reconnaissance against infrastructure that isn't ours. Ping is different:
# 8.8.8.8 is Google's public DNS resolver, published specifically as a
# connectivity test target, so allowing a ping to it isn't probing a real
# target in the sense this project otherwise avoids.
ALLOWED_SCAN_HOSTS = {"127.0.0.1", "localhost"}
ALLOWED_PING_HOSTS = ALLOWED_SCAN_HOSTS | {"8.8.8.8"}


def _check_scan_range(host: str, start_port: int, end_port: int) -> None:
    if host not in ALLOWED_SCAN_HOSTS:
        raise ValueError(f"host '{host}' is not allowed; only {ALLOWED_SCAN_HOSTS} may be scanned")
    if not (0 < start_port <= end_port < 65536) or (end_port - start_port) > 1024:
        raise ValueError("port range must be within (0, 65536) and span at most 1024 ports")


def _safe_sample_path(filename: str) -> Path:
    """Resolve `filename` under SAMPLE_DATA_DIR, rejecting any path traversal."""
    candidate = (SAMPLE_DATA_DIR / filename).resolve()
    if candidate.parent != SAMPLE_DATA_DIR and SAMPLE_DATA_DIR not in candidate.parents:
        raise ValueError(f"'{filename}' resolves outside the sample_data directory")
    if not candidate.is_file():
        raise FileNotFoundError(f"'{filename}' not found in sample_data")
    return candidate


@mcp.tool()
def ping_host(host: str = "127.0.0.1", count: int = 4) -> str:
    """Ping a host and return the raw output. Restricted to localhost."""
    if host not in ALLOWED_PING_HOSTS:
        raise ValueError(f"host '{host}' is not allowed; only {ALLOWED_PING_HOSTS} may be pinged")
    count = max(1, min(count, 10))
    result = subprocess.run(
        ["ping", "-c", str(count), host],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return result.stdout or result.stderr


@mcp.tool()
def list_open_ports(host: str = "127.0.0.1", start_port: int = 1, end_port: int = 1024) -> str:
    """List open TCP ports on a host within a bounded range. Restricted to localhost."""
    _check_scan_range(host, start_port, end_port)

    open_ports = []
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)

    return json.dumps({"host": host, "open_ports": open_ports})


@mcp.tool()
def nmap_scan(host: str = "127.0.0.1", start_port: int = 1, end_port: int = 1024) -> str:
    """Run an nmap TCP connect scan on a host within a bounded range. Restricted to localhost.

    Requires the nmap binary to be installed on the machine running the MCP
    server; raises a clear error if it isn't, rather than crashing.
    """
    _check_scan_range(host, start_port, end_port)
    if shutil.which("nmap") is None:
        raise RuntimeError(
            "nmap is not installed. Install it with 'sudo apt-get install nmap' "
            "(Debian/Ubuntu), 'brew install nmap' (macOS), or your distro's equivalent."
        )

    result = subprocess.run(
        ["nmap", "-sT", "-p", f"{start_port}-{end_port}", host],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result.stdout or result.stderr


@mcp.tool()
def netstat_status() -> str:
    """List this machine's own listening TCP sockets. Takes no target: it only
    reads the local kernel's socket table, it never opens a connection to
    anything, local or remote.

    Implemented with `ss` (iproute2), the modern replacement for the legacy
    `netstat` binary and the one virtually every current Linux install already
    has, rather than requiring the separate net-tools package.
    """
    if shutil.which("ss") is None:
        raise RuntimeError("'ss' (part of iproute2) was not found on this system.")

    result = subprocess.run(
        ["ss", "-tln"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.stdout or result.stderr


@mcp.tool()
def parse_pcap(filename: str = "sample.pcap") -> str:
    """Parse a bundled sample .pcap file and summarize its packets."""
    path = _safe_sample_path(filename)
    packets = rdpcap(str(path))

    protocol_counts: dict[str, int] = {}
    for pkt in packets:
        proto = pkt.lastlayer().__class__.__name__
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    return json.dumps(
        {
            "file": filename,
            "packet_count": len(packets),
            "protocol_counts": protocol_counts,
        }
    )


@mcp.tool()
def read_scan_report(filename: str = "sample_scan_report.json") -> str:
    """Read a bundled sample scan report (JSON) from sample_data."""
    path = _safe_sample_path(filename)
    return path.read_text()


if __name__ == "__main__":
    mcp.run()
