"""Zero-trust policy layer: the gate every tool call must pass before it runs.

Three checks, in order:
1. Is the tool on the allowlist at all?
2. Do its arguments satisfy a strict Pydantic schema (host/target allowlists,
   bounded ranges, filename allowlist)?
3. Is the tool marked sensitive, meaning it additionally requires a human
   approval before it is allowed to execute?

This module has no dependency on LangGraph, the LLM, or the MCP server, so it
can be tested in complete isolation.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

# Port scanning stays localhost-only. Ping additionally allows 8.8.8.8,
# Google's public DNS resolver, published specifically as a connectivity
# test target, so it isn't a real target in the sense this project avoids.
ALLOWED_SCAN_HOSTS = {"127.0.0.1", "localhost"}
ALLOWED_PING_HOSTS = ALLOWED_SCAN_HOSTS | {"8.8.8.8"}
ALLOWED_SAMPLE_FILES = {"sample.pcap", "sample_scan_report.json"}

ALLOWED_TOOLS = {
    "ping_host",
    "list_open_ports",
    "nmap_scan",
    "netstat_status",
    "parse_pcap",
    "read_scan_report",
}
# netstat_status is deliberately not sensitive: it only reads the local
# kernel's existing socket table and never opens a connection to anything,
# unlike list_open_ports/nmap_scan which actively probe, even if only
# against localhost.
SENSITIVE_TOOLS = {"list_open_ports", "nmap_scan"}


class PingHostArgs(BaseModel):
    host: str = "127.0.0.1"
    count: int = Field(default=4, ge=1, le=10)

    @field_validator("host")
    @classmethod
    def host_allowed(cls, v: str) -> str:
        if v not in ALLOWED_PING_HOSTS:
            raise ValueError(f"host '{v}' is not on the allowlist {sorted(ALLOWED_PING_HOSTS)}")
        return v


class _HostPortRangeArgs(BaseModel):
    """Shared shape for tools that scan a bounded port range on an allowed host."""

    host: str = "127.0.0.1"
    start_port: int = Field(default=1, gt=0, lt=65536)
    end_port: int = Field(default=1024, gt=0, lt=65536)

    @field_validator("host")
    @classmethod
    def host_allowed(cls, v: str) -> str:
        if v not in ALLOWED_SCAN_HOSTS:
            raise ValueError(f"host '{v}' is not on the allowlist {sorted(ALLOWED_SCAN_HOSTS)}")
        return v

    @model_validator(mode="after")
    def range_is_bounded(self) -> "_HostPortRangeArgs":
        if self.start_port > self.end_port:
            raise ValueError("start_port must be <= end_port")
        if self.end_port - self.start_port > 1024:
            raise ValueError("port range must span at most 1024 ports")
        return self


class ListOpenPortsArgs(_HostPortRangeArgs):
    pass


class NmapScanArgs(_HostPortRangeArgs):
    pass


class NetstatStatusArgs(BaseModel):
    """No fields: netstat_status takes no arguments, it only reads local state."""


class ParsePcapArgs(BaseModel):
    filename: str = "sample.pcap"

    @field_validator("filename")
    @classmethod
    def filename_allowed(cls, v: str) -> str:
        if v not in ALLOWED_SAMPLE_FILES:
            raise ValueError(f"filename '{v}' is not on the sample_data allowlist")
        return v


class ReadScanReportArgs(BaseModel):
    filename: str = "sample_scan_report.json"

    @field_validator("filename")
    @classmethod
    def filename_allowed(cls, v: str) -> str:
        if v not in ALLOWED_SAMPLE_FILES:
            raise ValueError(f"filename '{v}' is not on the sample_data allowlist")
        return v


TOOL_ARG_MODELS: dict[str, type[BaseModel]] = {
    "ping_host": PingHostArgs,
    "list_open_ports": ListOpenPortsArgs,
    "nmap_scan": NmapScanArgs,
    "netstat_status": NetstatStatusArgs,
    "parse_pcap": ParsePcapArgs,
    "read_scan_report": ReadScanReportArgs,
}


class PolicyResult(BaseModel):
    allowed: bool
    sensitive: bool
    reason: str
    validated_args: Optional[dict[str, Any]] = None


def evaluate_policy(tool_name: str, arguments: dict[str, Any]) -> PolicyResult:
    if tool_name not in ALLOWED_TOOLS:
        return PolicyResult(
            allowed=False,
            sensitive=False,
            reason=f"tool '{tool_name}' is not on the tool allowlist",
        )

    sensitive = tool_name in SENSITIVE_TOOLS
    model_cls = TOOL_ARG_MODELS[tool_name]
    try:
        validated = model_cls(**arguments)
    except ValidationError as exc:
        first_error = exc.errors()[0]["msg"] if exc.errors() else str(exc)
        return PolicyResult(
            allowed=False,
            sensitive=sensitive,
            reason=f"argument validation failed: {first_error}",
        )

    return PolicyResult(
        allowed=True,
        sensitive=sensitive,
        reason="ok",
        validated_args=validated.model_dump(),
    )
