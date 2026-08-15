"""Shared event dataclass — mirrors the backend's unified schema exactly.

Per AGENTS.md rule 1, both collectors must produce JSON matching this shape.
Platform-specific fields never leak into shared code paths.
"""

from dataclasses import asdict, dataclass


@dataclass
class Event:
    run_id: str
    platform: str  # "windows" | "linux"
    event_type: str  # "process_create" | "network_connection" | "file_write" | "registry_write"
    timestamp: str  # UTC ISO-8601
    pid: int | None = None
    ppid: int | None = None
    process_name: str | None = None
    command_line: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    file_path: str | None = None
    registry_key: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)
