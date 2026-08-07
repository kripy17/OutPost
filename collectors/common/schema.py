"""Shared event dataclass — mirrors the backend's unified schema exactly.

Per AGENTS.md rule 1, both collectors must produce JSON matching this shape.
Platform-specific fields never leak into shared code paths.
"""

from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class Event:
    run_id: str
    platform: str  # "windows" | "linux"
    event_type: str  # "process_create" | "network_connection" | "file_write" | "registry_write"
    timestamp: str  # UTC ISO-8601
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    file_path: Optional[str] = None
    registry_key: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
