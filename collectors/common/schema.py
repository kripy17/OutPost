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
    host_id: str | None = None
    source_event_id: str | None = None
    boot_id: str | None = None
    process_start_time: str | None = None
    raw_record: str | None = None
    log_source: str | None = None
    exe_path: str | None = None
    query: str | None = None
    tls_sni: str | None = None
    user: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    hashes: str | None = None
    integrity_level: str | None = None
    session_id: str | None = None
    connection_status: str | None = None
    process_guid: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)
