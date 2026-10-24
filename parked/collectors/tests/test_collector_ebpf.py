import sys
from pathlib import Path

_LINUX = Path(__file__).resolve().parent.parent / "linux"
sys.path.insert(0, str(_LINUX))

try:
    from collectors.linux.collector_ebpf import parse_trace_line
except ModuleNotFoundError:
    from collector_ebpf import parse_trace_line


def test_parse_trace_line_execve():
    line = 'curl-12345 [001] .... 1234.5678: sys_enter_execve: filename: "/usr/bin/curl", argv: ["curl", "http://example.com"]'
    ev = parse_trace_line(line, "run_ebpf_123")
    assert ev is not None
    assert ev["run_id"] == "run_ebpf_123"
    assert ev["event_type"] == "process_create"
    assert ev["pid"] == 12345
    assert ev["process_name"] == "curl"
    assert ev["exe_path"] == "/usr/bin/curl"
    assert ev["log_source"] == "ebpf"
    assert ev["platform"] == "linux"


def test_parse_trace_line_connect():
    line = "nc-54321 [002] .... 1234.5679: sys_enter_connect: fd: 3, uservaddr: sin_port: 4444, 203.0.113.88"
    ev = parse_trace_line(line, "run_ebpf_123")
    assert ev is not None
    assert ev["run_id"] == "run_ebpf_123"
    assert ev["event_type"] == "network_connection"
    assert ev["pid"] == 54321
    assert ev["process_name"] == "nc"
    assert ev["dest_ip"] == "203.0.113.88"
    assert ev["dest_port"] == 4444
    assert ev["log_source"] == "ebpf"


def test_parse_trace_line_loopback_ignored():
    line = "nc-54321 [002] .... 1234.5679: sys_enter_connect: fd: 3, uservaddr: sin_port: 8080, 127.0.0.1"
    ev = parse_trace_line(line, "run_ebpf_123")
    assert ev is None


def test_parse_trace_line_memfd_create():
    line = 'dropper-777 [001] .... 1234.5680: sys_enter_memfd_create: uname: "payload.elf", flags: 1'
    ev = parse_trace_line(line, "run_ebpf_123")
    assert ev is not None
    assert ev["run_id"] == "run_ebpf_123"
    assert ev["event_type"] == "file_write"
    assert ev["pid"] == 777
    assert ev["process_name"] == "dropper"
    assert ev["file_path"] == "memfd:payload.elf"
    assert ev["log_source"] == "ebpf"


def test_parse_trace_line_ptrace():
    line = "injector-888 [003] .... 1234.5681: sys_enter_ptrace: request: PTRACE_POKETEXT, pid: 123"
    ev = parse_trace_line(line, "run_ebpf_123")
    assert ev is not None
    assert ev["run_id"] == "run_ebpf_123"
    assert ev["event_type"] == "process_create"
    assert ev["pid"] == 888
    assert ev["process_name"] == "injector"
    assert "PTRACE_POKETEXT" in ev["command_line"]
    assert ev["log_source"] == "ebpf"


def test_parse_trace_line_invalid():
    line = "random garbage line that is not a tracepoint"
    ev = parse_trace_line(line, "run_ebpf_123")
    assert ev is None
