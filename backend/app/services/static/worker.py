"""Isolated, resource-limited static analysis worker subprocess.

Protects the FastAPI main process from hostile file exploits, infinite loops,
memory exhaustion, and parser segfaults:
1. Memory limit (512 MB via RLIMIT_AS).
2. CPU time budget (5.0 seconds via RLIMIT_CPU).
3. Wall-clock timeout (10.0 seconds).
4. Proxy environment hygiene (proxy variables cleared; not kernel network namespace isolation).
5. Crashes and timeouts are caught and reported as structured results, never
   swallowed or crashing the API.
"""

import json
import logging
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any

from .fidelity import create_static_fidelity_block
from .verdict import assess_static_evidence

logger = logging.getLogger(__name__)


def _build_minimal_worker_env() -> dict[str, str]:
    """Build a minimal sanitized environment for the worker child process without host secrets."""
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
    repo_dir = os.path.abspath(os.path.join(backend_dir, ".."))

    existing_pythonpath = os.environ.get("PYTHONPATH", "")
    paths = [p for p in sys.path if p]
    for d in (backend_dir, repo_dir):
        if d not in paths:
            paths.append(d)
    if existing_pythonpath:
        for ep in existing_pythonpath.split(os.pathsep):
            if ep and ep not in paths:
                paths.append(ep)
    combined_pythonpath = os.pathsep.join(paths)

    clean_env: dict[str, str] = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": combined_pythonpath,
        "PYTHONUNBUFFERED": "1",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        # Neutralize network proxy environment variables (does not constitute OS network namespace isolation)
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
        "NO_PROXY": "*",
        "http_proxy": "",
        "https_proxy": "",
        "all_proxy": "",
        "no_proxy": "*",
    }

    if "TMPDIR" in os.environ:
        clean_env["TMPDIR"] = os.environ["TMPDIR"]
    elif "TEMP" in os.environ:
        clean_env["TEMP"] = os.environ["TEMP"]

    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        clean_env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]

    return clean_env


def _set_worker_rlimits() -> None:
    """Apply strict resource limits to child worker process, raising on failure."""
    try:
        # 512 MB Virtual Memory limit
        mem_limit = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
    except (ValueError, OSError) as exc:
        raise OSError(f"Failed to enforce RLIMIT_AS (512MB): {exc}") from exc

    try:
        # 5 CPU seconds
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    except (ValueError, OSError) as exc:
        raise OSError(f"Failed to enforce RLIMIT_CPU (5s): {exc}") from exc


def execute_in_isolated_worker(
    data: bytes,
    timeout_sec: float = 10.0,
    force_in_process: bool = False,
) -> dict[str, Any]:
    """Execute static analysis in an isolated worker subprocess with rlimits."""
    start_time = time.monotonic()

    # In testing or environments where subprocess is undesirable, allow in-process execution
    if force_in_process or os.environ.get("OUTPOST_DISABLE_STATIC_WORKER") == "1":
        from .pipeline import run_complete_static_pipeline
        res = run_complete_static_pipeline(data)
        elapsed_ms = int((time.monotonic() - start_time) * 1000)
        res["analysis_fidelity"] = create_static_fidelity_block(
            duration_ms=elapsed_ms,
            worker_sandboxed=False,
            format_type=res.get("format", "unknown"),
        )
        return res

    temp_dir = tempfile.mkdtemp(prefix="outpost_worker_")
    input_file = os.path.join(temp_dir, "input.bin")
    output_file = os.path.join(temp_dir, "output.json")

    try:
        with open(input_file, "wb") as f:
            f.write(data)

        cmd = [sys.executable, "-m", "app.services.static.worker", input_file, output_file]
        worker_env = _build_minimal_worker_env()

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=worker_env,
                preexec_fn=_set_worker_rlimits if os.name != "nt" else None,  # noqa: PLW1509
            )
        except (subprocess.SubprocessError, OSError) as exc:
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            logger.error("Failed to launch static worker subprocess with rlimits: %s", exc)
            return {
                "status": "rlimit_enforcement_failed",
                "error": f"Failed to enforce mandatory worker resource limits: {exc}",
                "could_not_analyze": ["Worker launch aborted due to rlimit enforcement failure"],
                "analysis_fidelity": create_static_fidelity_block(duration_ms=elapsed_ms, worker_sandboxed=True),
                **assess_static_evidence(
                    findings=[],
                    capabilities=[],
                    embedded_indicators=[],
                    structural_anomalies=[],
                    benign_signals=[],
                    could_not_analyze=["Worker launch aborted due to rlimit enforcement failure"],
                    is_parser_error=True,
                    parser_error_reason=f"Mandatory worker resource limit enforcement failed: {exc}",
                ),
            }

        try:
            stdout, stderr = proc.communicate(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            elapsed_ms = int((time.monotonic() - start_time) * 1000)
            return {
                "status": "parser_timeout",
                "error": f"Static analysis worker timed out after {timeout_sec:.1f}s",
                "could_not_analyze": ["Full static analysis aborted due to resource timeout"],
                "analysis_fidelity": create_static_fidelity_block(duration_ms=elapsed_ms, worker_sandboxed=True),
                **assess_static_evidence(
                    findings=[],
                    capabilities=[],
                    embedded_indicators=[],
                    structural_anomalies=[],
                    benign_signals=[],
                    could_not_analyze=[f"Worker timed out after {timeout_sec}s"],
                    is_parser_error=True,
                    parser_error_reason=f"Static analysis worker exceeded execution budget ({timeout_sec}s)",
                ),
            }

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        if proc.returncode != 0:
            err_msg = stderr.decode("latin1", "ignore").strip()[:300]
            logger.warning("Static analysis worker failed (exit %d): %s", proc.returncode, err_msg)

            # Detect resource limit signals
            status_code = "parser_failed"
            reason = f"Worker crashed or aborted (exit code {proc.returncode})"
            if proc.returncode in (-24, 152):  # SIGXCPU
                status_code = "rlimit_cpu_exceeded"
                reason = "Worker exceeded allocated CPU time budget (5.0s)"
            elif proc.returncode in (-9, 137, -6, 134):  # SIGKILL / SIGABRT (OOM killer or rlimit)
                status_code = "rlimit_memory_exceeded"
                reason = "Worker exceeded allocated virtual memory budget (512MB)"
            elif "MemoryError" in err_msg:
                status_code = "rlimit_memory_exceeded"
                reason = "Worker exhausted memory (RLIMIT_AS 512MB enforced)"

            return {
                "status": status_code,
                "error": f"{reason}: {err_msg}",
                "could_not_analyze": [reason],
                "analysis_fidelity": create_static_fidelity_block(duration_ms=elapsed_ms, worker_sandboxed=True),
                **assess_static_evidence(
                    findings=[],
                    capabilities=[],
                    embedded_indicators=[],
                    structural_anomalies=[],
                    benign_signals=[],
                    could_not_analyze=[reason],
                    is_parser_error=True,
                    parser_error_reason=reason,
                ),
            }

        if not os.path.exists(output_file):
            return {
                "status": "parser_failed",
                "error": "Worker produced no output artifact",
                "could_not_analyze": ["Worker output file missing"],
                "analysis_fidelity": create_static_fidelity_block(duration_ms=elapsed_ms, worker_sandboxed=True),
                **assess_static_evidence(
                    findings=[],
                    capabilities=[],
                    embedded_indicators=[],
                    structural_anomalies=[],
                    benign_signals=[],
                    could_not_analyze=["Worker output file missing"],
                    is_parser_error=True,
                    parser_error_reason="Worker produced no output",
                ),
            }

        with open(output_file, "r", encoding="utf-8") as f:
            result = json.load(f)

        result["analysis_fidelity"] = create_static_fidelity_block(
            duration_ms=elapsed_ms,
            worker_sandboxed=True,
            format_type=result.get("format", "unknown"),
        )
        return result

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    # Child worker entry point
    if len(sys.argv) < 3:
        sys.exit(1)

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    try:
        with open(in_path, "rb") as f_in:
            blob = f_in.read()

        try:
            from .pipeline import run_complete_static_pipeline
        except (ImportError, ValueError):
            import pathlib
            backend_dir = str(pathlib.Path(__file__).resolve().parent.parent.parent.parent)
            if backend_dir not in sys.path:
                sys.path.insert(0, backend_dir)
            from app.services.static.pipeline import run_complete_static_pipeline

        parsed_result = run_complete_static_pipeline(blob)

        with open(out_path, "w", encoding="utf-8") as f_out:
            json.dump(parsed_result, f_out)
        sys.exit(0)
    except Exception as exc:
        sys.stderr.write(f"Worker exception: {exc}\n")
        sys.exit(2)
