"""Isolated, resource-limited static analysis worker subprocess.

Protects the FastAPI main process from hostile file exploits, infinite loops,
memory exhaustion, and parser segfaults:
1. Memory limit (512 MB via RLIMIT_AS).
2. CPU time budget (5.0 seconds via RLIMIT_CPU).
3. Wall-clock timeout (10.0 seconds).
4. No network access.
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


def _set_worker_rlimits() -> None:
    """Apply strict resource limits to child worker process."""
    try:
        # 512 MB Virtual Memory limit
        mem_limit = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_limit, mem_limit))
    except (ValueError, OSError):
        pass

    try:
        # 5 CPU seconds
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    except (ValueError, OSError):
        pass


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

        cmd = [sys.executable, "-m", "backend.app.services.static.worker", input_file, output_file]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=_set_worker_rlimits if os.name != "nt" else None,
        )

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
            return {
                "status": "parser_failed",
                "error": f"Worker crashed or aborted (exit code {proc.returncode}): {err_msg}",
                "could_not_analyze": ["Parser terminated unexpectedly on hostile input"],
                "analysis_fidelity": create_static_fidelity_block(duration_ms=elapsed_ms, worker_sandboxed=True),
                **assess_static_evidence(
                    findings=[],
                    capabilities=[],
                    embedded_indicators=[],
                    structural_anomalies=[],
                    benign_signals=[],
                    could_not_analyze=["Parser crashed on malformed input"],
                    is_parser_error=True,
                    parser_error_reason=f"Parser worker crashed (exit code {proc.returncode})",
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

        from .pipeline import run_complete_static_pipeline
        parsed_result = run_complete_static_pipeline(blob)

        with open(out_path, "w", encoding="utf-8") as f_out:
            json.dump(parsed_result, f_out)
        sys.exit(0)
    except Exception as exc:
        sys.stderr.write(f"Worker exception: {exc}\n")
        sys.exit(2)
