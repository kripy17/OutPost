"""Analysis Fidelity Block Generator for OutPost.

Every static and dynamic analysis report must expose an explicit fidelity block
documenting the execution environment, tier, observation method, applied
evasion countermeasures, and fundamental blindspots/limitations of the tier.
"""

from typing import Any, Literal

EnvironmentTier = Literal["offline_static", "tier_0_wine", "tier_1_linux", "tier_2_windows_vm"]


def create_static_fidelity_block(
    duration_ms: int = 0,
    worker_sandboxed: bool = True,
    format_type: str = "unknown",
) -> dict[str, Any]:
    """Generate the fidelity descriptor for static analysis jobs."""
    limitations = [
        "Static analysis only: runtime memory decryption and dynamic packing stages are unexecuted.",
        "Dynamic API hashing and in-memory module loading cannot be observed without live trace.",
    ]
    if format_type in ("pe", "dll"):
        limitations.append("Windows PE executables require Tier 2 Windows Guest for complete behavior validation.")
    elif format_type == "office":
        limitations.append("VBA execution and external template retrieval not triggered during static inspection.")

    return {
        "environment": "isolated_static_worker" if worker_sandboxed else "in_process_static_parser",
        "environment_tier": "offline_static",
        "observation_method": "structural_binary_and_ast_parser",
        "run_duration_ms": max(1, duration_ms),
        "evasion_countermeasures_applied": ["rlimit_constrained_execution", "timeout_bounding"],
        "is_emulated_or_best_effort": False,
        "limitations": limitations,
    }


def create_dynamic_fidelity_block(
    environment: str,
    tier: EnvironmentTier,
    observation_method: str,
    duration_ms: int,
    evasion_countermeasures: list[str] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Generate the fidelity descriptor for dynamic sandbox execution runs."""
    default_limits = list(limitations or [])
    is_best_effort = (tier == "tier_0_wine")

    if is_best_effort:
        default_limits.extend([
            "Wine compatibility layer: kernel drivers, RPC interfaces, and Defender AMSI telemetry are not emulated.",
            "Process parent-child relationships and service control manager events may deviate from Windows kernel.",
            "Results are low-fidelity best-effort indicators, not authoritative Windows execution traces.",
        ])

    return {
        "environment": environment,
        "environment_tier": tier,
        "observation_method": observation_method,
        "run_duration_ms": duration_ms,
        "evasion_countermeasures_applied": evasion_countermeasures or [],
        "is_emulated_or_best_effort": is_best_effort,
        "limitations": default_limits,
    }
