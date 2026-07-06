# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A/B the agentic Ghidra RE stage across models (local Qwen vs cloud Claude).

Replays a saved Ghidra project through the interpret container's agentic loop
once per model and writes the analyses + reliability metrics side-by-side.
Increment-2 measurement tooling — see
docs/superpowers/specs/2026-07-06-local-re-ab-design.md. Sibling of llm_ab_summary.py.
"""
import argparse  # noqa: F401
import json
import time
from pathlib import Path

from stages.interpret import run_interpret


def build_re_configs(base_config: dict, models: list[str]) -> list[dict]:
    """One interpret_config per arm. A model whose name starts with 'local'
    routes through the LiteLLM router (re_backend=local) with escalation pinned
    to itself (pure-local, no Claude fallback). Cloud models keep base config."""
    configs: list[dict] = []
    for m in models:
        cfg = {**base_config, "model": m}
        if m.startswith("local"):
            cfg["re_backend"] = "local"
            cfg["escalation_model"] = m
        configs.append(cfg)
    return configs


def extract_metrics(arm_result: dict) -> dict:
    """Mechanical reliability metrics for one arm. Tool-call errors (the
    router translation-fidelity signal) come from the audit tool_call_log file."""
    analysis = arm_result.get("analysis", {}) or {}
    err = arm_result.get("error") or analysis.get("error")
    completed = arm_result.get("enabled") is True and not err and bool(analysis)

    logged = errors = 0
    audit_path = (arm_result.get("audit") or {}).get("tool_call_log")
    if audit_path and Path(audit_path).exists():
        log = json.loads(Path(audit_path).read_text())
        logged = len(log)
        errors = sum(1 for e in log if "error" in e)

    return {
        "completed": completed,
        "tool_calls_used": arm_result.get("tool_calls_used", 0),
        "tool_calls_logged": logged,
        "tool_call_errors": errors,
        "tool_call_error_rate": round(errors / logged, 3) if logged else 0.0,
        "duration_seconds": arm_result.get("duration_seconds"),
        "model_final": arm_result.get("model_final", ""),
        "family": analysis.get("family") or analysis.get("family_guess", ""),
        "error": err,
    }


def run_re_ab(ghidra_result: dict, output_dir: Path, base_config: dict,
              models: list[str], interpret_cmd: str, ghidra_cmd: str,
              interpret_timeout: int = 1200) -> dict[str, dict]:
    """Replay the agentic RE loop once per model against the same Ghidra project.

    Each arm writes into its own output subdir so the audit tool_call_log files
    don't clobber between arms. Returns {model: run_interpret_result + wall_seconds}.
    """
    results: dict[str, dict] = {}
    for cfg in build_re_configs(base_config, models):
        model = cfg["model"]
        arm_dir = output_dir / ("arm_" + model.replace("/", "_").replace(":", "_"))
        arm_dir.mkdir(parents=True, exist_ok=True)
        t0 = time.time()
        res = run_interpret(ghidra_result, arm_dir, interpret_cmd, True,
                            interpret_timeout, cfg, ghidra_cmd)
        res["wall_seconds"] = round(time.time() - t0, 1)
        results[model] = res
    return results
