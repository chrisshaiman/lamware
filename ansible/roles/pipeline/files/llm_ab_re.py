# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A/B the agentic Ghidra RE stage across models (local Qwen vs cloud Claude).

Replays a saved Ghidra project through the interpret container's agentic loop
once per model and writes the analyses + reliability metrics side-by-side.
Increment-2 measurement tooling — see
docs/superpowers/specs/2026-07-06-local-re-ab-design.md. Sibling of llm_ab_summary.py.
"""
import argparse
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
            # Thinking-on models share the token budget between hidden reasoning and
            # the answer; the production 4096 starves the answer. Give the local arm room.
            cfg["max_output_tokens"] = max(cfg.get("max_output_tokens", 0), 8192)
        configs.append(cfg)
    return configs


def analysis_completed(arm_result: dict) -> bool:
    """Did this run produce a usable, structured analysis?

    THE single definition. `lamware_eval.rebuild` re-scores persisted cells
    offline and previously carried its own copy that checked `parse_note` while
    this one did not — so re-scoring a sweep produced a different
    completed_rate than the sweep itself (#380).

    `parse_note` is the case that matters and the one the live path missed. When
    the model's final response is not valid JSON the raw text is preserved in
    `narrative` and a note is set: `enabled` is still True, there is no `error`,
    and `analysis` is a non-empty dict — so every other condition holds and the
    cell counted as a success. In the 29-sample MOTIF sweep that reported
    completed_rate 1.0 while the two largest samples returned nothing usable.
    """
    analysis = arm_result.get("analysis") or {}
    err = arm_result.get("error") or analysis.get("error")
    return (arm_result.get("enabled") is True
            and not err
            and bool(analysis)
            and not analysis.get("parse_note"))


# At or above this share of failed tool calls, the cell measured nothing about
# the model and everything about the infrastructure. Chosen from the corpus:
# claim-bearing cells run at 5 errors in 444 calls (1.1%), and the one cell with
# a genuinely dead tool layer was 5 of 5 (100%). Nothing observed lands between.
TOOL_LAYER_BROKEN_THRESHOLD = 0.5


def is_tool_error(entry: dict) -> bool:
    """Did this logged tool call fail to produce a usable result?

    Two shapes reach the log, and only the first was ever counted (#316):

        {"tool": …, "args": …, "error": "…"}             validation refused it
        {"tool": …, "args": …, "result": {"error": "…"}}  it ran and failed

    The second is the one that matters. `run_ghidra_tool` returns `{"error": …}`
    for a non-zero exit, a timeout, or unparseable output, and every one of
    those scored as a success because the CALL completed — which is how a cell
    with 8 of 8 tool calls failing reported `tool_call_error_rate: 0.0`.
    """
    if entry.get("error"):
        return True
    result = entry.get("result")
    return isinstance(result, dict) and bool(result.get("error"))


def extract_metrics(arm_result: dict) -> dict:
    """Mechanical reliability metrics for one arm. Tool-call errors (the
    router translation-fidelity signal) come from the audit tool_call_log file."""
    analysis = arm_result.get("analysis", {}) or {}
    err = arm_result.get("error") or analysis.get("error")
    completed = analysis_completed(arm_result)

    logged = errors = 0
    audit_path = (arm_result.get("audit") or {}).get("tool_call_log")
    if audit_path and Path(audit_path).exists():
        log = json.loads(Path(audit_path).read_text())
        logged = len(log)
        errors = sum(1 for e in log if is_tool_error(e))

    error_rate = round(errors / logged, 3) if logged else 0.0
    return {
        "completed": completed,
        # A cell whose tool layer was dead says nothing about the model. Scored
        # as an ordinary zero-claim result, it contributed a misleading 0/0 to
        # both arms of an A/B as though depth had been fairly tested on it.
        "tool_layer_broken": bool(logged) and error_rate >= TOOL_LAYER_BROKEN_THRESHOLD,
        # A distinct outcome from both success and error: the run finished, the
        # model answered, and the answer could not be parsed. Folding it into
        # either loses the signal (#380).
        "parse_failed": bool(analysis.get("parse_note")),
        "tool_calls_used": arm_result.get("tool_calls_used", 0),
        "tool_calls_logged": logged,
        "tool_call_errors": errors,
        "tool_call_error_rate": error_rate,
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


def _load_labels(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {}


def _render_compare(sample: str, metrics: dict, results: dict, labels: dict) -> str:
    lines = [f"# RE A/B — {sample}\n"]
    lbl = labels.get(sample, {})
    if lbl:
        lines.append(f"**Expected (ground truth):** family=`{lbl.get('family', '?')}` "
                     f"techniques={lbl.get('techniques', [])}\n")
    models = list(metrics.keys())
    lines.append("| metric | " + " | ".join(models) + " |")
    lines.append("|" + "---|" * (len(models) + 1))
    for k in ["model_final", "completed", "tool_calls_used", "tool_calls_logged",
              "tool_call_errors", "tool_call_error_rate", "duration_seconds", "family", "error"]:
        row = [str(metrics[m].get(k)) for m in models]
        lines.append(f"| {k} | " + " | ".join(row) + " |")
    for model in models:
        lines.append(f"\n## {model} — analysis\n")
        lines.append("```json")
        lines.append(json.dumps(results[model].get("analysis", {}), indent=2, default=str))
        lines.append("```")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="A/B the agentic Ghidra RE stage across models.")
    ap.add_argument("analysis_dirs", nargs="+",
                    help="pipeline analysis dirs (each has report.json + project/)")
    ap.add_argument("--cloud", default="claude-sonnet-4-6", help="cloud model (production RE baseline)")
    ap.add_argument("--local", default="local-qwen-re", help="local model (routes via re_backend=local)")
    ap.add_argument("--config", default="/opt/pipeline/config.json",
                    help="pipeline config.json (its 'interpret' block is the base config)")
    ap.add_argument("--interpret-cmd", default="/opt/interpret/run-interpret")
    ap.add_argument("--ghidra-cmd", default="/opt/ghidra/run-ghidra")
    ap.add_argument("--out-dir", default=None, help="default: <analysis_dir>/re_ab")
    ap.add_argument("--labels", default=str(Path(__file__).parent / "re_ab_labels.json"))
    args = ap.parse_args()

    base = json.loads(Path(args.config).read_text())["interpret"]
    labels = _load_labels(args.labels)
    models = [args.cloud, args.local]

    for d in args.analysis_dirs:
        dpath = Path(d)
        sample = dpath.name
        report = json.loads((dpath / "report.json").read_text())
        gr = report["ghidra"]
        out = Path(args.out_dir) if args.out_dir else dpath / "re_ab"
        out.mkdir(parents=True, exist_ok=True)
        results = run_re_ab(gr, out, base, models, args.interpret_cmd, args.ghidra_cmd)
        metrics = {}
        for model, res in results.items():
            safe = model.replace("/", "_").replace(":", "_")
            (out / f"ab_re_{safe}.json").write_text(json.dumps(res, indent=2, default=str))
            metrics[model] = extract_metrics(res)
        (out / "ab_re_compare.md").write_text(_render_compare(sample, metrics, results, labels))
        print(f"[{sample}] -> {out / 'ab_re_compare.md'}")
        for model, m in metrics.items():
            print(f"   {model}: completed={m['completed']} "
                  f"tool_err_rate={m['tool_call_error_rate']} family={m['family']} "
                  f"{m['duration_seconds']}s")


if __name__ == "__main__":
    main()
