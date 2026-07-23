# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A/B a single-shot analysis stage across local models vs the saved Claude output.

Loads a saved pipeline report, detects the single-shot type (.NET / Go / PowerShell),
rebuilds the exact init payload the pipeline would send, and runs it through the
interpret container once per local model over the LiteLLM UDS. Writes each model's
structured analysis + a grounding (fabrication) scorecard next to the report. The
Claude baseline is the `llm_interpretation.analysis` already in the report — not re-run.

Usage (on the sandbox host, pipeline user):
    python llm_ab_singleshot.py <report.json> \
        --models local-qwen-re local-qwen32-re local-gptoss-re
"""
import argparse
import json
import time
from pathlib import Path

from grounding_check import grounding_scorecard
from stages.interpret import run_interpret
from stages.single_shot_init import build_dotnet_init, build_go_init, build_ps_init

# The single-shot call is one longer request; give a wide ceiling so a slow dense
# model (qwen3:32b) is not cut off. A timeout is still a valid negative result.
# Budget must sit well ABOVE the reasoning budget: with think:true, thinking tokens
# count against max_tokens, so a tight ceiling truncates or starves the final JSON
# (universal reasoning-model behavior; observed here as stop_reason=max_tokens).
EVAL_TIMEOUT = 3600
MAX_OUTPUT_TOKENS = 16384


def build_singleshot_configs(models: list[str]) -> list[dict]:
    """One interpret_config per model. Local model names route single-shot local."""
    cfgs = []
    for m in models:
        cfg = {"model": m, "max_output_tokens": MAX_OUTPUT_TOKENS}
        if m.startswith("local-"):
            cfg["single_shot_backend"] = "local"
        cfgs.append(cfg)
    return cfgs


def init_for_report(report: dict) -> dict | None:
    """Detect the single-shot stage in a saved report and rebuild its init payload."""
    llm_context = {}
    if report.get("bazaar_family"):
        llm_context["bazaar_family"] = report["bazaar_family"]
    cape_sigs = [s.get("name", "") for s in report.get("cape", {}).get("signatures", [])]

    dotnet = report.get("dotnet_analysis", {})
    go = report.get("go_analysis", {})
    ps = report.get("powershell_analysis", {})

    if dotnet.get("analysis_success"):
        return build_dotnet_init(dotnet, llm_context, cape_sigs)
    if go.get("analysis_success"):
        return build_go_init(go, llm_context)
    if ps.get("analysis_success"):
        return build_ps_init(ps, llm_context, cape_sigs)
    return None


def source_text_for(init: dict) -> str:
    """Grounding corpus: the serialized init payload holds all source material."""
    return json.dumps(init)


def run_ab(report: dict, interpret_cmd: str, ghidra_cmd: str,
           output_dir: Path, models: list[str]) -> dict[str, dict]:
    """Run the report's single-shot payload through each model; grounding-score each."""
    init = init_for_report(report)
    if init is None:
        raise SystemExit("No single-shot stage (dotnet/go/powershell) found in report.")
    source_text = source_text_for(init)
    results: dict[str, dict] = {}
    for cfg in build_singleshot_configs(models):
        model = cfg["model"]
        t0 = time.time()
        res = run_interpret(init, output_dir,
                            interpret_cmd=interpret_cmd,
                            interpret_enabled=True,
                            interpret_timeout=EVAL_TIMEOUT,
                            interpret_config=cfg,
                            ghidra_cmd=ghidra_cmd)
        analysis = res.get("analysis", {})
        results[model] = {
            "analysis_type": init.get("analysis_type"),
            "seconds": round(time.time() - t0, 1),
            "analysis": analysis,
            "grounding": grounding_scorecard(analysis, source_text),
            "usage": res.get("usage", {}),
            "error": res.get("error"),
        }
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="A/B a single-shot stage across local models.")
    ap.add_argument("report", help="path to a saved pipeline report.json")
    ap.add_argument("--models", nargs="+",
                    default=["local-qwen-re", "local-qwen32-re", "local-gptoss-re"],
                    help="model names to run (must exist in LiteLLM model_list)")
    ap.add_argument("--interpret-cmd", default="/opt/interpret/run-interpret")
    ap.add_argument("--ghidra-cmd", default="/opt/ghidra/run-ghidra")
    ap.add_argument("--out-dir", default=None,
                    help="output dir (default: <report>/../llm_audit)")
    args = ap.parse_args()

    report_path = Path(args.report)
    report = json.loads(report_path.read_text())
    out_dir = Path(args.out_dir) if args.out_dir else report_path.parent / "llm_audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Claude baseline = what the report already shipped.
    baseline = report.get("llm_interpretation", {}).get("analysis", {})
    (out_dir / "ab_singleshot_baseline_claude.json").write_text(json.dumps(baseline, indent=2))

    results = run_ab(report, args.interpret_cmd, args.ghidra_cmd, out_dir, args.models)
    for model, r in results.items():
        safe = model.replace("/", "_").replace(":", "_")
        (out_dir / f"ab_singleshot_{safe}.json").write_text(json.dumps(r, indent=2))
        g = r["grounding"]
        print(f"[{model}] {r['seconds']}s type={r['analysis_type']} "
              f"grounded={g['grounded']}/{g['total']} fabricated={g['fabricated']} "
              f"err={r['error']}")


if __name__ == "__main__":
    main()
