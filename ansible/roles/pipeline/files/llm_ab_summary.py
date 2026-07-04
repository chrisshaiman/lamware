# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A/B the executive summary across models (local Ollama vs cloud Anthropic).

Runs a saved report.json through the interpret container once per model and
writes the summaries side-by-side for human comparison, plus the wall-clock per
model (a throughput signal). Increment-1 measurement tooling — see
docs/superpowers/plans/2026-07-04-local-llm-summaries.md.

Usage:
    python llm_ab_summary.py <report.json> --local local-qwen --cloud claude-haiku-4-5
"""
import argparse
import json
import time
from pathlib import Path

from stages.interpret import run_summarize


def build_ab_payloads(report: dict, models: list[str]) -> list[dict]:
    """One summarize payload per model — for side-by-side local-vs-cloud comparison."""
    return [
        {"type": "summarize", "report": report, "config": {"summary_model": m}}
        for m in models
    ]


def run_ab(report: dict, interpret_cmd: str, models: list[str]) -> dict[str, dict]:
    """Summarize the report once per model; return {model: {summary, seconds}}."""
    results: dict[str, dict] = {}
    for payload in build_ab_payloads(report, models):
        model = payload["config"]["summary_model"]
        t0 = time.time()
        summary = run_summarize(payload["report"], interpret_cmd, True, payload["config"])
        results[model] = {"seconds": round(time.time() - t0, 1), "summary": summary}
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description="A/B summarize a report across models.")
    ap.add_argument("report", help="path to a pipeline report.json")
    ap.add_argument("--local", default="local-qwen", help="local model name")
    ap.add_argument("--cloud", default="claude-haiku-4-5", help="cloud model name")
    ap.add_argument("--interpret-cmd", default="/opt/interpret/run-interpret",
                    help="interpret container wrapper")
    ap.add_argument("--out-dir", default=None,
                    help="where to write ab_summary_<model>.json (default: <report>/../llm_audit)")
    args = ap.parse_args()

    report_path = Path(args.report)
    report = json.loads(report_path.read_text())
    out_dir = Path(args.out_dir) if args.out_dir else report_path.parent / "llm_audit"
    out_dir.mkdir(parents=True, exist_ok=True)

    results = run_ab(report, args.interpret_cmd, [args.local, args.cloud])
    for model, r in results.items():
        safe = model.replace("/", "_").replace(":", "_")
        (out_dir / f"ab_summary_{safe}.json").write_text(json.dumps(r["summary"], indent=2))
        print(f"[{model}] {r['seconds']}s -> {out_dir / ('ab_summary_' + safe + '.json')}")


if __name__ == "__main__":
    main()
