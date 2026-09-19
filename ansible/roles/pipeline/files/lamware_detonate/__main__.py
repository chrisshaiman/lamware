# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CLI: python -m lamware_detonate run --sample <path> --runs N [--machine clean]

The front door that did not exist. Every #518 batch was a bespoke shell script
because running this measurement required one, and the scripts diverged: only
the last of them pinned the guest, and by then two batches had been discarded.
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import requests

# The measurement definitions live in the pipeline modules and are REUSED rather
# than reimplemented here. observed_behaviour is defined once, in
# evasion_baseline.sample_metrics, where it was fixed BEFORE the comparison
# existed (#517); a second copy in this file is how the primary metric quietly
# becomes two different numbers.
#
# evasion_baseline and stages.* deploy FLAT to /opt/pipeline, so they import as
# top-level modules rather than from a package.
from evasion_baseline import sample_metrics
from stages.cape import (
    CAPE_API_URL,
    cape_headers,
    detonation_health,
    extract_cape_intel,
)

from lamware_detonate.aggregate import render, summarize
from lamware_detonate.batch import run_batch

STORAGE = Path("/opt/CAPEv2/storage/analyses")


def _submit(sample: Path, fields: dict) -> int:
    with sample.open("rb") as fh:
        resp = requests.post(f"{CAPE_API_URL}/tasks/create/file/",
                             files={"file": (sample.name, fh)},
                             data=fields, headers=cape_headers(), timeout=120)
    resp.raise_for_status()
    body = resp.json()
    if body.get("error"):
        raise ValueError(f"CAPE rejected submission: {body.get('error_value', body)}")
    return int(body["data"]["task_ids"][0])


def _poll_status(task_id: int) -> str:
    resp = requests.get(f"{CAPE_API_URL}/tasks/status/{task_id}/",
                        headers=cape_headers(), timeout=20)
    resp.raise_for_status()
    return resp.json().get("data", "") or ""


def _fetch_report(task_id: int) -> dict:
    path = STORAGE / str(task_id) / "reports" / "report.json"
    with path.open() as fh:
        return json.load(fh)


def _measure(full_report: dict) -> tuple[str, dict, dict]:
    """(tier, metrics, health) for one completed analysis."""
    health = detonation_health(full_report)
    task_id = (full_report.get("info") or {}).get("id")
    intel = extract_cape_intel({"id": task_id}) if task_id else {}
    metrics = sample_metrics({"cape": intel})
    return health.get("tier", "UNKNOWN"), metrics, health


def main() -> None:
    ap = argparse.ArgumentParser(prog="lamware_detonate",
                                 description="Repeat one detonation N times and stratify by tier.")
    ap.add_argument("cmd", choices=["run"])
    ap.add_argument("--sample", required=True, type=Path)
    ap.add_argument("--runs", type=int, default=20)
    # Pinned by default, but still explicit in the recorded provenance. There is
    # no way to ask for "whatever machine is free" -- see batch.I1.
    ap.add_argument("--machine", default="clean")
    ap.add_argument("--package", default="exe")
    ap.add_argument("--analysis-timeout", type=int, default=200)
    ap.add_argument("--options", default="procmemdump=1,procdump=1",
                    help="CAPE per-task options. `memory` is refused (batch.P1).")
    ap.add_argument("--deadline", type=float, default=3600.0,
                    help="Per-run wall clock before the BATCH aborts. Task 1131 took >30 min.")
    ap.add_argument("--out", type=Path, default=None,
                    help="Where to write the JSON scorecard (default: alongside the sample).")
    args = ap.parse_args()

    if "memory" in args.options:
        ap.error("`memory` is not submittable: 8.6 GB per run with delete_memdump=no "
                 "filled the disk and silently stalled CAPE below freespace=50000 (batch.P1)")
    if not args.sample.is_file():
        ap.error(f"sample not readable: {args.sample}")

    started = datetime.now(UTC)
    print(f"sample={args.sample.name} runs={args.runs} machine={args.machine} "
          f"started={started.isoformat()}", flush=True)

    result = run_batch(sample=args.sample, machine=args.machine, runs=args.runs,
                       submit=_submit, poll_status=_poll_status,
                       fetch_report=_fetch_report, measure=_measure,
                       package=args.package, analysis_timeout_s=args.analysis_timeout,
                       options=args.options, deadline_s=args.deadline,
                       log=lambda m: print(m, flush=True))
    result.sample_name = args.sample.name

    summary = summarize(result)
    summary["provenance"] = {
        "started": started.isoformat(),
        "finished": datetime.now(UTC).isoformat(),
        "sample_path": str(args.sample),
        "package": args.package,
        "analysis_timeout_s": args.analysis_timeout,
        "options": args.options,
        "cape_api": CAPE_API_URL,
    }
    summary["runs_detail"] = [
        {"index": r.index, "task_id": r.task_id, "tier": r.tier,
         "machine": r.machine, "error": r.error,
         "metrics": r.metrics, "health": r.health}
        for r in result.runs
    ]

    out = args.out or args.sample.parent / f"detonate-{args.sample.stem}-{int(time.time())}.json"
    out.write_text(json.dumps(summary, indent=2, default=str))
    print()
    print(render(summary))
    print()
    print(f"scorecard: {out}")

    # A batch that aborted produced a partial measurement. Exiting non-zero means
    # a caller cannot mistake it for a completed one.
    raise SystemExit(1 if result.aborted else 0)


if __name__ == "__main__":
    main()
