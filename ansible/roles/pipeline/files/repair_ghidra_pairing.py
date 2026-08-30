# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Repair the canonical Ghidra pairing in reports written before #490.

`propagate_project_dir` used to name the analysed file with the most functions
without checking that the project still held it. On 3 of the 10 corpus samples
with any Ghidra output it named a program Ghidra could not open, so every
interpret-stage tool call failed while the report showed `triggered: true`, 63
analysed files and no warning.

#492 fixed selection at REPORT time. Reports already on disk keep the bad
pairing, and re-running the pipeline to fix a field would change the sample data
underneath every result derived from it. This repairs the field in place
instead.

WRITES ARE OPT-IN. Default is a dry run, because rewriting `report.json` with no
backup and no record of what changed is #405, and doing it to fix #490 would be
a poor trade. With `--apply` each file is backed up beside itself first and the
repair is appended to `analysis_warnings`, so the report says what happened to
it rather than quietly presenting different values than it did yesterday.

A pairing is only replaced when the replacement is VERIFIED to open and the
current one is VERIFIED not to. An inconclusive probe changes nothing: it is not
evidence, and a repair tool that edits on a maybe is worse than the defect.

Usage:
    python3 repair_ghidra_pairing.py /opt/pipeline/eval-corpus/*/report.json
    python3 repair_ghidra_pairing.py --apply /opt/pipeline/eval-corpus/*/report.json
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stages.ghidra import make_ghidra_verifier  # noqa: E402


def candidate_projects(report_path: Path, af: dict, stored: str | None) -> list[str]:
    """Project directories that might hold this analysis, best guess first.

    Three, because a report is not always beside the project that produced it.
    A corpus entry carries a copy of the project next to `report.json`, while
    `host_output_dir` still names the `/opt/pipeline/reports/<task>` directory
    the analysis actually ran in — and `cleanup.sh` deletes those after 7 days.
    Trying the neighbour first means a corpus sample repairs even after its
    original task directory is long gone.
    """
    out = []
    for path in (report_path.parent / "project",
                 (Path(af["host_output_dir"]) / "project"
                  if af.get("host_output_dir") else None),
                 stored):
        if path and str(path) not in out:
            out.append(str(path))
    return out


def ranked_programs(ghidra: dict) -> list[dict]:
    """Successful analyses, most functions first — the same preference order
    selection uses, so a repair picks the best OPENABLE one rather than merely
    a different one."""
    usable = [af for af in (ghidra.get("analyzed_files") or [])
              if isinstance(af, dict) and af.get("analysis_success")
              and af.get("program_name")]
    return sorted(usable,
                  key=lambda af: (af.get("functions_count") or 0,
                                  len(af.get("imports") or [])),
                  reverse=True)


def diagnose(report: dict, report_path: Path, verify) -> dict:
    """What, if anything, should change about this report's canonical pairing.

    status:
      no_ghidra   — nothing to repair
      ok          — the stored pairing opens; left alone
      repaired    — a different pairing opens and the stored one does not
      unopenable  — nothing opens; left alone, because inventing a pairing
                    would be a worse answer than the true one
      unverified  — the probe could not answer; left alone
    """
    ghidra = report.get("ghidra")
    if not isinstance(ghidra, dict):
        return {"status": "no_ghidra"}
    stored_project = ghidra.get("project_dir")
    stored_program = ghidra.get("program_name")
    if not stored_project or not stored_program:
        return {"status": "no_ghidra"}

    old = (stored_project, stored_program)
    if verify(stored_project, stored_program) is True:
        return {"status": "ok", "old": old}

    inconclusive = False
    for af in ranked_programs(ghidra):
        program = af["program_name"]
        for project in candidate_projects(report_path, af, stored_project):
            verdict = verify(project, program)
            if verdict is True:
                return {
                    "status": "repaired", "old": old, "new": (project, program),
                    "functions": af.get("functions_count"),
                    "warning": (
                        f"Ghidra: canonical pairing repaired (#490) — was "
                        f"{stored_program[:16]} in {stored_project}, which the "
                        f"project does not hold; now {program[:16]} "
                        f"({af.get('functions_count')} functions) in {project}"),
                }
            if verdict is None:
                inconclusive = True

    if inconclusive:
        return {"status": "unverified", "old": old}
    return {"status": "unopenable", "old": old}


def apply_repair(report_path: Path, report: dict, result: dict) -> Path:
    """Write the repair, backing up the original beside it first.

    The backup is not politeness. `--replay` overwriting `report.json` in place
    with no way to tell what it destroyed is #405, and a repair tool that
    repeats it would be trading one silent rewrite for another.
    """
    backup = report_path.with_suffix(".json.pre-490")
    if not backup.exists():
        shutil.copy2(report_path, backup)

    project, program = result["new"]
    report["ghidra"]["project_dir"] = project
    report["ghidra"]["program_name"] = program
    warnings = report["ghidra"].setdefault("analysis_warnings", [])
    if isinstance(warnings, list) and result["warning"] not in warnings:
        warnings.append(result["warning"])

    tmp = report_path.with_suffix(".json.repair-tmp")
    tmp.write_text(json.dumps(report, indent=2, default=str))
    tmp.replace(report_path)
    return backup


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("reports", nargs="+", help="report.json paths")
    ap.add_argument("--apply", action="store_true",
                    help="write the repairs (default: report what would change)")
    ap.add_argument("--ghidra-cmd", default="/opt/ghidra/run-ghidra")
    args = ap.parse_args()

    verify = make_ghidra_verifier(args.ghidra_cmd)
    counts: dict = {}
    for raw in args.reports:
        path = Path(raw)
        try:
            report = json.loads(path.read_text())
        except (OSError, ValueError) as e:
            print(f"  [read-fail]  {path}: {e}")
            counts["read_fail"] = counts.get("read_fail", 0) + 1
            continue

        result = diagnose(report, path, verify)
        status = result["status"]
        counts[status] = counts.get(status, 0) + 1
        label = path.parent.name

        if status == "repaired":
            _, program = result["new"]
            action = "REPAIRED" if args.apply else "would repair"
            print(f"  [{status}]   {label}: {action} "
                  f"{result['old'][1][:16]} -> {program[:16]} "
                  f"({result['functions']} functions)")
            if args.apply:
                backup = apply_repair(path, report, result)
                print(f"               backup: {backup}")
        elif status == "unopenable":
            print(f"  [{status}] {label}: nothing in the project opens — "
                  f"needs re-analysis, not repair")
        elif status == "unverified":
            print(f"  [{status}] {label}: probe could not answer; unchanged")

    print("\nsummary:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing")
    if not args.apply and counts.get("repaired"):
        print("dry run — re-run with --apply to write these")
    return 0


if __name__ == "__main__":
    sys.exit(main())
