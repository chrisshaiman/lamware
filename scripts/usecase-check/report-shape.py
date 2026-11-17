#!/usr/bin/python3 -I
"""ADR-031 use-case check: did every pipeline stage still work?

    report-shape.py <report.json>                      print the stage predicates as JSON
    report-shape.py <report.json> --baseline <b.json>  compare; exit 1 if a stage regressed

A permissions change here rarely crashes anything: a stage that loses read access
comes back empty or skipped, and the report just gets thinner. So each predicate is
"this stage did its job", and a run passes when every predicate that held in the
baseline still holds. Counts and contents are not compared: repeated runs of the same
sample differ, and that is not what this check is for. Standard library only.
"""
from __future__ import annotations

import json
import os
import sys


def _nonempty(v) -> bool:
    return bool(v) and v not in ("", [], {})


def predicates(report: dict, report_dir: str) -> dict[str, bool]:
    r = report
    g = lambda *ks: _get(r, ks)  # noqa: E731
    p = {
        "triage.yara_ran": _nonempty(g("triage", "yara_status")),
        "triage.floss_ran": _nonempty(g("triage", "floss")),
        "cape.reported": g("cape", "status") == "reported",
        "cape.memory_dump_requested": g("cape", "memory_dump_requested") is True,
        "pcap.has_pcap": (g("pcap_analysis", "pcap_size") or 0) > 0,
        "pcap.zeek_ran": _nonempty(g("pcap_analysis", "zeek")),
        "pcap.suricata_ran": _nonempty(g("pcap_analysis", "suricata")),
        "volatility.plugins_ran": _nonempty(g("volatility", "plugins_run")),
        "dotnet.succeeded": g("dotnet_analysis", "analysis_success") is True,
        "ghidra.analyzed_files": _nonempty(g("ghidra", "analyzed_files")),
        "interpret.analysis": _nonempty(g("llm_interpretation", "analysis")),
        "screenshots.succeeded": g("screenshots", "analysis_success") is True,
        "visual.analysis": _nonempty(g("visual_analysis", "analysis")),
        "summary.executive": _nonempty(g("executive_summary", "executive_summary")),
        "iocs.extracted": _nonempty(r.get("extracted_iocs")),
        "mitre.mapped": _nonempty(r.get("mitre_mapping")),
    }
    for name, kind in (("report.pdf", "file"), ("pcap_analysis", "dir"), ("vol_procdump", "dir"),
                       ("cape_injections", "dir"), ("llm_audit", "dir")):
        path = os.path.join(report_dir, name)
        if kind == "file":
            p[f"artifact.{name}"] = os.path.isfile(path) and os.path.getsize(path) > 0
        else:
            p[f"artifact.{name}"] = os.path.isdir(path) and any(os.scandir(path))
    return p


def _get(d, keys):
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def compare(now: dict[str, bool], base: dict[str, bool]) -> list[str]:
    """Predicates true in the baseline and not now. New truths are fine."""
    return sorted(k for k, v in base.items() if v and not now.get(k, False))


def main(argv: list[str]) -> int:
    path = argv[0]
    with open(path, encoding="utf-8") as f:
        now = predicates(json.load(f), os.path.dirname(os.path.abspath(path)))
    if "--baseline" not in argv:
        print(json.dumps(now, indent=1, sort_keys=True))
        return 0
    with open(argv[argv.index("--baseline") + 1], encoding="utf-8") as f:
        base = json.load(f)
    lost = compare(now, base)
    held = sum(1 for v in base.values() if v)
    if lost:
        print(f"REGRESSED: {len(lost)} of {held} baseline stages no longer hold: {', '.join(lost)}")
        return 1
    print(f"OK: all {held} baseline stages still hold")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
