# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The on-disk half of the #686 correlation fixture.

`fixtures/correlation_report_v655.json` is the cape and volatility sections of
the real host report v655_5b4f596d3cf5, trimmed: its STRUCTURE is real (which
keys each row has, value types, which values are null, PIDs, VAD bounds,
injection addresses, which Cape PIDs have a Volatility cmdline row and which of
those pairs differ), and every string a sample or guest could have chosen is
synthetic. The C2 config is added: the real run decoded none.

cross_correlate also reads files — Cape's files.json, the injection buffers,
the VAD dumps and the memory image — so `materialise` writes synthetic ones
under a temp root and points the report at them. With them every rule fires on
the fixture, so the golden covers all five. The golden
(`correlation_report_v655.golden.json`) was produced by origin/main's
correlation_rules.py (ac1767f) through this same function, before #686.

A plain module (loaded by path, like dotnet_formbook_shape.py) rather than a
conftest fixture, so the golden generator and the Hypothesis test (which cannot
take function-scoped fixtures) can both call it.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent
REPORT = json.loads((FIXTURES / "correlation_report_v655.json").read_text(encoding="utf-8"))
GOLDEN = json.loads((FIXTURES / "correlation_report_v655.golden.json").read_text(encoding="utf-8")) \
    if (FIXTURES / "correlation_report_v655.golden.json").exists() else None

C2_HOST = "c2-host.example.com"
_CAPE_BYTES = b"\x90" * 64
_CHANGED_BYTES = b"\xcc" * 64


def _dump_name(name) -> bool:
    return isinstance(name, str) and name.strip().lower() not in ("disabled", "error outputting file")


def materialise(root: Path) -> tuple[dict, str, str]:
    """(report, cape_storage_root, pipeline_reports_root) with every file the
    report names written under `root`. Callers point correlation_rules'
    _CAPE_STORAGE_ROOT / _PIPELINE_REPORTS_ROOT at the two roots."""
    report = copy.deepcopy(REPORT)
    storage = root / "storage"
    reports = root / "reports"
    task = storage / str(report["cape"]["task_id"])
    task.mkdir(parents=True, exist_ok=True)
    out = reports / report["task_id"]
    (out / "cape_injections").mkdir(parents=True, exist_ok=True)
    vad_dir = out / "vol_vadinfo"
    vad_dir.mkdir(parents=True, exist_ok=True)

    # Cape's manifest: one file the sample wrote that a process then loaded,
    # one it wrote that nothing loaded, and one of Cape's own dump artifacts.
    loaded = next(r["Path"] for r in report["volatility"]["plugins"]["dlllist"]
                  if isinstance(r.get("Path"), str))
    records = [{"category": "files", "filepath": loaded},
               {"category": "files", "filepath": "C:\\Users\\u\\AppData\\Local\\Temp\\x.dll"},
               {"category": "CAPE", "filepath": "C:\\abc\\CAPE\\1_2"}]
    (task / "files.json").write_text("\n".join(json.dumps(r) for r in records) + "\n")
    (task / "memory.dmp").write_bytes(b"\0" * 64 + C2_HOST.encode() + b"\0" * 64)

    # Injection buffers as Cape captured them.
    for buf in report["cape"]["injection_buffers"]:
        path = out / buf["path"]
        path.write_bytes(_CAPE_BYTES)
        buf["path"] = str(path)

    # VAD dumps. Sparse: only the bytes a rule reads are written. The first
    # buffer's address holds different bytes (self-modified), the second the
    # same ones; every dump carries the C2 host, so the VAD scan finds it too.
    vads = report["volatility"]["plugins"]["vadinfo"]
    for vad in vads:
        if _dump_name(vad["File output"]):
            with open(vad_dir / vad["File output"], "wb") as fh:
                fh.write(b"\0" * 32 + C2_HOST.encode())
    for i, buf in enumerate(report["cape"]["injection_buffers"]):
        addr = int(buf["injection_address"], 16)
        vad = next(v for v in vads if v["PID"] == buf["target_pid"]
                   and v["Start VPN"] <= addr <= v["End VPN"])
        assert _dump_name(vad["File output"]), "fixture lost its dumped injection VAD"
        with open(vad_dir / vad["File output"], "r+b") as fh:
            fh.seek(addr - vad["Start VPN"])
            fh.write(_CHANGED_BYTES if i == 0 else _CAPE_BYTES)
    report["volatility"]["vad_dump_dir"] = str(vad_dir)
    return report, str(storage), str(reports)


def comparable(findings: list[dict], warnings: list[str], root: Path) -> dict:
    """Findings and warnings with the temp root replaced, so two runs under
    different temp directories compare equal."""
    text = json.dumps({"findings": findings, "correlation_warnings": warnings})
    return json.loads(text.replace(json.dumps(str(root))[1:-1], "<root>"))
