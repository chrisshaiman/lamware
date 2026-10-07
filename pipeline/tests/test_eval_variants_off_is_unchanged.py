# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""`--variants 0` (the default) must produce exactly what a run produced before #715.

Behavioural, against a golden captured from the code BEFORE the change: the
whole CLI (`lamware_eval.__main__.main`) runs over a two-sample corpus with the
interpret container faked, and the scorecard, the cell directories and every
persisted `result.json` are compared byte for byte with
`fixtures/eval_variants_off_golden.json`.

The golden was written by running `produce()` below against origin/main at
2358e79 (the parent of the #715 branch), with this file imported over THAT
checkout's `lamware_eval`. This module therefore imports only names that
existed then; the variant code is exercised elsewhere
(test_eval_order_variants.py).

Mutation-tested: recording the variant fields at K=0, moving v0's directory, or
appending the new scorecard sections without variants each fails this test.
"""
import json
import sys
from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "eval_variants_off_golden.json"

CANON = "c" * 64
PAYLOAD = "d" * 64
IMPORTS = [f"KERNEL32.DLL::Fn{i}" for i in range(8)]
STRINGS = [f"http://c2.invalid/{i}" for i in range(6)]


def _file(name: str, **kw) -> dict:
    return {"program_name": name, "sha256": name, "functions_count": 9,
            "analysis_success": True, "in_project": True, "source": None,
            "project_dir": f"/opt/pipeline/reports/r/{name[:4]}/project",
            "host_output_dir": f"/opt/pipeline/reports/r/{name[:4]}",
            "entry_point": "entry", "imports": list(IMPORTS),
            "strings_of_interest": list(STRINGS), "decompiled_functions": [], **kw}


def native_report() -> dict:
    return {"ghidra": {"program_name": CANON, "project_dir": "/x/project",
                       "analyzed_files": [_file(CANON)]},
            "cape": {"mitre_ttps": [{"id": "T1055"}, {"id": "T1071"}, {"id": "T1027"}]}}


def payload_report() -> dict:
    """A routed sample read through an unpacked payload (#646)."""
    return {"ghidra": {"dotnet_routed": True, "program_name": PAYLOAD,
                       "project_dir": "/x/project",
                       "analyzed_files": [_file(PAYLOAD, source="cape_payload",
                                                cape_type="Amadey Payload")]},
            "cape": {"mitre_ttps": [{"id": "T1055"}, {"id": "T1105"}]}}


def fake_interpret(init, out, *a, **kw) -> dict:
    """A deterministic stand-in for the container whose answer depends on the
    ORDER of the shown lists, as the measured agent's did: the technique it
    claims is chosen by the first import, the IOC is the first string."""
    first = (init.get("imports") or [""])[0]
    tid = {"KERNEL32.DLL::Fn0": "T1055", "KERNEL32.DLL::Fn1": "T1071",
           "KERNEL32.DLL::Fn2": "T1027"}.get(first, "T1105")
    return {"enabled": True, "duration_seconds": 30.0, "usage": {}, "tool_calls_used": 0,
            "analysis": {
                "malware_family_guess": "x",
                "code_level_iocs": [
                    {"value": (init.get("strings_of_interest") or ["none"])[0],
                     "type": "url", "context": "c"},
                    {"value": "http://made.up/never", "type": "url", "context": "c"}],
                "attack_techniques": [{"id": tid, "name": tid}],
                "capabilities": ["c"]}}


def build_corpus(root: Path) -> Path:
    """Two corpus samples (one native, one unpacked payload) and a manifest."""
    samples = []
    for sha, fam, report in (("a" * 64, "amadey", native_report()),
                             ("b" * 64, "rhadamanthys", payload_report())):
        d = root / f"{fam}_{sha[:8]}"
        for f in report["ghidra"]["analyzed_files"]:
            (d / Path(f["host_output_dir"]).name / "project").mkdir(parents=True)
        (d / "report.json").write_text(json.dumps(report))
        samples.append({"sha256": sha, "mb_family": fam, "corpus_dir": str(d)})
    manifest = root / "corpus.json"
    manifest.write_text(json.dumps({"samples": samples}))
    (root / "config.json").write_text(json.dumps(
        {"interpret": {"max_imports": 6, "max_strings": 4}}))
    return manifest


def patch_runner(mp, runner, interpret=fake_interpret) -> None:
    mp.setattr(runner, "run_interpret", interpret)
    mp.setattr(runner, "make_ghidra_verifier", lambda cmd: None)
    mp.setattr(runner, "_server_sampling", lambda: {})
    mp.setattr(runner.time, "time", lambda: 1000.0)


def produce(root: Path, extra_args: tuple[str, ...] = ()) -> dict:
    """Run the CLI end to end; return everything it wrote, paths made relative."""
    from lamware_eval import __main__ as cli
    from lamware_eval import runner

    manifest = build_corpus(root)
    with pytest.MonkeyPatch.context() as mp:
        patch_runner(mp, runner)
        mp.setattr(cli, "gather_provenance", lambda *a, **k: None)
        mp.setattr(sys, "argv", ["lamware_eval", "run", "--corpus", str(manifest),
                                 "--arms", "qwen@10,qwen@10+corr", "--label", "g",
                                 "--config", str(root / "config.json"),
                                 "--out-dir", str(root / "out"), *extra_args])
        cli.main()
    files = {}
    for p in sorted(root.rglob("result.json")):
        files[str(p.relative_to(root))] = p.read_text()
    return {"scorecard": (root / "out" / "g.md").read_text(), "results": files}


def test_variants_off_writes_what_the_code_before_715_wrote(tmp_path, capsys):
    golden = json.loads(GOLDEN.read_text())
    got = produce(tmp_path)
    assert got["scorecard"] == golden["scorecard"]
    assert sorted(got["results"]) == sorted(golden["results"])
    for path, text in golden["results"].items():
        assert got["results"][path] == text, path


def test_the_explicit_zero_is_the_default(tmp_path, capsys):
    got = produce(tmp_path, ("--variants", "0"))
    golden = json.loads(GOLDEN.read_text())
    assert got == {"scorecard": golden["scorecard"], "results": golden["results"]}
