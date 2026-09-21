# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""An eval corpus sample must carry its own Ghidra project (#631).

On 2026-09-11 four corpus reports were refreshed in the same second from the
post-rebuild run outputs. The refresh copied `report.json` and not the Ghidra
project, so `report["ghidra"]["project_dir"]` came to point at
`/opt/pipeline/reports/r5_<sample>/...` — a transient per-run directory. Those
directories were later deleted, and from then on every agent tool call on those
samples failed:

    realpath: /opt/pipeline/reports/r5_unclassified_42b9c406/shellcode_0_N/A/project:
              No such file or directory

The eval scored those cells `tool_layer_broken` and refused to count them, which
is why this surfaced at all. But nothing failed at the moment the corpus was
broken, and the four untouched samples — still carrying their July projects
INSIDE their corpus dirs — went on working, so the corpus looked half-healthy
for nine days.

No code in this repo writes into eval-corpus/; that refresh was done by hand.
There is therefore no code path to fix, and this check IS the fix: a corpus
whose reports point outside themselves is not frozen evidence, whatever it
looks like on disk.

The assertion is on the manifest + report pair, so it runs without the corpus
being present — CI has no /opt/pipeline. Where the corpus IS present, it also
checks the directory really exists.
"""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = sorted((ROOT / "ansible" / "roles" / "pipeline" / "files" / "eval").glob("*.json"))


def _samples(manifest: Path):
    data = json.loads(manifest.read_text())
    return data.get("samples", data) if isinstance(data, dict) else data


def test_there_are_manifests_to_check():
    """Guards the guard: a glob that matches nothing would pass every test below."""
    assert MANIFESTS, "no corpus manifests found — this file would vacuously pass"


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_every_sample_names_a_corpus_dir(manifest):
    for s in _samples(manifest):
        assert s.get("corpus_dir"), f"{manifest.name}: sample without corpus_dir: {s}"


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_no_report_points_its_project_outside_its_own_corpus_dir(manifest):
    """The check that would have failed on 2026-09-11."""
    checked = 0
    for s in _samples(manifest):
        cdir = Path(s["corpus_dir"])
        report = cdir / "report.json"
        if not report.exists():
            continue                      # corpus not deployed here (CI)
        ghidra = json.loads(report.read_text()).get("ghidra") or {}
        pdir = ghidra.get("project_dir")
        if not pdir:
            continue                      # no Ghidra project: .NET and friends
        checked += 1
        assert Path(pdir).is_relative_to(cdir), (
            f"{cdir.name}: project_dir escapes the corpus dir and will not "
            f"survive cleanup of the run that produced it:\n  {pdir}")
        assert Path(pdir).is_dir(), (
            f"{cdir.name}: project_dir does not exist, so every tool call in "
            f"every cell for this sample will fail:\n  {pdir}")
    if checked == 0:
        pytest.skip(f"{manifest.name}: no deployed reports with a project_dir")


@pytest.mark.parametrize("manifest", MANIFESTS, ids=lambda m: m.name)
def test_no_project_dir_contains_a_path_separator_artifact(manifest):
    """`shellcode_0_N/A` — the malformed name that made these paths
    unreconstructable even before the directories were deleted."""
    for s in _samples(manifest):
        report = Path(s["corpus_dir"]) / "report.json"
        if not report.exists():
            continue
        pdir = (json.loads(report.read_text()).get("ghidra") or {}).get("project_dir") or ""
        assert "N/A" not in pdir, f"{s['corpus_dir']}: unresolved address in path: {pdir}"
