# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The curated eval corpus has to be able to reach a host (#487).

`corpus.json` is seeded with `force: false` so an operator-grown corpus is not
clobbered. That is correct, and it stays. What was wrong is that it was the ONLY
path: a host that had ever run the eval could never receive an updated
selection, so commit 53b260c — which re-picked the corpus for what it EXERCISES
rather than for family diversity — changed the repo and nothing else.

The deployed manifest stayed on its 2026-07-24 version. Measured on the sandbox:
all 7 of its samples produce ZERO cross-tool correlations, while all 10
correlations on the box sit in the 6 samples it does not contain. Run the #420
evidence axis against it and every `+corr` cell is byte-identical to its base
arm — a clean null result with nothing in the output to say why.

Parsed from the YAML rather than grepped: this file's comments name both paths
and both force values, so a text search would find them whether or not the tasks
survive.
"""
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "pipeline"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))
MANIFEST = ROLE / "files" / "eval" / "corpus.json"


def _ini_copies() -> list[dict]:
    return [t["ansible.builtin.copy"] for t in TASKS
            if isinstance(t, dict)
            and isinstance(t.get("ansible.builtin.copy"), dict)]


def _copies_of(src: str) -> list[dict]:
    return [t["ansible.builtin.copy"] for t in TASKS
            if isinstance(t, dict)
            and isinstance(t.get("ansible.builtin.copy"), dict)
            and t["ansible.builtin.copy"].get("src") == src]


def test_the_curated_manifests_reach_a_path_ansible_owns():
    """Without this the repo's selection is unreachable on any host that has
    run the eval once."""
    tasks = [t for t in TASKS
             if isinstance(t, dict)
             and isinstance(t.get("ansible.builtin.copy"), dict)
             and any(str(i).startswith("corpus-") for i in (t.get("loop") or []))]
    assert tasks, "no task ships the curated corpus manifests"
    for t in tasks:
        c = t["ansible.builtin.copy"]
        assert c.get("force") is True, c
        assert c["dest"].startswith("{{ pipeline_install_dir }}/eval/"), c


def test_both_modalities_ship_and_neither_is_pooled():
    """Two experiments, never pooled (#505). Splitting the MANIFEST is what
    enforces it: the provenance stamp records which corpus produced a scorecard
    and its hash changes when the manifest does, so a pooled run would have to
    misreport its own corpus."""
    shipped = set()
    for t in TASKS:
        if not isinstance(t, dict):
            continue
        c = t.get("ansible.builtin.copy")
        if isinstance(c, dict) and isinstance(t.get("loop"), list):
            shipped |= {i for i in t["loop"] if str(i).startswith("corpus-")}
    assert shipped == {"corpus-native.json", "corpus-dotnet.json"}, shipped


def test_the_pooled_manifest_is_removed_from_hosts_that_have_one():
    """Leaving a manifest spanning both modalities on disk is an invitation to
    run the comparison the split exists to prevent."""
    removals = [t["ansible.builtin.file"] for t in TASKS
                if isinstance(t, dict)
                and isinstance(t.get("ansible.builtin.file"), dict)
                and t["ansible.builtin.file"].get("state") == "absent"
                and "corpus.repo.json" in str(t["ansible.builtin.file"].get("path"))]
    assert removals, "the pooled corpus.repo.json is left behind"


def test_the_operator_corpus_is_still_protected():
    """The fix must not become "overwrite the operator's corpus", which is the
    thing force:false was there to prevent."""
    seeds = [c for c in _copies_of("eval/corpus.json")
             if c["dest"].endswith("/eval/corpus.json")]
    assert seeds, "the operator-owned seed task disappeared"
    assert all(c.get("force") is False for c in seeds), seeds


def test_the_operator_seed_is_the_only_thing_written_to_corpus_json():
    dests = {c["dest"] for c in _copies_of("eval/corpus.json")}
    assert dests == {"{{ pipeline_install_dir }}/eval/corpus.json"}, dests


def test_divergence_is_reported_rather_than_hidden():
    """A stale corpus is not a deploy failure — the operator's file is
    legitimately theirs — but a run against a manifest that silently differs
    produces a scorecard nobody can interpret later (#486)."""
    debugs = [t for t in TASKS
              if isinstance(t, dict) and "ansible.builtin.debug" in t
              and "corpus" in str(t.get("name", "")).lower()]
    assert debugs, "nothing reports corpus divergence"
    msg = str(debugs[0]["ansible.builtin.debug"]["msg"])
    assert "DIVERGES" in msg
    assert "corpus.repo.json" in msg, "the message must say what to use instead"


def test_the_divergence_check_survives_a_host_with_no_corpus_yet():
    """A first deploy has no corpus.json. Slurping it must not fail the run, and
    the comparison must not run on an undefined variable."""
    slurps = [t for t in TASKS
              if isinstance(t, dict) and "ansible.builtin.slurp" in t
              and "corpus" in str(t.get("name", "")).lower()]
    assert slurps, "no slurp of the deployed corpus"
    assert slurps[0].get("failed_when") is False

    debugs = [t for t in TASKS
              if isinstance(t, dict) and "ansible.builtin.debug" in t
              and "corpus" in str(t.get("name", "")).lower()]
    guard = " ".join(str(c) for c in debugs[0]["when"])
    assert "is defined" in guard, debugs[0]["when"]


# --- the manifest itself ---


@pytest.mark.parametrize("name,modality", [
    ("corpus-native.json", "native_pe"),
    ("corpus-dotnet.json", "dotnet"),
])
def test_each_shipped_manifest_is_valid_and_declares_its_modality(name, modality):
    """#426 asked for the criterion to be recorded. Modality joins it, because a
    manifest that cannot say which experiment it belongs to is one somebody will
    eventually pool (#505)."""
    data = json.loads((MANIFEST.parent / name).read_text(encoding="utf-8"))
    assert data.get("samples"), "no samples"
    assert data["_selection"]["criterion"], "no selection criterion recorded"
    assert data["_selection"]["modality"] == modality
    for i, s in enumerate(data["samples"]):
        for field in ("sha256", "mb_family", "corpus_dir"):
            assert s.get(field), f"sample {i} missing {field}"


def test_no_sample_appears_in_both_corpora():
    """The whole point. One sample in both would make a pooled run possible
    without anyone choosing to pool."""
    def shas(n):
        return {s["sha256"] for s in
                json.loads((MANIFEST.parent / n).read_text())["samples"]}
    assert not shas("corpus-native.json") & shas("corpus-dotnet.json")


def test_the_samples_belonging_to_neither_are_named_rather_than_dropped():
    """raccoonstealer and icedid produced no PE and are not .NET, so neither
    analyser gave the agent anything to read. Silently absent from both files
    would read as an oversight."""
    for n in ("corpus-native.json", "corpus-dotnet.json"):
        excl = json.loads((MANIFEST.parent / n).read_text())["_selection"].get(
            "excluded_from_both")
        assert excl and len(excl) == 2, n
        assert all(e.get("reason") for e in excl), excl


@pytest.mark.parametrize("field", ["sha256", "corpus_dir"])
@pytest.mark.parametrize("name", ["corpus-native.json", "corpus-dotnet.json"])
def test_a_shipped_manifest_has_no_duplicates(name, field):
    data = json.loads((MANIFEST.parent / name).read_text(encoding="utf-8"))
    values = [s[field] for s in data["samples"]]
    assert len(values) == len(set(values)), f"duplicate {field}"
