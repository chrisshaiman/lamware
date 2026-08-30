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


def _copies_of(src: str) -> list[dict]:
    return [t["ansible.builtin.copy"] for t in TASKS
            if isinstance(t, dict)
            and isinstance(t.get("ansible.builtin.copy"), dict)
            and t["ansible.builtin.copy"].get("src") == src]


def test_the_curated_manifest_reaches_a_path_ansible_owns():
    """Without this the repo's selection is unreachable on any host that has
    run the eval once."""
    forced = [c for c in _copies_of("eval/corpus.json") if c.get("force") is True]
    assert forced, "no force:true copy of the eval corpus manifest"
    dests = [c["dest"] for c in forced]
    assert all(d.endswith("corpus.repo.json") for d in dests), dests


def test_the_operator_corpus_is_still_protected():
    """The fix must not become "overwrite the operator's corpus", which is the
    thing force:false was there to prevent."""
    seeds = [c for c in _copies_of("eval/corpus.json")
             if c["dest"].endswith("/eval/corpus.json")]
    assert seeds, "the operator-owned seed task disappeared"
    assert all(c.get("force") is False for c in seeds), seeds


def test_the_two_paths_are_different_files():
    dests = {c["dest"] for c in _copies_of("eval/corpus.json")}
    assert len(dests) == 2, dests


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


def test_the_shipped_manifest_is_valid_and_records_why_it_was_selected():
    """#426 asked for the criterion to be recorded. It is — in the file that
    never deployed, which is the whole of #487."""
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert data.get("samples"), "no samples"
    assert data["_selection"]["criterion"], "no selection criterion recorded"
    for i, s in enumerate(data["samples"]):
        for field in ("sha256", "mb_family", "corpus_dir"):
            assert s.get(field), f"sample {i} missing {field}"


@pytest.mark.parametrize("field", ["sha256", "corpus_dir"])
def test_the_shipped_manifest_has_no_duplicates(field):
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    values = [s[field] for s in data["samples"]]
    assert len(values) == len(set(values)), f"duplicate {field}"
