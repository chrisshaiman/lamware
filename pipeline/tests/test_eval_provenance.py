# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A scorecard could not say what it was run against (#486).

`render_scorecard` opened with an operator-supplied `--label` and nothing else,
and the output path was derived from that same label. Two runs whose numbers
mean entirely different things were textually indistinguishable, and the second
destroyed the first.

That is the mechanism that lets a confound go unnoticed rather than a defect in
itself. Two live examples when this was written:

  #478  scorecards from before the INetSim DNS fix measured samples that could
        not resolve a domain
  #490  three corpus samples had a Ghidra pairing that opened nothing, repaired
        on 2026-08-29 — before and after are different corpora with one name

The tests below are mostly about what the stamp must not do: guess, omit a field
it could not read, or claim the manifest when only part of it ran.
"""
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from lamware_eval.provenance import (
    corpus_identity,
    deployed_code,
    gather,
    guest_images,
    render,
)
from lamware_eval.scorecard import render_scorecard, write_scorecard

MANIFEST = {"samples": [
    {"sha256": "a" * 64, "mb_family": "x", "corpus_dir": "/tmp/a"},
    {"sha256": "b" * 64, "mb_family": "y", "corpus_dir": "/tmp/b"},
]}


@pytest.fixture
def manifest(tmp_path):
    p = tmp_path / "corpus.json"
    p.write_text(json.dumps(MANIFEST))
    return p


# --- corpus identity ---


def test_the_manifest_is_identified_by_its_contents_not_its_name(manifest, tmp_path):
    """Two files both called corpus.json are not the same corpus. The hash is
    what makes a scorecard from before a corpus change distinguishable from one
    after."""
    before = corpus_identity(str(manifest))["corpus_sha256"]
    MANIFEST["samples"].append({"sha256": "c" * 64, "mb_family": "z",
                                "corpus_dir": "/tmp/c"})
    manifest.write_text(json.dumps(MANIFEST))
    after = corpus_identity(str(manifest))["corpus_sha256"]
    MANIFEST["samples"].pop()
    assert before != after


def test_a_filtered_run_is_not_recorded_as_the_whole_manifest(manifest):
    """`--samples` makes a different corpus from the manifest it came from. A
    pilot on one sample must not read later as a sweep over twelve."""
    out = corpus_identity(str(manifest), samples_run=["a" * 64])
    assert out["corpus_samples"] == 2
    assert out["samples_run"] == ["a" * 12]


def test_an_unreadable_manifest_says_so_rather_than_going_quiet():
    """'We could not read this' and 'this did not apply' are different claims."""
    out = corpus_identity("/nonexistent/corpus.json")
    assert "unreadable" in out["corpus_sha256"]
    assert out["corpus_samples"] is None


def test_a_malformed_manifest_still_yields_a_hash(tmp_path):
    p = tmp_path / "corpus.json"
    p.write_text("{not json")
    out = corpus_identity(str(p))
    assert out["corpus_sha256"] and "unreadable" not in out["corpus_sha256"]
    assert out["corpus_samples"] is None


# --- deployed code ---


def test_the_pipeline_commit_comes_from_what_the_deploy_recorded(tmp_path):
    p = tmp_path / "deploy-provenance.json"
    p.write_text(json.dumps({"sha": "885a10a02954ef063b034", "dirty": False,
                             "deployed_at": "2026-08-30T06:23:09Z"}))
    out = deployed_code(p)
    assert out["pipeline_sha"] == "885a10a02954"
    assert out["deployed_at"] == "2026-08-30T06:23:09Z"
    assert "pipeline_dirty" not in out


def test_a_dirty_deploy_is_flagged_because_the_sha_does_not_describe_it(tmp_path):
    """#384: the deploy tars the working tree, so a dirty deploy shipped
    something no commit describes."""
    p = tmp_path / "deploy-provenance.json"
    p.write_text(json.dumps({"sha": "abc123abc123", "dirty": True}))
    assert deployed_code(p)["pipeline_dirty"] is True
    assert "**(deployed from a dirty tree)**" in render(
        {"pipeline_sha": "abc123abc123", "pipeline_dirty": True})


def test_a_missing_deploy_record_reports_unknown(tmp_path):
    out = deployed_code(tmp_path / "absent.json")
    assert out["pipeline_sha"] == "unknown"


# --- guest images ---


def test_an_aged_guest_image_is_flagged(tmp_path):
    """An aged guest changes sample behaviour silently, which confounds any
    comparison spanning a rebuild — the llama.cpp restart problem one layer
    down."""
    img = tmp_path / "windows11-guest.qcow2"
    img.write_bytes(b"x")
    now = datetime.now(UTC) + timedelta(days=116)
    out = guest_images(tmp_path, now=now)
    assert out[0]["age_days"] == 116
    assert out[0]["stale"] is True
    assert "STALE" in render({"guest_images": out})


def test_a_fresh_guest_image_is_not_flagged(tmp_path):
    img = tmp_path / "windows11-guest.qcow2"
    img.write_bytes(b"x")
    out = guest_images(tmp_path, now=datetime.now(UTC) + timedelta(days=10))
    assert out[0]["stale"] is False
    assert "STALE" not in render({"guest_images": out})


def test_the_oldest_image_is_reported_first(tmp_path):
    for name in ("a.qcow2", "b.qcow2"):
        (tmp_path / name).write_bytes(b"x")
    import os
    os.utime(tmp_path / "a.qcow2", (0, datetime.now(UTC).timestamp() - 86400 * 200))
    out = guest_images(tmp_path)
    assert out[0]["image"] == "a.qcow2"


def test_a_missing_image_directory_is_not_an_error():
    assert guest_images(Path("/nonexistent/images")) == []


# --- rendering, and the wiring that makes it visible ---


def test_the_block_renders_every_field_it_was_given(manifest):
    md = render(gather(str(manifest), samples_run=["a" * 64]))
    assert "## Provenance" in md
    assert "corpus" in md and "sha256" in md
    assert "samples run (1)" in md
    assert "pipeline" in md


def test_no_provenance_renders_nothing_rather_than_an_empty_heading():
    assert render(None) == ""
    assert render({}) == ""


def test_the_scorecard_actually_carries_the_block(manifest):
    """#380's lesson. Asserting on `render` alone would pass with
    render_scorecard never calling it."""
    md = render_scorecard("t", [], {}, gather(str(manifest)))
    assert "## Provenance" in md
    assert md.index("## Provenance") < md.index("## Summary (per arm)"), (
        "a reader who scrolls past it has already started reading the numbers")


def test_a_scorecard_without_provenance_still_renders():
    md = render_scorecard("t", [], {})
    assert "# RE Eval — t" in md
    assert "## Provenance" not in md


# --- the overwrite guard ---


def test_an_existing_scorecard_is_not_silently_replaced(tmp_path):
    """The path is derived from --label, which defaults to a fixed string in
    both entry points. A second run destroyed the first with no backup and no
    way to tell what it destroyed — #405, one directory over."""
    out = tmp_path / "eval.md"
    out.write_text("the first run")
    with pytest.raises(SystemExit) as e:
        write_scorecard(out, "the second run", force=False)
    assert "refusing to overwrite" in str(e.value)
    assert out.read_text() == "the first run"


def test_force_replaces_it(tmp_path):
    out = tmp_path / "eval.md"
    out.write_text("the first run")
    write_scorecard(out, "the second run", force=True)
    assert out.read_text() == "the second run"


def test_a_new_scorecard_writes_without_ceremony(tmp_path):
    out = tmp_path / "eval.md"
    write_scorecard(out, "hello", force=False)
    assert out.read_text() == "hello"


def test_both_entry_points_guard_the_write():
    """Parsed, not grepped: both modules discuss the guard in comments."""
    import ast
    files = (Path(__file__).resolve().parents[2]
             / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval")
    for module in ("__main__.py", "rebuild.py"):
        tree = ast.parse((files / module).read_text(encoding="utf-8"))
        called = {n.func.id for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        assert "write_scorecard" in called, f"{module} writes the file directly"
        assert "gather_provenance" in called, f"{module} stamps nothing"
