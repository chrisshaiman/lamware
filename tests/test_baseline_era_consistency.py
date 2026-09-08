# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A baseline must not attribute old numbers to new images (#518, #576).

The two halves of the record come from different places: the metrics from
STORED report.json files, the era from the live image directory at capture
time. Nothing tied them together, so re-running the tool after a rebuild — over
reports produced on the OLD images — emitted:

    image    windows11-guest.qcow2 built 2026-09-04
    TOTAL observed_behaviour across 5 sample(s): 232

which is indistinguishable from a post-rebuild baseline and is the pre-rebuild
number. Observed on a control run, 2026-09-07.

A report written before an image existed cannot have been produced on it, so
this is checkable rather than a matter of remembering.
"""
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "ansible" / "roles" / "pipeline" / "files" / "evasion_baseline.py"
spec = importlib.util.spec_from_file_location("evasion_baseline", SRC)
eb = importlib.util.module_from_spec(spec)
sys.modules["evasion_baseline"] = eb
spec.loader.exec_module(eb)


def _corpus(tmp_path, report_mtime, n=2):
    """A corpus of n samples whose reports are stamped report_mtime."""
    samples = []
    for i in range(n):
        d = tmp_path / f"sample_{i}"
        d.mkdir()
        (d / "report.json").write_text(json.dumps({"cape": {"malscore": 1.0}}))
        os.utime(d / "report.json", (report_mtime, report_mtime))
        samples.append({"sha256": f"{i:064x}", "corpus_dir": str(d)})
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps({"samples": samples}))
    return manifest


def _images(tmp_path, image_mtime):
    d = tmp_path / "images"
    d.mkdir()
    img = d / "windows11-guest.qcow2"
    img.write_bytes(b"x")
    os.utime(img, (image_mtime, image_mtime))
    return d


def test_reports_older_than_the_image_are_flagged(tmp_path, monkeypatch):
    """The exact shape observed: reports from 08-29, image rebuilt 09-04."""
    monkeypatch.setattr(eb, "GUEST_IMAGE_DIR", _images(tmp_path, image_mtime=2000))
    base = eb.capture(str(_corpus(tmp_path, report_mtime=1000)))
    assert base["era"]["consistent"] is False
    assert len(base["era"]["stale_reports"]) == 2


def test_reports_newer_than_the_image_are_accepted(tmp_path, monkeypatch):
    """A genuine post-rebuild capture: detonated after the image was built."""
    monkeypatch.setattr(eb, "GUEST_IMAGE_DIR", _images(tmp_path, image_mtime=1000))
    base = eb.capture(str(_corpus(tmp_path, report_mtime=2000)))
    assert base["era"]["consistent"] is True
    assert base["era"]["stale_reports"] == []


def test_the_mismatch_is_visible_in_the_rendered_output(tmp_path, monkeypatch):
    """Whoever reads the terminal must see it, not just the JSON."""
    monkeypatch.setattr(eb, "GUEST_IMAGE_DIR", _images(tmp_path, image_mtime=2000))
    out = eb.render(eb.capture(str(_corpus(tmp_path, report_mtime=1000))))
    assert "ERA MISMATCH" in out
    assert "NOT produced on the images named above" in out


def test_a_clean_capture_says_nothing_alarming(tmp_path, monkeypatch):
    monkeypatch.setattr(eb, "GUEST_IMAGE_DIR", _images(tmp_path, image_mtime=1000))
    out = eb.render(eb.capture(str(_corpus(tmp_path, report_mtime=2000))))
    assert "ERA MISMATCH" not in out


def test_every_report_carries_its_own_timestamp(tmp_path, monkeypatch):
    """Without this the JSON cannot be re-checked after the fact."""
    monkeypatch.setattr(eb, "GUEST_IMAGE_DIR", _images(tmp_path, image_mtime=1000))
    base = eb.capture(str(_corpus(tmp_path, report_mtime=2000)))
    for m in base["samples"].values():
        assert m["report_mtime_epoch"] == 2000


@pytest.mark.parametrize("stale,allow,should_write", [
    (True, False, False),   # the bug: refuse
    (True, True, True),     # deliberate control capture
    (False, False, True),   # normal post-rebuild capture
])
def test_writing_is_refused_when_the_era_does_not_hold(tmp_path, monkeypatch,
                                                      stale, allow, should_write):
    """Refusing to WRITE matters more than printing a warning: the JSON is what
    gets committed and read months later, by which time nobody has the
    terminal output."""
    img_m, rep_m = (2000, 1000) if stale else (1000, 2000)
    monkeypatch.setattr(eb, "GUEST_IMAGE_DIR", _images(tmp_path, image_mtime=img_m))
    corpus = _corpus(tmp_path, report_mtime=rep_m)
    out = tmp_path / "baseline.json"
    argv = ["evasion_baseline", "--corpus", str(corpus), "--out", str(out)]
    if allow:
        argv.append("--allow-stale-reports")
    monkeypatch.setattr(sys, "argv", argv)
    if should_write:
        eb.main()
        assert out.exists()
    else:
        with pytest.raises(SystemExit) as e:
            eb.main()
        assert "pre-date" in str(e.value)
        assert not out.exists(), "a mislabelled baseline was written anyway"
