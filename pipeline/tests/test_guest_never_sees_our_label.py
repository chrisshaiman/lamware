# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The filename the guest sees must not carry our label for the sample (#634).

Samples were submitted to Cape under their curation name, and the guest wrote
it into its own process command lines and module paths:

    "C:\\WINDOWS\\sysnative\\regsvr32.exe" C:\\WINDOWS\\TEMP\\WarmCookie_36b43e83.exe.dll

Five of sixteen corpus samples leaked their family that way, into the
behavioural evidence that only the `+corr` arm receives. Technique recall is
scored against a HELD-OUT key (#491), and a model told the family can recall
that family's TTPs from training rather than deriving them. Nothing downstream
catches it: the leaked name genuinely IS in the evidence, so a claim citing it
is genuinely grounded. `warmcookie` scored the run's only perfect recall.

The extension has to survive the rename — Cape picks its analysis package from
it and Windows launches the file by it — so a test that only checks "the family
name is gone" would pass for a submission Cape cannot route.
"""
import hashlib

import pytest
from stages.cape import derive_extension, derive_filename


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "WarmCookie_36b43e83.exe"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    return p


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_the_curation_label_never_reaches_the_guest(sample):
    out = derive_filename(sample, "exe", original_name="WarmCookie_36b43e83.exe")
    assert "warmcookie" not in out.lower()
    assert out == f"{_sha(sample)}.exe"


def test_the_extension_survives_the_rename(sample):
    """Cape routes on the extension; dropping it changes the analysis package."""
    assert derive_filename(sample, "exe", "WarmCookie_36b43e83.exe").endswith(".exe")
    assert derive_filename(sample, "dll", "Evil_Thing.dll").endswith(".dll")


def test_the_name_is_content_derived_not_random(sample, tmp_path):
    """Two submissions of the same bytes must get the same guest name, or
    detonations of one sample stop being comparable to each other."""
    twin = tmp_path / "totally_different_name.exe"
    twin.write_bytes(sample.read_bytes())
    assert derive_filename(sample, "exe", "a.exe") == derive_filename(twin, "exe", "b.exe")


def test_different_samples_get_different_names(tmp_path):
    a, b = tmp_path / "a.exe", tmp_path / "b.exe"
    a.write_bytes(b"MZ" + b"\x00" * 32)
    b.write_bytes(b"MZ" + b"\x01" * 32)
    assert derive_filename(a, "exe") != derive_filename(b, "exe")


@pytest.mark.parametrize("orig,pkg,want", [
    ("x.dll", "exe", ".dll"),        # the original name wins over the package
    ("", "dll", ".dll"),             # fall back to the package map
    ("", "", ""),                    # nothing to go on: no extension invented
    ("archive.tar.gz", "exe", ".gz"),
])
def test_extension_is_taken_from_the_best_available_source(tmp_path, orig, pkg, want):
    p = tmp_path / "blob"
    p.write_bytes(b"\x00")
    assert derive_extension(p, pkg, orig) == want


def test_the_original_name_is_still_reachable_when_asked_for(sample):
    """Escape hatch for a sample whose own name is behaviourally load-bearing."""
    assert derive_filename(sample, "exe", "WarmCookie_36b43e83.exe",
                           neutral=False) == "WarmCookie_36b43e83.exe"


def test_run_pipeline_logs_both_names():
    """They differ now. An operator reading one line would not know which."""
    from pathlib import Path
    src = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
           / "files" / "run-pipeline.py").read_text()
    assert "Filename (guest)" in src and "Filename (analyst)" in src
