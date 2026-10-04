# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The upload spool write never follows or reuses a name (#537).

/opt/pipeline/spool is group lamware 2770 and not sticky: every lamware member
can create, rename and unlink names in it. The upload was written with
Path.write_bytes() and then chmod'ed by path, so a symlink planted at the name,
or swapped in between the two calls, was followed by both.
"""
import os
import stat
import sys

import pytest

for _key in list(sys.modules):
    if _key.startswith("app.investigate"):
        del sys.modules[_key]

from app.routers import samples  # noqa: E402


def test_spool_file_is_created_at_0640_whatever_the_umask(tmp_path):
    old = os.umask(0o077)
    try:
        p = tmp_path / "sub_sample.exe"
        samples._write_spool_file(p, b"MZ" + b"\0" * 62)
    finally:
        os.umask(old)
    assert p.read_bytes() == b"MZ" + b"\0" * 62
    assert stat.S_IMODE(p.stat().st_mode) == 0o640


def test_a_planted_symlink_is_not_followed(tmp_path):
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep\n")
    os.chmod(victim, 0o600)
    p = tmp_path / "sub_sample.exe"
    p.symlink_to(victim)
    with pytest.raises(OSError):
        samples._write_spool_file(p, b"sample bytes")
    assert victim.read_bytes() == b"keep\n"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600
    assert p.is_symlink(), "the planted name was not ours to remove"


def test_an_existing_file_is_not_overwritten(tmp_path):
    p = tmp_path / "sub_sample.exe"
    p.write_bytes(b"first\n")
    with pytest.raises(FileExistsError):
        samples._write_spool_file(p, b"second")
    assert p.read_bytes() == b"first\n"
