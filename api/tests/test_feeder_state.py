# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the feeder-control state.json writer (app.routers.feeder._update_state).

Importing app.routers.feeder is CI-safe: app.database creates its engine lazily
(no connection at import), so no live DB is needed. We evict any app.investigate
stubs first (other test modules register ModuleType fakes in sys.modules) so this
import resolves the real module from disk.
"""
import json
import os
import stat as stat_mod
import sys

import pytest

# Evict stub registrations left by test_orchestrator.py / test_system_prompt.py so
# our genuine import below resolves the real app package from the filesystem.
for _key in list(sys.modules):
    if _key.startswith("app.investigate"):
        del sys.modules[_key]

from app.routers import feeder  # noqa: E402


@pytest.mark.skipif(os.name == "nt", reason="POSIX file-mode semantics; runs in CI Linux")
def test_update_state_preserves_group_rw(tmp_path, monkeypatch):
    """After the API rewrites state.json, group-rw must survive.

    state.json is owned by the feeder (pipeline) with group ``lamware`` at mode
    0664. The API resets consecutive_failures via an atomic tmp-file + os.replace.
    os.replace swaps in the tmp file, which is created with the API process umask
    (commonly 022 -> 0644, group read-only). Without restoring the mode, the feeder
    — a different user relying on group-write — would be silently locked out of its
    own state file. This test fails at 0644 before the mode-preservation fix.
    """
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"consecutive_failures": 3, "total_samples": 10}))
    os.chmod(state, 0o664)
    monkeypatch.setattr(feeder.settings, "auto_feeder_state", str(state))

    assert feeder._update_state({"consecutive_failures": 0}) is True

    mode = stat_mod.S_IMODE(os.stat(state).st_mode)
    assert mode == 0o664, f"expected group-rw 0o664, got {oct(mode)}"

    # Merge semantics: updated key changed, untouched keys preserved.
    data = json.loads(state.read_text())
    assert data["consecutive_failures"] == 0
    assert data["total_samples"] == 10


def test_update_state_creates_when_missing(tmp_path, monkeypatch):
    """A missing state.json is created (feeder not yet started) rather than erroring."""
    state = tmp_path / "state.json"
    monkeypatch.setattr(feeder.settings, "auto_feeder_state", str(state))

    assert feeder._update_state({"consecutive_failures": 0}) is True
    assert json.loads(state.read_text())["consecutive_failures"] == 0
