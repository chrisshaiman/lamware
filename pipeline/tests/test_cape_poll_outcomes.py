# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A CAPE task that never started is not a timeout (#795).

On 2026-10-16 CAPE's scheduler sat below cuckoo.conf's 50 GB free-space floor
and started nothing, silently; the pipeline waited its 20 minutes and recorded
`timeout`, severity low, 0 correlations, as if the sample had run and hung. The
poll now says which of the two happened, and the pipeline refuses to submit at
all when the floor is already breached, with the shortfall as the reason.

These drive `poll_cape_task` with a scripted sequence of CAPE statuses and a
near-zero wait, and `cape_storage_shortfall_mb` with a scripted disk_usage.
"""
import collections
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from stages import cape  # noqa: E402


def _responses(statuses):
    """requests.get stand-in returning each status in turn, then the last forever."""
    seq = list(statuses)

    def _get(*_a, **_k):
        status = seq.pop(0) if len(seq) > 1 else seq[0]
        resp = MagicMock()
        resp.json.return_value = {"data": {"id": 7, "status": status}}
        return resp
    return _get


@pytest.fixture
def fast_poll(monkeypatch):
    monkeypatch.setattr(cape, "CAPE_TIMEOUT", 0.05)
    monkeypatch.setattr(cape, "CAPE_POLL_INTERVAL", 0.01)
    monkeypatch.setattr(cape.time, "sleep", lambda _s: None)


def test_pending_throughout_is_never_started_not_timeout(fast_poll):
    with patch.object(cape.requests, "get", _responses(["pending"])):
        out = cape.poll_cape_task(7)
    assert out["status"] == "never_started", out
    assert out["last_cape_status"] == "pending"
    assert out["id"] == 7


def test_started_then_overrun_is_a_timeout(fast_poll):
    with patch.object(cape.requests, "get", _responses(["pending", "running"])):
        out = cape.poll_cape_task(7)
    assert out["status"] == "timeout", out
    assert out["last_cape_status"] == "running"


def test_no_answer_from_cape_is_never_started(fast_poll):
    """An API that never answers is also 'nothing started', not a hung sample."""
    def _boom(*_a, **_k):
        raise cape.requests.RequestException("down")
    with patch.object(cape.requests, "get", _boom):
        out = cape.poll_cape_task(7)
    assert out["status"] == "never_started"
    assert out["last_cape_status"] == ""


def test_reported_returns_capes_data(fast_poll):
    with patch.object(cape.requests, "get", _responses(["pending", "running", "reported"])):
        out = cape.poll_cape_task(7)
    assert out["status"] == "reported" and out["id"] == 7


def test_a_terminal_failure_is_returned_at_once_not_waited_out(fast_poll):
    calls = collections.Counter()
    inner = _responses(["running", "failed_analysis"])

    def _get(*a, **k):
        calls["n"] += 1
        return inner(*a, **k)
    with patch.object(cape.requests, "get", _get):
        out = cape.poll_cape_task(7)
    assert out["status"] == "failed_analysis"
    assert calls["n"] == 2, "kept polling after CAPE said the task had failed"


# --- the free-space floor -----------------------------------------------------

def _usage(free_bytes):
    return MagicMock(free=free_bytes)


def test_below_the_floor_reports_the_shortfall(monkeypatch):
    monkeypatch.setattr(cape.shutil, "disk_usage", lambda _p: _usage(49_900 << 20))
    assert cape.cape_storage_shortfall_mb(floor_mb=50_000) == 100


def test_at_or_above_the_floor_is_not_blocked(monkeypatch):
    monkeypatch.setattr(cape.shutil, "disk_usage", lambda _p: _usage(50_000 << 20))
    assert cape.cape_storage_shortfall_mb(floor_mb=50_000) is None
    monkeypatch.setattr(cape.shutil, "disk_usage", lambda _p: _usage(200_000 << 20))
    assert cape.cape_storage_shortfall_mb(floor_mb=50_000) is None


def test_unreadable_storage_does_not_refuse_to_detonate(monkeypatch):
    def _denied(_p):
        raise PermissionError("storage")
    monkeypatch.setattr(cape.shutil, "disk_usage", _denied)
    assert cape.cape_storage_shortfall_mb(floor_mb=50_000) is None


def test_the_floor_default_matches_capes_shipped_value():
    """cuckoo.conf ships freespace = 50000; the pipeline's default must agree,
    or a fresh deploy checks a different number than CAPE does."""
    from lamware_pipeline.config import PipelineConfig
    assert PipelineConfig.model_fields["cape_freespace_floor_mb"].default == 50000
