# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The production submit path must pin the guest and must not request RAM dumps.

Both defects were live in `submit_to_cape` until 2026-09-18 and both are the
silent kind.

  Guest pinning   kvm.conf tags BOTH guests x64, and the pipeline submitted
                  tags=['x64'] with no machine. CAPE therefore used whichever
                  guest was free -- `clean` (pinned custom CPU) or `office`
                  (host-passthrough CPU, Office installed) -- and the report
                  recorded nowhere which one ran the sample. Two runs of one
                  sample could differ for a reason that left no trace. Tasks
                  1132/1133 were discarded over exactly this.

  memory=1        hardcoded for the life of the function. 8.6 GB per run, with
                  conf/memory.conf delete_memdump=no, filled the disk and CAPE
                  silently stopped scheduling below freespace=50000 while every
                  service still reported active.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from lamware_pipeline.cape_guest import (  # noqa: E402
    derive_machine,
    machine_of,
    verify_ran_on,
)
from stages.cape import submit_to_cape  # noqa: E402

# --- routing -----------------------------------------------------------------

def test_office_samples_route_to_the_office_guest():
    """Office is a real routing decision, not a pin that could be a constant:
    the office guest is the one with Office installed."""
    assert derive_machine(["x64", "office"], "clean", "office") == "office"


def test_everything_else_routes_to_clean():
    assert derive_machine(["x64"], "clean", "office") == "clean"
    assert derive_machine([], "clean", "office") == "clean"
    assert derive_machine(None, "clean", "office") == "clean"


def test_a_blank_machine_name_is_refused():
    """An empty config value must fail loudly rather than submit unpinned."""
    with pytest.raises(ValueError, match="machine must be pinned"):
        derive_machine(["x64"], "", "office")
    with pytest.raises(ValueError, match="machine must be pinned"):
        derive_machine(["x64", "office"], "clean", "")


# --- verification ------------------------------------------------------------

def test_the_guest_cape_used_is_read_back_not_assumed():
    # CAPE's task view carries `machine` as a bare string.
    assert machine_of({"machine": "clean"}) == "clean"
    # Its report.json carries it as a dict.
    assert machine_of({"machine": {"name": "clean"}}) == "clean"


def test_a_pin_that_stopped_holding_is_detected():
    assert verify_ran_on({"machine": "office"}, "clean") is not None
    assert verify_ran_on({"machine": "clean"}, "clean") is None


def test_an_unreadable_machine_field_is_a_failure_not_a_pass():
    reason = verify_ran_on({}, "clean")
    assert reason is not None
    assert "could not determine" in reason and "refusing to assume" in reason


# --- the submission itself ---------------------------------------------------

def _submit(**kw):
    """Capture the form fields submit_to_cape would POST."""
    captured = {}

    def fake_post(url, files=None, data=None, headers=None, timeout=None):
        captured.update(data or {})
        resp = MagicMock()
        resp.json.return_value = {"data": {"task_ids": [4242]}}
        resp.raise_for_status.return_value = None
        return resp

    with patch("stages.cape.requests.post", side_effect=fake_post):
        task_id = submit_to_cape(Path(__file__), tags=["x64"], **kw)
    return task_id, captured


def test_submission_without_a_machine_is_refused():
    with pytest.raises(ValueError, match="machine must be pinned"):
        _submit()


def test_the_machine_reaches_the_api():
    task_id, data = _submit(machine="clean")
    assert task_id == 4242
    assert data["machine"] == "clean"


def test_no_memory_dump_is_requested_by_default():
    _, data = _submit(machine="clean")
    assert "memory" not in data, (
        "8.6 GB per run with delete_memdump=no filled the disk and CAPE silently "
        "stopped scheduling below freespace=50000")


def test_a_memory_dump_is_requested_only_when_asked_for():
    """The flag must actually do something -- a knob wired to nothing would pass
    the test above for the wrong reason."""
    _, data = _submit(machine="clean", memory_dump=True)
    assert data["memory"] == "1"


def test_procdump_options_are_unchanged():
    """In-guest process dumping is what the payload extraction depends on and is
    NOT the thing that filled the disk."""
    _, data = _submit(machine="clean")
    assert data["options"] == "procmemdump=1,procdump=1"
