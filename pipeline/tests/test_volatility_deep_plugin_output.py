# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Plugin output that json.loads cannot read must fail that plugin, not the stage (#692).

`run_single_plugin` parsed Volatility's stdout with `json.loads` and caught only
`JSONDecodeError`. Two other exceptions come out of `json.loads` for text that
is well-formed JSON, and both are reachable from the guest:

    pstree nested N processes deep     RecursionError   from N = 4,998
    (bare `[` nesting)                 RecursionError   from 9,998 levels
    an integer of 5,000 digits         ValueError       (int conversion limit)

Measured on Python 3.12.13, main thread and a ThreadPoolExecutor worker alike.
Process nesting is the sample's to choose: each process spawns the next.

Where it escaped to, on origin/main (9a9d0b3):

  - Phase 1 plugins run inside a future whose `except Exception` already
    records `{"error": str(e)}`, so pstree alone did not end the stage.
  - The vadinfo call after Phase 1 has no handler, and run-pipeline wraps
    run_volatility in `except TimeoutError` only: the raise discarded every
    plugin's output and ended the run before report.json was written
    (test_a_deep_vadinfo_does_not_end_the_stage drives that path).

The fix fails closed at the parse, so every caller gets the same
`{"error": ...}` a timeout or a non-zero exit gives. The message names the
exception type only, never plugin output, which is guest-chosen text.

These tests go through `run_single_plugin` with `subprocess.run` replaced, the
way test_volatility_malfind_pids does; nothing here needs a memory image.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

# conftest.py puts ansible/roles/pipeline/files on sys.path.
from stages import volatility

# Guest-chosen text that must never reach an error message.
MARKER = "SAMPLE_CHOSEN_NAME_692"

DEPTH = 10_000   # the issue's figure; 4,998 is the first failing depth measured


def deep_pstree(depth: int) -> str:
    """A pstree JSON `depth` processes deep, built without O(n^2) string growth."""
    opening = "".join(
        f'{{"PID": {i + 1}, "PPID": {i}, "ImageFileName": "{MARKER}.exe", "__children": ['
        for i in range(depth))
    return "[" + opening + "]}" * depth + "]"


class _Result:
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


@pytest.fixture
def plugin_stdout(monkeypatch):
    """Answer each plugin's subprocess.run from a dict keyed by plugin name."""
    answers: dict[str, str] = {}

    def fake_run(cmd, **kwargs):
        return _Result(answers.get(cmd[2], "[]"))

    monkeypatch.setattr(volatility.subprocess, "run", fake_run)
    return answers


def run_plugin(plugin: str = "windows.pstree") -> object:
    return volatility.run_single_plugin(Path("/nonexistent/memory.dmp"), plugin,
                                        Path("/nonexistent/out"), "vol")


def assert_failed_closed(output, exc_name: str) -> None:
    assert isinstance(output, dict), output
    assert set(output) == {"error"}, "no 'raw' copy of plugin output on this path"
    assert exc_name in output["error"]
    assert MARKER not in output["error"]
    assert len(output["error"]) < 200


def test_the_constructed_tree_really_is_too_deep_to_parse():
    # Precondition: if a future Python raises the limit, the tests below would
    # pass without exercising anything. Fail here instead.
    with pytest.raises(RecursionError):
        json.loads(deep_pstree(DEPTH))
    json.loads(deep_pstree(100))


def test_a_too_deep_plugin_output_is_recorded_not_raised(plugin_stdout):
    plugin_stdout["windows.pstree"] = deep_pstree(DEPTH)
    assert_failed_closed(run_plugin(), "RecursionError")


def test_a_too_deep_output_behind_progress_noise_is_recorded_not_raised(plugin_stdout):
    # The first json.loads fails fast on the noise (JSONDecodeError); the
    # RecursionError then comes from the bracket-extraction retry.
    plugin_stdout["windows.pstree"] = (
        "Volatility 3 Framework 2.27.0\nProgress:  100.00\t\tPDB scanning finished\n"
        + deep_pstree(DEPTH))
    assert_failed_closed(run_plugin(), "RecursionError")


def test_an_integer_past_the_conversion_limit_is_recorded_not_raised(plugin_stdout):
    plugin_stdout["windows.pslist"] = '[{"PID": ' + "7" * 5000 + f', "Name": "{MARKER}"}}]'
    assert_failed_closed(run_plugin("windows.pslist"), "ValueError")


def test_a_deep_but_parseable_tree_still_parses(plugin_stdout):
    plugin_stdout["windows.pstree"] = deep_pstree(1_000)
    output = run_plugin()
    assert isinstance(output, list) and output[0]["PID"] == 1


def test_a_well_formed_output_is_unchanged(plugin_stdout):
    rows = [{"PID": 4, "ImageFileName": "System", "__children": []}]
    plugin_stdout["windows.pstree"] = "Progress: 100.00\n" + json.dumps(rows)
    assert run_plugin() == rows


def _run_stage(tmp_path: Path, standard: list[str], cape_injection_pids=None) -> dict:
    dump = tmp_path / "memory.dmp"
    dump.write_bytes(b"\0")   # exists, so the vadinfo and procdump paths run
    with contextlib.redirect_stdout(io.StringIO()):
        return volatility.run_volatility(
            {"id": 1, "status": "reported", "memory": str(dump)}, tmp_path,
            volatility_cmd="vol", volatility_triggers=[],
            volatility_standard_plugins=standard, volatility_extra_plugins={},
            malfind_enabled=False, malfind_min_size=256, malfind_max_size=10485760,
            malfind_min_score=2, malfind_max_candidates=5, malfind_benign_processes=[],
            get_cape_signatures_fn=lambda cape: [], memory_dump_requested=True,
            cape_injection_pids=cape_injection_pids, parallel_workers=2)


@pytest.fixture
def dump_at(monkeypatch, tmp_path):
    monkeypatch.setattr(volatility, "get_memory_dump_path", lambda _d: tmp_path / "memory.dmp")


def test_a_deep_pstree_costs_only_pstree(plugin_stdout, dump_at, tmp_path):
    pslist = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    plugin_stdout["windows.pstree"] = deep_pstree(DEPTH)
    plugin_stdout["windows.pslist"] = json.dumps(pslist)

    result = _run_stage(tmp_path, ["windows.pstree", "windows.pslist"])

    assert result["plugins"]["pslist"] == pslist
    assert_failed_closed(result["plugins"]["pstree"], "RecursionError")
    assert "insights" in result


def test_a_deep_vadinfo_does_not_end_the_stage(plugin_stdout, dump_at, tmp_path):
    # The unguarded call: on origin/main this raised out of run_volatility.
    pslist = [{"PID": 4, "PPID": 0, "ImageFileName": "System"}]
    plugin_stdout["windows.pslist"] = json.dumps(pslist)
    plugin_stdout["windows.vadinfo"] = deep_pstree(DEPTH)

    result = _run_stage(tmp_path, ["windows.pslist"], cape_injection_pids=[4])

    assert result["plugins"]["pslist"] == pslist
    assert_failed_closed(result["plugins"]["vadinfo"], "RecursionError")
    assert "vad_dump_dir" not in result
    assert "insights" in result
