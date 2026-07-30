# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The forensic trail must survive the runs that die (#197).

The existing audit log is written once at the end from an in-memory list, so a
SIGKILLed run leaves an EMPTY llm_audit directory — and the runs that exhaust the
container budget are exactly the ones worth understanding.

Reconstructing the 2026-07-28 qwen@30 run meant hand-parsing the llama.cpp container
log, and produced three wrong conclusions before the right one (LRU cache misses; a
"finding" that turned out to be the identity `reprocessed = (1 - sim_best) x ctx`; and
94 minutes attributed to Ghidra that was actually one cancelled synthesis request).

The property under test is therefore not "the trail is written" but "the trail is
readable after an abrupt death at any point".
"""
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from stages.interpret import TurnTrail  # noqa: E402


@pytest.fixture()
def trail(tmp_path):
    return TurnTrail(tmp_path / "x.trail.jsonl", started=1000.0)


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_every_event_is_on_disk_immediately(trail):
    """No buffering: the row must be readable before the next call, not at close."""
    trail.event("run_start", model="m")
    assert len(_rows(trail.path)) == 1
    trail.tool("decompile_function", {"name": "FUN_1"}, result={"code": "x"})
    assert len(_rows(trail.path)) == 2


def test_rows_are_one_json_object_per_line(trail):
    trail.event("run_start")
    trail.tool("t", {}, result={})
    trail.status("hello")
    for row in _rows(trail.path):
        assert isinstance(row, dict)
        assert "seq" in row and "t" in row and "phase" in row and "event" in row


def test_result_bytes_are_recorded_per_call(trail):
    """Result SIZE is the signal the per-value char cap does not bound."""
    big = {"strings": ["s" * 100 for _ in range(50)]}
    trail.tool("get_strings_at", {"range": 4096}, result=big)
    row = _rows(trail.path)[-1]
    assert row["result_bytes"] > 5000
    assert row["cumulative_result_bytes"] == row["result_bytes"]


def test_cumulative_bytes_accumulate(trail):
    trail.tool("a", {}, result={"x": "y" * 100})
    trail.tool("b", {}, result={"x": "y" * 100})
    rows = _rows(trail.path)
    assert rows[1]["cumulative_result_bytes"] > rows[0]["cumulative_result_bytes"]


def test_phase_flips_to_synthesis_on_the_container_marker():
    """The cancelled run spent 90 of 180 minutes in synthesis and nothing recorded it."""
    for marker in ("Hit max tool calls (30), requesting final analysis",
                   "requesting final analysis"):
        t = TurnTrail(Path(__file__).parent / "_tmp.jsonl", started=0.0)
        t.path.unlink(missing_ok=True)
        t.tool("a", {}, result={})
        assert _rows(t.path)[-1]["phase"] == "loop"
        t.status(marker)
        t.tool("b", {}, result={})
        assert _rows(t.path)[-1]["phase"] == "synthesis"
        t.path.unlink(missing_ok=True)


def test_errors_are_recorded_not_swallowed(trail):
    trail.tool("bad_tool", {"a": 1}, error="validation failed")
    row = _rows(trail.path)[-1]
    assert row["error"] == "validation failed"
    assert row["result_bytes"] == 0


def test_instrumentation_never_breaks_the_run(tmp_path):
    """A trail that cannot write must degrade quietly — it is diagnostics, not the job."""
    unwritable = tmp_path / "nonexistent-dir" / "x.jsonl"
    t = TurnTrail(unwritable, started=0.0)
    t.event("run_start")          # must not raise
    t.tool("a", {}, result={})    # must not raise
    assert t._broken is True


def test_args_and_status_are_truncated(trail):
    """A trail row must not itself become a huge blob."""
    trail.tool("t", {"blob": "x" * 5000}, result={})
    trail.status("y" * 5000)
    rows = _rows(trail.path)
    assert len(rows[0]["args"]) <= 200
    assert len(rows[1]["message"]) <= 300


def test_tool_output_content_is_persisted_not_just_its_size(trail):
    """A byte count is not evidence. Chain-of-custody asks what the model SAW."""
    body = {"decompiled": "int main(){ /* real code */ }", "name": "main"}
    trail.tool("decompile_function", {"name": "main"}, result=body)
    row = _rows(trail.path)[-1]
    assert row["result_path"], "tool result content was not persisted"
    saved = json.loads(Path(row["result_path"]).read_text())
    assert saved == body, "persisted result must be verbatim, not summarised"


def test_persisted_results_are_untruncated(trail):
    """The cap that shapes what the model sees is applied BEFORE this; trimming here
    would misrepresent the record."""
    body = {"decompiled": "A" * 60000}
    trail.tool("decompile_function", {"name": "big"}, result=body)
    saved = json.loads(Path(_rows(trail.path)[-1]["result_path"]).read_text())
    assert len(saved["decompiled"]) == 60000


def test_turn_records_text_and_thinking_in_full(trail):
    """The half the orchestrator cannot see — and the half #197 actually asks for."""
    thinking = "Let me check the imports. " * 200
    text = "The sample resolves APIs dynamically. " * 50
    trail.turn({"turn_index": 3, "stop_reason": "tool_use", "text": text,
                "thinking": thinking,
                "tool_calls": [{"name": "decompile_function", "input": "{}"}],
                "usage": {"input_tokens": 100, "output_tokens": 20}})
    row = _rows(trail.path)[-1]
    assert row["thinking"] == thinking, "reasoning must be recorded in full"
    assert row["text"] == text
    assert row["thinking_chars"] == len(thinking)
    assert row["tool_calls"][0]["name"] == "decompile_function"
    assert row["stop_reason"] == "tool_use"


def test_stream_heartbeat_is_recorded(trail):
    """Distinguishes a slow turn from a hung one — previously indistinguishable."""
    trail.stream_progress({"turn_index": 2, "output_tokens": 75, "thinking_tokens": 25})
    row = _rows(trail.path)[-1]
    assert row["event"] == "stream"
    assert row["output_tokens"] == 75 and row["thinking_tokens"] == 25


def test_reader_renders_reasoning():
    """The data being present is not the same as it being readable."""
    from lamware_eval.trail import render_reasoning
    rows = [{"seq": 1, "t": 60.0, "phase": "loop", "event": "turn", "turn_index": 1,
             "stop_reason": "tool_use", "text": "Checking imports.",
             "thinking": "The IAT looks stripped.",
             "tool_calls": [{"name": "list_functions", "input": "{}"}]}]
    out = render_reasoning(rows)
    assert "The IAT looks stripped." in out
    assert "Checking imports." in out
    assert "list_functions" in out


def test_reader_says_so_when_there_are_no_turn_records():
    """An older container emits none; silence would read as 'the model did not reason'."""
    from lamware_eval.trail import render_reasoning
    out = render_reasoning([{"seq": 1, "t": 0, "phase": "loop", "event": "tool"}])
    assert "no turn records" in out


def test_trail_survives_a_hard_kill():
    """The whole point: SIGKILL the writer mid-run, the rows so far must still parse.

    Uses SIGKILL specifically — the container reaper does not give the process a chance
    to flush, and that is precisely how the audit log came to be empty.
    """
    script = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(ROOT / "ansible" / "roles" / "pipeline" / "files")!r})
        from stages.interpret import TurnTrail
        from pathlib import Path
        t = TurnTrail(Path({"TRAILPATH"!r}), started=time.time())
        for i in range(20):
            t.tool("decompile_function", {{"n": i}}, result={{"code": "x" * 500}})
        sys.stdout.write("written\\n"); sys.stdout.flush()
        time.sleep(60)
    """)
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        target = Path(td) / "killed.jsonl"
        proc = subprocess.Popen(
            [sys.executable, "-c", script.replace("TRAILPATH", str(target).replace("\\", "\\\\"))],
            stdout=subprocess.PIPE, text=True)
        assert proc.stdout.readline().strip() == "written"
        proc.kill()          # SIGKILL — no cleanup, no flush opportunity
        proc.wait(timeout=10)

        rows = _rows(target)
        assert len(rows) == 20, f"expected 20 rows to survive SIGKILL, got {len(rows)}"
        assert rows[-1]["cumulative_result_bytes"] > 0
