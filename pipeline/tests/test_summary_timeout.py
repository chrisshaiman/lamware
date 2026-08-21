# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The summary stage's timeout must fit a CPU-generated summary (#429 follow-up).

300s was hardcoded at the `communicate()` call. Measured 2026-08-20, qwen3.6 on
llama.cpp with the real report prompt (~2,800 tokens):

    generation   1,959-3,402 output tokens at ~10 tok/s   ->  215-340s

The length is not a defect and not new. Every surviving historical report shows a
summary of the same order — local-qwen (Ollama) recorded 478, 479, 698, 1672, 1696,
1714, 1755, 1843 and 1921 output tokens, and all of them SUCCEEDED. The stage has
always run just inside the limit; moving to llama.cpp, which generates somewhat
longer, pushed it over.

Two things made the failure hard to see, and both are worth keeping in mind:

  - `communicate()` discards stdout on TimeoutExpired, so the summary was lost AND
    the request-shape events that would have explained it went with it. The run
    reported an empty summary with no evidence attached.
  - An empty summary is stored without error, so it reads as "nothing to say"
    rather than "the stage was killed" — the same shape as #411.

This does NOT assert a specific number beyond a floor. The point is that a budget a
normal run finishes 15 seconds inside is not a margin.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "stages"
       / "interpret.py").read_text(encoding="utf-8")
TMPL = (ROOT / "ansible" / "roles" / "pipeline" / "templates"
        / "config.json.j2").read_text(encoding="utf-8")

#: Slowest generation observed, plus room for prompt processing and container start.
OBSERVED_WORST_SECONDS = 340


def test_summarize_timeout_is_not_hardcoded():
    """It was `timeout=300` inline, so no deployment could raise it."""
    assert not re.search(r"communicate\([^)]*timeout=\s*300\b", SRC, re.S), (
        "the summarize timeout is hardcoded again")
    assert re.search(r"communicate\([^)]*timeout=timeout_s", SRC, re.S), (
        "summarize must use the configurable timeout")


def test_default_timeout_exceeds_the_slowest_observed_generation():
    m = re.search(r'interpret_config\.get\("summary_timeout",\s*(\d+)\)', SRC)
    assert m, "summary_timeout default not found"
    assert int(m.group(1)) > OBSERVED_WORST_SECONDS, (
        f"default {m.group(1)}s does not clear the slowest observed run "
        f"({OBSERVED_WORST_SECONDS}s); a normal run must not finish just inside it")


def test_config_template_exposes_the_knob():
    m = re.search(r'"summary_timeout":\s*\{\{\s*interpret_summary_timeout\s*\|\s*default\((\d+)\)', TMPL)
    assert m, "summary_timeout is not rendered into config.json"
    assert int(m.group(1)) > OBSERVED_WORST_SECONDS


def test_timeout_error_reports_the_actual_budget():
    """The old message said '(300s)' as a literal, so a raised timeout would have
    reported a number it no longer used."""
    assert re.search(r'timed out \(\{timeout_s\}s\)', SRC), (
        "the timeout error must name the budget actually applied")
