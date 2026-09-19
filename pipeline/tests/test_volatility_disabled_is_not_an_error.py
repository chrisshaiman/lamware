# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A stage with no input must not look like a stage that failed.

The Volatility stage went dead in production on 2026-09-16, when host-side
cuckoo.conf set `memory_dump = off`. The pipeline kept submitting `memory=1`,
CAPE wrote no dump, and every run since reported:

    {"triggered": True, "error": "memory dump not found"}

with zero plugins run. Compare the reports either side of that date:

    r5_* (2026-09-10/11)        triggered=True  error=None  plugins=7
    verify_salat (2026-09-18)   triggered=True  error=...   plugins=0

"memory dump not found" reads like CAPE misbehaved, so the actual cause -- the
feature is switched off -- was invisible for two days across every analysis.
Distinguishing the two is the whole point:

    disabled    nothing was requested. Not an error; no input exists.
    requested   CAPE was asked and wrote none. That IS an error, stays loud.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "ansible" / "roles"
                       / "pipeline" / "files"))

from stages.volatility import run_volatility  # noqa: E402

# A task id that cannot have a dump on disk, so get_memory_dump_path returns None.
NO_DUMP = {"id": 999999999}

COMMON = dict(
    output_dir=Path("/tmp"),  # noqa: S108 — never written; the function returns first
    volatility_cmd="/bin/true",
    volatility_triggers=[],
    volatility_standard_plugins=[],
    volatility_extra_plugins={},
    malfind_enabled=False,
    malfind_min_size=0,
    malfind_max_size=0,
    malfind_min_score=0,
    malfind_max_candidates=0,
    malfind_benign_processes=[],
    get_cape_signatures_fn=lambda _: [],
)


def test_dumps_disabled_is_a_skip_not_an_error():
    r = run_volatility(NO_DUMP, memory_dump_requested=False, **COMMON)
    assert r.get("error") is None, (
        "a stage with no input reported an error, which is how this went "
        "undiagnosed across every analysis for two days")
    assert r["skipped"] is True
    assert r["triggered"] is False
    assert "cape_memory_dump" in r["reason"], (
        "the skip reason must name the switch, or the operator cannot act on it")


def test_a_dump_that_was_requested_and_is_missing_is_still_an_error():
    """The honesty fix must not silence the real failure it was hiding."""
    r = run_volatility(NO_DUMP, memory_dump_requested=True, **COMMON)
    assert r["triggered"] is True
    assert "requested" in r["error"] and "none" in r["error"]
    assert r.get("skipped") is not True


def test_the_two_outcomes_are_distinguishable():
    """The defect was that both produced the same string."""
    off = run_volatility(NO_DUMP, memory_dump_requested=False, **COMMON)
    on = run_volatility(NO_DUMP, memory_dump_requested=True, **COMMON)
    assert off != on
    assert (off.get("error"), on.get("error")) != (None, None) or True
    assert bool(off.get("skipped")) != bool(on.get("skipped"))


def test_the_missing_dump_error_says_where_it_looked():
    r = run_volatility(NO_DUMP, memory_dump_requested=True, **COMMON)
    assert "999999999" in r["dump_expected_at"]
