# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A stats query that could not run must not render as a quiet week.

`_scalar` wrapped every query in `except Exception: return 0`. A database the
API cannot reach therefore produced "0 analyses, 0 IOCs, $0.00 spend" — byte-
identical to a platform that has simply not been used. The dashboard reads that
as calm.

This is the codebase's own design principle 3, which the README states as
enforced: "A failed analyzer must never silently masquerade as a clean result."
It was enforced in the pipeline (`correlation_warnings`, `PayloadAccessError`,
Ghidra `analysis_warnings`) and not in the API. `spend.py:_zeroed` is the same
fix already applied to the neighbouring endpoint, and carries an `error` field
for exactly this reason.

Zero is still returned — the response has to keep its shape — so the assertions
below are about `errors`, not about the numbers.
"""
import logging

import pytest
from app.routers.stats import _scalar


class _Session:
    """Minimal stand-in. `exec` raises for the SQL listed in `failing`."""

    def __init__(self, value=7, failing=()):
        self.value = value
        self.failing = failing

    def exec(self, statement):  # noqa: A003 - mirrors the sqlmodel API
        if str(statement) in self.failing:
            raise RuntimeError("connection refused")
        return self

    def scalar(self):
        return self.value


def test_a_healthy_query_records_no_error():
    errors: list[str] = []
    assert _scalar(errors, "total_analyses", _Session(42), "SELECT 1") == 42
    assert errors == []


def test_a_failed_query_names_itself_in_errors():
    """THE bug: this used to return 0 and say nothing."""
    errors: list[str] = []
    value = _scalar(errors, "total_analyses", _Session(failing=("SELECT 1",)), "SELECT 1")
    assert value == 0, "the response keeps its shape"
    assert errors == ["total_analyses"], "and says which query produced it"


def test_a_failure_is_distinguishable_from_a_genuine_zero():
    """The whole point. Both return 0; only one of them is an outage."""
    quiet: list[str] = []
    assert _scalar(quiet, "analyses_today", _Session(0), "SELECT 1") == 0

    broken: list[str] = []
    assert _scalar(broken, "analyses_today", _Session(failing=("SELECT 1",)), "SELECT 1") == 0

    assert quiet != broken, (
        "an empty table and an unreachable database produce identical output")


def test_a_null_result_is_a_real_zero_not_an_error():
    """COALESCE handles most of it, but a NULL scalar must not be miscounted as
    a failure — that would cry outage on an empty platform."""
    errors: list[str] = []
    assert _scalar(errors, "cost_today", _Session(None), "SELECT 1", as_float=True) == 0.0
    assert errors == []


def test_each_failing_query_is_listed_separately():
    """Partial failure is the realistic case — one bad column, not a dead DB."""
    errors: list[str] = []
    for name in ("total_analyses", "total_iocs", "cost_week"):
        _scalar(errors, name, _Session(failing=("SELECT 1",)), "SELECT 1")
    _scalar(errors, "total_samples", _Session(3), "SELECT 1")
    assert errors == ["total_analyses", "total_iocs", "cost_week"]


def test_the_failure_is_logged(caplog):
    """An operator has to be able to find the cause, not just the symptom."""
    from app.routers import stats

    errors: list[str] = []
    with caplog.at_level(logging.WARNING, logger=stats.__name__):
        _scalar(errors, "cost_total", _Session(failing=("SELECT 1",)), "SELECT 1")
    assert "cost_total" in caplog.text
    assert "connection refused" in caplog.text


def test_float_casting_still_works():
    errors: list[str] = []
    assert _scalar(errors, "cost_today", _Session("1.25"), "SELECT 1", as_float=True) == 1.25
    assert isinstance(_scalar(errors, "total_analyses", _Session("9"), "SELECT 1"), int)


# --- the endpoint publishes it -------------------------------------------

@pytest.mark.parametrize("failing", [(), ("SELECT COUNT(*) FROM analyses",)])
def test_the_response_always_carries_an_errors_key(failing):
    """Always present, so a consumer can tell "checked, clean" from "never
    populated" without treating a missing key as either — the same contract
    correlation_warnings settled on."""
    import asyncio

    from app.routers.stats import get_stats

    payload = asyncio.run(get_stats(auth=None, session=_Session(failing=failing)))
    assert "errors" in payload
    assert payload["errors"] == (["total_analyses"] if failing else [])
    assert payload["total_samples"] == 7, "the other queries still answer"
