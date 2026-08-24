# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The base-rate queries must exclude analyses that predate persistence.

These queries exist to answer "how often does correlation fire" (#423), and the
answer is worthless if the denominator includes the 998 analyses recorded before
the tables existed. Those rows have no correlations and no warnings, so counting
them would report a fire rate near zero regardless of the truth — a confident
wrong number, which is the dangerous kind.

`correlation_warnings IS NOT NULL` is therefore the invariant — that column is
NULL until correlation has been recorded, so it doubles as the "this ran"
marker — and it is asserted per query rather than trusted to review.

The queries were run against a real PostgreSQL before landing — a throwaway
database built from `alembic upgrade head --sql`, seeded with one analysis in
each of the four states, which returned coverage 3/1/4, fire_rate 1 of 3, and
blind_rate clean=1 blind=1 produced=1. This file guards the properties that
would silently change afterwards.
"""
import re

import pytest
from lamware_pipeline.correlation_base_rate import (
    BY_RULE,
    QUERIES,
)


@pytest.mark.parametrize("name", sorted(QUERIES))
def test_every_query_scopes_to_analyses_correlation_actually_ran_for(name):
    """The invariant. A query without this counts pre-persistence analyses as
    'correlation found nothing', which is exactly the claim it cannot support."""
    sql = QUERIES[name]
    assert "correlation_warnings IS NOT NULL" in sql, (
        f"{name} has no correlation_warnings filter, so its denominator "
        f"includes analyses recorded before the column existed")


@pytest.mark.parametrize("name", sorted(QUERIES))
def test_no_query_takes_a_parameter(name):
    """They are run by hand at a psql prompt. A placeholder would fail there,
    and a formatted-in value would be an injection point in a tool nobody
    expects to be one."""
    sql = QUERIES[name]
    assert "%s" not in sql and "{" not in sql, f"{name} is not standalone"


@pytest.mark.parametrize("name", sorted(QUERIES))
def test_every_query_is_read_only(name):
    """These are analysis queries against production. Nothing here may write."""
    forbidden = ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "CREATE")
    upper = QUERIES[name].upper()
    for word in forbidden:
        assert not re.search(rf"\b{word}\b", upper), f"{name} contains {word}"


def test_the_per_rule_query_groups_by_rule_type():
    """#423's acceptance criterion: "a query answers how many analyses produced
    >= 1 correlation, by rule type"."""
    upper = " ".join(BY_RULE.upper().split())
    assert "GROUP BY C.TYPE" in upper
    assert "COUNT(DISTINCT C.ANALYSIS_ID)" in upper, (
        "counting rows rather than analyses reports a sample with three "
        "findings as three samples")


def test_the_blind_rate_query_separates_the_three_states():
    """clean / blind / produced. Collapsing the first two is #411."""
    upper = QUERIES["blind_rate"].upper()
    assert "CARDINALITY(A.CORRELATION_WARNINGS)" in upper, (
        "cannot tell blind from clean without inspecting the warnings themselves")
    for label in ("CLEAN", "BLIND", "PRODUCED_FINDINGS"):
        assert label in upper


def test_cardinality_is_used_rather_than_a_null_test():
    """`correlation_warnings IS NOT NULL` says correlation RAN; only the array's
    LENGTH says whether it could see. Substituting the null test for either
    branch reports every clean analysis wrongly — and the WHERE clause has
    already excluded NULL, so that branch would match nothing at all.

    Asserted on the cardinality expressions specifically. A looser check for
    "= 0" passes on `f.n = 0`, which appears in both branches regardless.
    """
    upper = " ".join(QUERIES["blind_rate"].upper().split())
    assert "CARDINALITY(A.CORRELATION_WARNINGS) = 0" in upper, "clean branch"
    assert "CARDINALITY(A.CORRELATION_WARNINGS) > 0" in upper, "blind branch"


def test_the_warning_frequency_query_unnests_the_column():
    """Which rules go unevaluated, corpus-wide. One unnest now that warnings are
    a column; it needed a join and a GROUP BY over a whole table before."""
    upper = " ".join(QUERIES["warning_frequency"].upper().split())
    assert "UNNEST(A.CORRELATION_WARNINGS)" in upper
    assert "GROUP BY W" in upper


def test_the_corpus_query_ranks_by_rule_diversity():
    """#420 needs samples that exercise MORE THAN ONE rule; a sample with six
    findings from one rule tests one rule six times."""
    upper = " ".join(QUERIES["corpus_candidates"].upper().split())
    assert "COUNT(DISTINCT C.TYPE)" in upper
    assert "ORDER BY DISTINCT_RULES DESC" in upper


def test_coverage_reports_the_unrecorded_count_too():
    """The first number to read: how much of the history these queries can
    speak for at all. Reporting only `recorded` hides that the answer covers a
    fraction of the corpus."""
    upper = QUERIES["coverage"].upper()
    assert "NOT_RECORDED" in upper and "TOTAL" in upper
