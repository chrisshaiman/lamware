# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A router that filters on a report_json path needs an index for it.

`/api/evasions` filtered three queries on

    report_json->'evasion_analysis'->>'enabled' = 'true'

with nothing to support it. `report_json` totals 3.3 GB across 1096 rows, so each
query sequentially scanned and detoasted the lot: 4674 + 4320 + 5033 ms = 14.0s,
against the smoke gate's 15s timeout. The page was never broken — the captured
HTML showed it stuck in its own loading skeleton — and one run squeezed under the
wire, which is why it read as a flake for three deploys.

An expression index took the endpoint from ~14.0s to ~2.4s (0005).

This test is about the CLASS, not the instance: any router filtering on a
`report_json->...` path that is not covered by an index is the same defect, and
this repo's tables are large enough that the difference is a timeout rather than
a slowdown. A `report_json ? 'key'` containment test is exempt — GIN on the whole
document is a different, much larger decision than a single expression index.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROUTERS = sorted((ROOT / "api" / "app" / "routers").glob("*.py"))
MIGRATIONS = "\n".join(p.read_text() for p in
                       sorted((ROOT / "api" / "alembic" / "versions").glob("*.py")))

# report_json->'a'->>'b' = ... — an equality filter on a scalar at a fixed path.
FILTER = re.compile(r"report_json\s*->\s*'([a-z_]+)'\s*->>\s*'([a-z_]+)'\s*=", re.I)


def test_there_are_routers_to_check():
    """Guards the guard: an empty glob would pass every assertion below."""
    assert ROUTERS, "no routers found"


def _filters_in(text: str) -> set[tuple[str, str]]:
    return set(FILTER.findall(text))


@pytest.mark.parametrize("router", ROUTERS, ids=lambda p: p.name)
def test_every_report_json_equality_filter_has_an_index(router):
    filters = _filters_in(router.read_text())
    missing = []
    for outer, inner in filters:
        # The migration must index the same expression. Whitespace varies, so
        # compare on the path pair rather than on a formatted string.
        pat = re.compile(
            rf"CREATE INDEX[^;]*?report_json\s*->\s*'{outer}'\s*->>\s*'{inner}'",
            re.I | re.S)
        if not pat.search(MIGRATIONS):
            missing.append(f"report_json->'{outer}'->>'{inner}'")
    assert not missing, (
        f"{router.name} filters on unindexed report_json path(s): {missing}. "
        "report_json is multi-GB; an unindexed filter is a full detoasting scan "
        "and shows up as a timeout, not a slowdown. Add an expression index.")


def test_the_evasion_filter_is_the_one_we_measured():
    """Pins the instance that motivated this, so a later reader can check the
    measurement rather than trust the prose."""
    assert _filters_in((ROOT / "api" / "app" / "routers" / "evasions.py").read_text()) \
        >= {("evasion_analysis", "enabled")}


def _run_migration() -> tuple[list[str], list[str]]:
    """Execute 0005's upgrade and downgrade against a stub `op`, returning the SQL
    each emitted.

    Executed rather than grepped. Text assertions on this file passed with the
    migration gutted, because `IF NOT EXISTS` survives in the docstring and
    `DROP INDEX` survives in a module constant — the prose outlived the code it
    described, which is the guard defect this repo keeps finding.
    """
    import importlib.util
    import sys
    import types

    up: list[str] = []
    down: list[str] = []
    target = up

    stub = types.ModuleType("alembic")
    stub.op = types.SimpleNamespace(execute=lambda sql: target.append(str(sql)))
    saved = sys.modules.get("alembic")
    sys.modules["alembic"] = stub
    try:
        path = ROOT / "api" / "alembic" / "versions" / "0005_index_evasion_enabled.py"
        spec = importlib.util.spec_from_file_location("_mig0005", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.upgrade()
        target = down
        mod.downgrade()
    finally:
        if saved is not None:
            sys.modules["alembic"] = saved
        else:
            del sys.modules["alembic"]
    return up, down


def test_the_index_migration_is_reversible():
    """A migration that cannot be undone is one nobody will run on a live host."""
    up, down = _run_migration()
    assert any("DROP INDEX" in s.upper() for s in down), down
    assert any("idx_analyses_evasion_enabled" in s for s in down), down


def test_the_index_is_idempotent():
    """It was created by hand on the host while diagnosing. Without IF NOT EXISTS
    the migration fails against the very host it was measured on."""
    up, _ = _run_migration()
    assert up, "upgrade() emitted no SQL"
    assert any("IF NOT EXISTS" in s.upper() for s in up), up


def test_the_upgrade_indexes_the_measured_expression():
    up, _ = _run_migration()
    joined = " ".join(up)
    assert "CREATE INDEX" in joined.upper()
    assert "'evasion_analysis'" in joined and "'enabled'" in joined, joined
