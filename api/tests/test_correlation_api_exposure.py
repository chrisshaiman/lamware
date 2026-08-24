# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The analysis detail endpoint must return correlations and their warnings.

`correlations: []` on its own is ambiguous three ways — correlation ran and the
sample was clean, it ran blind, or it predates persistence — so the endpoint
returns `correlation_warnings` alongside, always, and preserves the null-vs-[]
distinction through JSON. #412 is the same defect one stage up: the UI showed a
stage as complete when every plugin inside it had failed.

The migration and the models are compared field by field here because there is
no PostgreSQL in this job. `test_alembic_drift.py` does the real comparison, and
it SKIPS unless LAMWARE_MIGRATION_TEST_URL is set — which it is not, in CI.
"""
import ast
from pathlib import Path

import pytest
from app.models import Analysis, Correlation

API_DIR = Path(__file__).resolve().parents[1]
ROUTER = (API_DIR / "app" / "routers" / "analyses.py").read_text(encoding="utf-8")
MIGRATION = (API_DIR / "alembic" / "versions"
             / "0003_persist_correlation_findings.py").read_text(encoding="utf-8")


def _detail_return_keys() -> set[str]:
    """Keys of the dict `get_analysis` returns, off the parsed tree."""
    tree = ast.parse(ROUTER)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "get_analysis")
    ret = next(n for n in ast.walk(fn)
               if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict))
    return {k.value for k in ret.value.keys if isinstance(k, ast.Constant)}


@pytest.mark.parametrize("key", ["correlations", "correlation_warnings"])
def test_the_detail_response_carries(key):
    assert key in _detail_return_keys()


def test_both_are_returned_together():
    """Either alone is misleading: findings without the warnings column cannot
    be told from never-recorded, and warnings without findings say nothing about
    what was found."""
    keys = _detail_return_keys()
    pair = {"correlations", "correlation_warnings"}
    assert pair <= keys, f"missing {sorted(pair - keys)}"


def test_the_warnings_are_passed_through_without_defaulting_to_a_list():
    """`analysis.correlation_warnings or []` would collapse null into [], which
    turns "never recorded" into "checked, clean" at the API boundary — the exact
    claim the column exists to avoid making."""
    tree = ast.parse(ROUTER)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "get_analysis")
    ret = next(n for n in ast.walk(fn)
               if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict))
    value = next(v for k, v in zip(ret.value.keys, ret.value.values, strict=True)
                 if isinstance(k, ast.Constant) and k.value == "correlation_warnings")
    assert isinstance(value, ast.Attribute), (
        "correlation_warnings is transformed on the way out; null must survive")
    assert value.attr == "correlation_warnings"


# --- migration matches the models -------------------------------------------

def _migration_columns(table: str) -> set[str]:
    tree = ast.parse(MIGRATION)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "create_table"
                and node.args and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == table):
            return {
                a.args[0].value for a in node.args[1:]
                if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute)
                and a.func.attr == "Column" and a.args
                and isinstance(a.args[0], ast.Constant)
            }
    raise AssertionError(f"create_table({table!r}) not found in the migration")


@pytest.mark.parametrize("model,table", [(Correlation, "correlations")])
def test_the_migration_creates_exactly_the_model_fields(model, table):
    """A column in the model and not the migration means the app queries a
    column production does not have — and the drift sentinel that would catch
    it skips without a throwaway database."""
    assert _migration_columns(table) == set(model.model_fields)


def test_the_migration_adds_the_warnings_column_to_analyses():
    tree = ast.parse(MIGRATION)
    added = {
        node.args[1].args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_column" and len(node.args) > 1
        and isinstance(node.args[1], ast.Call) and node.args[1].args
        and isinstance(node.args[1].args[0], ast.Constant)
    }
    assert "correlation_warnings" in added
    assert "correlation_warnings" in Analysis.model_fields


def test_the_downgrade_reverses_everything_the_upgrade_did():
    """An irreversible migration is one nobody dares run."""
    tree = ast.parse(MIGRATION)
    up = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade")
    down = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "downgrade")

    def ops(fn, name):
        return {
            n.args[0].value for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == name and n.args and isinstance(n.args[0], ast.Constant)
        }

    assert ops(up, "create_table") == ops(down, "drop_table")
    assert ops(up, "create_index") == ops(down, "drop_index")
    assert "analyses" in ops(down, "drop_column") or ops(down, "drop_column")


def test_the_warnings_column_is_nullable_with_no_server_default():
    """NULL is a meaning here — 'this analysis predates persistence' — not an
    absence to be defaulted away. A server_default of '{}' would relabel all 998
    pre-existing analyses as "ran and found nothing to warn about"."""
    block = MIGRATION[MIGRATION.index("add_column"):]
    block = block[:block.index(")\n\n")]
    assert "correlation_warnings" in block
    assert "nullable=True" in block
    assert "server_default" not in block
    assert Analysis.model_fields["correlation_warnings"].default is None
