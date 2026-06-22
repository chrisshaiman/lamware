# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Drift guard: the agent's Ghidra arg validators must match the pipeline's.

The investigation agent (`api/app/investigate/tool_validators.py`) hand-mirrors the
Ghidra argument validators defined in the pipeline interpret stage
(`ansible/roles/pipeline/templates/stages/interpret.py.j2`). The pipeline copy lives
in a Jinja template and cannot be imported, so this test extracts BOTH validator dicts
and their numeric bounds from source and asserts they are identical.

If the pipeline tightens a regex/bound or adds a tool and the agent copy is not updated,
the agentic path would keep the looser rule — a silent bypass of the arg-validation
control. This guard fails in CI instead. The permanent fix is to de-template the pipeline
so both import one shared module; until then, this is the guard. (Same pattern as the
Alembic ORM<->DB drift sentinel.)

Pure stdlib + file reads — no imports from app, so it is immune to the sibling
exec-with-stubs tests' sys.modules pollution and needs no app dependencies.

Author: Christopher Shaiman
License: Apache 2.0
"""

import ast
import re
from pathlib import Path

# api/tests/ -> api/ -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[2]
_AGENT_SRC = _REPO_ROOT / "api" / "app" / "investigate" / "tool_validators.py"
_PIPELINE_SRC = (
    _REPO_ROOT
    / "ansible"
    / "roles"
    / "pipeline"
    / "templates"
    / "stages"
    / "interpret.py.j2"
)


def _extract_dict(source: str, var_name: str) -> dict:
    """ast.literal_eval the dict literal assigned to var_name.

    Relies on the assignment opening with `VAR = {` and the dict closing with a `}`
    at column 0 (true for both files). ast.literal_eval — not brace counting — because
    the regex values contain literal braces (e.g. `^.{1,200}$`).
    """
    lines = source.splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.startswith(f"{var_name} = {{")
    )
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("}"))
    rhs = "\n".join(lines[start : end + 1]).split("=", 1)[1].strip()
    return ast.literal_eval(rhs)


def _extract_bound(source: str, arg: str) -> int:
    """Return the integer upper bound from `int(args["<arg>"]) > <N>`."""
    m = re.search(rf'int\(args\["{arg}"\]\)\s*>\s*(\d+)', source)
    assert m, f"could not find numeric bound for {arg!r}"
    return int(m.group(1))


def test_ghidra_validator_dicts_match():
    """Agent GHIDRA_ARG_VALIDATORS must equal the pipeline TOOL_ARG_VALIDATORS."""
    agent = _extract_dict(_AGENT_SRC.read_text(), "GHIDRA_ARG_VALIDATORS")
    pipeline = _extract_dict(_PIPELINE_SRC.read_text(), "TOOL_ARG_VALIDATORS")
    assert agent == pipeline, (
        "VALIDATOR DRIFT: the agent's GHIDRA_ARG_VALIDATORS no longer matches the "
        "pipeline's TOOL_ARG_VALIDATORS. Re-sync "
        "api/app/investigate/tool_validators.py with interpret.py.j2.\n"
        f"agent   = {agent}\npipeline = {pipeline}"
    )


def test_numeric_bounds_match():
    """The range/length upper bounds must match across both validator copies."""
    agent_src = _AGENT_SRC.read_text()
    pipeline_src = _PIPELINE_SRC.read_text()
    for arg in ("range", "length"):
        agent_bound = _extract_bound(agent_src, arg)
        pipeline_bound = _extract_bound(pipeline_src, arg)
        assert agent_bound == pipeline_bound, (
            f"VALIDATOR DRIFT: the {arg!r} upper bound differs — "
            f"agent={agent_bound}, pipeline={pipeline_bound}. Re-sync the two copies."
        )
