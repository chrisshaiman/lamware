# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""api/app/flow.py mirrors two pipeline facts it cannot import (#653).

The API and the pipeline are separate packages, so flow.py keeps its own copies:

  ROUTED_ANALYSERS       which Stage 4 branches hand a sample to another
                         analyser (pipeline: stages/ghidra.py ROUTED_FLAGS)
  _INTERPRET_PRECEDENCE  the order Stage 4.5 tries those analysers
                         (pipeline: the if/elif chain in run-pipeline.py)

A routed analyser added to the pipeline but not to flow.py would draw that
sample's flow as if nothing were routed: the original -> Ghidra edge "absent"
instead of "skipped, routed to X". That is the silent-skip the view exists to
expose. Structural, because the two packages cannot import each other; both
sides are read with ast, never regex.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GHIDRA = ROOT / "ansible/roles/pipeline/files/stages/ghidra.py"
RUN_PIPELINE = ROOT / "ansible/roles/pipeline/files/run-pipeline.py"
FLOW = ROOT / "api/app/flow.py"


def _assigned(path: Path, name: str):
    for node in ast.walk(ast.parse(path.read_text())):
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} not found in {path.name}: the probe is broken")


def test_flow_knows_every_routed_branch():
    pipeline = set(_assigned(GHIDRA, "ROUTED_FLAGS"))
    flow = {row[0] for row in _assigned(FLOW, "ROUTED_ANALYSERS")}
    assert pipeline, "ROUTED_FLAGS is empty"
    assert flow == pipeline, f"only in pipeline: {pipeline - flow}; only in flow: {flow - pipeline}"


def _stage45_order() -> list[str]:
    """Report keys in the order run-pipeline's Stage 4.5 chain tests them."""
    tree = ast.parse(RUN_PIPELINE.read_text())
    # `dotnet_data = report.get("dotnet_analysis", {})` -> dotnet_data: dotnet_analysis
    var_to_key = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "get"
                and isinstance(node.value.func.value, ast.Name)
                and node.value.func.value.id == "report"
                and node.value.args and isinstance(node.value.args[0], ast.Constant)
                and str(node.value.args[0].value).endswith("_analysis")):
            var_to_key[node.targets[0].id] = node.value.args[0].value
    start = next(n for n in ast.walk(tree)
                 if isinstance(n, ast.If) and "payload_target" in ast.unparse(n.test))
    order, node = [], start.orelse[0] if start.orelse else None
    while isinstance(node, ast.If):
        # Only dispatch branches: they test `<x>_data.get("analysis_success")`.
        # An `else:` whose body is a single `if` is indistinguishable from an
        # `elif` in the AST, and the final fallback mentions dotnet_data too.
        if "analysis_success" in ast.unparse(node.test):
            names = [n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)]
            order += [var_to_key[v] for v in names if v in var_to_key]
        node = node.orelse[0] if node.orelse else None
    # A branch may test its analysis twice (office: analysis_success and
    # has_macros); precedence is first appearance.
    return list(dict.fromkeys(order))


def test_flow_infers_the_interpretation_in_the_pipeline_order():
    order = _stage45_order()
    assert len(order) >= 7, f"read only {order}: the probe is broken"
    assert list(_assigned(FLOW, "_INTERPRET_PRECEDENCE")) == order
