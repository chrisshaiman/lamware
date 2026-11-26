# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The agent loop keeps one model from first turn to last (ADR-038, decision 6).

Structural, and only because nothing else can observe it: the switch lived inside
the agentic loop, which needs a Ghidra project and a tool-calling model to run end to
end. Parsed with `ast`, so a comment or a string mentioning escalation cannot satisfy
or trip it; the assertion is on assignments to the variable every loop request uses.
"""
import ast
from pathlib import Path

SRC = (Path(__file__).resolve().parents[2]
       / "ansible/roles/interpret/files/interpret-ghidra.py").read_text()


def _run() -> ast.FunctionDef:
    return next(n for n in ast.walk(ast.parse(SRC))
                if isinstance(n, ast.FunctionDef) and n.name == "_run")


def _assigned(fn: ast.FunctionDef, name: str) -> list[ast.AST]:
    out = []
    for n in ast.walk(fn):
        targets = (n.targets if isinstance(n, ast.Assign)
                   else [n.target] if isinstance(n, (ast.AugAssign, ast.AnnAssign)) else [])
        out += [n for t in targets for x in ast.walk(t) if isinstance(x, ast.Name) and x.id == name]
    return out


def test_the_loop_model_is_set_once_from_the_config():
    sets = _assigned(_run(), "current_model")
    assert len(sets) == 1, f"current_model is assigned {len(sets)} times; a run uses one model"
    (only,) = sets
    assert isinstance(only.value, ast.Name) and only.value.id == "model"


def test_the_container_reads_no_escalation_setting():
    keys = {n.value for n in ast.walk(_run()) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert not {k for k in keys if k.startswith("escalation")}, keys & {"escalation_model", "escalation_threshold"}
