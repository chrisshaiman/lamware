# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""An empty pipeline state on a failed query is a lie every client believes.

On connect, the WebSocket sends current state. A failure in that query used to
send `{"running": [], "recent_completed": [], "as_of": ""}` — exactly what an
idle platform looks like — so every dashboard rendered "nothing is running"
when the truth was "I could not look".

Same principle as `correlation_warnings` and `spend.py:_zeroed`: the shape stays
so consumers keep working, and the reason rides along in `error`.
"""
import ast
from pathlib import Path

import app.routers.ws as ws

_SRC = Path(ws.__file__).read_text(encoding="utf-8")


def _fallback_state() -> dict:
    """The literal the except-branch sends, read off the parsed tree.

    Parsed rather than grepped: the surrounding comment explains the bug and
    names every key, so a text search finds the words whether or not the code
    still sets them.
    """
    tree = ast.parse(_SRC)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "state" for t in node.targets):
            continue
        if isinstance(node.value, ast.Dict):
            return ast.literal_eval(node.value)
    raise AssertionError("no literal `state = {...}` assignment found in ws.py")


def test_the_fallback_state_carries_a_reason():
    """THE bug: this dict was indistinguishable from an idle platform."""
    state = _fallback_state()
    assert state.get("error"), (
        "the failed-query state says nothing about having failed, so a client "
        "cannot tell it from a platform with no work running")


def test_the_fallback_keeps_the_shape_clients_expect():
    """Adding `error` must not remove the keys the frontend indexes."""
    state = _fallback_state()
    for key in ("running", "recent_completed", "as_of"):
        assert key in state, f"clients read {key}; it must survive the failure path"
    assert state["running"] == []
    assert state["recent_completed"] == []


def test_the_healthy_path_does_not_set_an_error():
    """_get_current_state builds the success payload; it must not carry `error`,
    or the flag means nothing."""
    src = _SRC[_SRC.index("def _get_current_state"):]
    body = src[:src.index("\n\n\n")]
    tree = ast.parse("def f():\n" + "\n".join(
        "    " + line for line in body.splitlines()[1:]))
    returns = [n for n in ast.walk(tree) if isinstance(n, ast.Return)]
    dict_returns = [n.value for n in returns if isinstance(n.value, ast.Dict)]
    assert dict_returns, "expected _get_current_state to return a dict literal"
    for d in dict_returns:
        keys = [k.value for k in d.keys if isinstance(k, ast.Constant)]
        assert "error" not in keys, "the success payload must not claim an error"


def test_the_failure_is_logged():
    """A bare `except Exception: pass`-shaped handler leaves no trace for an
    operator to correlate against the client-visible symptom."""
    branch = _SRC[_SRC.index("WS initial state query failed"):]
    assert branch, "the failure path must log"
    tree = ast.parse(_SRC)
    logged = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr in {"warning", "error", "exception"}
        and any(isinstance(a, ast.Constant) and "state query failed" in str(a.value)
                for a in n.args)
    ]
    assert logged, "no log call carries the state-query failure"
