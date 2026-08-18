# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A valid-JSON non-object first frame must be rejected, not crash the handler.

The WebSocket auth handshake parses the first frame and guards only the parse:

    msg = json.loads(raw)
    except (TimeoutError, json.JSONDecodeError): ... close(4001)

    if msg.get("type") != "auth" or not msg.get("token"):

`json.loads` returns a list for `"[]"`, an int for `"1"`, `None` for `"null"`
and a str for a bare quoted string — all valid JSON, none of them dicts. Each
sailed past the `JSONDecodeError` guard and reached `.get()`, which raises
`AttributeError`. Nothing catches that, so the handler died mid-handshake:
`_log_failed_auth` never ran and the close code was never sent.

An unauthenticated client could therefore crash its own connection handler and
leave no trace of the attempt — on the auth path, where the record matters most.
This is the same audit-trail concern as #208, which is why the parity tests
exist next door.

The guard now type-checks before dispatching on content.
"""
import ast
import json
from pathlib import Path

import pytest

SRC_PATH = Path(__file__).resolve().parent.parent / "app" / "routers" / "ws.py"
SRC = SRC_PATH.read_text(encoding="utf-8")


@pytest.mark.parametrize("raw", ['[]', '1', 'null', '"token"', '3.14', 'true'])
def test_these_frames_are_valid_json_but_not_objects(raw):
    """The premise, asserted rather than assumed: the JSONDecodeError guard
    above genuinely does not catch these."""
    parsed = json.loads(raw)
    assert not isinstance(parsed, dict)
    with pytest.raises(AttributeError):
        parsed.get("type")


def test_the_guard_type_checks_before_dispatching():
    """THE bug. isinstance must come first, or .get() runs on a non-dict."""
    line = next(ln for ln in SRC.splitlines()
                if 'msg.get("type") != "auth"' in ln and not ln.lstrip().startswith("#"))
    assert "isinstance(msg, dict)" in line, (
        f"the auth guard calls .get() on an unvalidated parse result: {line.strip()}")
    assert line.index("isinstance") < line.index('msg.get("type")'), (
        "isinstance must be evaluated first — Python's `or` short-circuits left "
        "to right, so ordering is what makes this safe")


def test_the_guard_condition_is_correct_for_every_shape():
    """Evaluate the real condition against each frame shape."""
    line = next(ln for ln in SRC.splitlines()
                if 'msg.get("type") != "auth"' in ln and not ln.lstrip().startswith("#"))
    cond = line.strip().removeprefix("if ").removesuffix(":")
    rejected = ["[]", "1", "null", '"token"', '{}', '{"type": "hello"}',
                '{"type": "auth"}', '{"type": "auth", "token": ""}']
    accepted = ['{"type": "auth", "token": "jwt"}']
    for raw in rejected:
        assert eval(cond, {}, {"msg": json.loads(raw)}) is True, f"accepted {raw}"  # noqa: S307
    for raw in accepted:
        assert eval(cond, {}, {"msg": json.loads(raw)}) is False, f"rejected {raw}"  # noqa: S307


def test_a_rejected_frame_still_logs_and_closes():
    """The whole point: the attempt must leave a record. A handler that dies
    before this line logs nothing."""
    start = SRC.index('msg.get("type") != "auth"')
    block = SRC[start:start + 400]
    assert "_log_failed_auth(" in block
    assert "close(code=4001" in block


def test_attributeerror_is_not_papered_over_in_the_except():
    """Widening the parse guard would hide the bug rather than fix it, and
    would swallow genuine AttributeErrors from the auth code below."""
    assert "json.JSONDecodeError, AttributeError" not in SRC
    assert "AttributeError" not in SRC.split("_log_failed_auth")[0]


def test_the_module_still_parses():
    ast.parse(SRC)
