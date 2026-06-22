# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0

"""Tests for the investigation agent router — pure logic only.

Tests that require infrastructure (DB, auth, LiteLLM) are out of scope here.
This file covers:
  - VALID_MODELS constant contents
  - _validate_pin_body: all validation branches
  - _build_report_markdown: header, findings, transcript role mapping,
    tool_result truncation at 2000 chars

Loading strategy: same sys.modules stubbing used by test_investigate_tools.py.
We stub out the heavy imports (sqlalchemy, sqlmodel, fastapi, app.config, etc.)
before importing the router module, so no DB or HTTP stack is needed.
"""

import ast
import json
import sys
import types
from pathlib import Path


def test_no_endpoint_shadows_imported_dependency():
    """Endpoint handlers must not be named after imported FastAPI dependencies.

    Regression guard for the get_session shadowing bug: naming the
    GET /sessions/{session_id} handler `get_session` rebound the module-level
    `get_session` (imported from ..database), so every endpoint defined after
    it bound `Depends(get_session)` to the endpoint function — which takes
    `session_id: int` — injecting a spurious required query param. This only
    surfaces at FastAPI route construction, which the direct-call unit tests
    bypass, so we catch it statically here.
    """
    src = (Path(__file__).resolve().parent.parent / "app" / "routers" / "investigate.py").read_text()
    tree = ast.parse(src)
    # Names imported into the module (these are dependency callables).
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported.add(alias.asname or alias.name)
    # Top-level function defs must not reuse an imported name.
    func_names = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
    collisions = sorted(set(func_names) & imported)
    assert not collisions, (
        f"Function(s) {collisions} shadow imported dependencies — rename the "
        f"endpoint handler(s) to avoid breaking Depends() resolution."
    )
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stub every external dependency the router imports before loading it
# ---------------------------------------------------------------------------

# sqlalchemy — force-assigned so router.py's exec always sees this stub
# regardless of which file collected first.
_sa = types.ModuleType("sqlalchemy")
_sa.text = MagicMock()  # type: ignore[attr-defined]
sys.modules["sqlalchemy"] = _sa

# sqlmodel — force-assigned; includes col/select that the router imports.
_sm = types.ModuleType("sqlmodel")
_sm.Session = MagicMock()  # type: ignore[attr-defined]
_sm.col = MagicMock()  # type: ignore[attr-defined]
_sm.select = MagicMock()  # type: ignore[attr-defined]
sys.modules["sqlmodel"] = _sm

# fastapi
_fa = types.ModuleType("fastapi")
_fa.APIRouter = MagicMock()  # type: ignore[attr-defined]
_fa.Depends = MagicMock()  # type: ignore[attr-defined]


class _HTTPException(Exception):
    """Minimal HTTPException stub — carries status_code and detail."""

    def __init__(self, status_code: int = 500, detail: str = "") -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


_fa.HTTPException = _HTTPException  # type: ignore[attr-defined]
sys.modules["fastapi"] = _fa
_fa_resp = types.ModuleType("fastapi.responses")
_fa_resp.StreamingResponse = MagicMock()  # type: ignore[attr-defined]
sys.modules["fastapi.responses"] = _fa_resp

# app package stubs — must be in place before importing submodules.
# Force-assign the stubs that the exec'd router source imports from directly
# so this file is self-contained regardless of collection order.
_app_pkg = types.ModuleType("app")
sys.modules.setdefault("app", _app_pkg)

_app_config = types.ModuleType("app.config")
_settings = MagicMock()
_settings.investigation_max_turns = 50
_settings.investigation_cost_alert_usd = 2.0
# Include attributes used by other exec'd modules (orchestrator) so that if
# any earlier file's setdefault lost the race the comparison still works.
_settings.litellm_url = "http://127.0.0.1:4000"
_settings.litellm_key = "sk-test"
_settings.investigation_max_tool_calls_per_turn = 10
_app_config.settings = _settings  # type: ignore[attr-defined]
sys.modules["app.config"] = _app_config

_app_auth = types.ModuleType("app.auth")
_app_auth.require_auth = MagicMock()  # type: ignore[attr-defined]
_app_auth.require_role = MagicMock()  # type: ignore[attr-defined]
_app_auth.AuthContext = MagicMock()  # type: ignore[attr-defined]
sys.modules["app.auth"] = _app_auth

_app_audit = types.ModuleType("app.audit")
_app_audit.log_audit = MagicMock()  # type: ignore[attr-defined]
sys.modules["app.audit"] = _app_audit

_app_db = types.ModuleType("app.database")
_app_db.get_session = MagicMock()  # type: ignore[attr-defined]
# `engine` is needed because the orchestrator's _execute_tool_with_own_session
# lazily does `from app.database import engine`. When test files are collected
# together this stub can win the sys.modules slot, so it must be complete or
# that call-time import fails. Keep both stubs (here and test_orchestrator.py)
# carrying get_session AND engine.
_app_db.engine = MagicMock()  # type: ignore[attr-defined]
sys.modules["app.database"] = _app_db

# Investigate subpackage
_inv_pkg = types.ModuleType("app.investigate")
sys.modules.setdefault("app.investigate", _inv_pkg)

_inv_orch = types.ModuleType("app.investigate.orchestrator")
_inv_orch.run_conversation_turn = MagicMock()  # type: ignore[attr-defined]
sys.modules["app.investigate.orchestrator"] = _inv_orch

_inv_sp = types.ModuleType("app.investigate.system_prompt")
_inv_sp.build_system_prompt = MagicMock()  # type: ignore[attr-defined]
sys.modules["app.investigate.system_prompt"] = _inv_sp

_inv_models_pkg = types.ModuleType("app.models")
sys.modules.setdefault("app.models", _inv_models_pkg)

_inv_models = types.ModuleType("app.models.investigation")
_inv_models.InvestigationSession = MagicMock()  # type: ignore[attr-defined]
_inv_models.InvestigationMessage = MagicMock()  # type: ignore[attr-defined]
_inv_models.InvestigationPin = MagicMock()  # type: ignore[attr-defined]
sys.modules["app.models.investigation"] = _inv_models

# Stub the relative imports in investigate.py by inserting the stubs
# under the dotted names the router uses after Python resolves relative imports.
# The router lives at app.routers.investigate — its relative imports translate to:
#   ..auth        → app.auth          (already stubbed)
#   ..audit       → app.audit         (already stubbed)
#   ..config      → app.config        (already stubbed)
#   ..database    → app.database      (already stubbed)
#   ..investigate.orchestrator  → app.investigate.orchestrator (stubbed)
#   ..investigate.system_prompt → app.investigate.system_prompt (stubbed)
#   ..models.investigation      → app.models.investigation (stubbed)

_routers_pkg = types.ModuleType("app.routers")
sys.modules.setdefault("app.routers", _routers_pkg)

# ---------------------------------------------------------------------------
# Load the router module by exec'ing the source with relative imports rewritten
# ---------------------------------------------------------------------------

_ROUTER_SRC = (
    Path(__file__).resolve().parent.parent / "app" / "routers" / "investigate.py"
)
_source = _ROUTER_SRC.read_text(encoding="utf-8")

# Replace relative imports with absolute equivalents matching our stubs
_source_patched = (
    _source
    .replace("from ..auth import", "from app.auth import")
    .replace("from ..audit import", "from app.audit import")
    .replace("from ..config import", "from app.config import")
    .replace("from ..database import", "from app.database import")
    .replace("from ..investigate.orchestrator import", "from app.investigate.orchestrator import")
    .replace("from ..investigate.system_prompt import", "from app.investigate.system_prompt import")
    .replace("from ..models.investigation import", "from app.models.investigation import")
)

_ns: dict = {}
exec(_source_patched, _ns)  # noqa: S102

# Pull out the symbols under test
VALID_MODELS = _ns["VALID_MODELS"]
_validate_pin_body = _ns["_validate_pin_body"]
_build_report_markdown = _ns["_build_report_markdown"]
_get_owned_session = _ns["_get_owned_session"]


# ---------------------------------------------------------------------------
# VALID_MODELS
# ---------------------------------------------------------------------------


def test_valid_models_contains_expected():
    """VALID_MODELS must contain the three supported Claude model IDs."""
    assert "claude-sonnet-4-6" in VALID_MODELS
    assert "claude-opus-4-6" in VALID_MODELS
    assert "claude-haiku-4-5" in VALID_MODELS


def test_valid_models_count():
    assert len(VALID_MODELS) == 3, f"Expected 3 models, got {VALID_MODELS}"


def test_valid_models_are_strings():
    for m in VALID_MODELS:
        assert isinstance(m, str)


# ---------------------------------------------------------------------------
# _validate_pin_body
# ---------------------------------------------------------------------------


def test_validate_pin_body_missing_value():
    err = _validate_pin_body({})
    assert err is not None
    assert "value" in err


def test_validate_pin_body_note_missing_value():
    err = _validate_pin_body({"type": "note"})
    assert err is not None
    assert "value" in err


def test_validate_pin_body_note_with_value_passes():
    err = _validate_pin_body({"type": "note", "value": "Interesting RC4 key"})
    assert err is None


def test_validate_pin_body_valid_ioc():
    err = _validate_pin_body({"type": "ioc", "value": "1.2.3.4", "ioc_type": "ipv4-addr"})
    assert err is None


def test_validate_pin_body_valid_technique():
    err = _validate_pin_body({"type": "technique", "value": "T1055.003"})
    assert err is None


def test_validate_pin_body_valid_note():
    err = _validate_pin_body({"type": "note", "value": "Interesting RC4 key"})
    assert err is None


def test_validate_pin_body_invalid_type():
    err = _validate_pin_body({"type": "badtype", "value": "x"})
    assert err is not None
    assert "badtype" in err


def test_validate_pin_body_missing_type():
    err = _validate_pin_body({"value": "x"})
    assert err is not None


def test_validate_pin_body_ioc_missing_ioc_type():
    err = _validate_pin_body({"type": "ioc", "value": "evil.com"})
    assert err is not None
    assert "ioc_type" in err


def test_validate_pin_body_ioc_empty_ioc_type():
    err = _validate_pin_body({"type": "ioc", "value": "evil.com", "ioc_type": ""})
    assert err is not None
    assert "ioc_type" in err


def test_validate_pin_body_ioc_with_ioc_type_ok():
    err = _validate_pin_body({"type": "ioc", "value": "evil.com", "ioc_type": "domain-name"})
    assert err is None


# ---------------------------------------------------------------------------
# _build_report_markdown — header
# ---------------------------------------------------------------------------


_SAMPLE_SESSION = {
    "id": 42,
    "analysis_id": 7,
    "model": "claude-sonnet-4-6",
    "total_cost_usd": 0.1234,
    "created_at": "2026-06-10T12:00:00+00:00",
}


def test_report_header_contains_session_id():
    md = _build_report_markdown(_SAMPLE_SESSION, [], [])
    assert "42" in md


def test_report_header_contains_analysis_id():
    md = _build_report_markdown(_SAMPLE_SESSION, [], [])
    assert "7" in md


def test_report_header_contains_model():
    md = _build_report_markdown(_SAMPLE_SESSION, [], [])
    assert "claude-sonnet-4-6" in md


def test_report_header_contains_cost():
    md = _build_report_markdown(_SAMPLE_SESSION, [], [])
    # 4 decimal places
    assert "0.1234" in md


def test_report_header_contains_date():
    md = _build_report_markdown(_SAMPLE_SESSION, [], [])
    assert "2026-06-10" in md


# ---------------------------------------------------------------------------
# _build_report_markdown — findings
# ---------------------------------------------------------------------------


def test_report_findings_ioc_rendered():
    pins = [
        {
            "id": 1,
            "pin_type": "ioc",
            "value": "192.0.2.1",
            "ioc_type": "ipv4-addr",
            "context": "C2 beacon",
            "promoted": False,
            "created_at": "2026-06-10T12:00:00+00:00",
        }
    ]
    md = _build_report_markdown(_SAMPLE_SESSION, [], pins)
    assert "192.0.2.1" in md
    assert "ipv4-addr" in md
    assert "C2 beacon" in md


def test_report_findings_promoted_suffix():
    pins = [
        {
            "id": 2,
            "pin_type": "note",
            "value": "RC4 key from mutex",
            "ioc_type": None,
            "context": "",
            "promoted": True,
            "created_at": "2026-06-10T12:00:00+00:00",
        }
    ]
    md = _build_report_markdown(_SAMPLE_SESSION, [], pins)
    assert "promoted to analysis" in md


def test_report_findings_not_promoted_no_suffix():
    pins = [
        {
            "id": 3,
            "pin_type": "note",
            "value": "Some note",
            "ioc_type": None,
            "context": "",
            "promoted": False,
            "created_at": "2026-06-10T12:00:00+00:00",
        }
    ]
    md = _build_report_markdown(_SAMPLE_SESSION, [], pins)
    assert "promoted to analysis" not in md


def test_report_findings_no_pins_placeholder():
    md = _build_report_markdown(_SAMPLE_SESSION, [], [])
    assert "no findings pinned" in md.lower()


# ---------------------------------------------------------------------------
# _build_report_markdown — transcript role mapping
# ---------------------------------------------------------------------------


_MSGS_ROLES = [
    {"id": 1, "role": "user", "content": "What is the C2?", "tool_name": None, "created_at": "2026-06-10T12:00:00"},
    {"id": 2, "role": "assistant", "content": "The C2 is 192.0.2.1.", "tool_name": None, "created_at": "2026-06-10T12:01:00"},
    {"id": 3, "role": "tool_call", "content": json.dumps({"tool": "search_iocs", "args": {"q": "192.0.2.1"}}), "tool_name": "search_iocs", "created_at": "2026-06-10T12:01:30"},
    {"id": 4, "role": "tool_result", "content": json.dumps({"tool": "search_iocs", "result": {"matches": []}}), "tool_name": "search_iocs", "created_at": "2026-06-10T12:01:31"},
]


def test_report_user_message_heading():
    md = _build_report_markdown(_SAMPLE_SESSION, _MSGS_ROLES, [])
    assert "### Analyst" in md


def test_report_assistant_message_heading():
    md = _build_report_markdown(_SAMPLE_SESSION, _MSGS_ROLES, [])
    assert "### Agent" in md


def test_report_user_content_present():
    md = _build_report_markdown(_SAMPLE_SESSION, _MSGS_ROLES, [])
    assert "What is the C2?" in md


def test_report_assistant_content_present():
    md = _build_report_markdown(_SAMPLE_SESSION, _MSGS_ROLES, [])
    assert "The C2 is 192.0.2.1" in md


def test_report_tool_call_rendered():
    md = _build_report_markdown(_SAMPLE_SESSION, _MSGS_ROLES, [])
    assert "search_iocs" in md
    assert "**Tool:**" in md


def test_report_tool_result_rendered():
    md = _build_report_markdown(_SAMPLE_SESSION, _MSGS_ROLES, [])
    assert "**Result:**" in md


# ---------------------------------------------------------------------------
# _build_report_markdown — tool_result truncation at 2000 chars
# ---------------------------------------------------------------------------


def test_report_tool_result_truncated():
    big_result = "x" * 3000
    msgs = [
        {
            "id": 10,
            "role": "tool_result",
            "content": json.dumps({"tool": "run_python", "result": {"output": big_result}}),
            "tool_name": "run_python",
            "created_at": "2026-06-10T12:00:00",
        }
    ]
    md = _build_report_markdown(_SAMPLE_SESSION, msgs, [])
    assert "truncated" in md
    # The raw 3000-char blob should NOT appear verbatim
    assert big_result not in md


def test_report_tool_result_not_truncated_under_limit():
    small_result = "y" * 100
    msgs = [
        {
            "id": 11,
            "role": "tool_result",
            "content": json.dumps({"result": small_result}),
            "tool_name": "get_iocs",
            "created_at": "2026-06-10T12:00:00",
        }
    ]
    md = _build_report_markdown(_SAMPLE_SESSION, msgs, [])
    assert "truncated" not in md


def test_report_tool_result_truncation_boundary():
    """Content rendered to exactly 2000 chars should NOT be truncated.

    The router calls json.dumps(data, indent=2, default=str), so we need to
    account for the extra whitespace added by indent=2.
    json.dumps({"v": "x"*1987}, indent=2) produces exactly 2000 chars.
    """
    n = 1987
    msgs = [
        {
            "id": 12,
            "role": "tool_result",
            "content": json.dumps({"v": "x" * n}),
            "tool_name": "t",
            "created_at": "2026-06-10T12:00:00",
        }
    ]
    md = _build_report_markdown(_SAMPLE_SESSION, msgs, [])
    assert "truncated" not in md


def test_report_tool_result_truncation_one_over():
    """Content rendered to 2001 chars should be truncated.

    json.dumps({"v": "x"*1988}, indent=2) produces 2001 chars.
    """
    n = 1988
    msgs = [
        {
            "id": 13,
            "role": "tool_result",
            "content": json.dumps({"v": "x" * n}),
            "tool_name": "t",
            "created_at": "2026-06-10T12:00:00",
        }
    ]
    md = _build_report_markdown(_SAMPLE_SESSION, msgs, [])
    assert "truncated" in md


# ---------------------------------------------------------------------------
# _get_owned_session — ownership enforcement
# ---------------------------------------------------------------------------


def _make_auth(user_id: str, roles: list[str] | None = None) -> MagicMock:
    auth = MagicMock()
    auth.user_id = user_id
    auth.roles = roles or []
    return auth


def _make_session_obj(session_id: int, owner_sub: str) -> MagicMock:
    """Return a fake InvestigationSession-like object."""
    s = MagicMock()
    s.id = session_id
    s.user_sub = owner_sub
    return s


def _make_db(session_obj) -> MagicMock:
    """Return a fake DB whose .get() returns session_obj."""
    db = MagicMock()
    db.get.return_value = session_obj
    return db


def test_owned_session_owner_passes():
    """Session owner gets the session object back."""
    auth = _make_auth("user-123")
    session_obj = _make_session_obj(1, "user-123")
    db = _make_db(session_obj)

    result = _get_owned_session(1, auth, db)
    assert result is session_obj


def test_owned_session_admin_passes():
    """Admin role bypasses ownership check."""
    auth = _make_auth("admin-456", roles=["admin"])
    session_obj = _make_session_obj(1, "user-123")  # different owner
    db = _make_db(session_obj)

    result = _get_owned_session(1, auth, db)
    assert result is session_obj


def test_owned_session_non_owner_raises_403():
    """Non-owner without admin role gets 403."""
    auth = _make_auth("other-user")
    session_obj = _make_session_obj(1, "user-123")
    db = _make_db(session_obj)

    with pytest.raises(_HTTPException) as exc_info:
        _get_owned_session(1, auth, db)
    assert exc_info.value.status_code == 403
    assert "Not your session" in exc_info.value.detail


def test_owned_session_missing_raises_404():
    """Missing session raises 404."""
    auth = _make_auth("user-123")
    db = _make_db(None)  # db.get returns None

    with pytest.raises(_HTTPException) as exc_info:
        _get_owned_session(99, auth, db)
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# _validate_pin_body — pin value sanity checks (Change 3)
# ---------------------------------------------------------------------------


def test_validate_pin_body_value_too_long():
    """Value over 2048 chars is rejected."""
    err = _validate_pin_body({"type": "note", "value": "x" * 2049})
    assert err is not None
    assert "2048" in err


def test_validate_pin_body_value_at_limit_passes():
    """Value of exactly 2048 chars is accepted."""
    err = _validate_pin_body({"type": "note", "value": "x" * 2048})
    assert err is None


def test_validate_pin_body_control_char_rejected():
    """Null byte (control char < 0x20) is rejected."""
    err = _validate_pin_body({"type": "note", "value": "bad\x00value"})
    assert err is not None
    assert "control" in err


def test_validate_pin_body_newline_rejected():
    """Newline (\\n, ord 10 < 32) is a control char and should be rejected."""
    err = _validate_pin_body({"type": "note", "value": "line1\nline2"})
    assert err is not None
    assert "control" in err


def test_validate_pin_body_tab_allowed():
    """Tab (\\t) is explicitly permitted despite ord < 32."""
    err = _validate_pin_body({"type": "note", "value": "col1\tcol2"})
    assert err is None
