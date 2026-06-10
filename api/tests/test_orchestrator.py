# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0

"""Tests for the investigation agent LLM orchestrator.

Loading strategy: stub out all heavy imports (sqlalchemy, sqlmodel, httpx,
app.config, app.investigate.tools) via sys.modules before exec'ing
orchestrator.py, following the same pattern as test_investigate_tools.py.

Tests focus on the pure-Python parts:
  - parse_stream_line
  - ToolCallAccumulator
  - MODEL_COSTS / cost math
  - _build_openai_tools (input_schema → parameters conversion)

An optional async-generator integration test with a fake httpx stream is
included but kept simple. The deployed router integration covers the full path.
"""

import asyncio
import json
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

# ---------------------------------------------------------------------------
# Stub external dependencies before loading orchestrator.py
# ---------------------------------------------------------------------------

# sqlalchemy stub — include text() mock so other test files that load after
# this one (and get the already-installed stub via setdefault) don't fail
_sa = types.ModuleType("sqlalchemy")
_sa.text = MagicMock()  # type: ignore[attr-defined]
sys.modules.setdefault("sqlalchemy", _sa)

# sqlmodel stub
_sm = types.ModuleType("sqlmodel")
_sm.Session = MagicMock()  # type: ignore[attr-defined]
sys.modules.setdefault("sqlmodel", _sm)

# app.config stub
_cfg_pkg = types.ModuleType("app")
_cfg_mod = types.ModuleType("app.config")

_settings = MagicMock()
_settings.litellm_url = "http://127.0.0.1:4000"
_settings.litellm_key = "sk-test"
_settings.investigation_max_tool_calls_per_turn = 10
_cfg_mod.settings = _settings  # type: ignore[attr-defined]
sys.modules.setdefault("app", _cfg_pkg)
sys.modules.setdefault("app.config", _cfg_mod)

# app.investigate.tools stub — provide TOOL_DEFINITIONS and execute_tool
_inv_pkg = types.ModuleType("app.investigate")
_tools_mod = types.ModuleType("app.investigate.tools")

_STUB_TOOL_DEFINITIONS = [
    {
        "name": "search_iocs",
        "description": "Search for an IOC",
        "input_schema": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
        },
    },
    {
        "name": "pin_finding",
        "description": "Propose a finding",
        "input_schema": {
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "value": {"type": "string"},
                "context": {"type": "string"},
            },
            "required": ["type", "value", "context"],
        },
    },
]
_tools_mod.TOOL_DEFINITIONS = _STUB_TOOL_DEFINITIONS  # type: ignore[attr-defined]

_mock_execute_tool = MagicMock(return_value={"result": "ok"})
_tools_mod.execute_tool = _mock_execute_tool  # type: ignore[attr-defined]

sys.modules.setdefault("app.investigate", _inv_pkg)
sys.modules.setdefault("app.investigate.tools", _tools_mod)

# httpx stub — provide AsyncClient with a usable context manager
_httpx_mod = types.ModuleType("httpx")
_httpx_mod.AsyncClient = MagicMock()  # type: ignore[attr-defined]
_httpx_mod.HTTPStatusError = type("HTTPStatusError", (Exception,), {})  # type: ignore[attr-defined]
_httpx_mod.RequestError = type("RequestError", (Exception,), {})  # type: ignore[attr-defined]
sys.modules.setdefault("httpx", _httpx_mod)

# ---------------------------------------------------------------------------
# Load orchestrator.py via exec, replacing relative imports
# ---------------------------------------------------------------------------

_ORCH_SRC = (
    Path(__file__).resolve().parent.parent / "app" / "investigate" / "orchestrator.py"
)
_source = _ORCH_SRC.read_text(encoding="utf-8")

_source_patched = (
    _source
    .replace("from ..config import settings", "from app.config import settings")
    .replace(
        "from .tools import TOOL_DEFINITIONS, execute_tool",
        "from app.investigate.tools import TOOL_DEFINITIONS, execute_tool",
    )
)

_ns: dict = {}
exec(_source_patched, _ns)  # noqa: S102

# Pull out the symbols under test
parse_stream_line = _ns["parse_stream_line"]
ToolCallAccumulator = _ns["ToolCallAccumulator"]
MODEL_COSTS = _ns["MODEL_COSTS"]
_build_openai_tools = _ns["_build_openai_tools"]
run_conversation_turn = _ns["run_conversation_turn"]


# ---------------------------------------------------------------------------
# parse_stream_line tests
# ---------------------------------------------------------------------------


def test_parse_stream_line_valid():
    chunk = {"choices": [{"delta": {"content": "hello"}}]}
    line = f"data: {json.dumps(chunk)}"
    result = parse_stream_line(line)
    assert result == chunk


def test_parse_stream_line_done_sentinel():
    assert parse_stream_line("data: [DONE]") is None


def test_parse_stream_line_non_data_line():
    assert parse_stream_line("event: ping") is None
    assert parse_stream_line("") is None
    assert parse_stream_line(": keep-alive") is None


def test_parse_stream_line_malformed_json():
    # Should return None and log a warning, not raise
    result = parse_stream_line("data: {not valid json")
    assert result is None


def test_parse_stream_line_empty_data_prefix():
    # Edge case: "data: " with just whitespace after
    result = parse_stream_line("data:    ")
    # Not [DONE], but also not valid JSON — returns None
    assert result is None


# ---------------------------------------------------------------------------
# ToolCallAccumulator tests
# ---------------------------------------------------------------------------


def test_accumulator_single_call():
    acc = ToolCallAccumulator()
    acc.add_delta([{
        "index": 0,
        "id": "call_abc",
        "function": {"name": "search_iocs", "arguments": '{"value": "1.2.3.4"}'},
    }])
    blocks = acc.blocks()
    assert len(blocks) == 1
    assert blocks[0]["id"] == "call_abc"
    assert blocks[0]["name"] == "search_iocs"
    assert blocks[0]["arguments"] == '{"value": "1.2.3.4"}'


def test_accumulator_arguments_split_across_deltas():
    """Arguments streamed in multiple chunks must be concatenated."""
    acc = ToolCallAccumulator()
    # First chunk: name + start of args
    acc.add_delta([{
        "index": 0,
        "id": "call_xyz",
        "function": {"name": "pin_finding", "arguments": '{"type":'},
    }])
    # Second chunk: middle of args
    acc.add_delta([{
        "index": 0,
        "function": {"arguments": ' "ioc", "value":'},
    }])
    # Third chunk: end of args
    acc.add_delta([{
        "index": 0,
        "function": {"arguments": ' "1.2.3.4", "context": "C2"}'},
    }])

    blocks = acc.blocks()
    assert len(blocks) == 1
    parsed = json.loads(blocks[0]["arguments"])
    assert parsed["type"] == "ioc"
    assert parsed["value"] == "1.2.3.4"
    assert "context" in parsed


def test_accumulator_two_interleaved_calls():
    """Two parallel tool calls with interleaved deltas, keyed by index."""
    acc = ToolCallAccumulator()

    # Call 0 starts
    acc.add_delta([{"index": 0, "id": "call_0", "function": {"name": "search_iocs", "arguments": ""}}])
    # Call 1 starts
    acc.add_delta([{"index": 1, "id": "call_1", "function": {"name": "pin_finding", "arguments": ""}}])
    # Call 0 gets its args
    acc.add_delta([{"index": 0, "function": {"arguments": '{"value":"evil.com"}'}}])
    # Call 1 gets its args
    acc.add_delta([{"index": 1, "function": {"arguments": '{"type":"note","value":"x","context":"y"}'}}])

    blocks = acc.blocks()
    assert len(blocks) == 2
    assert blocks[0]["name"] == "search_iocs"
    assert blocks[1]["name"] == "pin_finding"
    args0 = json.loads(blocks[0]["arguments"])
    assert args0["value"] == "evil.com"


def test_accumulator_missing_id_fallback():
    """If id is absent from all deltas, the block id should be empty string."""
    acc = ToolCallAccumulator()
    acc.add_delta([{"index": 0, "function": {"name": "list_functions", "arguments": "{}"}}])
    blocks = acc.blocks()
    assert blocks[0]["id"] == ""


def test_accumulator_bool_false_when_empty():
    acc = ToolCallAccumulator()
    assert not acc


def test_accumulator_bool_true_when_populated():
    acc = ToolCallAccumulator()
    acc.add_delta([{"index": 0, "id": "x", "function": {"name": "search_iocs", "arguments": ""}}])
    assert acc


def test_accumulator_multiple_fragments_many_chunks():
    """10 argument fragments across 10 deltas must concatenate correctly."""
    acc = ToolCallAccumulator()
    # Start with name
    acc.add_delta([{"index": 0, "id": "call_many", "function": {"name": "search_iocs", "arguments": ""}}])
    fragments = ['{"val', 'ue"', ': "1', '.2.', '3.', '4"', ', "ty', 'pe"', ': "ip"}', ""]
    for frag in fragments:
        acc.add_delta([{"index": 0, "function": {"arguments": frag}}])
    blocks = acc.blocks()
    parsed = json.loads(blocks[0]["arguments"])
    assert parsed["value"] == "1.2.3.4"
    assert parsed["type"] == "ip"


# ---------------------------------------------------------------------------
# MODEL_COSTS and cost math tests
# ---------------------------------------------------------------------------


def test_model_costs_keys_present():
    assert "claude-sonnet-4-6" in MODEL_COSTS
    assert "claude-opus-4-6" in MODEL_COSTS
    assert "claude-haiku-4-5" in MODEL_COSTS


def test_model_costs_shape():
    for model, costs in MODEL_COSTS.items():
        assert "input" in costs, f"{model} missing 'input' cost"
        assert "output" in costs, f"{model} missing 'output' cost"
        assert costs["input"] > 0
        assert costs["output"] > 0


def test_cost_math_sonnet():
    """1000 input + 500 output tokens at Sonnet pricing."""
    costs = MODEL_COSTS["claude-sonnet-4-6"]
    expected = round(1000 * costs["input"] + 500 * costs["output"], 6)
    # 1000 * 3e-6 + 500 * 15e-6 = 0.003 + 0.0075 = 0.0105
    assert expected == round(0.0105, 6)


def test_cost_math_haiku_zero_tokens():
    costs = MODEL_COSTS["claude-haiku-4-5"]
    cost = round(0 * costs["input"] + 0 * costs["output"], 6)
    assert cost == 0.0


def test_cost_math_opus():
    costs = MODEL_COSTS["claude-opus-4-6"]
    # 2000 input + 1000 output
    cost = round(2000 * costs["input"] + 1000 * costs["output"], 6)
    # 2000 * 5e-6 + 1000 * 25e-6 = 0.01 + 0.025 = 0.035
    assert cost == round(0.035, 6)


# ---------------------------------------------------------------------------
# OpenAI tool format conversion tests
# ---------------------------------------------------------------------------


def test_build_openai_tools_shape():
    tools = _build_openai_tools()
    assert len(tools) == len(_STUB_TOOL_DEFINITIONS)
    for t in tools:
        assert t["type"] == "function"
        fn = t["function"]
        assert "name" in fn
        assert "description" in fn
        assert "parameters" in fn
        # Must NOT use input_schema key
        assert "input_schema" not in fn


def test_build_openai_tools_parameters_content():
    """parameters should be the same object as input_schema from TOOL_DEFINITIONS."""
    tools = _build_openai_tools()
    for i, openai_tool in enumerate(tools):
        original = _STUB_TOOL_DEFINITIONS[i]
        assert openai_tool["function"]["parameters"] == original["input_schema"]
        assert openai_tool["function"]["name"] == original["name"]
        assert openai_tool["function"]["description"] == original["description"]


def test_build_openai_tools_required_field_preserved():
    """The 'required' field inside input_schema must survive the conversion."""
    tools = _build_openai_tools()
    search_tool = next(t for t in tools if t["function"]["name"] == "search_iocs")
    assert "required" in search_tool["function"]["parameters"]
    assert "value" in search_tool["function"]["parameters"]["required"]


# ---------------------------------------------------------------------------
# Async-generator integration test with fake httpx
# ---------------------------------------------------------------------------


def _make_sse_lines(chunks: list[dict]) -> list[str]:
    """Convert a list of chunk dicts into SSE data lines."""
    lines = []
    for chunk in chunks:
        lines.append(f"data: {json.dumps(chunk)}")
    lines.append("data: [DONE]")
    return lines


async def _collect(gen) -> list[dict]:
    events = []
    async for event in gen:
        events.append(event)
    return events


def test_async_generator_simple_text_response():
    """Fake a single-chunk text response and verify token + done events."""
    # Build SSE lines for a simple text response
    chunks = [
        {"choices": [{"delta": {"content": "Hello, analyst!"}}], "usage": None},
        {"choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 20}},
    ]
    sse_lines = _make_sse_lines(chunks)

    # Build a fake httpx AsyncClient
    class FakeResponse:
        status_code = 200

        async def aiter_lines(self):
            for line in sse_lines:
                yield line

        def raise_for_status(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class FakeClient:
        def __init__(self, **kwargs):
            pass  # accept timeout= and other constructor kwargs

        def stream(self, method, url, **kwargs):
            return FakeResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    # Patch httpx.AsyncClient in the orchestrator's namespace
    _ns["httpx"].AsyncClient = FakeClient

    # Reset execute_tool mock
    _mock_execute_tool.reset_mock()

    events = asyncio.run(_collect(run_conversation_turn(
        messages=[{"role": "user", "content": "What is the C2 IP?"}],
        system_prompt="You are a malware analyst.",
        model="claude-sonnet-4-6",
        session=MagicMock(),
        report={},
        analysis_id=1,
    )))

    # Should have: one token event + one done event
    event_types = [e["event"] for e in events]
    assert "token" in event_types
    assert "done" in event_types

    token_events = [e for e in events if e["event"] == "token"]
    assert token_events[0]["data"]["content"] == "Hello, analyst!"

    done_event = next(e for e in events if e["event"] == "done")
    assert done_event["data"]["input_tokens"] == 100
    assert done_event["data"]["output_tokens"] == 20
    assert done_event["data"]["tool_calls_used"] == 0
    # Cost for sonnet: 100 * 3e-6 + 20 * 15e-6 = 0.0003 + 0.0003 = 0.0006
    assert done_event["data"]["cost"] == round(0.0006, 6)


def test_async_generator_tool_call_and_result():
    """Fake a tool-call response followed by a text response."""
    tool_args = json.dumps({"value": "192.0.2.1"})

    # Turn 1: model calls search_iocs
    turn1_chunks = [
        {
            "choices": [{
                "delta": {
                    "content": None,
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call_999",
                            "function": {"name": "search_iocs", "arguments": tool_args},
                        }
                    ],
                }
            }],
        },
        {"choices": [], "usage": {"prompt_tokens": 50, "completion_tokens": 10}},
    ]

    # Turn 2: model gives a final text answer
    turn2_chunks = [
        {"choices": [{"delta": {"content": "Found 1 match."}}]},
        {"choices": [], "usage": {"prompt_tokens": 60, "completion_tokens": 5}},
    ]

    call_count = 0

    class FakeResponse:
        def __init__(self, lines):
            self._lines = lines

        async def aiter_lines(self):
            for line in self._lines:
                yield line

        def raise_for_status(self):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    class FakeClient:
        def __init__(self, **kwargs):
            pass  # accept timeout= and other constructor kwargs

        def stream(self, method, url, **kwargs):
            nonlocal call_count
            if call_count == 0:
                call_count += 1
                return FakeResponse(_make_sse_lines(turn1_chunks))
            else:
                return FakeResponse(_make_sse_lines(turn2_chunks))

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    _ns["httpx"].AsyncClient = FakeClient
    _mock_execute_tool.reset_mock()
    _mock_execute_tool.return_value = {"matches": [], "count": 0}

    msgs = [{"role": "user", "content": "Is 192.0.2.1 in our DB?"}]
    events = asyncio.run(_collect(run_conversation_turn(
        messages=msgs,
        system_prompt="You are a malware analyst.",
        model="claude-sonnet-4-6",
        session=MagicMock(),
        report={},
        analysis_id=1,
    )))

    event_types = [e["event"] for e in events]
    assert "tool_call" in event_types
    assert "tool_result" in event_types
    assert "token" in event_types
    assert "done" in event_types

    tool_call_event = next(e for e in events if e["event"] == "tool_call")
    assert tool_call_event["data"]["tool"] == "search_iocs"
    assert tool_call_event["data"]["args"] == {"value": "192.0.2.1"}

    tool_result_event = next(e for e in events if e["event"] == "tool_result")
    assert tool_result_event["data"]["tool"] == "search_iocs"

    done = next(e for e in events if e["event"] == "done")
    assert done["data"]["tool_calls_used"] == 1
    # Total tokens: 50+60 input, 10+5 output
    assert done["data"]["input_tokens"] == 110
    assert done["data"]["output_tokens"] == 15

    # messages should have been mutated: user + assistant(tool_calls) + tool_result + assistant(text)
    assert len(msgs) == 4
    assert msgs[1]["role"] == "assistant"
    assert msgs[1]["tool_calls"][0]["id"] == "call_999"
    assert msgs[2]["role"] == "tool"
    assert msgs[3]["role"] == "assistant"
    assert msgs[3]["content"] == "Found 1 match."
