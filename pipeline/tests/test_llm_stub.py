# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The llm-stub answers every LLM stage with something that stage can use (ADR-036).

Checked against the interpret container's OWN prompts, schema and parser, loaded
from interpret-ghidra.py, so a prompt or schema change is checked without editing
this file:
  - every system prompt that lists its output keys gets a reply that the container's
    parse_final_response turns into a dict with exactly those keys;
  - the forced submit_analysis tool gets arguments the container's synthesis
    accepts (a non-empty malware_family_guess);
and end to end, a real stub server on a loopback socket driven by the anthropic SDK,
streaming and not, through the container's own streaming helper: tool use on the
first turn, text after a tool_result, a usage block on every reply.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import anthropic
import pytest

ROOT = Path(__file__).resolve().parents[2]
STUB_SRC = ROOT / "ansible/roles/llm-stub/files/llm_stub.py"
INTERPRET_SRC = ROOT / "ansible/roles/interpret/files/interpret-ghidra.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(name, None)
    return mod


stub = _load("_llm_stub_under_test", STUB_SRC)


@pytest.fixture(scope="module")
def ig():
    return _load("_interpret_for_stub_test", INTERPRET_SRC)


def _prompts() -> dict[str, str]:
    """Every module-level *_PROMPT string in the container, as Python builds it."""
    out = {}
    for node in ast.parse(INTERPRET_SRC.read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id.endswith("_PROMPT"):
            try:
                val = ast.literal_eval(node.value)
            except ValueError:
                continue
            if isinstance(val, str):
                out[node.targets[0].id] = val
    return out


PROMPTS = _prompts()
LISTING = {k: v for k, v in PROMPTS.items() if "containing:" in v or "must contain:" in v}


def test_the_container_has_prompts_that_list_their_keys():
    assert "SUMMARY_SYSTEM_PROMPT" in LISTING and "SYSTEM_PROMPT" in LISTING
    assert len(LISTING) >= 8, sorted(LISTING)


@pytest.mark.parametrize("name", sorted(LISTING))
def test_every_listed_key_comes_back_through_the_containers_parser(ig, name):
    body = {"model": "stub", "system": LISTING[name], "messages": [{"role": "user", "content": "x"}]}
    text = stub.answer(body)["content"][0]["text"]
    parsed = ig.parse_final_response(text)
    wanted = stub.keys_from_prompt(LISTING[name])
    assert wanted and set(wanted) <= set(parsed), (name, set(wanted) - set(parsed))
    for k, v in parsed.items():
        assert v not in ("", None), (name, k)


def test_the_summary_reply_has_a_non_empty_executive_summary(ig):
    body = {"model": "stub", "system": [{"type": "text", "text": PROMPTS["SUMMARY_SYSTEM_PROMPT"]}],
            "messages": [{"role": "user", "content": "x"}]}
    parsed = ig.parse_final_response(stub.answer(body)["content"][0]["text"])
    assert parsed["executive_summary"] and isinstance(parsed["kill_chain"], list)
    assert parsed["severity"] in ("low", "medium", "high", "critical")
    assert isinstance(parsed["mitre_techniques"][0], dict) and "id" in parsed["mitre_techniques"][0]


def test_the_forced_synthesis_tool_gets_arguments_the_container_accepts(ig):
    schema = ig.SUBMIT_ANALYSIS_SCHEMA
    args = stub.fill(schema)
    assert args.get("malware_family_guess"), "synthesis falls back without a family guess"
    assert set(schema.get("required", [])) <= set(args)


def test_a_prompt_without_a_key_list_gets_prose():
    out = stub.answer({"system": "Write a plain-English paragraph.", "messages": []})
    text = out["content"][0]["text"]
    assert text and not text.lstrip().startswith("{")


@pytest.mark.parametrize("schema, want", [
    ({"type": "string"}, "stub"),
    ({"type": "string", "enum": ["high", "low"]}, "high"),
    ({"type": ["null", "integer"], "minimum": 3}, 3),
    ({"anyOf": [{"type": "null"}, {"type": "boolean"}]}, False),
    ({"type": "array", "items": {"type": "string"}, "minItems": 2}, ["stub", "stub"]),
    ({"$defs": {"x": {"type": "number"}}, "type": "object", "properties": {"a": {"$ref": "#/$defs/x"}}}, {"a": 0.0}),
    ({"type": "string", "minLength": 9}, "stubstubs"),
])
def test_fill_satisfies_common_schema_shapes(schema, want):
    assert stub.fill(schema) == want


# --- end to end: the stub server and the anthropic SDK ---------------------------------

@pytest.fixture(scope="module")
def client():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), stub.StubHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield anthropic.Anthropic(base_url=f"http://127.0.0.1:{srv.server_address[1]}", api_key="sk-stub")
    srv.shutdown()


TOOLS = [{"name": "decompile_function", "description": "x",
          "input_schema": {"type": "object", "properties": {"name": {"type": "string"}},
                           "required": ["name"]}},
         {"name": "submit_analysis", "description": "x",
          "input_schema": {"type": "object", "properties": {"malware_family_guess": {"type": "string"}},
                           "required": ["malware_family_guess"]}}]


def test_streaming_first_turn_with_tools_calls_a_tool_through_the_containers_helper(client, ig):
    msg = ig.create_message(client, model="stub", max_tokens=100, system=PROMPTS["SYSTEM_PROMPT"],
                            tools=TOOLS, messages=[{"role": "user", "content": "analyse"}])
    assert msg.stop_reason == "tool_use"
    block = msg.content[0]
    assert block.type == "tool_use" and block.name == "decompile_function" and block.input == {"name": "stub"}
    assert msg.usage.input_tokens > 0 and msg.usage.output_tokens > 0


def test_after_a_tool_result_the_stub_answers_in_text(client, ig):
    first = client.messages.create(model="stub", max_tokens=100, system=PROMPTS["SYSTEM_PROMPT"],
                                   tools=TOOLS, messages=[{"role": "user", "content": "analyse"}])
    tool = first.content[0]
    msgs = [{"role": "user", "content": "analyse"},
            {"role": "assistant", "content": [tool.model_dump()]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool.id, "content": "ok"}]}]
    with client.messages.stream(model="stub", max_tokens=100, system=PROMPTS["SYSTEM_PROMPT"],
                                tools=TOOLS, messages=msgs) as s:
        final = s.get_final_message()
    assert final.stop_reason == "end_turn"
    assert ig.parse_final_response(final.content[0].text).get("malware_family_guess")


def test_a_forced_tool_choice_is_honoured(client):
    msg = client.messages.create(model="stub", max_tokens=100, tools=TOOLS,
                                 tool_choice={"type": "tool", "name": "submit_analysis"},
                                 messages=[{"role": "user", "content": "x"},
                                           {"role": "assistant", "content": "done"},
                                           {"role": "user", "content": [{"type": "tool_result",
                                                                         "tool_use_id": "t", "content": "x"}]}])
    assert msg.content[0].name == "submit_analysis" and msg.content[0].input["malware_family_guess"]


def test_count_tokens_and_unknown_paths(client):
    assert client.messages.count_tokens(model="stub", messages=[{"role": "user", "content": "hi"}]).input_tokens > 0
    with pytest.raises(anthropic.NotFoundError):
        client.post("/v1/chat/completions", body={}, cast_to=object)


def test_the_stub_refuses_a_non_loopback_address():
    assert stub.main(["--host", "0.0.0.0", "--port", "0"]) == 2


def test_replies_are_deterministic():
    body = {"model": "stub", "system": PROMPTS["SUMMARY_SYSTEM_PROMPT"], "messages": [{"role": "user", "content": "x"}]}
    assert json.dumps(stub.answer(body)) == json.dumps(stub.answer(body))
