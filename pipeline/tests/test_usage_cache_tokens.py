# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Prompt-cache tokens must be recorded and priced, not dropped (#718).

Anthropic reports `cache_creation_input_tokens` and `cache_read_input_tokens`
SEPARATELY from `input_tokens` — they are not a share of it. Every system prompt
in interpret-ghidra.py carries `cache_control: ephemeral`, but every usage
extraction kept only input/output, so a cloud run where caching engaged emitted
a `usage` with no trace of its cache writes (billed at 1.25x input) or reads
(0.1x), and db_ingest, the eval scorecard and the feeder budget priced none.

These tests drive the real code: the container's extractors and its `main()`
loop against a stub client whose responses carry cache counts, and the three
pricers against usage dicts that carry them. A source-text check could not tell
"the key is mentioned" from "the key reaches the emitted final".
"""
from __future__ import annotations

import ast
import importlib.util
import io
import json
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("anthropic", reason="pip install './pipeline[test]'")
import anthropic  # noqa: E402
import db_ingest  # noqa: E402
from lamware_eval import rebuild, runner  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible" / "roles" / "interpret" / "files" / "interpret-ghidra.py"
FEEDER_T = ROOT / "ansible" / "roles" / "auto-feeder" / "templates" / "auto-feeder.py.j2"

CACHE_KEYS = ("cache_creation_input_tokens", "cache_read_input_tokens")


@pytest.fixture
def mod():
    """The container script, imported fresh (it has module-level state)."""
    name = "_interpret_cache_usage_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    try:
        spec.loader.exec_module(m)
        yield m
    finally:
        sys.modules.pop(name, None)


def _sdk_usage(i, o, cw=None, cr=None):
    """The SDK's Usage shape: cache fields are Optional and may be None."""
    return types.SimpleNamespace(input_tokens=i, output_tokens=o,
                                 cache_creation_input_tokens=cw,
                                 cache_read_input_tokens=cr)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def test_an_anthropic_response_carries_its_cache_counts(mod):
    resp = types.SimpleNamespace(usage=_sdk_usage(120, 40, 2_000, 8_000))
    assert mod.usage_from_response(resp) == {
        "input_tokens": 120, "output_tokens": 40,
        "cache_creation_input_tokens": 2_000, "cache_read_input_tokens": 8_000}


def test_a_response_without_cache_fields_reads_them_as_zero(mod):
    """The local /v1/messages route omits them; the SDK may set them None."""
    absent = types.SimpleNamespace(
        usage=types.SimpleNamespace(input_tokens=7, output_tokens=3))
    none = types.SimpleNamespace(usage=_sdk_usage(7, 3))
    for resp in (absent, none):
        u = mod.usage_from_response(resp)
        assert u == {"input_tokens": 7, "output_tokens": 3,
                     "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}


def test_a_dict_shaped_usage_carries_its_cache_counts(mod):
    """A response whose usage arrived as a plain dict, not an SDK object."""
    resp = types.SimpleNamespace(usage={"input_tokens": 5, "output_tokens": 2,
                                        "cache_creation_input_tokens": 70,
                                        "cache_read_input_tokens": 600})
    assert mod.usage_from_response(resp) == {
        "input_tokens": 5, "output_tokens": 2,
        "cache_creation_input_tokens": 70, "cache_read_input_tokens": 600}


def test_the_openai_leg_reports_zero_cache_in_the_same_shape(mod):
    u = mod.openai_usage({"prompt_tokens": 1448, "completion_tokens": 584})
    assert u == {"input_tokens": 1448, "output_tokens": 584,
                 "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}


def test_request_result_trail_event_carries_cache_counts(mod, monkeypatch):
    emitted: list[dict] = []
    monkeypatch.setattr(mod, "emit", emitted.append)
    resp = types.SimpleNamespace(usage=_sdk_usage(10, 5, 300, 900),
                                 stop_reason="end_turn")
    mod.log_request_result("synth_2a", resp, 1.0)
    assert emitted[0]["usage"]["cache_creation_input_tokens"] == 300
    assert emitted[0]["usage"]["cache_read_input_tokens"] == 900


class _HttpResp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _Http:
    def __init__(self, body):
        self._body = body

    def post(self, *a, **kw):
        return _HttpResp(self._body)


def test_single_shot_local_leg_yields_zero_cache(mod, monkeypatch):
    monkeypatch.setattr(mod, "emit", lambda *_: None)
    body = {"choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 9}}
    text, usage = mod.single_shot_completion(
        True, None, _Http(body), "http://x", "k", "local-qwen", "sys", "hi", 64, "t")
    assert text == "ok"
    assert usage == {"input_tokens": 50, "output_tokens": 9,
                     "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}


def test_single_shot_cloud_leg_carries_cache(mod):
    """Seven single-shot stages (dotnet, java, office, ...) ride this path."""
    msg = types.SimpleNamespace(
        content=[types.SimpleNamespace(type="text", text="done")],
        usage=_sdk_usage(30, 12, 4_000, 0))
    client = types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **kw: msg))
    _, usage = mod.single_shot_completion(
        False, client, None, "", "", "claude-x", "sys", "hi", 64, "t")
    assert usage["cache_creation_input_tokens"] == 4_000
    assert usage["cache_read_input_tokens"] == 0


# ---------------------------------------------------------------------------
# The agentic loop: accumulation and every emitted final
# ---------------------------------------------------------------------------

FINAL_JSON = json.dumps({"malware_family_guess": "formbook", "capabilities": ["x"]})

# Per-call usage, in call order. A cache WRITE on the first request, READS after —
# the shape a cached system prompt produces across a loop.
PER_CALL = [(10, 5, 2_000, 0), (11, 6, 0, 2_000), (12, 7, 0, 2_000), (13, 8, 0, 2_000)]


class _Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Message:
    def __init__(self, content, stop_reason, usage):
        self.content = content
        self.stop_reason = stop_reason
        self.model = "stub-model"
        self.usage = usage


class _Stream:
    def __init__(self, message):
        self._message = message

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(())

    def get_final_message(self):
        return self._message


class _APIDown(anthropic.APIError):
    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class _Model:
    """Scripted Messages API. `script` is a list of 'tool' | 'text' | 'bad' | 'fail'
    per stream() call; create() answers a forced submit_analysis."""

    def __init__(self, script):
        self._script = list(script)
        self.calls = 0

    def _usage(self):
        i, o, cw, cr = PER_CALL[self.calls]
        self.calls += 1
        return _sdk_usage(i, o, cw, cr)

    def stream(self, **kwargs):
        step = self._script.pop(0)
        if step == "fail":
            raise _APIDown("overloaded")
        if step == "crash":
            raise RuntimeError("transport died mid-stream")
        usage = self._usage()
        if step == "tool":
            return _Stream(_Message([_Block(type="tool_use", id=f"tu_{self.calls}",
                                            name="decompile_function",
                                            input={"name": "f"})], "tool_use", usage))
        text = FINAL_JSON if step == "text" else "not json at all"
        return _Stream(_Message([_Block(type="text", text=text)], "end_turn", usage))

    def create(self, **kwargs):
        usage = self._usage()
        return _Message([_Block(type="tool_use", id="tu_s", name="submit_analysis",
                                input={"malware_family_guess": "formbook",
                                       "capabilities": ["x"]})], "tool_use", usage)


def _drive(mod, monkeypatch, script, orchestrator, max_tool_calls=20):
    model = _Model(script)
    monkeypatch.setattr(mod.anthropic, "Anthropic",
                        lambda **kw: types.SimpleNamespace(messages=model))
    monkeypatch.setenv("LITELLM_API_KEY", "test-key")
    init = {"type": "init",
            "ghidra_data": {"program": {"name": "sample.exe"}, "functions": [],
                            "strings": [], "imports": []},
            "config": {"re_backend": "cloud", "model": "stub-model",
                       "max_tool_calls": max_tool_calls, "max_tool_calls_per_turn": 3}}
    monkeypatch.setattr(mod.sys, "stdin", io.StringIO(
        "".join(json.dumps(m) + "\n" for m in [init, *orchestrator])))
    out = io.StringIO()
    monkeypatch.setattr(mod.sys, "stdout", out)
    with pytest.raises(SystemExit):
        mod.main()
    emitted = [json.loads(ln) for ln in out.getvalue().splitlines()
               if ln.strip().startswith("{")]
    return model, emitted


def _expected(n_calls: int) -> dict:
    i, o, cw, cr = (sum(c[k] for c in PER_CALL[:n_calls]) for k in range(4))
    return {"input_tokens": i, "output_tokens": o,
            "cache_creation_input_tokens": cw, "cache_read_input_tokens": cr}


TOOL_RESULT = {"type": "tool_result", "result": {"code": "int f(void) { return 0; }"}}


def test_the_happy_path_final_sums_cache_across_turns(mod, monkeypatch):
    model, emitted = _drive(mod, monkeypatch, ["tool", "text"], [TOOL_RESULT])
    final = emitted[-1]
    assert final["type"] == "final" and "error" not in final["analysis"]
    assert model.calls == 2
    assert final["usage"] == _expected(2)
    turns = [e for e in emitted if e["type"] == "turn"]
    assert [t["usage"]["cache_creation_input_tokens"] for t in turns] == [2_000, 0]
    assert [t["usage"]["cache_read_input_tokens"] for t in turns] == [0, 2_000]


def test_the_cloud_recovery_call_is_billed_with_its_cache(mod, monkeypatch):
    """cloud_synthesize: end_turn text fails to parse, one forced create()."""
    model, emitted = _drive(mod, monkeypatch, ["tool", "bad"], [TOOL_RESULT])
    final = emitted[-1]
    assert model.calls == 3
    assert final["analysis"]["malware_family_guess"] == "formbook"
    assert final["usage"] == _expected(3)


def test_the_forced_final_carries_cache(mod, monkeypatch):
    model, emitted = _drive(mod, monkeypatch, ["tool", "text"],
                            [{"type": "force_final", "reason": "interpret timeout"}])
    final = emitted[-1]
    assert final["type"] == "final" and "error" not in final["analysis"]
    assert model.calls == 2
    assert final["usage"] == _expected(2)


def test_the_max_calls_final_carries_cache(mod, monkeypatch):
    model, emitted = _drive(mod, monkeypatch, ["tool", "text"], [TOOL_RESULT],
                            max_tool_calls=1)
    final = emitted[-1]
    assert final["type"] == "final" and "error" not in final["analysis"]
    assert model.calls == 2
    assert final["usage"] == _expected(2)


@pytest.mark.parametrize("step", ["fail", "crash"])
def test_an_error_final_still_reports_the_cache_already_spent(mod, monkeypatch, step):
    """The loop's APIError and unhandled-exception exits."""
    _, emitted = _drive(mod, monkeypatch, ["tool", step], [TOOL_RESULT])
    final = emitted[-1]
    assert "error" in final["analysis"]
    assert final["usage"] == _expected(1)


def test_a_failed_forced_final_still_reports_the_cache_already_spent(mod, monkeypatch):
    _, emitted = _drive(mod, monkeypatch, ["tool", "fail"],
                        [{"type": "force_final", "reason": "interpret timeout"}])
    final = emitted[-1]
    assert "error" in final["analysis"]
    assert final["usage"] == _expected(1)


def test_a_failed_max_calls_final_still_reports_the_cache_already_spent(mod, monkeypatch):
    _, emitted = _drive(mod, monkeypatch, ["tool", "fail"], [TOOL_RESULT],
                        max_tool_calls=1)
    final = emitted[-1]
    assert "error" in final["analysis"]
    assert final["usage"] == _expected(1)


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

USAGE = {"input_tokens": 1_000_000, "output_tokens": 100_000,
         "cache_creation_input_tokens": 2_000_000, "cache_read_input_tokens": 10_000_000}
# claude-sonnet-4-6 at $3/$15, cache write 3 x 1.25 = 3.75, read 3 x 0.1 = 0.30:
#   1M x 3 + 0.1M x 15 + 2M x 3.75 + 10M x 0.30 = 3 + 1.5 + 7.5 + 3 = 15.00
SONNET_46_COST = 15.0


def test_rough_cost_prices_cache_at_the_standard_multipliers():
    assert runner._rough_cost("claude-sonnet-4-6", USAGE) == SONNET_46_COST


def test_rough_cost_honours_explicit_cache_rates(monkeypatch):
    """Long-form entry: a model whose cache rates are not the default multiples.
    $10/$50, write $12.50, read $0.25:
      1M x 10 + 0.1M x 50 + 2M x 12.5 + 10M x 0.25 = 10 + 5 + 25 + 2.5 = 42.50"""
    monkeypatch.setitem(runner._RATES, "stub-explicit", (10.0, 50.0, 12.5, 0.25))
    assert runner._rough_cost("stub-explicit", USAGE) == 42.5


def test_rough_cost_of_a_pre_718_usage_is_unchanged():
    old = {"input_tokens": 1_000_000, "output_tokens": 100_000}
    assert runner._rough_cost("claude-sonnet-4-6", old) == 4.5


def test_the_rescorer_prices_with_the_sweeps_own_function():
    """rebuild kept a copy of _rough_cost; a re-score must not disagree with the
    sweep that produced the cell. Behaviourally: same answer on a cache usage."""
    assert not hasattr(rebuild, "_cost"), "the private copy is back"
    assert rebuild._rough_cost("claude-sonnet-4-6", USAGE) == SONNET_46_COST


def test_db_ingest_prices_cache_tokens():
    report = {"llm_interpretation": {"model_used": "claude-sonnet-4-6", "usage": USAGE}}
    assert round(db_ingest._calculate_llm_cost(report), 6) == SONNET_46_COST


def test_db_ingest_prices_cache_on_every_section_and_plain_english(monkeypatch):
    monkeypatch.setitem(db_ingest._LLM_PRICING, "stub-explicit",
                        {"input": 10.0, "output": 50.0,
                         "cache_write": 12.5, "cache_read": 0.25})
    report = {"executive_summary": {"model": "stub-explicit", "usage": USAGE},
              "plain_english_usage": USAGE, "plain_english_model": "stub-explicit"}
    assert round(db_ingest._calculate_llm_cost(report), 6) == 85.0


def test_db_ingest_cache_only_usage_is_not_the_fallback_estimate():
    """A fully-cached request can report input_tokens=0; that is spend, not
    'no usage data' (which bills a flat $0.50)."""
    report = {"llm_interpretation": {
        "model_used": "claude-sonnet-4-6",
        "usage": {"input_tokens": 0, "output_tokens": 0,
                  "cache_creation_input_tokens": 0,
                  "cache_read_input_tokens": 1_000_000}}}
    assert round(db_ingest._calculate_llm_cost(report), 6) == 0.30


def _feeder_estimate_cost():
    """estimate_cost from the auto-feeder template, exec'd on its own.

    The template has Jinja elsewhere; this function has none, so it is compiled
    from the parsed source rather than rendered."""
    src = FEEDER_T.read_text(encoding="utf-8")
    start = src.index("def estimate_cost(")
    end = src.index("\n# ---", start)
    fn_src = src[start:end]
    ast.parse(fn_src)
    ns: dict = {"json": json, "Path": Path}
    exec(compile(fn_src, "<estimate_cost>", "exec"), ns)  # noqa: S102
    return ns["estimate_cost"]


def test_the_feeder_budget_counts_cache_tokens(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"llm_interpretation": {"usage": USAGE}}))
    # The feeder's own flat Sonnet estimate, $3/$15, with the cache multiples.
    assert round(_feeder_estimate_cost()(report), 6) == SONNET_46_COST
