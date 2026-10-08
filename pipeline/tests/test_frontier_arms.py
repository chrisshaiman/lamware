# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The frontier eval arms run correctly through the router.

opus55@10 (Claude Opus 5.5) and fable51@10 (Claude Fable 5.1) differ from the
older Claude arms in ways Anthropic documents (2026-10):

  - forced tool use is a 400: tool_choice type "tool"/"any" is not supported.
    cloud_synthesize forces submit_analysis, so the only recovery path for an
    unparseable final would fail every time;
  - thinking is always on, and an explicit `thinking` setting other than
    adaptive, non-default sampling parameters, and an assistant prefill are
    each a 400. None of them may reach the request;
  - a refusal is an HTTP 200 with stop_reason "refusal" and `stop_details`. The
    loop read it as an end_turn with nothing parseable, so a refused cell would
    have reached the scorecard as zero recall. Both run with the standard cyber
    safeguards, so a refusal is possible;
  - cache READ is not the standard 0.1x of input (Opus 5.5 0.05x, Fable 5.1
    0.025x).

And one every cloud arm got wrong (#722): left unset, the arm inherited the
host's `re_backend: local` and ran a Claude model through the local synthesis
paths. Every cloud arm now says "router", which also resolves the eval aliases.

Every test drives real code: the container's main() against a scripted client,
the eval's own composition from the container's emitted final, and the pricer.
"""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import types
from pathlib import Path

import pytest

pytest.importorskip("anthropic", reason="pip install './pipeline[test]'")
import anthropic  # noqa: E402
import httpx  # noqa: E402
from lamware_eval import runner  # noqa: E402
from lamware_eval.arms import Arm, registered_arms, resolve_arm  # noqa: E402
from lamware_eval.corpus import CorpusSample  # noqa: E402
from lamware_eval.metrics import aggregate, cell_error, compose_cell  # noqa: E402
from lamware_eval.stats import paired_comparison  # noqa: E402
from llm_ab_re import extract_metrics  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ansible" / "roles" / "interpret" / "files" / "interpret-ghidra.py"

FINAL_JSON = json.dumps({"malware_family_guess": "formbook", "capabilities": ["x"]})
TOOL_RESULT = {"type": "tool_result", "result": {"code": "int f(void) { return 0; }"}}
# The documented message, as the SDK renders a 400 body.
FORCED_400 = ('tool_choice: type "tool" and "any" are not supported for this model.')
REFUSAL_DETAILS = {"type": "refusal", "category": "cyber",
                   "explanation": "This request could enable cyber harm."}


@pytest.fixture
def mod():
    name = "_interpret_frontier_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    try:
        spec.loader.exec_module(m)
        yield m
    finally:
        sys.modules.pop(name, None)


def _usage(i, o, cw=0, cr=0):
    return types.SimpleNamespace(input_tokens=i, output_tokens=o,
                                 cache_creation_input_tokens=cw,
                                 cache_read_input_tokens=cr)


class _Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Message:
    """Plain attributes, no stop_details unless given: the SDK 0.52 Message shape."""

    def __init__(self, content, stop_reason, usage, stop_details=None):
        self.content = content
        self.stop_reason = stop_reason
        self.model = "stub-model"
        self.usage = usage
        if stop_details is not None:
            self.stop_details = stop_details


class _Stream:
    def __init__(self, message, events=()):
        self._message = message
        self._events = list(events)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(self._events)

    def get_final_message(self):
        return self._message


def _bad_request(message: str) -> anthropic.BadRequestError:
    req = httpx.Request("POST", "http://litellm.invalid/v1/messages")
    body = {"type": "error", "error": {"type": "invalid_request_error", "message": message}}
    return anthropic.BadRequestError(f"Error code: 400 - {json.dumps(body)}",
                                     response=httpx.Response(400, request=req), body=body)


# Per-call usage, in call order; the final's usage must be their sum.
PER_CALL = [(100, 10, 2_000, 0), (110, 20, 0, 2_000), (120, 30, 0, 2_000),
            (130, 40, 0, 2_000)]


def _sum(n: int) -> dict:
    i, o, cw, cr = (sum(c[k] for c in PER_CALL[:n]) for k in range(4))
    return {"input_tokens": i, "output_tokens": o,
            "cache_creation_input_tokens": cw, "cache_read_input_tokens": cr}


class _Model:
    """Scripted Messages API.

    `script`: per stream() call — 'tool', 'text', 'bad' (unparseable end_turn),
    'refuse' (stop_details on the message), 'refuse_streamed' (stop_details only
    on the message_delta event, as SDK 0.52 delivers it).
    `create_script`: per create() call — 'submit', 'reject_forced' (the 400 when
    tool_choice is forced, a submit otherwise), 'other_400', 'refuse'.
    """

    def __init__(self, script, create_script=("submit",)):
        self._script = list(script)
        self._create = list(create_script)
        self.calls = 0
        self.create_kwargs: list[dict] = []
        self.stream_kwargs: list[dict] = []

    def _next_usage(self):
        i, o, cw, cr = PER_CALL[self.calls]
        self.calls += 1
        return _usage(i, o, cw, cr)

    def stream(self, **kwargs):
        self.stream_kwargs.append(kwargs)
        step = self._script.pop(0)
        if step == "tool":
            # Thinking is always on for these models, and with the default
            # `display: omitted` the block's text is empty; only the signature
            # carries it. It has to go back unchanged.
            return _Stream(_Message([_Block(type="thinking", thinking="",
                                            signature=f"sig_{self.calls}"),
                                     _Block(type="tool_use", id=f"tu_{self.calls}",
                                            name="decompile_function",
                                            input={"name": "f"})],
                                    "tool_use", self._next_usage()))
        if step == "refuse":
            return _Stream(_Message([], "refusal", self._next_usage(),
                                    stop_details=dict(REFUSAL_DETAILS)))
        if step == "refuse_streamed":
            delta = types.SimpleNamespace(stop_reason="refusal",
                                          stop_details=dict(REFUSAL_DETAILS))
            event = types.SimpleNamespace(type="message_delta", delta=delta)
            return _Stream(_Message([], "refusal", self._next_usage()), [event])
        text = FINAL_JSON if step == "text" else "not json at all"
        return _Stream(_Message([_Block(type="text", text=text)], "end_turn",
                                self._next_usage()))

    def create(self, **kwargs):
        self.create_kwargs.append(kwargs)
        step = self._create[0] if len(self._create) == 1 else self._create.pop(0)
        forced = (kwargs.get("tool_choice") or {}).get("type") in ("tool", "any")
        if step == "reject_forced" and forced:
            raise _bad_request(FORCED_400)
        if step == "other_400":
            raise _bad_request("tools.0.input_schema: invalid schema")
        if step == "refuse":
            return _Message([], "refusal", self._next_usage(),
                            stop_details=dict(REFUSAL_DETAILS))
        return _Message([_Block(type="tool_use", id="tu_s", name="submit_analysis",
                                input={"malware_family_guess": "formbook",
                                       "capabilities": ["x"]})],
                        "tool_use", self._next_usage())


def _drive(mod, monkeypatch, model, orchestrator, *, re_backend="cloud",
           router=None, max_tool_calls=20, model_name="eval-fable51", config=None):
    """Run main() to its exit. With `router`, the client built for
    LITELLM_ROUTER_BASE_URL is `router` and the passthrough one is `model`.
    `config`, when given, is the init config as is (an arm_config result)."""
    def factory(**kw):
        if router is not None and kw.get("base_url") == "http://router.invalid":
            return types.SimpleNamespace(messages=router)
        return types.SimpleNamespace(messages=model)

    monkeypatch.setattr(mod.anthropic, "Anthropic", factory)
    monkeypatch.setenv("LITELLM_API_KEY", "test-key")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm.invalid/anthropic")
    if router is not None:
        monkeypatch.setenv("LITELLM_ROUTER_BASE_URL", "http://router.invalid")
    else:
        monkeypatch.delenv("LITELLM_ROUTER_BASE_URL", raising=False)
    init = {"type": "init",
            "ghidra_data": {"program": {"name": "sample.exe"}, "functions": [],
                            "strings": [], "imports": []},
            "config": config or {
                "re_backend": re_backend, "model": model_name,
                "escalation_model": model_name,
                "max_tool_calls": max_tool_calls, "max_tool_calls_per_turn": 3}}
    monkeypatch.setattr(mod.sys, "stdin", io.StringIO(
        "".join(json.dumps(m) + "\n" for m in [init, *orchestrator])))
    out = io.StringIO()
    monkeypatch.setattr(mod.sys, "stdout", out)
    with pytest.raises(SystemExit) as exc:
        mod.main()
    emitted = [json.loads(ln) for ln in out.getvalue().splitlines()
               if ln.strip().startswith("{")]
    return emitted, exc.value.code


# ---------------------------------------------------------------------------
# Forced tool use: one retry with auto, only when the model rejects forcing
# ---------------------------------------------------------------------------

def test_a_model_that_rejects_forced_tool_choice_is_retried_once_with_auto(mod, monkeypatch):
    model = _Model(["tool", "bad"], create_script=["reject_forced"])
    emitted, code = _drive(mod, monkeypatch, model, [TOOL_RESULT])
    final = emitted[-1]
    assert code == 0 and final["type"] == "final"
    assert final["analysis"]["malware_family_guess"] == "formbook"
    choices = [kw.get("tool_choice") for kw in model.create_kwargs]
    assert choices == [{"type": "tool", "name": "submit_analysis"}, {"type": "auto"}]
    # The retry is told to call the tool, since nothing forces it to.
    instruction = model.create_kwargs[1]["messages"][-1]["content"]
    assert "submit_analysis" in instruction and "prose" in instruction
    assert any(t["name"] == "submit_analysis" for t in model.create_kwargs[1]["tools"])
    # Billed: two loop turns plus the retry. The rejected 400 had no usage.
    assert model.calls == 3
    assert final["usage"] == _sum(3)


def test_a_model_that_accepts_forced_tool_choice_makes_one_call(mod, monkeypatch):
    """The Claude arms: unchanged, one forced call, no retry."""
    model = _Model(["tool", "bad"], create_script=["submit"])
    emitted, _ = _drive(mod, monkeypatch, model, [TOOL_RESULT])
    assert [kw.get("tool_choice") for kw in model.create_kwargs] == [
        {"type": "tool", "name": "submit_analysis"}]
    assert emitted[-1]["analysis"]["malware_family_guess"] == "formbook"
    assert emitted[-1]["usage"] == _sum(3)


def test_any_other_400_is_not_retried(mod, monkeypatch):
    """A malformed request is not the forced-choice rejection; retrying it with
    auto would hide the real error. The original analysis is kept."""
    model = _Model(["tool", "bad"], create_script=["other_400"])
    emitted, _ = _drive(mod, monkeypatch, model, [TOOL_RESULT])
    assert len(model.create_kwargs) == 1
    assert emitted[-1]["analysis"].get("parse_note")
    assert emitted[-1]["usage"] == _sum(2)


# ---------------------------------------------------------------------------
# Refusals end the run as a refused final, never as an analysis
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("step", ["refuse", "refuse_streamed"])
def test_a_refusal_in_the_loop_ends_with_a_refused_final(mod, monkeypatch, step):
    model = _Model(["tool", step])
    emitted, code = _drive(mod, monkeypatch, model, [TOOL_RESULT])
    final = emitted[-1]
    assert code == 0 and final["type"] == "final"
    assert final["analysis"] == {"error": "refused", "refusal": {
        "category": "cyber", "explanation": REFUSAL_DETAILS["explanation"],
        "phase": "loop"}}
    assert final["usage"] == _sum(2), "the refused turn's tokens were spent"
    assert final["tool_calls_used"] == 1
    assert model.create_kwargs == [], "a refusal must not be 'recovered'"
    # The turn trail records it, category included.
    turn = [e for e in emitted if e["type"] == "turn"][-1]
    assert turn["stop_reason"] == "refusal"
    assert turn["stop_details"]["category"] == "cyber"
    assert any(e["type"] == "status" and "refused" in e["message"] for e in emitted)


def test_the_orchestrator_trail_keeps_the_refusal_category(mod, monkeypatch, tmp_path):
    """The container's turn event, fed to the orchestrator's TurnTrail as the
    stage does: the category must survive into the persisted trail."""
    from stages.interpret import TurnTrail
    emitted, _ = _drive(mod, monkeypatch, _Model(["tool", "refuse"]), [TOOL_RESULT])
    trail = TurnTrail(tmp_path / "t.trail.jsonl", started=0.0)
    trail.turn([e for e in emitted if e["type"] == "turn"][-1])
    row = json.loads(trail.path.read_text().splitlines()[-1])
    assert row["stop_reason"] == "refusal"
    assert row["stop_details"]["category"] == "cyber"


def test_a_refusal_on_the_recovery_call_is_a_refused_final(mod, monkeypatch):
    model = _Model(["tool", "bad"], create_script=["refuse"])
    emitted, _ = _drive(mod, monkeypatch, model, [TOOL_RESULT])
    final = emitted[-1]
    assert final["analysis"]["error"] == "refused"
    assert final["analysis"]["refusal"]["phase"] == "synth_cloud_recover"
    assert final["usage"] == _sum(3)


def test_a_refused_single_shot_raises_with_its_usage(mod):
    msg = _Message([], "refusal", _usage(30, 2), stop_details=dict(REFUSAL_DETAILS))
    client = types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **kw: msg))
    with pytest.raises(mod.ModelRefused) as exc:
        mod.single_shot_completion(False, client, None, "", "", "eval-fable51",
                                   "sys", "hi", 64, "java_cfr")
    assert exc.value.refusal["category"] == "cyber"
    assert exc.value.refusal["phase"] == "java_cfr"
    assert exc.value.usage["input_tokens"] == 30


# ---------------------------------------------------------------------------
# Routing: the alias is only resolvable on the router
# ---------------------------------------------------------------------------

def test_router_backend_sends_the_loop_and_recovery_to_the_router(mod, monkeypatch):
    passthrough = _Model([])
    router = _Model(["tool", "bad"], create_script=["submit"])
    emitted, _ = _drive(mod, monkeypatch, passthrough, [TOOL_RESULT],
                        re_backend="router", router=router)
    assert passthrough.calls == 0 and passthrough.create_kwargs == []
    # Cloud semantics on the router: the forced Anthropic recovery ran there,
    # not the local two-phase synthesis, and it was billed.
    assert router.calls == 3 and len(router.create_kwargs) == 1
    assert emitted[-1]["analysis"]["malware_family_guess"] == "formbook"
    assert emitted[-1]["usage"] == _sum(3)


# The host's deployed config.json, as run_arm receives it: re_backend local since
# #584 (2026-09-08).
HOST_CFG = {"model": "local-qwen-llamacpp-re", "re_backend": "local",
            "single_shot_backend": "local", "max_output_tokens": 4096,
            "max_tool_calls_per_turn": 3}


@pytest.mark.parametrize("arm_name", registered_arms())
def test_no_arm_inherits_the_hosts_local_backend(arm_name):
    """#722. EVERY registered arm (variants included) sets both backends itself,
    and every arm whose model is not a local alias gets "router": under the
    host's config, an arm that inherited would come out "local"."""
    arm = resolve_arm(arm_name)
    cfg = runner.arm_config(arm, HOST_CFG, "agentic")
    want = "local" if arm.model.startswith("local-") else "router"
    assert arm.re_backend == want, f"{arm_name} declares {arm.re_backend!r}"
    assert cfg["re_backend"] == want and cfg["single_shot_backend"] == want
    # And it is the arm's value, not the host's: a host config holding a value
    # no arm uses must not survive into any arm's config.
    odd = runner.arm_config(arm, {**HOST_CFG, "re_backend": "inherited",
                                  "single_shot_backend": "inherited"}, "agentic")
    assert odd["re_backend"] == want and odd["single_shot_backend"] == want


def test_an_arm_without_a_backend_is_refused():
    """No third value: "inherit the deployed config" is how #722 happened."""
    with pytest.raises(ValueError, match="re_backend"):
        runner.arm_config(Arm("x", "claude-sonnet-5", None, 10), HOST_CFG, "agentic")


@pytest.mark.parametrize("arm_name,alias", [
    ("opus55@10", "eval-opus55"), ("fable51@10", "eval-fable51"),
    ("claude-sonnet-5", "claude-sonnet-5"), ("claude-opus-5", "claude-opus-5")])
def test_cloud_arms_run_their_own_model_on_the_router(arm_name, alias):
    cfg = runner.arm_config(resolve_arm(arm_name), HOST_CFG, "agentic")
    assert cfg["model"] == cfg["escalation_model"] == alias
    assert cfg["max_tool_calls"] == 10


# ---------------------------------------------------------------------------
# The arm, end to end: arm_config -> the container, on the router
# ---------------------------------------------------------------------------

def _arm_drive(mod, monkeypatch, arm_name, router, orchestrator, **cfg_over):
    passthrough = _Model([])
    cfg = {**runner.arm_config(resolve_arm(arm_name), HOST_CFG, "agentic"), **cfg_over}
    emitted, code = _drive(mod, monkeypatch, passthrough, orchestrator,
                           router=router, config=cfg)
    assert passthrough.calls == 0 and passthrough.create_kwargs == [], (
        "the arm's alias reached the /anthropic passthrough")
    return emitted, code


@pytest.mark.parametrize("arm_name", ["fable51@10", "opus55@10"])
def test_the_arms_recovery_takes_the_auto_retry(mod, monkeypatch, arm_name):
    """Both models reject forced tool use. Under the HOST's config, the arm's
    unparseable final reaches cloud_synthesize on the router, the forced call
    400s, and the one retry with tool_choice auto produces the analysis."""
    router = _Model(["tool", "bad"], create_script=["reject_forced"])
    emitted, code = _arm_drive(mod, monkeypatch, arm_name, router, [TOOL_RESULT])
    assert code == 0 and emitted[-1]["type"] == "final"
    assert emitted[-1]["analysis"]["malware_family_guess"] == "formbook"
    assert [kw.get("tool_choice") for kw in router.create_kwargs] == [
        {"type": "tool", "name": "submit_analysis"}, {"type": "auto"}]
    assert {kw["model"] for kw in router.stream_kwargs + router.create_kwargs} == {
        resolve_arm(arm_name).model}
    assert emitted[-1]["usage"] == _sum(3)


# Parameters these models reject with a 400 (thinking is always on; sampling is
# fixed), and that this harness must therefore never send on the arm's path.
_REJECTED_PARAMS = {"thinking", "temperature", "top_p", "top_k"}


def _requests(model: _Model) -> list[dict]:
    return model.stream_kwargs + model.create_kwargs


@pytest.mark.parametrize("scenario", ["recover", "max_calls", "force_final"])
def test_no_request_on_the_fable_path_sends_a_rejected_parameter(mod, monkeypatch,
                                                                  scenario):
    """Every request the arm makes, on each of the three routes to a final:
    the unparseable-final recovery, the max-calls final, and the orchestrator's
    force_final. None sends thinking/temperature/top_p/top_k, none ends on an
    assistant turn (a prefill), and a forced tool_choice appears only on the
    attempt the model rejects."""
    over = {}
    orchestrator = [TOOL_RESULT]
    if scenario == "recover":
        router = _Model(["tool", "bad"], create_script=["reject_forced"])
    elif scenario == "max_calls":
        router = _Model(["tool", "text"])
        over = {"max_tool_calls": 1}
    else:
        router = _Model(["tool", "text"])
        orchestrator = [{"type": "force_final", "reason": "budget"}]
    emitted, code = _arm_drive(mod, monkeypatch, "fable51@10", router, orchestrator,
                               **over)
    assert code == 0 and emitted[-1]["analysis"]["malware_family_guess"] == "formbook"
    reqs = _requests(router)
    assert len(reqs) >= 2
    for kw in reqs:
        assert not (_REJECTED_PARAMS & set(kw)), sorted(_REJECTED_PARAMS & set(kw))
        assert kw["messages"][-1]["role"] == "user", "ends on an assistant turn"
    forced = [kw for kw in reqs
              if (kw.get("tool_choice") or {}).get("type") in ("tool", "any")]
    assert forced == router.create_kwargs[:1] if scenario == "recover" else forced == []


def test_the_thinking_block_goes_back_unchanged(mod, monkeypatch):
    """Thinking is always on; the block (empty text under the default display,
    plus its signature) must be replayed as the model returned it."""
    router = _Model(["tool", "text"])
    _arm_drive(mod, monkeypatch, "fable51@10", router, [TOOL_RESULT])
    replayed = router.stream_kwargs[1]["messages"][-2]
    assert replayed["role"] == "assistant"
    assert replayed["content"][0] == {"type": "thinking", "thinking": "",
                                      "signature": "sig_0"}


# ---------------------------------------------------------------------------
# The eval: a refused cell is counted and excluded, never scored as zero
# ---------------------------------------------------------------------------

def _cell(arm, sample, analysis, *, recall_hit: bool):
    """A cell composed exactly as run_arm composes it, from a container result."""
    res = {"enabled": True, "analysis": analysis, "tool_calls_used": 1}
    techniques = ["T1055", "T1082"]
    if recall_hit and "error" not in analysis:
        analysis = {**analysis, "attack_techniques": [{"id": "T1055"}]}
        res["analysis"] = analysis
    s = CorpusSample(sample * 64, "amadey", "/d")
    return compose_cell(arm, s, analysis, "source", None, 10.0, 0.5,
                        extract_metrics(res), cell_error(res, analysis),
                        cape_techniques=techniques,
                        input_read={"kind": "native_pe", "variant": 0,
                                    "variant_effective": None,
                                    "input_sha": f"{sample}-0"})


def _refused_final(mod, monkeypatch) -> dict:
    emitted, _ = _drive(mod, monkeypatch, _Model(["tool", "refuse"]), [TOOL_RESULT])
    return emitted[-1]["analysis"]


def test_a_refused_cell_is_counted_and_excluded_from_the_statistics(mod, monkeypatch):
    refused = _refused_final(mod, monkeypatch)
    ok = {"malware_family_guess": "x", "capabilities": ["c"]}
    cells = [_cell("qwen@10", "a", ok, recall_hit=True),
             _cell("qwen@10", "b", ok, recall_hit=True),
             _cell("fable51@10", "a", refused, recall_hit=False),
             _cell("fable51@10", "b", ok, recall_hit=True)]
    r_cell = cells[2]
    assert r_cell["refused"] is True and r_cell["completed"] is False
    assert r_cell["error"].startswith("refused (category=cyber")

    summ = aggregate(cells)["fable51@10"]
    assert summ["n"] == 2 and summ["refused"] == 1 and summ["n_valid"] == 1
    # Scored as zero, the refused cell would pull this to 0.25.
    assert summ["mean_technique_recall"] == 0.5
    assert summ["completed_rate"] == 1.0
    assert summ["total_cost_usd"] == 1.0, "a refused cell still cost money"

    pc = paired_comparison(cells, "qwen@10", "fable51@10", "technique_recall")
    assert pc["pairs"] == 1 and pc["unpaired"] == 1
    assert pc["sample_effects"] == {"b" * 12: 0.0}


def test_the_scorecard_shows_refusals():
    from lamware_eval.scorecard import render_scorecard
    ok = {"malware_family_guess": "x", "capabilities": ["c"]}
    refused = {"error": "refused", "refusal": {"category": "cyber", "explanation": None,
                                               "phase": "loop"}}
    cells = [_cell("fable51@10", "a", refused, recall_hit=False),
             _cell("fable51@10", "b", ok, recall_hit=True)]
    md = render_scorecard("t", cells, aggregate(cells))
    # The per-cell error column names the category and the phase.
    assert "refused (category=cyber, phase=loop)" in md
    # The summary row counts it, in its own column.
    lines = md.splitlines()
    header = next(ln for ln in lines if ln.startswith("| arm | n |"))
    row = next(ln for ln in lines if ln.startswith("| fable51@10 | 2 |"))
    cols = [c.strip() for c in header.split("|")]
    vals = [c.strip() for c in row.split("|")]
    assert vals[cols.index("refused")] == "1"
    assert vals[cols.index("n_valid")] == "1"


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

_USAGE = {"input_tokens": 1_000_000, "output_tokens": 100_000,
          "cache_creation_input_tokens": 2_000_000,
          "cache_read_input_tokens": 10_000_000}


@pytest.mark.parametrize("alias,rates,cost", [
    # 10 + 5 + 25 + 2.5
    ("eval-fable51", (10.0, 50.0, 12.5, 0.25), 42.5),
    # 4 + 2 + 10 + 2
    ("eval-opus55", (4.0, 20.0, 5.0, 0.20), 18.0),
])
def test_frontier_arms_are_priced_at_their_own_cache_rates(alias, rates, cost):
    """The read is NOT the 0.1x default on either (0.1x would be $1.00 / $0.40)."""
    assert runner._model_rates(alias) == rates
    assert runner._rough_cost(alias, _USAGE) == cost


def test_every_cloud_arm_is_priced():
    """A cloud arm with no rate scores $0, the same as a free local arm."""
    for name in registered_arms():
        arm = resolve_arm(name)
        if arm.re_backend == "router":
            assert arm.model in runner._RATES, f"{name}: {arm.model} has no rate"


def test_sonnet5_is_priced_at_the_standard_rate():
    """$2/$10 became the standard price; the $3/$15 rise for 2026-09-01 was
    cancelled (Anthropic pricing page, read 2026-10-08)."""
    assert runner._model_rates("claude-sonnet-5") == (2.0, 10.0, 2.5, 0.2)
