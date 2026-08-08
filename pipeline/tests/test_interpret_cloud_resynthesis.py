# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cloud responses that fail to parse must be recovered, not discarded (#317).

Structured-output protection was gated on `re_backend == "local"` — both the
grammar-constrained `submit_analysis` call and the parse-failure retry. Cloud got
neither, and cloud is what PRODUCTION runs: `config.json.j2` never sets
`re_backend`, so `config.get("re_backend") != "local"` is the default path.

Measured 2026-08-07, `573e68608bbb` (amadey), claude-sonnet-5:

    parse_note: "Failed to parse structured JSON from model response;
                 raw text preserved in narrative."

3,224 output tokens holding a family guess, four capabilities, techniques and IOCs
— generated, billed, and scored as zero claims.

The recovery schema is NOT the local one. `SUBMIT_ANALYSIS_SCHEMA` types
`code_level_iocs` as an array of strings, contradicting all seven system prompts
("list of {type, value, context} objects"). Reusing it would flatten the field
that makes cloud output worth having: every claude-sonnet-5 IOC on raccoonstealer
and icedid carried a context, while qwen@15 emitted 12 of 17 as bare `DAT_`
symbols. A recovery that strips context is worse than the failure it repairs.
"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTERPRET = (ROOT / "ansible" / "roles" / "interpret" / "files"
             / "interpret-ghidra.py")
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

SRC = INTERPRET.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _assign(name: str):
    """Value of a module-level assignment.

    Resolves references to other module-level constants — the schemas are built
    from shared fragments, so plain `literal_eval` fails on the Name node. Parsing
    rather than importing is deliberate: importing `interpret-ghidra.py` pulls in
    `anthropic` and `httpx` and runs module-level setup for a test that only needs
    to read two dicts.
    """
    consts: dict[str, object] = {}
    target = None
    for node in TREE.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not names:
            continue
        try:
            value = eval(  # noqa: S307 - AST-compiled from this repo's own source
                compile(ast.Expression(node.value), "<schema>", "eval"),
                {"__builtins__": {}}, dict(consts))
        except Exception:  # noqa: BLE001 - non-literal assignments are not schemas
            continue
        for n in names:
            consts[n] = value
            if n == name:
                target = value
    if target is None:
        raise AssertionError(f"{name} not found (or not resolvable) at module level")
    return target


def _func(name: str) -> ast.AST:
    for node in ast.walk(TREE):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function {name} not found")


# ---------------------------------------------------------------------------
# The recovery schema
# ---------------------------------------------------------------------------

def test_cloud_schema_types_iocs_as_objects_not_strings():
    """THE thing that makes this fix a fix rather than a regression.

    Forcing cloud output through the local string-typed schema would discard the
    `context` on every IOC — the difference between "0x811c9dc5 — FNV-1a hash
    offset-basis" and "0x811c9dc5".
    """
    schema = _assign("CLOUD_SUBMIT_ANALYSIS_SCHEMA")
    items = schema["properties"]["code_level_iocs"]["items"]
    assert items["type"] == "object", (
        "code_level_iocs must be objects — the string form drops IOC context, "
        "which is the field that makes cloud analyses useful")
    assert "context" in items["properties"], "the context field must survive recovery"
    assert "value" in items["properties"]


def test_cloud_schema_does_not_reuse_the_contradictory_local_one():
    """The local schema contradicts the prompts. Copying it here would propagate
    the contradiction into the one path added to FIX a data-loss bug."""
    local = _assign("SUBMIT_ANALYSIS_SCHEMA")
    cloud = _assign("CLOUD_SUBMIT_ANALYSIS_SCHEMA")
    assert local["properties"]["code_level_iocs"]["items"]["type"] == "string", (
        "if the local schema has been fixed to objects, delete this test and "
        "collapse the two schemas — the divergence exists only to avoid a "
        "behaviour change to the local arm mid-evaluation")
    assert cloud != local


def test_cloud_schema_carries_every_field_the_prompts_ask_for():
    """A forced tool call returns only declared properties.

    Omitting a field here would silently drop it during recovery — trading one
    kind of data loss for another, which is the failure this fix exists to end.
    """
    schema = _assign("CLOUD_SUBMIT_ANALYSIS_SCHEMA")
    for field in ("malware_family_guess", "capabilities", "attack_techniques",
                  "novel_techniques", "code_level_iocs", "yara_suggestion",
                  "narrative", "working_notes"):
        assert field in schema["properties"], (
            f"{field} is requested by the system prompts but cannot be returned "
            f"by a forced tool call that does not declare it")


# ---------------------------------------------------------------------------
# Wire format — the two backends have opposite requirements
# ---------------------------------------------------------------------------

def test_cloud_uses_the_object_tool_choice_form():
    """Anthropic requires the object form. llama.cpp accepts ONLY a string and
    silently ignores an object — which hid a never-applied forced tool_choice for
    six synthesis runs. The two must not be unified."""
    fn = _func("cloud_synthesize")
    src = ast.unparse(fn)
    assert "'type': 'tool'" in src or '"type": "tool"' in src, (
        "cloud tool_choice must be the object form {'type':'tool','name':...}")
    assert "submit_analysis" in src


def test_local_still_uses_the_string_tool_choice_form():
    """Guards the other direction: 'fixing' the local leg to match cloud would
    re-break it, because llama.cpp rejects the object outright."""
    fn = _func("synthesize_analysis")
    src = ast.unparse(fn)
    assert "'tool_choice': 'required'" in src or '"tool_choice": "required"' in src


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def test_the_retry_is_no_longer_gated_on_local_only():
    """The regression. `re_backend == "local"` guarded the whole retry, so the
    default (production) path could never reach it."""
    assert 'if config.get("re_backend") == "local" and (not final_text.strip()' not in SRC, (
        "the parse-failure retry must not be gated on the local backend — that "
        "excludes production, which is exactly what #317 is")
    assert "cloud_synthesize(ctx)" in SRC, "cloud must have a recovery path"
    assert "local_synthesize(ctx)" in SRC, "local recovery must be preserved"


def test_recovery_failure_keeps_the_original_analysis():
    """Recovery returning None must not replace a partial result with nothing.

    The unparsed text still sits in `narrative`, which is what a human would read
    to recover the analysis by hand — strictly better than an empty dict.
    """
    fn_src = SRC[SRC.index("recovered = cloud_synthesize(ctx)"):]
    guard = fn_src[:400]
    assert "if recovered is not None" in guard, (
        "a failed recovery must leave the original analysis in place")


def test_the_recovery_bills_its_tokens():
    """An unbilled retry looks free and would distort the cost comparison that
    decides whether production moves off Claude. Same reporting failure #299
    fixed for the local synthesis leg."""
    src = ast.unparse(_func("cloud_synthesize"))
    assert "total_input_tokens" in src and "total_output_tokens" in src, (
        "the recovery call must add its usage to the run totals")
    assert "usage_from_response" in src


def test_recovered_analyses_are_marked():
    """A recovered analysis must be distinguishable from one that parsed cleanly,
    or the scorecard cannot tell how often this path fires."""
    assert "Recovered via forced submit_analysis" in SRC


def test_the_happy_path_is_unchanged():
    """This fix must not add a call to runs that already work.

    Recovery is reached only from inside `if needs_resynth:`, so a cloud run whose
    JSON parses makes exactly as many requests as before.
    """
    idx = SRC.index("needs_resynth = not final_text.strip()")
    block = SRC[idx:idx + 1600]
    assert "if needs_resynth:" in block
    call_at = block.index("cloud_synthesize(ctx)")
    gate_at = block.index("if needs_resynth:")
    assert gate_at < call_at, "recovery must be inside the parse-failure branch"
