# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The forced-tool schema and the system prompts must describe the same shape (#321).

All seven system prompts ask for:

    code_level_iocs: list of {"type": "...", "value": "...", "context": "..."} objects

while `SUBMIT_ANALYSIS_SCHEMA` typed it as an array of **strings**.

That was not cosmetic. llama.cpp grammar-constrains tool arguments, so on the local
path the SCHEMA won — the model was forced to emit bare strings while its prompt
asked for objects. Cloud, unconstrained, followed the prompt. Neither model was
being inconsistent; each obeyed whichever instruction was binding on its path, and
the difference was scored as a model difference.

`context` is the field that turns a token into a finding:

    with    0x811c9dc5 — "FNV-1a hash offset-basis used to validate decrypted data"
    without 0x811c9dc5

Measured 2026-08-07: every claude-sonnet-5 IOC on raccoonstealer and icedid carried
a context; qwen@15 emitted 12 of 17 as bare `DAT_` symbols. Part of that gap was the
harness forbidding the local arm from supplying context at all.

A forced tool call can also only return properties the schema names, so the previous
six-property version silently dropped `working_notes`, `novel_techniques` and
`yara_suggestion` during forced serialisation — a second, quieter instance of the
same class.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTERPRET = (ROOT / "ansible" / "roles" / "interpret" / "files"
             / "interpret-ghidra.py")
SRC = INTERPRET.read_text(encoding="utf-8")
TREE = ast.parse(SRC)

# Fields the prompts promise. Parsed from the prompt text below, not hardcoded, so
# adding a field to the prompts without adding it to the schema fails here.
_PROMPT_FIELD = re.compile(r"^-\s+([a-z_]+):", re.MULTILINE)


def _resolve(name: str):
    """Module-level assignment value, resolving references to earlier constants."""
    consts: dict[str, object] = {}
    found = None
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
                found = value
    assert found is not None, f"{name} not found or not resolvable"
    return found


def _prompt_bodies() -> list[str]:
    """The system prompts that document the output contract."""
    out = []
    for node in TREE.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not any(n.endswith("_SYSTEM_PROMPT") for n in names):
            continue
        val = node.value
        text = val.value if isinstance(val, ast.Constant) else None
        if isinstance(text, str) and "code_level_iocs" in text:
            out.append(text)
    return out


SCHEMA = _resolve("SUBMIT_ANALYSIS_SCHEMA")
PROMPTS = _prompt_bodies()


def test_the_prompts_were_actually_found():
    """Guards the guard: zero prompts makes every comparison below vacuous."""
    assert len(PROMPTS) >= 5, f"only found {len(PROMPTS)} prompts declaring IOCs"
    for p in PROMPTS:
        assert "code_level_iocs" in p


def test_the_schema_types_iocs_as_objects_like_every_prompt_asks():
    """THE fix. The prompts say objects; the schema said strings; the grammar made
    the schema win."""
    items = SCHEMA["properties"]["code_level_iocs"]["items"]
    assert items["type"] == "object", (
        f"schema types code_level_iocs items as {items['type']!r}, but all "
        f"{len(PROMPTS)} prompts ask for objects")
    for prompt in PROMPTS:
        assert re.search(r"code_level_iocs:.*objects", prompt, re.S), (
            "a prompt stopped asking for objects — reconcile it with the schema "
            "rather than letting them drift apart again")


def test_context_survives_into_the_schema():
    """`context` is the difference between a finding and a token. Dropping it is
    how the local arm ended up unable to explain its own IOCs."""
    props = SCHEMA["properties"]["code_level_iocs"]["items"]["properties"]
    for field in ("type", "value", "context"):
        assert field in props, f"{field} missing — the prompts promise it"
    assert SCHEMA["properties"]["code_level_iocs"]["items"]["required"] == ["value"], (
        "only `value` should be required; an IOC without context is still an IOC, "
        "and forcing context invites the model to invent one")


def test_every_field_the_prompts_promise_is_in_the_schema():
    """A forced tool call returns ONLY properties the schema names, so a field the
    prompt asks for and the schema omits is silently discarded."""
    promised: set[str] = set()
    for prompt in PROMPTS:
        promised |= set(_PROMPT_FIELD.findall(prompt))
    missing = sorted(promised - set(SCHEMA["properties"]))
    assert not missing, (
        f"the prompts ask for {missing} but the schema cannot return them — a "
        f"forced tool call drops undeclared properties")


def test_the_two_schemas_are_now_one():
    """#317 forked a cloud schema purely to avoid inheriting the string-typed IOCs.
    With the contradiction gone there is nothing to diverge on, and two schemas that
    must stay identical will not."""
    assert _resolve("CLOUD_SUBMIT_ANALYSIS_SCHEMA") == SCHEMA


def test_required_stays_minimal():
    """Requiring more invites fabrication: a model with nothing to say must either
    invent a value or fail the grammar. amadey and latrodectus legitimately had
    nothing, and said so."""
    assert set(SCHEMA["required"]) == {
        "malware_family_guess", "capabilities", "narrative"}
