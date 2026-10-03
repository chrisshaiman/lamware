# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The agentic .NET tools find the loader that the single-shot path missed (#646).

redet644_5b4f596d3cf5 (formbook), 2026-09-27: the single-shot path sent 97,135
characters of decompiled C# in one request (38,263 input tokens, 2,690 s), and
the answer was the decoy — "Local Game Logic Execution". The malicious part was
a few lines that build a byte list and load it through
`LateBinding.LateGet(Thread.GetDomain(), null, "Load", ...)`; a grep for
`Assembly.Load` finds nothing.

These tests call the tool functions on a synthetic corpus with that shape
(tests/fixtures/dotnet_formbook_shape.py: a ~100k-character decoy and one small
malicious method). They observe what the agent would be shown — the construct
list, a method's source, a search hit, the size bounds — not the source of the
functions.
"""
import importlib.util
import json
import time
from pathlib import Path

import pytest
from llm_ab_re import is_semantic_tool_error, is_transport_tool_error
from stages import dotnet_agentic, dotnet_tools
from stages.dotnet_agentic import (
    DotnetToolBroker,
    build_dotnet_agentic_init,
    build_dotnet_interpret_init,
)
from stages.dotnet_tools import (
    LINES_MAX,
    NOT_FOUND,
    SOURCE_PAGE_CHARS,
    CSharpIndex,
    DotnetToolbox,
    mask_source,
    scan_suspicious_constructs,
    validate_dotnet_args,
)
from stages.interpret import agent_payload

_spec = importlib.util.spec_from_file_location(
    "dotnet_formbook_shape", Path(__file__).parent / "fixtures" / "dotnet_formbook_shape.py")
shape = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shape)

SRC = shape.formbook_shaped_source()
IGNITE = f"CardBattle.Formalar.{shape.MALICIOUS_CLASS}.{shape.MALICIOUS_METHOD}"


@pytest.fixture(scope="module")
def tools() -> DotnetToolbox:
    return DotnetToolbox(SRC)


def test_the_corpus_has_formbooks_shape():
    """The decoy dominates, as it did on the host: the malicious method is a
    small fraction of a source near the single-shot cap."""
    assert 90_000 < len(SRC) < 120_000
    idx = CSharpIndex(SRC)
    t = idx.find_types(shape.MALICIOUS_CLASS)[0]
    ignite = next(m for m in t.members if m.name == shape.MALICIOUS_METHOD)
    assert ignite.chars < 0.01 * len(SRC)
    assert "Assembly.Load(" not in mask_source(SRC), (
        "the corpus must not CALL the identifier a grep finds")


# --- the suspicious-construct scan ------------------------------------------------

def test_the_scan_ranks_the_loader_method_first():
    """THE property: the method that builds bytes and loads them by name is the
    first place the agent is told to read, ahead of a 70k-character decoy."""
    sc = scan_suspicious_constructs(CSharpIndex(SRC))
    top = sc["locations"][0]
    assert top["location"] == IGNITE, [loc["location"] for loc in sc["locations"]]
    cats = {f["category"] for f in top["findings"]}
    assert {"reflection_by_name", "late_binding", "assembly_load", "byte_building"} <= cats
    by_name = next(f for f in top["findings"] if f["category"] == "reflection_by_name")
    assert by_name["match"] == '"Load"'
    assert "LateBinding.LateGet" in top["example"]


def test_a_comment_naming_an_api_is_not_a_finding():
    """A sample can write any API name in a comment to steer the reader. The
    fixture's comment names Assembly.Load; no code calls it."""
    import re
    pattern = dict((c, p) for c, _, p in dotnet_tools.CONSTRUCT_PATTERNS)["assembly_load"]
    in_comment = [m for m in re.finditer(pattern, SRC) if m.group(0).startswith("Assembly")]
    assert in_comment, "the probe is broken: the comment no longer matches the pattern"
    sc = scan_suspicious_constructs(CSharpIndex(SRC))
    for loc in sc["locations"]:
        for f in loc["findings"]:
            assert "Assembly.Load" not in f["match"], loc


def test_a_string_literal_is_scanned_even_though_it_is_masked():
    """Strings are blanked for brace counting; the scan must still see them,
    because "Load" as a string IS the signal."""
    idx = CSharpIndex('class A { void M() { Call("Load"); } }')
    assert '"Load"' not in idx.masked
    sc = scan_suspicious_constructs(idx)
    assert sc["locations"][0]["location"] == "A.M"


def test_the_scan_is_bounded_and_says_so():
    many = "class A {\n" + "\n".join(
        f'void M{i}() {{ Process.Start("x{i}"); }}' for i in range(80)) + "\n}"
    sc = scan_suspicious_constructs(CSharpIndex(many), max_locations=10)
    assert len(sc["locations"]) == 10
    assert sc["locations_total"] == 80
    assert sc["truncated"] is True
    assert sc["category_totals"]["process"] == 80


# --- get_method_source ------------------------------------------------------------

def test_get_method_source_returns_the_loader_and_nothing_else(tools):
    r = tools.call("get_method_source", {"class_name": shape.MALICIOUS_CLASS,
                                         "method_name": shape.MALICIOUS_METHOD})
    assert "error" not in r, r
    assert r["class"] == "CardBattle.Formalar.BattleForm"
    assert shape.LOAD_LINE_MARK in r["source"]
    assert "Thread.GetDomain()" in r["source"]
    assert shape.DECOY_MARK not in r["source"]
    assert r["truncated"] is False and r["pages"] == 1
    assert r["source"].rstrip().endswith("}")


def test_the_full_class_name_and_a_dotted_method_name_both_resolve(tools):
    a = tools.call("get_method_source", {"class_name": "CardBattle.Formalar.BattleForm",
                                         "method_name": "BattleForm.Ignite"})
    assert shape.LOAD_LINE_MARK in a["source"]


def test_a_pinvoke_declaration_is_fetchable(tools):
    """`extern` methods end in `;`, not a body; they are still members."""
    r = tools.call("get_method_source", {"class_name": "BattleForm",
                                         "method_name": "VirtualAlloc"})
    assert "DllImport" in r["source"] and "extern" in r["source"]


def test_a_long_method_is_paged_and_no_page_drops_anything(tools):
    """Bounded, and the bound says so; every character is reachable."""
    first = tools.call("get_method_source", {"class_name": "BattleForm",
                                             "method_name": shape.DECOY_METHOD})
    assert first["truncated"] is True and first["pages"] > 1
    assert len(first["source"]) <= SOURCE_PAGE_CHARS
    assert "page=1" in first["note"]
    pages = [first["source"]] + [
        tools.call("get_method_source", {"class_name": "BattleForm",
                                         "method_name": shape.DECOY_METHOD,
                                         "page": p})["source"]
        for p in range(1, first["pages"])]
    idx = tools.index
    m = next(m for m in idx.find_types("BattleForm")[0].members
             if m.name == shape.DECOY_METHOD)
    whole = idx.source[idx.line_start_of(m.start):m.end]
    assert "".join(pages).split("\n", 1)[1] == whole, "paging lost or duplicated text"
    past = tools.call("get_method_source", {"class_name": "BattleForm",
                                            "method_name": shape.DECOY_METHOD,
                                            "page": first["pages"]})
    assert past["source"] == "" and "does not exist" in past["note"]


def test_get_class_source_pages_cover_the_class_exactly(tools):
    first = tools.call("get_class_source", {"class_name": "BattleForm"})
    pages = [tools.call("get_class_source", {"class_name": "BattleForm", "page": p})["source"]
             for p in range(first["pages"])]
    t = tools.index.find_types("BattleForm")[0]
    assert "".join(pages) == tools.index.source[tools.index.line_start_of(t.start):t.end]
    assert all(len(p) <= SOURCE_PAGE_CHARS for p in pages)


# --- search_source ------------------------------------------------------------------

def test_search_finds_the_member_loaded_by_name(tools):
    r = tools.call("search_source", {"pattern": shape.LOAD_LINE_MARK})
    assert r["total_hits"] == 1 and r["truncated"] is False
    hit = r["hits"][0]
    assert hit["location"] == IGNITE
    assert "LateBinding.LateGet" in hit["text"]
    assert SRC.split("\n")[hit["line"] - 1].strip() == hit["text"]


def test_search_reports_truncation_when_it_bites(tools):
    r = tools.call("search_source", {"pattern": r"lblKarta\d+", "max_hits": 5})
    assert len(r["hits"]) == 5
    assert r["total_hits"] > 1000
    assert r["truncated"] is True and "TRUNCATED" in r["note"]


def test_search_with_context_returns_the_neighbouring_lines(tools):
    r = tools.call("search_source", {"pattern": shape.LOAD_LINE_MARK, "context_lines": 2})
    ctx = r["hits"][0]["context"]
    assert len(ctx) == 5 and any("GetExportedTypes" in line for line in ctx)


def test_a_catastrophic_pattern_is_stopped_not_waited_for(monkeypatch):
    """The pattern is the model's, the text is the sample's, and Python's `re`
    has no timeout. `(a+)+$` against 44 a's and a '!' does not finish; the
    sandbox's timeout, enforced from outside, stops it, and the broker answers
    the call as a bad pattern without blocking the process that brokers every
    tool call. (Here the outside timeout is the broker's backstop: the local
    stand-in for the container has no podman --timeout.)"""
    monkeypatch.setattr(dotnet_agentic, "STARTUP_GRACE_S", 0)
    t0 = time.monotonic()
    r = DotnetToolBroker(SRC, timeout=1).call("search_source", {"pattern": "(a+)+$"})
    assert time.monotonic() - t0 < 10
    assert "Invalid search pattern" in r["error"]
    assert is_semantic_tool_error({"tool": "search_source", "result": r})


def test_an_uncompilable_pattern_is_a_model_error_not_a_dead_tool(tools):
    r = tools.call("search_source", {"pattern": "LateGet("})
    assert "Invalid search pattern" in r["error"]
    entry = {"tool": "search_source", "args": {}, "result": r}
    assert is_semantic_tool_error(entry) and not is_transport_tool_error(entry)


# --- get_source_lines -----------------------------------------------------------------

def test_source_lines_read_around_a_reported_line(tools):
    line = tools.call("search_source", {"pattern": shape.LOAD_LINE_MARK})["hits"][0]["line"]
    r = tools.call("get_source_lines", {"start_line": line - 2, "end_line": line + 2})
    assert shape.LOAD_LINE_MARK in r["source"] and r["truncated"] is False
    assert r["location"] == IGNITE


def test_source_lines_are_bounded(tools):
    r = tools.call("get_source_lines", {"start_line": 100, "end_line": 900})
    assert r["end_line"] - r["start_line"] + 1 <= LINES_MAX
    assert len(r["source"]) <= SOURCE_PAGE_CHARS
    assert r["truncated"] is True and "TRUNCATED" in r["note"]


# --- negative answers, and the eval's reading of them ---------------------------------

@pytest.mark.parametrize("tool,args", [
    ("get_method_source", {"class_name": "BattleForm", "method_name": "NoSuchMethod"}),
    ("get_method_source", {"class_name": "NoSuchClass", "method_name": "Ignite"}),
    ("list_methods", {"class_name": "NoSuchClass"}),
    ("get_source_lines", {"start_line": 10_000_000, "end_line": 10_000_000}),
])
def test_not_found_is_an_answer_not_a_broken_tool_layer(tools, tool, args):
    """llm_ab_re voids a cell whose tool errors look like TRANSPORT failures. A
    model asking for a method that is not there is the measurement (#631)."""
    r = tools.call(tool, args)
    assert NOT_FOUND in r["error"]
    entry = {"tool": tool, "args": args, "result": r}
    assert is_semantic_tool_error(entry) and not is_transport_tool_error(entry)


def test_a_truncated_source_says_its_coverage_in_negative_answers():
    """The analyser keeps 100,000 characters of a larger decompilation. "Not
    found" must not read as "absent from the program" then."""
    tb = DotnetToolbox(shape.formbook_shaped_source(truncate_at=60_000),
                       analyser_truncated=True, source_bytes_total=4_468_045)
    r = tb.call("get_method_source", {"class_name": "BattleForm", "method_name": "Nope"})
    assert "4,468,045" in r["coverage_note"]


def test_a_method_cut_off_by_the_analyser_is_still_readable():
    """Truncation lands mid-method with no closing braces; the partial method
    must still be fetchable rather than vanish from the index."""
    cut = shape.formbook_shaped_source(truncate_at=20_000)
    tb = DotnetToolbox(cut, analyser_truncated=True, source_bytes_total=len(SRC))
    r = tb.call("get_method_source", {"class_name": "BattleForm",
                                      "method_name": shape.DECOY_METHOD})
    assert "error" not in r and r["total_chars"] > 15_000


# --- argument validation ---------------------------------------------------------------

@pytest.mark.parametrize("tool,args", [
    ("decompile_function", {"name": "main"}),                 # a Ghidra tool
    ("get_method_source", {"class_name": "A"}),               # missing method_name
    ("get_method_source", {"class_name": "A", "method_name": "B", "page": -1}),
    ("get_method_source", {"class_name": "A" * 201, "method_name": "B"}),
    ("get_class_source", {"class_name": "A\nB"}),
    ("search_source", {"pattern": ""}),
    ("search_source", {"pattern": "x" * 201}),
    ("search_source", {"pattern": "x", "max_hits": 0}),
    ("search_source", {"pattern": "x", "context_lines": 9}),
    ("get_source_lines", {"start_line": 0, "end_line": 5}),
    ("get_source_lines", {"start_line": "ten", "end_line": 5}),
])
def test_bad_arguments_are_refused_before_anything_runs(tool, args):
    assert validate_dotnet_args(tool, args) is not None


def test_good_arguments_pass():
    assert validate_dotnet_args("search_source", {"pattern": '"Load"', "max_hits": 50}) is None
    assert validate_dotnet_args("list_classes", {}) is None


# --- masking ------------------------------------------------------------------------

def test_braces_in_strings_chars_and_comments_do_not_shift_spans():
    """The fixture puts `{` and `}` in a regular string, a verbatim string with
    doubled quotes, an interpolated string with an escaped brace, a char
    literal and a comment. Counted, any of them would end BattleForm early and
    move every method after it."""
    masked = mask_source(SRC)
    assert len(masked) == len(SRC)
    assert masked.count("\n") == SRC.count("\n")
    idx = CSharpIndex(SRC)
    t = idx.find_types("BattleForm")[0]
    names = [m.name for m in t.members]
    assert names == ["BattleForm", "Animatsiya", "Ignite", "Sarlavha", "VirtualAlloc",
                     "InitializeComponent"]
    assert SRC[t.end - 1] == "}" and idx.line_of(t.end - 1) > idx.line_of(
        next(m for m in t.members if m.name == "InitializeComponent").end - 1)


def test_compiler_generated_type_names_parse():
    """quasarrat's stored source is a single `internal class <Module>`; a
    plain-identifier pattern parsed that file as zero types."""
    idx = CSharpIndex("internal class <Module>\n{\n\tstatic <Module>()\n\t{\n\t}\n"
                      "\tinternal static void M<T>(T x)\n\t{\n\t}\n}\n")
    t = idx.find_types("<Module>")[0]
    assert [m.name for m in t.members] == ["<Module>", "M"]


# --- the payload -------------------------------------------------------------------------

def test_the_agent_payload_is_a_map_not_the_source():
    init = build_dotnet_agentic_init(shape.dotnet_analysis(SRC), {}, [])
    sent = agent_payload(init)
    assert "decompiled_source" in init, "the orchestrator needs the source to serve tools"
    assert "decompiled_source" not in sent
    text = json.dumps(sent)
    assert shape.DECOY_MARK not in text
    assert len(text) < 0.25 * len(SRC)
    assert sent["suspicious_constructs"]["locations"][0]["location"] == IGNITE
    toc_ignite = [m for c in sent["table_of_contents"]["classes"]
                  for m in c["members"] if m["name"] == "Ignite"]
    assert toc_ignite and toc_ignite[0]["sig"] == "void Ignite()"
    assert sent["assembly"]["entry_points"] == ["CardBattle.Program.Main"]


def test_the_single_shot_payload_is_unchanged():
    from stages.single_shot_init import build_dotnet_init
    d = shape.dotnet_analysis(SRC)
    assert build_dotnet_interpret_init(d, {}, [], "single_shot") == build_dotnet_init(d, {}, [])
    assert "decompiled_source" in agent_payload(build_dotnet_init(d, {}, []))


def test_an_unknown_mode_is_refused():
    with pytest.raises(ValueError):
        build_dotnet_interpret_init(shape.dotnet_analysis(SRC), {}, [], "agentc")
