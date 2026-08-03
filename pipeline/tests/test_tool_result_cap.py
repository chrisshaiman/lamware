# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The tool-result cap must bound the whole result, not just string fields (#242).

The original capped only `isinstance(value, str)`, so a LIST-valued result was never
bounded. Measured on the 2026-07-28 qwen@30 run: `get_strings_at` returned **49,613
bytes against a 12,000-char cap**, and the turn carrying it cost 33.4 minutes of a
180-minute run. Many short string fields whose total was large escaped the same way.

Two properties are non-negotiable and both are asserted here:

  1. The total serialized result stays within budget, whatever shape it is.
  2. Truncation is never silent. A model that receives half a function assumes it saw
     all of it and makes claims about code it was never shown — which the grounding
     metric then scores as fabrication when the harness dropped the evidence.
"""
import json
import string
import sys
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from stages.interpret import TOOL_RESULT_CHAR_CAP, cap_tool_result  # noqa: E402

CAP = 2000  # small cap keeps the fixtures readable


def _size(result: dict) -> int:
    return len(json.dumps(result, default=str))


def test_the_regression_case_list_valued_results_are_bounded():
    """get_strings_at shape: the exact result that returned 49.6KB uncapped."""
    result = {"address": "0x0041b500", "strings": ["s" * 120 for _ in range(400)]}
    capped = cap_tool_result(result, CAP)
    assert _size(capped) <= CAP * 1.2, (
        f"list result still {_size(capped)}B against a {CAP} cap — this is #242")
    assert len(capped["strings"]) < 400


def test_many_small_string_fields_are_bounded_in_total():
    """No single field exceeds the cap, but the total did — also previously uncapped."""
    result = {f"field_{i}": "x" * 500 for i in range(20)}
    capped = cap_tool_result(result, CAP)
    assert _size(capped) <= CAP * 1.2


def test_single_huge_string_is_still_truncated():
    result = {"code": "x" * 50000}
    capped = cap_tool_result(result, CAP)
    assert len(capped["code"]) < 50000
    assert "TRUNCATED" in capped["code"]


def test_truncation_is_never_silent():
    for result in (
        {"code": "x" * 50000},
        {"strings": ["s" * 100 for _ in range(500)]},
    ):
        capped = cap_tool_result(result, CAP)
        blob = json.dumps(capped)
        assert "TRUNCATED" in blob, f"silent truncation for {list(result)}"


def test_dropped_element_count_is_reported():
    """'kept 3 of 400' is actionable; a silently short list is not."""
    result = {"strings": ["s" * 200 for _ in range(400)]}
    capped = cap_tool_result(result, CAP)
    assert "note" in capped
    assert "of 400" in capped["note"]
    assert str(len(capped["strings"])) in capped["note"]


def test_lists_are_trimmed_by_whole_elements():
    """Cutting mid-element would hand the model a malformed entry to interpret."""
    result = {"functions": [{"name": f"FUN_{i:08x}", "xrefs": i} for i in range(500)]}
    capped = cap_tool_result(result, CAP)
    for item in capped["functions"]:
        assert isinstance(item, dict)
        assert "name" in item and "xrefs" in item


def test_metadata_survives_a_huge_payload():
    """A truncated result must stay interpretable."""
    result = {"address": "0x0041b500", "count": 400, "status": "ok",
              "strings": ["s" * 500 for _ in range(200)]}
    capped = cap_tool_result(result, CAP)
    assert capped["address"] == "0x0041b500"
    assert capped["count"] == 400
    assert capped["status"] == "ok"


def test_metadata_size_is_charged_against_the_budget():
    """Metadata is copied through unconditionally, so its SIZE must be subtracted or the
    total silently exceeds the cap.

    Written after a negative check found the previous metadata test could not fail:
    it asserted the fields survive, which `out = dict(small)` guarantees whether or not
    the budget accounts for them. The property that can actually break is the total.
    """
    # Short strings and scalars alike — both are metadata, both are copied through
    # unconditionally, so both must be charged against the budget.
    bulky_metadata = {f"meta_{i}": "m" * 100 for i in range(10)}   # ~1,000 chars
    bulky_metadata.update({f"n_{i}": i for i in range(10)})
    result = {**bulky_metadata, "code": "x" * 50000}
    capped = cap_tool_result(result, CAP)
    assert _size(capped) <= CAP * 1.2, (
        f"total {_size(capped)}B exceeds the {CAP} cap — metadata size is not being "
        f"charged against the payload budget")


def test_small_results_are_untouched():
    """No-op below budget, so cloud-model behaviour is unchanged."""
    result = {"code": "int main(){return 0;}", "status": "ok"}
    assert cap_tool_result(result, CAP) == result


def test_existing_note_is_preserved():
    result = {"note": "list truncated to top 200 by xref", "code": "x" * 50000}
    capped = cap_tool_result(result, CAP)
    assert "top 200 by xref" in capped["note"]
    assert "TRUNCATED" in capped["note"]


def test_non_dict_results_pass_through():
    assert cap_tool_result("plain string", CAP) == "plain string"
    assert cap_tool_result(None, CAP) is None


def test_idempotent():
    result = {"strings": ["s" * 200 for _ in range(400)]}
    once = cap_tool_result(result, CAP)
    twice = cap_tool_result(once, CAP)
    assert _size(twice) <= _size(once)


def test_production_cap_is_sane():
    assert 2000 <= TOOL_RESULT_CHAR_CAP <= 20000


def test_serialized_result_fits_the_cap_including_container_overhead():
    """The cap must bound the number a CALLER measures, not an internal sum (#242).

    Measured 2026-08-02 on a live deep run: a decompile_function result recorded
    12,064 B against a 12,000 cap, carrying no truncation marker. The cap had budgeted
    the sum of field contents; the trail recorded json.dumps() of the whole object.
    Those differ by the dict's own serialization — braces, quoted keys, colons, commas
    — plus the quotes and escape expansion on every string.

    64 B is harmless. A cap that bounds a different quantity than the one anyone
    observes is not: #242's acceptance criterion was written in the units the cap did
    not control, so it could never be satisfied exactly.
    """
    result = {
        "code": "int main() {\n    return 0;\n}\n" * 900,   # newlines: 1 char -> 2 in JSON
        "strings": ["evil.example/c2" * 40 for _ in range(60)],
        "address": "0x0041b500",
        "status": "ok",
    }
    capped = cap_tool_result(result, cap=TOOL_RESULT_CHAR_CAP)
    serialized = len(json.dumps(capped, default=str))
    assert serialized <= TOOL_RESULT_CHAR_CAP, (
        f"serialized result is {serialized} B against a {TOOL_RESULT_CHAR_CAP} cap — "
        f"the cap must budget its own container serialization and string escaping, "
        f"or it bounds a number nobody can observe")


def test_many_small_keys_is_where_the_overhead_gap_is_widest():
    """Structural cost scales with FIELD COUNT, not payload size.

    A result of many short keys is the adversarial case: each one contributes quotes,
    a colon and a comma that the old per-field accounting never counted.
    """
    result = {f"field_{i:03d}": f"value {i}" for i in range(120)}
    result["code"] = "A" * 40000
    capped = cap_tool_result(result, cap=TOOL_RESULT_CHAR_CAP)
    assert len(json.dumps(capped, default=str)) <= TOOL_RESULT_CHAR_CAP


def test_escape_heavy_payload_still_fits():
    """Quotes and backslashes double under JSON encoding; decompilation is full of both."""
    result = {"code": '"\\' * 9000, "status": "ok"}
    capped = cap_tool_result(result, cap=TOOL_RESULT_CHAR_CAP)
    assert len(json.dumps(capped, default=str)) <= TOOL_RESULT_CHAR_CAP


# ---------------------------------------------------------------------------
# Property: the invariant, not the examples
# ---------------------------------------------------------------------------

_KEYS = st.text(alphabet=string.ascii_lowercase + "_", min_size=1, max_size=12)
_PAYLOAD = st.one_of(
    st.text(max_size=3000),                       # quotes/backslashes/newlines included
    st.lists(st.text(max_size=200), max_size=60),
    st.integers(),
    st.none(),
)


@settings(max_examples=250, deadline=None)
@given(result=st.dictionaries(_KEYS, _PAYLOAD, min_size=1, max_size=25),
       cap=st.integers(min_value=1200, max_value=20000))
def test_capped_result_never_exceeds_its_cap_when_serialized(result, cap):
    """For ANY result and any cap: json.dumps(capped) fits.

    The examples above encode the two shapes that were actually wrong — container
    overhead and escape expansion. This encodes the rule they are instances of, which
    is what stops the next unconsidered shape from slipping through. Hypothesis is
    free to find the field counts, key lengths and escape densities that hurt most.
    """
    capped = cap_tool_result(result, cap=cap)
    assert len(json.dumps(capped, default=str)) <= cap


@settings(max_examples=150, deadline=None)
@given(result=st.dictionaries(_KEYS, _PAYLOAD, min_size=1, max_size=15))
def test_capping_is_idempotent(result):
    """Capping an already-capped result must not keep shrinking or keep growing.

    The function's own comment records a bug where the note was appended after
    budgeting, so a second pass grew the result each time. That is a property, and
    properties are cheaper to hold than to re-derive.
    """
    once = cap_tool_result(result, cap=TOOL_RESULT_CHAR_CAP)
    twice = cap_tool_result(once, cap=TOOL_RESULT_CHAR_CAP)
    assert len(json.dumps(twice, default=str)) <= TOOL_RESULT_CHAR_CAP
    assert set(twice) == set(once), "capping must not add or drop keys on a second pass"
