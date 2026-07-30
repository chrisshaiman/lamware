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
import sys
from pathlib import Path

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
