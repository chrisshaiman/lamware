# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""derive_flow on real reports: each of this week's silent hand-off bugs must show (#653).

The fixtures in fixtures/flow/ are real report.json files from the sandbox,
trimmed to the keys api/app/flow.py reads (no code, strings, IOCs, network data,
model output or CAPE paths). Each test names the bug it would have shown:

    rednat_179dcccf0614  cobaltstrike before #648: payload programs erased
    v648_179dcccf0614    the same sample after #648
    v651_5b4f596d3cf5    formbook, .NET routed, payloads via #646's branch
    rednat_d22c96565d26  latrodectus: Ghidra import of the original failed (#647)
    rednat_25d18a2bf31f  a native sample, original analysed via #644's copy

These are behavioural tests: they call the function on recorded data.
"""
import copy
import json
from pathlib import Path

import pytest
from app.flow import ABSENT, FAILED, OK, ROUTED_ANALYSERS, SKIPPED, derive_flow

FIXTURES = Path(__file__).parent / "fixtures" / "flow"


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def node(flow: dict, node_id: str) -> dict:
    return next(n for n in flow["nodes"] if n["id"] == node_id)


def edge(flow: dict, edge_id: str) -> dict:
    return next(e for e in flow["edges"] if e["id"] == edge_id)


FORMBOOK = "v651_5b4f596d3cf5"
COBALT_BEFORE_648 = "rednat_179dcccf0614"
COBALT_AFTER_648 = "v648_179dcccf0614"
LATRODECTUS = "rednat_d22c96565d26"
NATIVE = "rednat_25d18a2bf31f"
ALL = [FORMBOOK, COBALT_BEFORE_648, COBALT_AFTER_648, LATRODECTUS, NATIVE]


# --- formbook: routed to ILSpy, payloads through Ghidra (#646) --------------

def test_formbook_original_is_skipped_because_it_was_routed_to_ilspy():
    e = edge(derive_flow(load(FORMBOOK)), "sample-ghidra")
    assert e["status"] == SKIPPED
    assert "routed to ILSpy" in e["reason"]
    assert e["carried"] == 0


def test_formbook_cape_to_ghidra_carries_the_formbook_payload():
    e = edge(derive_flow(load(FORMBOOK)), "cape-ghidra-payloads")
    assert e["status"] == OK
    assert (e["expected"], e["carried"]) == (5, 5)
    fb = [i for i in e["items"] if i["label"] == "Formbook Payload"]
    assert len(fb) == 1
    assert fb[0]["status"] == "loaded" and fb[0]["functions"] == 377


def test_formbook_shows_that_most_cape_payloads_were_never_forwarded():
    """CAPE extracted 20; run-pipeline forwards the five largest ≥ 1 KB."""
    e = edge(derive_flow(load(FORMBOOK)), "cape-ghidra-payloads")
    assert e["extracted"] == 20
    assert e["not_forwarded"] == 15


def test_formbook_agent_read_the_unlabelled_payload_not_the_formbook_one():
    """v651 predates 7ac9807: the agent read the biggest program. The flow must
    show which, since that is the bug 7ac9807 fixes."""
    flow = derive_flow(load(FORMBOOK))
    e = edge(flow, "ghidra-re_agent")
    assert e["status"] == OK
    [item] = e["items"]
    assert item["label"] == "(unlabelled)"
    assert item["functions"] == 4064
    assert item["sha256"] == "47d96441be8b"
    assert "not recorded" in e["reason"]
    wrapper = edge(flow, "ilspy-re_agent")
    assert wrapper["status"] == SKIPPED
    assert node(flow, "ilspy")["role"] == "wrapper"


# --- cobaltstrike: #648 erased payload programs -----------------------------

def test_cobaltstrike_before_648_shows_the_lost_programs():
    e = edge(derive_flow(load(COBALT_BEFORE_648)), "cape-ghidra-payloads")
    assert e["status"] == FAILED
    lost = sorted(i["sha256"] for i in e["items"] if i["status"] == "lost")
    assert lost == ["41de0aed8bb1", "c8cb49d3b4e4"]
    assert all(i["functions"] == 940 for i in e["items"] if i["status"] == "lost")
    # A lost program is not carried: it claims functions nobody can open.
    assert e["carried"] == 3
    assert "2 lost of 5" in e["reason"]


def test_cobaltstrike_after_648_carries_all_five():
    e = edge(derive_flow(load(COBALT_AFTER_648)), "cape-ghidra-payloads")
    assert e["status"] == OK
    assert (e["expected"], e["carried"]) == (5, 5)
    assert e["counts"] == {"loaded": 5}


# --- latrodectus: the import failed and the note blamed the export (#647) ----

def test_latrodectus_original_failed_with_the_import_error():
    e = edge(derive_flow(load(LATRODECTUS)), "sample-ghidra")
    assert e["status"] == FAILED
    assert "Import failed" in e["reason"]
    assert "ExportAnalysis" not in e["reason"], "the misleading note must not win"
    [item] = e["items"]
    assert item["status"] == "failed"
    assert (e["expected"], e["carried"]) == (1, 0)


def test_latrodectus_payloads_still_reached_ghidra():
    e = edge(derive_flow(load(LATRODECTUS)), "cape-ghidra-payloads")
    assert e["status"] == OK
    assert e["counts"] == {"loaded": 4}


def test_latrodectus_volatility_skipped_with_its_recorded_reason():
    flow = derive_flow(load(LATRODECTUS))
    assert node(flow, "volatility")["status"] == SKIPPED
    assert "did not match Volatility triggers" in node(flow, "volatility")["reason"]
    assert edge(flow, "volatility-ghidra")["status"] == SKIPPED


# --- native sample ---------------------------------------------------------

def test_native_sample_original_loaded_from_the_pipeline_copy():
    e = edge(derive_flow(load(NATIVE)), "sample-ghidra")
    assert e["status"] == OK
    [item] = e["items"]
    assert item["status"] == "loaded" and item["functions"] == 2384
    assert item["source"] == "pipeline_copy"
    assert "#644" in e["note"]


def test_native_injection_buffers_are_skipped_not_missing():
    e = edge(derive_flow(load(NATIVE)), "cape-ghidra-injections")
    assert e["status"] == SKIPPED
    assert e["expected"] == 43 and e["carried"] == 0
    assert "Artifact extraction only" in e["reason"]


# --- dropper: the original alongside its dropped PEs (#649) -----------------

def _cobalt_after_649() -> dict:
    """rednat_179dcccf0614 as #649's run_ghidra would record it: the beacon
    first in analyzed_files, then the dropped 781f65c7."""
    r = copy.deepcopy(load(COBALT_BEFORE_648))
    g = r["ghidra"]
    g["original_sample_included"] = True
    g["original_sample_source"] = "cape_storage"
    sha = "179dcccf0614" + "0" * 52
    g["analyzed_files"].insert(0, {"program_name": sha, "sha256": sha, "filename": sha,
                                   "functions_count": 300, "analysis_success": True})
    return r


def test_a_dropper_before_649_shows_the_original_was_skipped():
    e = edge(derive_flow(load(COBALT_BEFORE_648)), "sample-ghidra")
    assert e["status"] == SKIPPED
    assert "before #649" in e["reason"]


def test_a_dropper_after_649_shows_the_original_loaded():
    flow = derive_flow(_cobalt_after_649())
    e = edge(flow, "sample-ghidra")
    assert e["status"] == OK, e
    [item] = e["items"]
    assert item["functions"] == 300 and item["source"] == "cape_storage"
    dropped = edge(flow, "cape-ghidra-dropped")
    assert [i["functions"] for i in dropped["items"] if i.get("functions")] == [928], (
        "the original was counted as a dropped PE")


def test_a_native_canonical_input_names_the_program_read():
    """Since the owner's decision on #649 the native path reads the canonical
    program and records it in llm_interpretation.input."""
    r = _cobalt_after_649()
    r["llm_interpretation"] = {**(r.get("llm_interpretation") or {}), "input": {
        "kind": "canonical", "program_name": "781f65c7f109f41c03974d5af8df05ef5d32eb47bd665fff2c1033bd033a1c00",
        "source": "dropped_pe", "functions_count": 928, "cape_type": None,
        "chosen_because": "canonical"}}
    r["llm_interpretation"].pop("error", None)
    e = edge(derive_flow(r), "ghidra-re_agent")
    assert e["status"] == OK and e["reason"] == "canonical"
    [item] = e["items"]
    assert item["kind"] == "canonical" and item["functions"] == 928
    assert item["sha256"] == "781f65c7f109"


def test_a_native_input_that_is_the_original_is_labelled_so():
    r = _cobalt_after_649()
    r["llm_interpretation"] = {**(r.get("llm_interpretation") or {}), "input": {
        "kind": "canonical", "program_name": "179dcccf0614" + "0" * 52,
        "source": "original_sample", "functions_count": 300, "cape_type": None,
        "chosen_because": "canonical"}}
    r["llm_interpretation"].pop("error", None)
    flow = derive_flow(r)
    [item] = edge(flow, "ghidra-re_agent")["items"]
    assert item["label"] == "original sample"
    # Edges into the agent from a routed analyser. Not "every *-re_agent edge but
    # Ghidra's": #674 added correlation-re_agent, which is not a wrapper edge.
    routed_nodes = {node_id for _f, _k, node_id, _l in ROUTED_ANALYSERS}
    assert not [e for e in flow["edges"] if e["to"] == "re_agent"
                and e["from"] in routed_nodes], "a native read drew a wrapper edge"


def test_a_dropper_whose_original_could_not_be_loaded_says_why():
    r = load(COBALT_BEFORE_648)
    r["ghidra"]["original_sample_included"] = False
    r["ghidra"]["original_sample_note"] = "pipeline's copy is a DIFFERENT file"
    e = edge(derive_flow(r), "sample-ghidra")
    assert e["status"] == SKIPPED
    assert "DIFFERENT file" in e["reason"]


# --- absent is never zero ---------------------------------------------------

def test_a_key_the_report_does_not_have_is_absent_not_zero():
    """rednat_179 predates cape.injection_buffers. "0 buffers" would be a claim
    the report never made."""
    e = edge(derive_flow(load(COBALT_BEFORE_648)), "cape-ghidra-injections")
    assert e["status"] == ABSENT
    assert e["carried"] is None and e["expected"] is None and e["items"] is None


def test_an_empty_report_is_absent_everywhere():
    flow = derive_flow({})
    assert {n["status"] for n in flow["nodes"]} == {ABSENT}
    assert {e["status"] for e in flow["edges"]} == {ABSENT}
    assert all(e["carried"] is None and e["expected"] is None for e in flow["edges"])


@pytest.mark.parametrize("name", ALL)
def test_every_absent_edge_has_no_count(name):
    for e in derive_flow(load(name))["edges"]:
        if e["status"] == ABSENT:
            assert e["carried"] is None, e["id"]
            assert e["reason"], f"{e['id']} is absent without saying why"


@pytest.mark.parametrize("name", ALL)
def test_every_non_ok_edge_says_why(name):
    for e in derive_flow(load(name))["edges"]:
        if e["status"] != OK:
            assert e["reason"], e["id"]


# --- silent drops ----------------------------------------------------------

def test_a_payload_with_no_ghidra_result_is_missing_and_fails_the_edge():
    r = load(COBALT_AFTER_648)
    r["ghidra"]["analyzed_files"] = [f for f in r["ghidra"]["analyzed_files"]
                                     if not str(f.get("sha256", "")).startswith("77887c827e75")]
    e = edge(derive_flow(r), "cape-ghidra-payloads")
    assert e["status"] == FAILED
    missing = [i for i in e["items"] if i["status"] == "missing"]
    assert [i["sha256"] for i in missing] == ["77887c827e75"]
    assert e["carried"] == 4


def test_a_routed_sample_before_646_shows_its_payloads_were_never_sent():
    """The shape main's run-pipeline writes for a routed sample: the flag and
    an empty list. formbook's payloads existed and went nowhere."""
    r = load(FORMBOOK)
    r["ghidra"] = {"triggered": True, "dotnet_routed": True, "analyzed_files": []}
    del r["llm_interpretation"]["input"]
    flow = derive_flow(r)
    e = edge(flow, "cape-ghidra-payloads")
    assert e["status"] == SKIPPED
    assert "never sent to Ghidra" in e["reason"]
    assert e["expected"] == 5 and e["carried"] == 0
    assert node(flow, "ghidra")["status"] == SKIPPED
    # Without a recorded input, the agent edge is inferred, and says so.
    agent = edge(flow, "ilspy-re_agent")
    assert agent["status"] == OK and agent["inferred"] is True
    assert edge(flow, "ghidra-re_agent")["status"] == SKIPPED


# --- behavioural evidence shown to the agent (#674) --------------------------

def _with_evidence_record(rec: dict | None) -> dict:
    r = copy.deepcopy(load(NATIVE))
    inp = {"kind": "canonical", "program_name": "25d18a2bf31f" + "0" * 52,
           "source": "original_sample", "functions_count": 10, "chosen_because": "canonical"}
    if rec is not None:
        inp["correlated_evidence"] = rec
    r["llm_interpretation"]["input"] = inp
    return r


def test_evidence_the_agent_was_given_is_drawn_with_its_sections():
    rec = {"given": True, "keys": ["cape_signatures", "volatility_insights"], "bytes": 4119,
           "counts": {"cape_signatures": 24, "volatility_insights": 4}}
    e = edge(derive_flow(_with_evidence_record(rec)), "correlation-re_agent")
    assert (e["from"], e["to"], e["status"]) == ("correlation", "re_agent", OK)
    assert [i["label"] for i in e["items"]] == ["cape_signatures", "volatility_insights"]
    assert e["carried"] == 2 and e["expected"] == 2 and e["bytes"] == 4119


@pytest.mark.parametrize("reason, says", [
    ("disabled_by_config", "interpret_correlated_evidence is false"),
    ("single_shot_path", "single-shot"),
    ("report_has_none", "no signatures"),
    ("something_new", "not given: something_new"),
])
def test_evidence_not_given_is_skipped_with_the_recorded_reason(reason, says):
    e = edge(derive_flow(_with_evidence_record({"given": False, "reason": reason})),
             "correlation-re_agent")
    assert e["status"] == SKIPPED and e["carried"] == 0
    assert says in e["reason"]


def test_a_report_from_before_674_is_absent_not_skipped():
    """Unknown is not "no": these reports never recorded what the agent saw."""
    for r in (load(NATIVE), _with_evidence_record(None)):
        e = edge(derive_flow(r), "correlation-re_agent")
        assert e["status"] == ABSENT and e["carried"] is None
        assert "predates #674" in e["reason"]


def test_no_agent_run_means_no_evidence_edge_claim():
    r = copy.deepcopy(load(NATIVE))
    r["llm_interpretation"] = {"enabled": True, "reason": "no_analysis_data"}
    assert edge(derive_flow(r), "correlation-re_agent")["status"] == SKIPPED
    r.pop("llm_interpretation")
    assert edge(derive_flow(r), "correlation-re_agent")["status"] == ABSENT


# --- the response is derived, never the report ------------------------------

def test_the_raw_report_does_not_leak_into_the_flow():
    r = copy.deepcopy(load(NATIVE))
    marker = "SECRET_DECOMPILED_BODY_7f3a"
    r["ghidra"]["analyzed_files"][0]["decompiled_functions"] = [{"code": marker}]
    r["ghidra"]["analyzed_files"][0]["strings_of_interest"] = [marker]
    r["executive_summary"] = marker
    assert marker not in json.dumps(derive_flow(r))


def test_attacker_controlled_labels_are_capped():
    r = load(COBALT_AFTER_648)
    r["cape"]["large_payloads"][0]["cape_type"] = "<img src=x onerror=alert(1)>" + "A" * 5000
    label = edge(derive_flow(r), "cape-ghidra-payloads")["items"][0]["label"]
    assert label.startswith("<img src=x onerror=alert(1)>")
    assert len(label) <= 300


def test_non_dict_sections_do_not_crash():
    flow = derive_flow({"cape": "oops", "ghidra": ["x"], "llm_interpretation": 3,
                        "triage": None, "cross_correlations": "no"})
    assert node(flow, "cape")["status"] == ABSENT
    assert node(flow, "ghidra")["status"] == ABSENT
