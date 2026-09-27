# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The agent's payload must not carry host paths (#634).

#634 fixed the leak through the detonated filename — samples were submitted as
`WarmCookie_36b43e83.exe`, so the guest wrote our label into its own command
lines. This closes the remaining route, which no naming convention can reach
because the corpus directory is itself named after the family:

    analyzed_files[].project_dir      /opt/pipeline/reports/eval-amadey-573e6860/project
    analyzed_files[].host_output_dir  /opt/pipeline/reports/redet_179dcccf0614
    project_dir                       /opt/pipeline/eval-corpus/amadey_573e6860/project

Those three are the only path-shaped keys in a ghidra_result, measured across
every corpus report rather than assumed.

Severity, stated honestly: BOTH arms of the #420 comparison saw these equally, so
this never biased that A/B — unlike the filename leak, which was in behavioural
evidence only. It still hands a family label to a model asked to derive one, and
it inflates absolute capability numbers for every arm alike.

`run_interpret` is the single choke point: the pipeline and the eval harness both
call it, so sanitising there covers both rather than leaving one path to drift
(#380).
"""
import json

import pytest
from stages.interpret import run_interpret, without_host_paths

LEAKY = {
    "program_name": "573e68608bbb",
    "functions_count": 336,
    "project_dir": "/opt/pipeline/eval-corpus/amadey_573e6860/project",
    "analyzed_files": [
        {"program_name": "p1", "functions_count": 5,
         "project_dir": "/opt/pipeline/reports/eval-WarmCookie-36b43e83/project",
         "host_output_dir": "/opt/pipeline/reports/redet_quasarrat"},
    ],
    "decompiled_functions": [{"name": "entry", "code": "void entry(void){}"}],
}


def test_no_family_name_survives_in_the_payload():
    """The property that matters, asserted on the output rather than the keys."""
    text = json.dumps(without_host_paths(LEAKY)).lower()
    for family in ("amadey", "warmcookie", "quasarrat"):
        assert family not in text, f"{family} still reachable by the agent"


@pytest.mark.parametrize("key", ["project_dir", "host_output_dir"])
def test_the_path_keys_are_removed_not_blanked(key):
    """An empty string still tells the agent a path existed. Absence does not."""
    out = without_host_paths(LEAKY)
    assert key not in out
    assert all(key not in af for af in out["analyzed_files"])


def test_the_analysis_data_is_untouched():
    """Stripping paths must not cost the agent anything it can use."""
    out = without_host_paths(LEAKY)
    assert out["functions_count"] == 336
    assert out["program_name"] == "573e68608bbb"
    assert out["decompiled_functions"] == LEAKY["decompiled_functions"]
    assert out["analyzed_files"][0]["functions_count"] == 5


def test_the_callers_dict_is_not_mutated():
    """run-pipeline writes ghidra_result into the report AFTER this call, and the
    report SHOULD keep the paths — repair_ghidra_pairing.py needs them to find the
    project (#490). Mutating in place would silently break that tool."""
    before = json.dumps(LEAKY, sort_keys=True)
    without_host_paths(LEAKY)
    assert json.dumps(LEAKY, sort_keys=True) == before


@pytest.mark.parametrize("payload", [{}, {"analyzed_files": None},
                                     {"analyzed_files": []}, {"analyzed_files": ["odd"]}])
def test_degenerate_payloads_do_not_raise(payload):
    """This runs on every analysis, including failed ones with a near-empty dict."""
    without_host_paths(payload)


def test_a_non_dict_passes_through():
    assert without_host_paths(None) is None


def test_run_interpret_sanitises_before_sending():
    """The function existing is not the fix; being CALLED on the payload is.

    Asserted on the source of the payload-building statement, because reaching
    the stdin write needs a live interpret container. Anchored on the assignment
    rather than the word, so the explanatory comment above it cannot satisfy it.
    """
    import inspect

    src = inspect.getsource(run_interpret)
    line = next(ln for ln in src.splitlines() if '"ghidra_data"' in ln)
    assert "without_host_paths(" in line, line


def test_the_tool_executor_still_gets_the_real_path():
    """The host runs Ghidra with its own local, taken BEFORE sanitising. If that
    ever reads from the payload instead, every tool call breaks."""
    import inspect

    src = inspect.getsource(run_interpret)
    assign = next(ln for ln in src.splitlines()
                  if "project_dir = ghidra_result.get" in ln)
    assert "without_host_paths" not in assign, assign
