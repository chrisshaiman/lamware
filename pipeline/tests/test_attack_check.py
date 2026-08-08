# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""ATT&CK ID/name validation (#318).

Nothing scored technique claims: `grounding_check` covers `code_level_iocs` only and
has no view of the catalog, so a cell could carry five fabricated mappings and still
report `grounded_ratio: 1.000`.

Every claimed pair below is VERBATIM from `depth-10-vs-15-n7` (2026-08-07). A check
that passes on invented examples but not on the output that motivated it is worthless.

The catalog is a data file, not a table in code, because writing one from memory is
the same failure the check exists to catch — demonstrated during design, when
`T1055.003` was asserted to be Process Hollowing. It is Thread Execution Hijacking.
Hence `unknown_id` is never an accusation: a short catalog under-reports, a wrong one
misleads, and only the second is unrecoverable.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"
sys.path.insert(0, str(FILES))

from attack_check import (  # noqa: E402
    check_techniques,
    id_name_conflicts,
    load_catalog,
)

CAT = load_catalog()

# Verbatim: raccoonstealer / qwen@15
RACCOON_15 = [
    {"id": "T1055.001", "name": "Process Memory Dumping"},
    {"id": "T1027.001", "name": "Obfuscated Files or Information"},
    {"id": "T1036.004", "name": "Windows Service"},
    {"id": "T1059.001", "name": "PowerShell"},
    {"id": "T1053.005", "name": "Service (Windows)"},
]

# Verbatim: icedid / claude-sonnet-5 — the full `Parent: Sub` presentation
CLAUDE_ICEDID = [
    {"id": "T1027.003", "name": "Obfuscated Files or Information: Steganography"},
    {"id": "T1140", "name": "Deobfuscate/Decode Files or Information"},
    {"id": "T1105", "name": "Ingress Tool Transfer"},
    {"id": "T1027.007", "name": "Obfuscated Files or Information: Dynamic API Resolution"},
]


def test_the_real_mismatches_are_caught():
    """Four of five wrong on the cell that motivated this."""
    res = check_techniques(RACCOON_15, CAT)
    assert len(res["mismatched"]) == 4, res["mismatched"]
    assert res["ok"] == 1, "T1059.001 PowerShell is correctly named"
    joined = " ".join(res["mismatched"])
    assert "Dynamic-link Library Injection" in joined
    assert "Scheduled Task" in joined


def test_a_parent_name_on_a_subtechnique_is_called_out_separately():
    """Distinct signal: the family was right and the `.00N` was invented."""
    res = check_techniques(RACCOON_15, CAT)
    assert any("T1027.001" in d for d in res["parent_name"]), res["parent_name"]


def test_the_full_parent_colon_sub_form_is_accepted():
    """Claude writes the full path. That is CORRECT and must not score as a
    mismatch — a false positive here would flag the better model as the worse one."""
    res = check_techniques(CLAUDE_ICEDID, CAT)
    assert res["mismatched"] == [], res["mismatched"]
    assert res["ok"] == 4


def test_an_unknown_id_is_not_called_a_fabrication():
    """THE safety property. The catalog is partial, so absence must be reported as
    'cannot check', never as 'the model invented this'."""
    res = check_techniques([{"id": "T1234.567", "name": "Whatever"}], CAT)
    assert res["unknown_id"] == ["T1234.567"]
    assert res["mismatched"] == []


def test_a_malformed_id_is_separated_from_an_unknown_one():
    res = check_techniques([{"id": "T1105.1", "name": "x"}, {"id": "nope", "name": "y"}],
                           CAT)
    assert len(res["malformed"]) == 2
    assert res["unknown_id"] == []


def test_the_nonexistent_subtechnique_is_reported():
    """`T1105.001` was claimed; T1105 has no sub-techniques. With a partial catalog
    this lands in unknown_id — correct and honest. It becomes `mismatched` only once
    a generated catalog can prove the ID does not exist."""
    res = check_techniques([{"id": "T1105.001", "name": "Web Protocols"}], CAT)
    assert res["unknown_id"] == ["T1105.001"]


# ---------------------------------------------------------------------------
# Catalog integrity
# ---------------------------------------------------------------------------

def test_provenance_rides_along_with_every_verdict():
    """No scorecard may quote a verdict without saying where the catalog came from."""
    res = check_techniques(RACCOON_15, CAT)
    assert res["catalog_provenance"]
    assert res["catalog_verified"] is False, (
        "the shipped seed is hand-entered; flip `verified` only when generated")


def test_a_missing_catalog_reports_itself_rather_than_passing_silently():
    """A check that cannot run must not look like a check that passed."""
    cat = load_catalog("/nonexistent/attack_catalog.json")
    assert cat["available"] is False
    res = check_techniques(RACCOON_15, cat)
    assert res["catalog_available"] is False
    assert res["mismatched"] == [], "an unavailable catalog must accuse nobody"
    assert len(res["unknown_id"]) == 5


def test_every_subtechnique_has_its_parent_in_the_catalog():
    """Required for parent-name detection to work at all."""
    known = json.loads((FILES / "attack_catalog.json").read_text())["techniques"]
    for tid in known:
        if "." in tid:
            assert tid.split(".")[0] in known, (
                f"{tid} has no parent entry, so a parent-name mislabel on it "
                f"would be invisible")


def test_the_catalog_records_the_error_that_motivated_the_data_file():
    """Regression guard on a specific wrong recollection made during design."""
    known = json.loads((FILES / "attack_catalog.json").read_text())["techniques"]
    assert known["T1055.003"] == "Thread Execution Hijacking"
    assert known["T1055.012"] == "Process Hollowing"


# ---------------------------------------------------------------------------
# Catalog-free cross-cell check
# ---------------------------------------------------------------------------

def test_one_id_with_two_names_is_a_conflict_without_any_catalog():
    """Works when the catalog is missing or too small: if the same ID appears with
    two names across cells, at least one is wrong whatever the catalog says.

    Verbatim — icedid gave T1055.003 two different names at two depths.
    """
    conflicts = id_name_conflicts([
        {"attack_techniques": [{"id": "T1055.003", "name": "Process Hollowing"}]},
        {"attack_techniques": [{"id": "T1055.003", "name": "Process Injection"}]},
    ])
    assert len(conflicts) == 1 and "T1055.003" in conflicts[0]


def test_consistent_naming_is_not_a_conflict():
    assert id_name_conflicts([
        {"attack_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"}]},
        {"attack_techniques": [{"id": "T1105", "name": "ingress  tool transfer"}]},
    ]) == []


def test_a_descriptive_suffix_is_not_a_conflict():
    """Found by backfilling: 4 of 7 raw conflicts were a canonical name with
    description appended, not a disagreement about the ID's meaning.

    Verbatim from the archive. Reporting these beside a genuine wrong pairing
    trains the reader to skim, which is how a check stops being read.
    """
    NOTE = (  # noqa: N806 - documents a real ambiguity, not a constant
        "A COLON separator is deliberately not used here. `_norm` treats 'A: B' as "
        "the Parent: Sub form and keeps only B, which is right for check_techniques "
        "and wrong for a description. Real cells append descriptions without a "
        "colon, so the prefix rule sees the canonical name intact.")
    assert NOTE
    assert id_name_conflicts([
        {"attack_techniques": [
            {"id": "T1140", "name": "Deobfuscate/Decode Files or Information"}]},
        {"attack_techniques": [
            {"id": "T1140", "name": "Deobfuscate/Decode Files or Information "
                                    "- runtime string reassembly"}]},
    ]) == []


def test_a_genuine_divergence_still_surfaces_past_the_prefix_rule():
    """The prefix rule must not swallow real disagreement — verbatim, icedid."""
    conflicts = id_name_conflicts([
        {"attack_techniques": [{"id": "T1059.001", "name": "Command Execution"}]},
        {"attack_techniques": [{"id": "T1059.001", "name": "PowerShell"}]},
    ])
    assert len(conflicts) == 1 and "T1059.001" in conflicts[0]
