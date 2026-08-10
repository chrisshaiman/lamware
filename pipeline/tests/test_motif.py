# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""MOTIF header normalisation and subset selection.

Two properties matter more than the rest and are asserted hardest:

  1. Machine is restored to MOTIF's RECORDED value, not an inferred one. MOTIF
     keeps the pre-defang header in its EMBER features, so guessing from the
     PE32/PE32+ magic would be a worse answer that happens to agree most of the
     time — and would silently mislabel the 285 AMD64 samples if the mapping were
     ever written the other way round.

  2. Subsystem STAYS ZERO. That field is what keeps a defanged sample unloadable
     by Windows. Restoring it would re-arm real malware on the host to gain
     nothing static analysis needs.
"""
import struct

import pytest
from lamware_eval.motif import (
    MACHINE_BY_NAME,
    NotAMotifSample,
    load_motif_index,
    normalise_bytes,
    read_header,
    select_ioc_subset,
    select_subset,
    subset_report,
)


def make_pe(machine: int = 0, subsystem: int = 0, magic: int = 0x10B) -> bytes:
    """A minimal well-formed PE, defanged the way MOTIF defangs."""
    e_lfanew = 0x80
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    coff = e_lfanew + 4
    # machine, nsections, timestamp, symtab, nsyms, optsize, characteristics
    struct.pack_into("<HHIIIHH", buf, coff, machine, 1, 0, 0, 0, 224, 0x102)
    opt = coff + 20
    struct.pack_into("<H", buf, opt, magic)
    struct.pack_into("<H", buf, opt + 68, subsystem)  # Subsystem
    return bytes(buf)


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

def test_the_fixture_is_shaped_like_a_defanged_motif_sample():
    """Guards the guard: if the fixture were not zeroed, every test below would
    be asserting against a case that never occurs."""
    machine, subsystem = read_header(make_pe())
    assert machine == 0, "fixture must start defanged"
    assert subsystem == 0


@pytest.mark.parametrize("name,expected", [("I386", 0x014C), ("AMD64", 0x8664)])
def test_machine_is_restored_from_the_recorded_name(name, expected):
    out, result = normalise_bytes(make_pe(), name)
    machine, _ = read_header(out)
    assert machine == expected
    assert result.machine_before == 0
    assert result.machine_after == expected


def test_subsystem_stays_zero():
    """THE safety property. A sample with Subsystem=0 will not load on Windows;
    that is the whole defang. Static analysis needs Machine and nothing else."""
    for name in MACHINE_BY_NAME:
        out, result = normalise_bytes(make_pe(), name)
        _, subsystem = read_header(out)
        assert subsystem == 0, f"{name}: normalisation re-armed the sample"
        assert result.subsystem == 0


def test_only_two_bytes_change():
    """A normalisation that rewrote anything else would be altering the sample
    under analysis — the results would no longer describe the real binary."""
    src = make_pe()
    out, _ = normalise_bytes(src, "I386")
    differing = [i for i, (a, b) in enumerate(zip(src, out)) if a != b]
    assert len(differing) <= 2, f"changed {len(differing)} bytes: {differing[:10]}"
    coff = struct.unpack_from("<I", src, 0x3C)[0] + 4
    assert all(coff <= i < coff + 2 for i in differing), (
        f"bytes changed outside the Machine field: {differing}")


def test_a_sample_with_a_real_machine_is_refused():
    """Not a MOTIF sample, or already normalised. Either way, overwriting a real
    binary's architecture is a silent corruption of the thing under test."""
    with pytest.raises(NotAMotifSample, match="already"):
        normalise_bytes(make_pe(machine=0x014C), "I386")


def test_normalisation_is_not_idempotent_by_silence():
    """Running it twice must FAIL rather than quietly no-op — a pipeline that
    normalises an already-normalised tree should say so."""
    out, _ = normalise_bytes(make_pe(), "I386")
    with pytest.raises(NotAMotifSample):
        normalise_bytes(out, "I386")


def test_an_unknown_machine_name_is_refused():
    with pytest.raises(NotAMotifSample, match="unknown machine"):
        normalise_bytes(make_pe(), "SPARC")


@pytest.mark.parametrize("payload,why", [
    (b"not a pe at all", "no MZ"),
    (b"MZ" + b"\0" * 10, "truncated"),
])
def test_non_pe_input_is_refused(payload, why):
    with pytest.raises(NotAMotifSample):
        normalise_bytes(payload, "I386")


def test_a_bad_pe_signature_is_refused():
    buf = bytearray(make_pe())
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    buf[e_lfanew:e_lfanew + 4] = b"XXXX"
    with pytest.raises(NotAMotifSample, match="PE signature"):
        normalise_bytes(bytes(buf), "I386")


# ---------------------------------------------------------------------------
# subset selection
# ---------------------------------------------------------------------------

def _rows(family: str, spec: list[tuple[str, int, bool]]) -> list[dict]:
    """spec: (report_url, count, has_ioc_url)"""
    out = []
    for report, count, has_ioc in spec:
        for i in range(count):
            out.append({
                "md5": f"{family}-{report}-{i:03d}", "sha256": "x" * 64,
                "family": family, "machine": "I386", "magic": "PE32",
                "report_url": report,
                "report_ioc_url": "ioc" if has_ioc else "",
                "report_date": "1/1/2020", "report_source": "s",
            })
    return out


# icedid's real shape: 142 samples, 6 reports, 102 from one of them.
ICEDID = _rows("icedid", [("palo", 102, True), ("talos", 26, False),
                          ("fortinet-a", 1, False), ("fortinet-b", 1, False),
                          ("eset-a", 1, False), ("eset-b", 11, False)])


def test_selection_spreads_across_reports_before_repeating_one():
    """THE point of this function. Samples sharing a report share its published
    IOC list, so 6 from one report is one independent ground truth, not six."""
    picked = select_subset(ICEDID, {"icedid": 6})
    assert len(picked) == 6
    assert len({r["report_url"] for r in picked}) == 6, (
        f"expected all 6 reports, got {sorted({r['report_url'] for r in picked})}")


def test_a_naive_first_n_would_fail_this():
    """Control: the obvious implementation takes 6 samples from the largest
    report and looks fine. This records what the test is defending against."""
    naive = sorted(ICEDID, key=lambda r: r["md5"])[:6]
    assert len({r["report_url"] for r in naive}) < 6


def test_oversubscribing_a_family_returns_what_exists():
    picked = select_subset(ICEDID, {"icedid": 1000})
    assert len(picked) == len(ICEDID)


def test_selection_is_deterministic():
    """A benchmark corpus that changes between builds is not a benchmark."""
    a = select_subset(ICEDID, {"icedid": 9})
    b = select_subset(ICEDID, {"icedid": 9})
    assert [r["md5"] for r in a] == [r["md5"] for r in b]


def test_samples_with_ioc_urls_are_preferred_within_a_report():
    rows = _rows("x", [("r1", 3, False)]) + _rows("x", [("r1b", 3, True)])
    for r in rows:
        r["report_url"] = "r1"  # collapse into one report
    picked = select_subset(rows, {"x": 3})
    assert all(r["report_ioc_url"] for r in picked), (
        "claim-level ground truth is the scarce resource; prefer it")


def test_multiple_families_are_each_selected():
    rows = ICEDID + _rows("emotet", [("e1", 5, True), ("e2", 5, False)])
    picked = select_subset(rows, {"icedid": 3, "emotet": 4})
    fams = {}
    for r in picked:
        fams[r["family"]] = fams.get(r["family"], 0) + 1
    assert fams == {"icedid": 3, "emotet": 4}


def test_the_report_records_the_limitation():
    """The subset's weakness must travel with it — distinct_reports is the number
    that matters, and it is not the sample count."""
    rep = subset_report(select_subset(ICEDID, {"icedid": 20}))
    assert rep["n"] == 20
    ice = rep["families"]["icedid"]
    assert ice["n"] == 20
    assert ice["distinct_reports"] == 6, (
        "20 samples but only 6 independent ground truths — the report must say so")
    assert ice["distinct_reports"] < ice["n"]


def test_load_index_drops_the_feature_vectors(tmp_path):
    """26 MB of EMBER features must not end up in a corpus manifest."""
    import json
    p = tmp_path / "motif.jsonl"
    p.write_text(json.dumps({
        "md5": "a" * 32, "sha256": "b" * 64, "reported_family": "IcedID",
        "header": {"coff": {"machine": "I386"}, "optional": {"magic": "PE32"}},
        "report_url": "u", "report_ioc_url": "", "report_date": "1/1/2020",
        "report_source": "s",
        "histogram": list(range(256)), "byteentropy": list(range(256)),
    }) + "\n", encoding="utf-8")
    rows = load_motif_index(p)
    assert len(rows) == 1
    assert rows[0]["family"] == "icedid", "family must be normalised to lowercase"
    assert rows[0]["machine"] == "I386"
    assert "histogram" not in rows[0] and "byteentropy" not in rows[0]


# ---------------------------------------------------------------------------
# IOC tier — the opposite bias, and why both are needed
# ---------------------------------------------------------------------------

def test_ioc_tier_returns_only_samples_with_claim_level_truth():
    picked = select_ioc_subset(ICEDID, {"icedid": 6})
    assert picked, "no IOC-bearing samples selected"
    assert all(r["report_ioc_url"] for r in picked)


def test_ioc_tier_clusters_within_a_report_rather_than_spreading():
    """The inverse of select_subset, on purpose. Measured in MOTIF,
    report_ioc_url is all-or-nothing per report — icedid's 102 IOC samples are
    one Palo Alto article. Clustering lets an analyst read one report and label
    several samples, which is the actual cost driver for #314."""
    picked = select_ioc_subset(ICEDID, {"icedid": 6}, per_report=3)
    counts: dict[str, int] = {}
    for r in picked:
        counts[r["report_url"]] = counts.get(r["report_url"], 0) + 1
    assert max(counts.values()) > 1, (
        f"IOC tier spread across reports instead of clustering: {counts}")


def test_the_two_tiers_disagree_which_is_the_point():
    """If breadth and IOC selection returned the same samples, one of them would
    be redundant. They must not."""
    breadth = {r["md5"] for r in select_subset(ICEDID, {"icedid": 6})}
    ioc = {r["md5"] for r in select_ioc_subset(ICEDID, {"icedid": 6})}
    assert breadth != ioc
    assert len({r["report_url"] for r in select_subset(ICEDID, {"icedid": 6})}) > \
           len({r["report_url"] for r in select_ioc_subset(ICEDID, {"icedid": 6})})


def test_ioc_tier_is_empty_for_a_family_with_no_ioc_reports():
    """emotet has 6 reports and zero report_ioc_urls. The tier must return
    nothing rather than silently falling back to samples without truth."""
    no_ioc = _rows("emotet", [("e1", 5, False), ("e2", 5, False)])
    assert select_ioc_subset(no_ioc, {"emotet": 4}) == []


def test_ioc_tier_backfills_from_a_single_report_family():
    """icedid's 102 IOC samples sit in ONE report. Requesting 6 must return 6 —
    capping at per_report would silently under-deliver the tier that exists to
    supply claim-level truth."""
    picked = select_ioc_subset(ICEDID, {"icedid": 6}, per_report=3)
    assert len(picked) == 6, f"under-delivered: {len(picked)}"
    assert len({r["report_url"] for r in picked}) == 1
    assert len({r["md5"] for r in picked}) == 6, "backfill returned duplicates"


def test_ioc_tier_still_prefers_spreading_before_backfilling():
    """Backfill is a fallback, not the strategy: with two IOC reports available
    and per_report=2, the first four picks must come from both."""
    rows = _rows("x", [("r1", 10, True)]) + _rows("x", [("r2", 10, True)])
    picked = select_ioc_subset(rows, {"x": 4}, per_report=2)
    assert len({r["report_url"] for r in picked}) == 2
