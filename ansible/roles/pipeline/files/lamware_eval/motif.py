# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""MOTIF corpus support: PE header normalisation and subset selection.

MOTIF (https://github.com/boozallen/MOTIF) ships 3,095 PE samples with ground
truth family labels derived from published threat reports. It is the only
labelled corpus available to this project without an access negotiation, which
makes it the path to answering #314 — recall is unmeasurable without labels.

The samples are DEFANGED by zeroing two PE header fields:

    Machine     0x14c/0x8664 -> 0x0
    Subsystem   2/3          -> 0

Measured on this host 2026-08-09, the same icedid sample through the same
run-ghidra:

    as shipped (Machine=0)       1 function,   0 imports
    Machine restored           617 functions, 67 imports
    our corpus icedid          75 functions,  45 imports   (control)

Ghidra selects its processor/language from Machine, so a zero there leaves it
unable to resolve an architecture and it produces essentially nothing — while
still reporting analysis_success (#367).

WE RESTORE MACHINE ONLY. Subsystem stays 0, which is what keeps the sample
unloadable by Windows. Static analysis needs the architecture; it does not need
the binary to be runnable, and re-arming malware to read it would be a bad
trade. Anything that "helpfully" restores Subsystem too should be reverted.
"""
from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

# MOTIF records the ORIGINAL header values in its EMBER features, so the true
# Machine is recoverable rather than inferred. Verified across all 3,095 rows:
# machine I386=2810 / AMD64=285, correlating exactly with magic PE32/PE32_PLUS.
MACHINE_BY_NAME: dict[str, int] = {
    "I386": 0x014C,
    "AMD64": 0x8664,
}

_MZ = b"MZ"
_PE = b"PE\0\0"
# Offsets from the start of the COFF header (which begins after the PE signature).
_COFF_MACHINE = 0
# Offset of Subsystem within the optional header, for both PE32 and PE32+.
_OPT_SUBSYSTEM = 68


class NotAMotifSample(ValueError):
    """The file is not the defanged PE this module knows how to repair."""


@dataclass(frozen=True)
class Normalisation:
    """What a normalisation did, so callers can assert on it rather than trust it."""
    machine_before: int
    machine_after: int
    subsystem: int
    changed: bool


def _pe_offsets(data: bytes) -> tuple[int, int]:
    """Return (coff_offset, optional_header_offset). Raises on a non-PE."""
    if data[:2] != _MZ:
        raise NotAMotifSample("no MZ signature")
    if len(data) < 0x40:
        raise NotAMotifSample("truncated DOS header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(data):
        raise NotAMotifSample(f"e_lfanew out of range: {e_lfanew:#x}")
    if data[e_lfanew:e_lfanew + 4] != _PE:
        raise NotAMotifSample("no PE signature at e_lfanew")
    coff = e_lfanew + 4
    return coff, coff + 20


def read_header(data: bytes) -> tuple[int, int]:
    """Return (machine, subsystem) as stored in the file."""
    coff, opt = _pe_offsets(data)
    machine = struct.unpack_from("<H", data, coff + _COFF_MACHINE)[0]
    subsystem = struct.unpack_from("<H", data, opt + _OPT_SUBSYSTEM)[0]
    return machine, subsystem


def normalise_bytes(data: bytes, machine_name: str) -> tuple[bytes, Normalisation]:
    """Restore the COFF Machine field from MOTIF's recorded value.

    Refuses a sample whose Machine is already non-zero: that is either not a
    MOTIF sample or one already normalised, and silently rewriting a real
    binary's architecture is worse than failing.
    """
    if machine_name not in MACHINE_BY_NAME:
        raise NotAMotifSample(
            f"unknown machine {machine_name!r}; known: {sorted(MACHINE_BY_NAME)}")
    coff, opt = _pe_offsets(data)
    before, subsystem = read_header(data)
    if before != 0:
        raise NotAMotifSample(
            f"Machine is already {before:#x}, not the zero MOTIF defanging leaves — "
            f"refusing to overwrite the architecture of a sample this did not defang")

    out = bytearray(data)
    struct.pack_into("<H", out, coff + _COFF_MACHINE, MACHINE_BY_NAME[machine_name])
    after, subsystem_after = read_header(bytes(out))

    # The defang must survive. If a future edit restores Subsystem as well, this
    # is where it gets caught rather than in a postmortem.
    if subsystem_after != 0:
        raise AssertionError(
            f"normalisation changed Subsystem to {subsystem_after} — it must stay 0 "
            f"so the sample remains unloadable by Windows")
    return bytes(out), Normalisation(before, after, subsystem_after, changed=True)


def normalise_file(src: Path, dst: Path, machine_name: str) -> Normalisation:
    """Normalise src into dst. Never edits in place — the original stays defanged."""
    data = src.read_bytes()
    out, result = normalise_bytes(data, machine_name)
    dst.write_bytes(out)
    dst.chmod(0o644)  # never executable; these are malware samples
    return result


# ---------------------------------------------------------------------------
# Subset selection
# ---------------------------------------------------------------------------
#
# The naive subset — take the first N of a family — is close to worthless here.
# icedid has 142 samples drawn from only 6 distinct threat reports, 102 of them
# from a single Palo Alto article. Ground truth is per-REPORT: samples sharing a
# report share its published IOC list, so N samples from one report is one
# independent label, not N.
#
# Selection therefore round-robins across reports before taking a second sample
# from any of them, and prefers samples carrying a report_ioc_url (the claim-level
# ground truth #314 needs). Ordering is by md5 so the subset is reproducible.


def load_motif_index(path: str | Path) -> list[dict]:
    """Load motif_dataset.jsonl, keeping only the fields the corpus needs.

    The full file is 26 MB, most of it EMBER feature vectors that nothing here
    reads. Dropping them keeps a corpus manifest reviewable in a diff.
    """
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rows.append({
                "md5": d["md5"],
                "sha256": d["sha256"],
                "family": str(d.get("reported_family", "")).lower(),
                "machine": d["header"]["coff"]["machine"],
                "magic": d["header"]["optional"]["magic"],
                "report_url": d.get("report_url") or "",
                "report_ioc_url": d.get("report_ioc_url") or "",
                "report_date": d.get("report_date") or "",
                "report_source": d.get("report_source") or "",
            })
    return rows


def select_subset(rows: list[dict], families: dict[str, int]) -> list[dict]:
    """Pick `families[name]` samples per family, maximising distinct reports.

    Returns rows in a stable order. Asks for more than a family can supply and
    you get everything it has — silently, because a corpus that shrinks when a
    family runs out is less surprising than one that raises mid-build. The count
    actually selected is in the result, so a caller can check.
    """
    picked: list[dict] = []
    for family in sorted(families):
        want = families[family]
        candidates = sorted((r for r in rows if r["family"] == family),
                            key=lambda r: (not r["report_ioc_url"], r["md5"]))
        by_report: dict[str, list[dict]] = {}
        for r in candidates:
            by_report.setdefault(r["report_url"], []).append(r)

        # Round-robin: one from each report, then a second from each, and so on.
        chosen: list[dict] = []
        depth = 0
        while len(chosen) < want:
            added = False
            for report in sorted(by_report):
                if len(chosen) >= want:
                    break
                bucket = by_report[report]
                if depth < len(bucket):
                    chosen.append(bucket[depth])
                    added = True
            if not added:  # every report exhausted
                break
            depth += 1
        picked.extend(chosen)
    return picked


def select_ioc_subset(rows: list[dict], families: dict[str, int],
                      per_report: int = 3) -> list[dict]:
    """Pick samples from reports that publish IOCs — the opposite bias to above.

    `select_subset` maximises distinct reports, which maximises independent FAMILY
    labels. It also, unavoidably, minimises claim-level ground truth: measured
    across MOTIF, `report_ioc_url` is all-or-nothing per report. icedid's 102
    IOC-bearing samples are all one Palo Alto article; its other five reports have
    none. Round-robining across reports therefore picks about one IOC sample in
    ten.

    For #314 the clustering is an ASSET, not a defect: an analyst reads one report
    and derives ground truth for several samples at once. So this tier
    deliberately takes `per_report` samples from each IOC-bearing report.

    The two tiers answer different questions and neither substitutes for the
    other. Keep both, and keep them labelled.
    """
    picked: list[dict] = []
    for family in sorted(families):
        want = families[family]
        by_report: dict[str, list[dict]] = {}
        for r in sorted((x for x in rows
                         if x["family"] == family and x["report_ioc_url"]),
                        key=lambda x: x["md5"]):
            by_report.setdefault(r["report_url"], []).append(r)

        # Take `per_report` from each IOC-bearing report, then come back round
        # for another `per_report` each until `want` is met. Backfilling from a
        # report already drawn from does NOT add independent ground truth — but
        # it does add analysis instances measurable against truth already read,
        # which is what recall scoring consumes. icedid is the case that forces
        # this: 102 IOC samples, all in one report.
        chosen: list[dict] = []
        depth = 0
        while len(chosen) < want:
            added = False
            for report in sorted(by_report):
                if len(chosen) >= want:
                    break
                chunk = by_report[report][depth * per_report:(depth + 1) * per_report]
                if chunk:
                    chosen.extend(chunk)
                    added = True
            if not added:  # every report exhausted
                break
            depth += 1
        picked.extend(chosen[:want])
    return picked


def subset_report(picked: list[dict]) -> dict:
    """Summarise a subset so its limitations travel with it."""
    out: dict = {"n": len(picked), "families": {}}
    for r in picked:
        fam = out["families"].setdefault(
            r["family"], {"n": 0, "reports": set(), "with_ioc_url": 0})
        fam["n"] += 1
        fam["reports"].add(r["report_url"])
        fam["with_ioc_url"] += bool(r["report_ioc_url"])
    for fam in out["families"].values():
        fam["distinct_reports"] = len(fam["reports"])
        del fam["reports"]
    return out
