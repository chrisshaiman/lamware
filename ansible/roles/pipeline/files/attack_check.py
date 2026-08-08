# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Validate `attack_techniques` ID/name pairs against a pinned ATT&CK catalog (#318).

`grounding_check` scores `code_level_iocs` against decompilation and has no view of
ATT&CK at all, so a cell can carry five fabricated technique mappings and still
report `grounded_ratio: 1.000`. Observed 2026-08-07 in `depth-10-vs-15-n7`:

    T1055.001 "Process Memory Dumping"   -> Dynamic-link Library Injection
    T1053.005 "Service (Windows)"        -> Scheduled Task
    T1027.001 "Obfuscated Files or ..."  -> parent's name on a sub-technique ID
    T1105.001 "Web Protocols"            -> T1105 has no sub-techniques at all

Two error shapes, worth separating because they have different causes: a parent name
attached to a sub-technique ID (the model knows the family and invents the `.00N`),
versus an outright wrong pairing.

WHY THIS IS A LOOKUP AND NOT A JUDGEMENT. Unlike #314 it needs no ground truth and no
analyst — the ID either exists with that name or it does not.

WHY THE CATALOG IS A DATA FILE. Writing one from memory is the same failure the check
exists to catch, and it is not hypothetical: while designing this, the author asserted
that `T1055.003` was Process Hollowing. It is Thread Execution Hijacking; Process
Hollowing is `T1055.012`. A recalled catalog would have shipped that error as ground
truth and flagged the correct answer as wrong.

So an ID absent from the catalog is reported as `unknown_id` and NEVER as a
fabrication. A short catalog under-reports; a wrong one actively misleads, and only
the second is unrecoverable. `catalog_provenance` rides along in every result so no
scorecard can quote a verdict without saying where the catalog came from.
"""
import json
import re
from pathlib import Path

_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DEFAULT_CATALOG = Path(__file__).with_name("attack_catalog.json")


def load_catalog(path: "str | Path | None" = None) -> dict:
    """Load the pinned catalog. Missing/corrupt is reported, never silently empty.

    An empty catalog would make every ID `unknown_id`, which reads as "nothing to
    see" — the failure mode where a check that cannot run looks like a check that
    passed.
    """
    p = Path(path) if path else _DEFAULT_CATALOG
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return {"techniques": {}, "provenance": f"UNAVAILABLE: {type(e).__name__}",
                "verified": False, "available": False}
    data.setdefault("techniques", {})
    data["available"] = bool(data["techniques"])
    return data


def _norm(name: str) -> str:
    """Compare names ignoring case, spacing, and the `Parent: Sub` presentation.

    claude-sonnet-5 writes `T1027.003 "Obfuscated Files or Information:
    Steganography"` — the full path, which is correct and must not be scored as a
    mismatch. Only the segment after the last colon is compared.
    """
    tail = str(name or "").split(":")[-1]
    return re.sub(r"[^a-z0-9]+", " ", tail.lower()).strip()


def check_techniques(techniques: list, catalog: dict | None = None) -> dict:
    """Bucket every technique entry. Returns counts plus the offending entries.

        ok          — ID known, name matches
        mismatched  — ID known, name does not match  (the finding)
        parent_name — mismatched AND the name given is the PARENT's name
        unknown_id  — well-formed ID absent from the catalog (NOT an accusation)
        malformed   — not a TNNNN[.NNN] ID at all
    """
    cat = catalog if catalog is not None else load_catalog()
    known: dict = cat.get("techniques", {})
    out: dict = {"ok": 0, "mismatched": [], "parent_name": [], "unknown_id": [],
                 "malformed": [], "n": 0,
                 "catalog_provenance": cat.get("provenance", "unknown"),
                 "catalog_verified": bool(cat.get("verified")),
                 "catalog_available": bool(cat.get("available"))}
    for entry in techniques or []:
        if isinstance(entry, dict):
            tid, name = str(entry.get("id", "")).strip(), str(entry.get("name", ""))
        else:
            tid, name = str(entry).strip(), ""
        out["n"] += 1
        if not _ID.match(tid):
            out["malformed"].append(tid or repr(entry))
            continue
        if tid not in known:
            out["unknown_id"].append(tid)
            continue
        if _norm(name) == _norm(known[tid]):
            out["ok"] += 1
            continue
        detail = f'{tid} "{name}" -> {known[tid]}'
        out["mismatched"].append(detail)
        # A sub-technique labelled with its parent's name is the commonest shape and
        # a distinct signal: the family was right and the `.00N` was invented.
        parent = tid.split(".")[0]
        if "." in tid and parent in known and _norm(name) == _norm(known[parent]):
            out["parent_name"].append(detail)
    return out


def id_name_conflicts(cells: list) -> list[str]:
    """IDs given DIFFERENT names across cells — wrong without any catalog at all.

    Independent of `check_techniques`, and the only part that still works when the
    catalog is missing or too small: if one ID appears with two names, at least one
    is wrong regardless of what the catalog says.
    """
    seen: dict[str, set] = {}
    for analysis in cells or []:
        for entry in (analysis or {}).get("attack_techniques") or []:
            if not isinstance(entry, dict):
                continue
            tid, name = str(entry.get("id", "")).strip(), _norm(entry.get("name", ""))
            if _ID.match(tid) and name:
                seen.setdefault(tid, set()).add(name)

    out = []
    for tid, names in sorted(seen.items()):
        # A name that merely EXTENDS another is a model appending description to the
        # canonical name ("deobfuscate decode files or information runtime string
        # reassembly"), not a disagreement about what the ID means. Backfilling over
        # the archive, 4 of 7 raw conflicts were this shape — reporting them beside a
        # genuine wrong pairing would train the reader to skim the list, which is how
        # a check stops being read at all.
        distinct = {n for n in names
                    if not any(n != o and n.startswith(o) for o in names)}
        if len(distinct) > 1:
            out.append(f"{tid}: {' | '.join(sorted(distinct))}")
    return out
