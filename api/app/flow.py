# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Which pipeline component fed which, derived from one analysis's report (#653).

Four bugs in one week were a component silently not feeding the next: the
original sample never reached Ghidra (#644), CAPE payload programs were erased
from their shared Ghidra project (#648), routed samples discarded CAPE's
payloads (#646), and a Ghidra import failure was reported as an export-script
problem (#647). Each was visible in ``report.json`` and nowhere else.

``derive_flow`` turns a stored report into a small graph: nodes are pipeline
components, edges are what one handed to the next, each with a status and,
where the report says, a reason. The endpoint returns this graph and never the
raw report, which holds decompiled code and attacker-controlled strings.

The rule the whole module exists to keep: **a key the report does not have is
``absent``, never zero.** Old reports predate most of these keys, and "0 items"
on an edge whose data was never recorded is the silent-success reading these
bugs hid behind. ``carried`` and ``expected`` are therefore ``None`` whenever
the count is not known, and only an integer when the report recorded it.

Pure function, no I/O: the tests call it on trimmed real reports.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

# Edge and node statuses.
OK = "ok"
SKIPPED = "skipped"
FAILED = "failed"
ABSENT = "absent"

# Item statuses. "carried" counts LOADED, EMPTY and READ: the items that
# arrived downstream in a usable form.
LOADED = "loaded"          # a Ghidra program with functions
EMPTY = "empty"            # loaded, zero functions recovered
LOST = "lost"              # claims functions, but Ghidra cannot open it (#648)
ITEM_FAILED = "failed"     # analysis_success false, with the recorded reason
ITEM_SKIPPED = "skipped"   # deliberately not analysed, with the recorded reason
MISSING = "missing"        # upstream recorded it, downstream has no trace of it
READ = "read"              # what the RE agent was given

_CARRIED = frozenset({LOADED, EMPTY, READ})
_BROKEN = frozenset({LOST, ITEM_FAILED, MISSING})

# Report strings are attacker-influenced (payload labels, filenames, notes).
# The UI renders them as text; the cap keeps one hostile value from dominating
# the response.
MAX_TEXT = 300
MAX_ITEMS = 100

# (ghidra routed flag, report key, node id, label, what the edge carries).
# Mirrors ROUTED_FLAGS in the pipeline's stages/ghidra.py and the order of the
# Stage 4 branches in run-pipeline.py.
ROUTED_ANALYSERS: tuple[tuple[str, str, str, str], ...] = (
    ("office_routed", "office_analysis", "olevba", "olevba"),
    ("powershell_routed", "powershell_analysis", "psdecode", "PSDecode"),
    ("script_routed", "script_analysis", "script_reader", "Script source"),
    ("dotnet_routed", "dotnet_analysis", "ilspy", "ILSpy"),
    ("go_routed", "go_analysis", "goresym", "GoReSym"),
    ("pyinstaller_routed", "pyinstaller_analysis", "pyinstaller", "PyInstaller"),
    ("java_routed", "java_analysis", "cfr", "CFR"),
)

# The order run-pipeline.py's Stage 4.5 tries the routed analysers before
# falling back to Ghidra. Used ONLY for reports that predate
# llm_interpretation.input, and every edge built from it says it was inferred.
_INTERPRET_PRECEDENCE = (
    "dotnet_analysis", "java_analysis", "office_analysis", "powershell_analysis",
    "script_analysis", "pyinstaller_analysis", "go_analysis",
)

# run_ghidra's verifier warning when a program claims functions but its
# project does not hold it (stages/ghidra.py::_pick_openable). The name is the
# first 16 characters of program_name.
_LOST_RE = re.compile(r"^Ghidra: (\S{1,16}) claims \S+ functions but is not in ")
_IMPORT_ERROR_RE = re.compile(r"ERROR REPORT: ([^\n]*)")


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    s = value if isinstance(value, str) else str(value)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _dict(value: Any) -> dict | None:
    return value if isinstance(value, dict) else None


def _list(value: Any) -> list | None:
    return value if isinstance(value, list) else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _short(sha: Any) -> str | None:
    """First 12 characters of a hash: enough to match, short enough to show."""
    return sha[:12] if isinstance(sha, str) and sha else None


def _node(node_id: str, label: str, status: str, detail: str | None = None,
          reason: str | None = None, **extra: Any) -> dict:
    node: dict[str, Any] = {"id": node_id, "label": _text(label), "status": status,
                            "detail": _text(detail) if detail else None,
                            "reason": _text(reason) if reason else None}
    node.update(extra)
    return node


def _edge(edge_id: str, src: str, dst: str, label: str, status: str,
          reason: str | None = None, items: list[dict] | None = None,
          expected: int | None = None, carried: int | None = None,
          **extra: Any) -> dict:
    """One hand-off. ``items`` None means the report does not list them."""
    edge: dict[str, Any] = {
        "id": edge_id, "from": src, "to": dst, "label": label, "status": status,
        "reason": _text(reason) if reason else None,
        "expected": expected, "carried": carried,
        "items": None, "items_truncated": 0, "counts": None,
    }
    if items is not None:
        edge["items"] = items[:MAX_ITEMS]
        edge["items_truncated"] = max(0, len(items) - MAX_ITEMS)
        edge["counts"] = dict(Counter(i["status"] for i in items))
        if carried is None:
            edge["carried"] = sum(1 for i in items if i["status"] in _CARRIED)
    edge.update(extra)
    return edge


def _item(label: str, status: str, detail: str | None = None, **extra: Any) -> dict:
    item: dict[str, Any] = {"label": _text(label), "status": status,
                            "detail": _text(detail) if detail else None}
    item.update({k: v for k, v in extra.items() if v is not None})
    return item


def _items_status(items: list[dict], empty_reason: str | None = None) -> tuple[str, str | None]:
    """Edge status from its items: any broken item fails the edge."""
    if not items:
        return OK, empty_reason
    broken = [i for i in items if i["status"] in _BROKEN]
    if broken:
        counts = Counter(i["status"] for i in broken)
        what = ", ".join(f"{n} {s}" for s, n in sorted(counts.items()))
        return FAILED, f"{what} of {len(items)}"
    if all(i["status"] == ITEM_SKIPPED for i in items):
        # "Artifact extraction only (188 bytes, < 1KB threshold)" differs per
        # item only in its numbers; one sentence covers them all.
        reasons = {re.sub(r"\d+", "N", i["detail"]) for i in items if i.get("detail")}
        what = reasons.pop() if len(reasons) == 1 else "reasons differ; see each item"
        return SKIPPED, f"all {len(items)} skipped: {what}"
    return OK, None


# ---------------------------------------------------------------------------
# Ghidra's per-file results
# ---------------------------------------------------------------------------


def _lost_prefixes(ghidra: dict) -> set[str]:
    out = set()
    for w in _list(ghidra.get("analysis_warnings")) or []:
        if isinstance(w, str):
            m = _LOST_RE.match(w)
            if m:
                out.add(m.group(1))
    return out


def _failure_reason(af: dict) -> str:
    """What the report says went wrong with one analysed file.

    An explicit ``error`` first. Then Ghidra's own ``ERROR REPORT`` lines: until
    #647 is fixed an import failure is recorded only in ghidra_stdout, while
    ``note`` blames the export script, which is the misdiagnosis #647 is about.
    """
    if af.get("error"):
        return _text(af["error"])
    lines: list[str] = []
    for key in ("ghidra_stdout", "ghidra_stderr"):
        out = af.get(key)
        if isinstance(out, str):
            lines += [m.strip() for m in _IMPORT_ERROR_RE.findall(out)]
    if lines:
        # The Import failed line is the verdict; the one before it is the cause.
        return _text(" / ".join(lines[:2]))
    if af.get("note"):
        return _text(af["note"])
    return "analysis_success is false and no reason was recorded"


def _ghidra_item(af: dict, label: str, lost: set[str], **extra: Any) -> dict:
    fc = _int(af.get("functions_count"))
    name = af.get("program_name")
    if not af.get("analysis_success"):
        return _item(label, ITEM_FAILED, _failure_reason(af), functions=fc, **extra)
    if isinstance(name, str) and name[:16] in lost:
        return _item(label, LOST,
                     f"claims {fc} functions but its Ghidra project does not hold it",
                     functions=fc, **extra)
    if not fc:
        return _item(label, EMPTY, "loaded, no functions recovered", functions=fc, **extra)
    return _item(label, LOADED, None, functions=fc, **extra)


def _payload_label(cape_type: Any) -> str:
    if isinstance(cape_type, str) and cape_type.strip():
        return cape_type.strip()
    return "(unlabelled)"


def _cape_type_of(af: dict) -> str | None:
    """CAPE's label for a payload program; older reports only have it in ``process``."""
    if isinstance(af.get("cape_type"), str):
        return af["cape_type"]
    proc = af.get("process")
    if isinstance(proc, str) and proc.startswith("cape_"):
        return proc[len("cape_"):]
    return None


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------


def derive_flow(report: dict) -> dict:
    """The component graph one report records. See the module docstring."""
    r = report if isinstance(report, dict) else {}
    nodes: list[dict] = []
    edges: list[dict] = []

    triage = _dict(r.get("triage"))
    cape = _dict(r.get("cape"))
    vol = _dict(r.get("volatility"))
    ghidra = _dict(r.get("ghidra"))
    llm = _dict(r.get("llm_interpretation"))

    # --- sample ---------------------------------------------------------
    name = r.get("sample_name")
    if not isinstance(name, str) or not name:
        path = r.get("sample")
        name = path.rsplit("/", 1)[-1] if isinstance(path, str) and path else None
    file_type = triage.get("file_type") if triage else None
    nodes.append(_node("sample", name or "sample", OK if name else ABSENT,
                       detail=file_type if isinstance(file_type, str) else None,
                       reason=None if name else "report records no sample name"))
    sample_sha = None
    if triage and isinstance(triage.get("hashes"), dict):
        sample_sha = triage["hashes"].get("sha256")

    # --- triage ---------------------------------------------------------
    nodes.append(_node("triage", "Triage", OK if triage else ABSENT,
                       reason=None if triage else "no triage section"))
    edges.append(_edge("sample-triage", "sample", "triage", "sample",
                       OK if triage else ABSENT,
                       reason=None if triage else "no triage section"))

    # --- CAPE -----------------------------------------------------------
    if cape is None:
        nodes.append(_node("cape", "CAPE", ABSENT, reason="no cape section"))
        edges.append(_edge("sample-cape", "sample", "cape", "detonation", ABSENT,
                           reason="no cape section"))
    else:
        cstatus = cape.get("status")
        task = cape.get("task_id")
        extracted = _int(cape.get("payloads_extracted"))
        bits = []
        if task is not None:
            bits.append(f"task {task}")
        if extracted is not None:
            bits.append(f"{extracted} payloads extracted")
        detail = " · ".join(bits) or None
        if cstatus == "reported":
            nodes.append(_node("cape", "CAPE", OK, detail))
            edges.append(_edge("sample-cape", "sample", "cape", "detonation", OK))
        else:
            why = cape.get("error") or (f"CAPE status: {cstatus}" if cstatus
                                        else "no CAPE status recorded")
            nodes.append(_node("cape", "CAPE", FAILED, detail, reason=why))
            edges.append(_edge("sample-cape", "sample", "cape", "detonation", FAILED,
                               reason=why))

    # --- Volatility -----------------------------------------------------
    if vol is None:
        nodes.append(_node("volatility", "Volatility", ABSENT, reason="no volatility section"))
        edges.append(_edge("cape-volatility", "cape", "volatility", "memory dump", ABSENT,
                           reason="no volatility section"))
    elif vol.get("triggered"):
        plugins = _list(vol.get("plugins_run"))
        detail = f"{len(plugins)} plugins run" if plugins is not None else None
        nodes.append(_node("volatility", "Volatility", OK, detail))
        edges.append(_edge("cape-volatility", "cape", "volatility", "memory dump", OK))
    else:
        why = vol.get("reason") or vol.get("error") or "not triggered; no reason recorded"
        st = FAILED if vol.get("error") else SKIPPED
        nodes.append(_node("volatility", "Volatility", st, reason=why))
        edges.append(_edge("cape-volatility", "cape", "volatility", "memory dump", st,
                           reason=why))

    # --- routed analysers (ILSpy, olevba, …) ----------------------------
    routed_by: list[tuple[str, str, str, str]] = []
    for flag, key, node_id, label in ROUTED_ANALYSERS:
        flagged = bool(ghidra and ghidra.get(flag))
        data = _dict(r.get(key))
        if not flagged and data is None:
            continue
        if flagged:
            routed_by.append((flag, key, node_id, label))
        # A .NET payload CAPE extracted, or PowerShell recovered from CAPE's
        # logs, reached the analyser from CAPE, not from the submitted file.
        src = "cape" if data and (data.get("extraction_source") or data.get("cape_extracted")) \
            else "sample"
        if data is None:
            nodes.append(_node(node_id, label, ABSENT, role="wrapper",
                               reason=f"routed here ({flag}) but the report has no {key}"))
            edges.append(_edge(f"{src}-{node_id}", src, node_id, "sample", ABSENT,
                               reason=f"no {key} section"))
            continue
        if data.get("analysis_success"):
            nodes.append(_node(node_id, label, OK, _analyser_detail(key, data),
                               role="wrapper" if flagged else None))
            edges.append(_edge(f"{src}-{node_id}", src, node_id,
                               "CAPE extraction" if src == "cape" else "sample", OK))
        else:
            why = data.get("error") or "analysis_success is false and no reason was recorded"
            nodes.append(_node(node_id, label, FAILED, reason=why,
                               role="wrapper" if flagged else None))
            edges.append(_edge(f"{src}-{node_id}", src, node_id,
                               "CAPE extraction" if src == "cape" else "sample", FAILED,
                               reason=why))

    # --- Ghidra ---------------------------------------------------------
    _ghidra(nodes, edges, r, cape, vol, ghidra, routed_by, sample_sha)

    # --- RE agent -------------------------------------------------------
    _re_agent(nodes, edges, r, ghidra, llm, routed_by)

    # --- cross-tool correlation ----------------------------------------
    cc = r.get("cross_correlations")
    warnings = _list(r.get("correlation_warnings"))
    if not isinstance(cc, list):
        nodes.append(_node("correlation", "Correlation", ABSENT,
                           reason="report records no cross_correlations"))
        for src in ("cape", "volatility"):
            edges.append(_edge(f"{src}-correlation", src, "correlation", "findings", ABSENT,
                               reason="report records no cross_correlations"))
    else:
        nodes.append(_node("correlation", "Correlation", OK, f"{len(cc)} findings",
                           warnings=[_text(w) for w in warnings or []]))
        if cape is None:
            edges.append(_edge("cape-correlation", "cape", "correlation", "behaviour",
                               ABSENT, reason="no cape section"))
        elif cape.get("status") == "reported":
            edges.append(_edge("cape-correlation", "cape", "correlation", "behaviour", OK))
        else:
            edges.append(_edge("cape-correlation", "cape", "correlation", "behaviour",
                               FAILED, reason="CAPE did not report"))
        if vol is None:
            edges.append(_edge("volatility-correlation", "volatility", "correlation",
                               "memory", ABSENT, reason="no volatility section"))
        elif vol.get("triggered"):
            edges.append(_edge("volatility-correlation", "volatility", "correlation",
                               "memory", OK))
        else:
            edges.append(_edge("volatility-correlation", "volatility", "correlation",
                               "memory", SKIPPED,
                               reason="Volatility did not run; memory rules had nothing to join"))

    # --- behavioural evidence shown to the RE agent (#674) --------------
    edges.append(_evidence_edge(llm))

    return {"nodes": nodes, "edges": edges}


# Why the agent was not given the behavioural evidence, by the reason
# stages/correlated_evidence.py records. Mirrors its NOT_GIVEN_* values.
_EVIDENCE_NOT_GIVEN = {
    "disabled_by_config": "turned off (interpret_correlated_evidence is false)",
    "single_shot_path": "this interpret path is single-shot and does not read it",
    "report_has_none": "no signatures, memory insights or correlation findings to give",
}


def _evidence_edge(llm: dict | None) -> dict:
    """Correlation -> RE agent: what behavioural evidence the agent was shown.

    The evidence is CAPE's signatures, Volatility's insights and the correlation
    findings and warnings (stages/correlated_evidence.py); it is drawn from the
    Correlation node because that is the stage that assembles the cross-tool
    view. Until #674 production never sent it, and a report from before then
    does not record it: that is ``absent``, not ``skipped``, because whether
    the agent saw it is unknown rather than known to be no.
    """
    eid, src, dst, label = "correlation-re_agent", "correlation", "re_agent", "behavioural evidence"
    if llm is None:
        return _edge(eid, src, dst, label, ABSENT, reason="no llm_interpretation section")
    if llm.get("enabled") is False or llm.get("reason") in ("not_triggered", "no_analysis_data"):
        return _edge(eid, src, dst, label, SKIPPED, reason="the RE agent did not run", carried=0)
    inp = _dict(llm.get("input"))
    rec = _dict(inp.get("correlated_evidence")) if inp else None
    if rec is None:
        return _edge(eid, src, dst, label, ABSENT,
                     reason="report does not record whether the agent was given it "
                            "(a single-shot path, or the report predates #674)")
    if rec.get("given") is True:
        keys = [k for k in _list(rec.get("keys")) or [] if isinstance(k, str)]
        items = [_item(k, READ) for k in keys]
        return _edge(eid, src, dst, label, OK, items=items, expected=len(items),
                     bytes=_int(rec.get("bytes")))
    why = rec.get("reason")
    known = _EVIDENCE_NOT_GIVEN.get(why) if isinstance(why, str) else None
    return _edge(eid, src, dst, label, SKIPPED, carried=0,
                 reason=known or f"not given: {_text(why) if why else 'no reason recorded'}")


def _analyser_detail(key: str, data: dict) -> str | None:
    if key == "dotnet_analysis":
        classes = _int(data.get("class_count"))
        dec = _dict(data.get("decompilation")) or {}
        chars = _int(dec.get("source_length"))
        bits = []
        if classes is not None:
            bits.append(f"{classes} classes")
        if chars is not None:
            bits.append(f"{chars:,} chars C#")
        return " · ".join(bits) or None
    if key == "office_analysis":
        return "macros found" if data.get("has_macros") else "no macros"
    if key == "powershell_analysis":
        layers = _int(data.get("layer_count"))
        return f"{layers} layers decoded" if layers is not None else None
    return None


def _ghidra(nodes: list[dict], edges: list[dict], r: dict, cape: dict | None,
            vol: dict | None, ghidra: dict | None,
            routed_by: list[tuple[str, str, str, str]], sample_sha: Any) -> None:
    if ghidra is None:
        nodes.append(_node("ghidra", "Ghidra", ABSENT, reason="no ghidra section"))
        for eid, src, label in (("sample-ghidra", "sample", "original sample"),
                                ("cape-ghidra-payloads", "cape", "CAPE payloads"),
                                ("cape-ghidra-dropped", "cape", "dropped PEs"),
                                ("cape-ghidra-injections", "cape", "injection buffers"),
                                ("volatility-ghidra", "volatility", "malfind regions")):
            edges.append(_edge(eid, src, "ghidra", label, ABSENT, reason="no ghidra section"))
        return

    files = [f for f in _list(ghidra.get("analyzed_files")) or [] if isinstance(f, dict)]
    lost = _lost_prefixes(ghidra)
    trigger = ghidra.get("trigger_reason")
    error = ghidra.get("error")
    triggered = ghidra.get("triggered")
    routed_label = routed_by[0][3] if routed_by else None
    # A routed sample on a pipeline before #646 recorded only the flag: Ghidra
    # never ran, whatever CAPE unpacked.
    routed_not_run = bool(routed_by) and trigger is None and not files and not error

    # -- node
    pe_skipped = _list(ghidra.get("pe_load_skipped"))
    loaded = sum(1 for f in files if f.get("analysis_success")
                 and (_int(f.get("functions_count")) or 0) > 0
                 and str(f.get("program_name") or "")[:16] not in lost)
    bits = [f"{loaded} programs loaded"]
    if pe_skipped:
        bits.append(f"{len(pe_skipped)} PE-load skipped (#390)")
    gwarn = [_text(w) for w in _list(ghidra.get("analysis_warnings")) or []]
    error_why = None
    if error:
        error_why = str(error)
        for k in ("original_sample_note", "payload_access_error"):
            if ghidra.get(k):
                error_why = f"{error_why}: {ghidra[k]}"
        nodes.append(_node("ghidra", "Ghidra", FAILED, reason=error_why, warnings=gwarn))
    elif not triggered:
        nodes.append(_node("ghidra", "Ghidra", SKIPPED, reason="not triggered"))
    elif routed_not_run:
        nodes.append(_node("ghidra", "Ghidra", SKIPPED,
                           reason=f"sample routed to {routed_label}; Ghidra analysed nothing"))
    else:
        nodes.append(_node("ghidra", "Ghidra", OK, " · ".join(bits), warnings=gwarn))

    # -- which PE-loader entries are the original, which are dropped PEs
    pe_entries = [f for f in files if f.get("source") is None]
    # Since #649 the native path analyses the original first whenever it can,
    # dropped PEs or not, and says so in original_sample_included. Before it,
    # dropped_pe_with_signatures meant the original was skipped.
    original_analysed = (trigger == "original_sample_is_pe"
                         or (trigger == "dropped_pe_with_signatures"
                             and ghidra.get("original_sample_included") is True))
    if original_analysed:
        originals, dropped = pe_entries[:1], pe_entries[1:]
    else:
        originals = [f for f in pe_entries
                     if sample_sha and f.get("sha256") == sample_sha]
        dropped = [f for f in pe_entries if f not in originals]

    # -- sample -> ghidra (the original)
    eid = "sample-ghidra"
    if error:
        edges.append(_edge(eid, "sample", "ghidra", "original sample", FAILED,
                           reason=error_why))
    elif not triggered:
        edges.append(_edge(eid, "sample", "ghidra", "original sample", SKIPPED,
                           reason="Ghidra not triggered", carried=0))
    elif routed_by:
        edges.append(_edge(eid, "sample", "ghidra", "original sample", SKIPPED,
                           reason=f"routed to {routed_label} (wrapper, not a native program)",
                           carried=0))
    elif original_analysed:
        source = ghidra.get("original_sample_source")
        note = ghidra.get("original_sample_note")
        items = [_ghidra_item(f, _text(r.get("sample_name") or "original sample"), lost,
                              sha256=_short(f.get("sha256")),
                              source=_text(source) if source else None)
                 for f in originals]
        if not items:
            items = [_item("original sample", MISSING,
                           "trigger_reason says the original was analysed, "
                           "but no result for it is recorded")]
        status, why = _items_status(items)
        if status == FAILED and len(items) == 1:
            why = items[0]["detail"]
        edges.append(_edge(eid, "sample", "ghidra", "original sample", status,
                           reason=why, items=items, expected=1,
                           note=_text(note) if note else None))
    elif trigger == "dropped_pe_with_signatures":
        if "original_sample_included" not in ghidra:
            why = ("CAPE dropped PE files; before #649 the original was analysed only "
                   "when there were none")
        else:
            note = ghidra.get("original_sample_note")
            why = (_text(note) if note else
                   "no loadable copy of the submitted sample; only dropped PEs went "
                   "to Ghidra")
        edges.append(_edge(eid, "sample", "ghidra", "original sample", SKIPPED,
                           reason=why, carried=0))
    elif trigger == "cape_payloads_via_shellcode_loader":
        edges.append(_edge(eid, "sample", "ghidra", "original sample", SKIPPED,
                           reason="no loadable original PE; only CAPE payloads went to Ghidra",
                           carried=0))
    else:
        edges.append(_edge(eid, "sample", "ghidra", "original sample", ABSENT,
                           reason="report records no trigger_reason"))

    # -- cape -> ghidra: CAPE's large payloads (shellcode loader)
    eid = "cape-ghidra-payloads"
    lps = _list(cape.get("large_payloads")) if cape else None
    extracted = _int(cape.get("payloads_extracted")) if cape else None
    payload_files = [f for f in files if f.get("source") == "cape_payload"]
    if cape is None:
        edges.append(_edge(eid, "cape", "ghidra", "CAPE payloads", ABSENT,
                           reason="no cape section"))
    elif lps is None and extracted is None:
        edges.append(_edge(eid, "cape", "ghidra", "CAPE payloads", ABSENT,
                           reason="report records no cape.large_payloads (CAPE extracted "
                                  "none, or the report predates the key)"))
    else:
        lps = [p for p in lps or [] if isinstance(p, dict)]
        by_sha: dict[str, list[dict]] = {}
        for f in payload_files:
            by_sha.setdefault(str(f.get("sha256") or ""), []).append(f)
        items = []
        for p in lps:
            label = _payload_label(p.get("cape_type"))
            extra = {"sha256": _short(p.get("sha256")), "size": _int(p.get("size"))}
            matches = by_sha.get(str(p.get("sha256") or "")) or []
            if matches:
                items.append(_ghidra_item(matches.pop(0), label, lost, **extra))
            elif error or not triggered or routed_not_run:
                items.append(_item(label, ITEM_SKIPPED,
                                   f"not sent to Ghidra: sample routed to {routed_label}"
                                   if routed_not_run else "Ghidra did not analyse payloads",
                                   **extra))
            else:
                items.append(_item(label, MISSING,
                                   "no Ghidra result recorded for this payload", **extra))
        # Results with no matching CAPE record (a report whose large_payloads
        # was trimmed, or a sha mismatch) are still shown, not dropped.
        for rest in by_sha.values():
            for f in rest:
                items.append(_ghidra_item(f, _payload_label(_cape_type_of(f)), lost,
                                          sha256=_short(f.get("sha256"))))
        status, why = _items_status(items, empty_reason="no CAPE payload ≥ 1 KB")
        if routed_not_run and items:
            status, why = SKIPPED, (f"sample routed to {routed_label}: CAPE's {len(items)} "
                                    f"payloads were never sent to Ghidra")
        not_forwarded = (extracted - len(lps)) if extracted is not None else None
        edges.append(_edge(eid, "cape", "ghidra", "CAPE payloads", status, reason=why,
                           items=items, expected=len(lps),
                           extracted=extracted,
                           not_forwarded=not_forwarded if not_forwarded else None,
                           not_forwarded_reason=(
                               "the pipeline forwards at most the 5 largest payloads "
                               "of ≥ 1 KB" if not_forwarded else None)))

    # -- cape -> ghidra: dropped PEs (PE loader)
    eid = "cape-ghidra-dropped"
    items = [_ghidra_item(f, _text(f.get("filename") or f.get("program_name") or "dropped PE"),
                          lost, sha256=_short(f.get("sha256"))) for f in dropped]
    skip_reason = ghidra.get("pe_load_skipped_reason")
    for sha in pe_skipped or []:
        items.append(_item(_short(sha) or "?", ITEM_SKIPPED,
                           _text(skip_reason) if skip_reason else "skipped; no reason recorded",
                           sha256=_short(sha)))
    if error:
        edges.append(_edge(eid, "cape", "ghidra", "dropped PEs", FAILED,
                           reason=ghidra.get("payload_access_error") or error))
    elif not triggered or routed_not_run:
        edges.append(_edge(eid, "cape", "ghidra", "dropped PEs", SKIPPED,
                           reason="Ghidra not triggered" if not triggered
                           else f"sample routed to {routed_label}"))
    elif trigger is None and not files:
        edges.append(_edge(eid, "cape", "ghidra", "dropped PEs", ABSENT,
                           reason="report records no trigger_reason"))
    else:
        status, why = _items_status(items, empty_reason="no dropped PE files")
        if ghidra.get("payload_access_error"):
            status, why = FAILED, _text(ghidra["payload_access_error"])
        edges.append(_edge(eid, "cape", "ghidra", "dropped PEs", status, reason=why,
                           items=items))

    # -- cape -> ghidra: injection buffers
    eid = "cape-ghidra-injections"
    bufs = _list(cape.get("injection_buffers")) if cape else None
    if bufs is None:
        edges.append(_edge(eid, "cape", "ghidra", "injection buffers", ABSENT,
                           reason="report records no cape.injection_buffers (written only "
                                  "when CAPE captured some, and only since #614)"))
    else:
        inj_files: dict[tuple, list[dict]] = {}
        for f in files:
            if f.get("source") == "cape_injection":
                inj_files.setdefault((str(f.get("pid")), str(f.get("injection_address"))),
                                     []).append(f)
        items = []
        for b in bufs:
            if not isinstance(b, dict):
                continue
            label = f"pid {b.get('target_pid')} @ {b.get('injection_address')}"
            size = _int(b.get("size"))
            matches = inj_files.get((str(b.get("target_pid")), str(b.get("injection_address"))))
            if matches:
                f = matches.pop(0)
                if not f.get("analysis_success") and f.get("note") \
                        and str(f["note"]).startswith("Artifact extraction only"):
                    items.append(_item(label, ITEM_SKIPPED, _text(f["note"]), size=size))
                else:
                    items.append(_ghidra_item(f, label, lost, size=size))
            elif error or not triggered or routed_not_run:
                items.append(_item(label, ITEM_SKIPPED, "Ghidra did not run on it", size=size))
            else:
                items.append(_item(label, MISSING, "no Ghidra result recorded for this buffer",
                                   size=size))
        status, why = _items_status(items)
        edges.append(_edge(eid, "cape", "ghidra", "injection buffers", status, reason=why,
                           items=items, expected=len(items)))

    # -- volatility -> ghidra: malfind regions
    eid = "volatility-ghidra"
    mal = [f for f in files if f.get("source") == "malfind_injection"]
    if vol is None:
        edges.append(_edge(eid, "volatility", "ghidra", "malfind regions", ABSENT,
                           reason="no volatility section"))
    elif not vol.get("triggered"):
        edges.append(_edge(eid, "volatility", "ghidra", "malfind regions", SKIPPED,
                           reason="Volatility did not run", carried=0))
    elif error or not triggered or routed_not_run:
        edges.append(_edge(eid, "volatility", "ghidra", "malfind regions", SKIPPED,
                           reason="Ghidra did not analyse candidates", carried=0))
    else:
        items = [_ghidra_item(f, f"pid {f.get('pid')} @ {f.get('injection_address')}", lost)
                 for f in mal]
        status, why = _items_status(items, empty_reason="no malfind region reached Ghidra")
        edges.append(_edge(eid, "volatility", "ghidra", "malfind regions", status,
                           reason=why, items=items))


def _re_agent(nodes: list[dict], edges: list[dict], r: dict, ghidra: dict | None,
              llm: dict | None, routed_by: list[tuple[str, str, str, str]]) -> None:
    if llm is None:
        nodes.append(_node("re_agent", "RE agent", ABSENT,
                           reason="no llm_interpretation section"))
        edges.append(_edge("ghidra-re_agent", "ghidra", "re_agent", "program", ABSENT,
                           reason="no llm_interpretation section"))
        return

    calls = _int(llm.get("tool_calls_used"))
    model = llm.get("model_final")
    inp = _dict(llm.get("input"))
    bits = []
    if inp and inp.get("program_name"):
        bits.append(f"read {str(inp['program_name'])[:12]}")
    if calls is not None:
        bits.append(f"{calls} tool calls")
    if isinstance(model, str) and model:
        bits.append(model)
    detail = " · ".join(bits) or None

    if llm.get("error"):
        status, why = FAILED, llm["error"]
    elif llm.get("enabled") is False or llm.get("reason") == "not_triggered":
        status, why = SKIPPED, ("interpretation disabled" if llm.get("enabled") is False
                                else "not triggered")
    elif llm.get("reason") == "no_analysis_data":
        status, why = SKIPPED, "no successful analysis to read"
    else:
        status, why = OK, None
    nodes.append(_node("re_agent", "RE agent", status, detail, reason=why,
                       timed_out=bool(llm.get("timed_out"))))

    if status == SKIPPED:
        edges.append(_edge("ghidra-re_agent", "ghidra", "re_agent", "program", SKIPPED,
                           reason=why, carried=0))
        return

    files = [f for f in _list((ghidra or {}).get("analyzed_files")) or []
             if isinstance(f, dict)]

    if inp is not None:
        # Recorded since #646: what the agent was actually given.
        prog = inp.get("program_name")
        match = next((f for f in files if f.get("program_name") == prog), None)
        cape_type = inp.get("cape_type") if "cape_type" in inp else (
            _cape_type_of(match) if match else None)
        if inp.get("source") == "original_sample":
            # Native path since #649: the canonical program can be the sample itself.
            label = "original sample"
        elif cape_type is not None or inp.get("source") == "cape_payload":
            label = _payload_label(cape_type)
        else:
            label = _text(prog or "program")
        chosen = inp.get("chosen_because")
        functions = _int(inp.get("functions_count"))
        item = _item(label, READ, f"program {_short(prog)}" if prog else None,
                     functions=functions, sha256=_short(prog), kind=_text(inp.get("kind") or ""))
        edges.append(_edge("ghidra-re_agent", "ghidra", "re_agent", "program", OK,
                           reason=(_text(chosen) if chosen
                                   else "chosen_because not recorded (report predates it)"),
                           items=[item], expected=1))
        wrapper = inp.get("wrapper_routed_by")
        for flag, _key, node_id, label_ in routed_by:
            if flag == wrapper or wrapper is None:
                edges.append(_edge(f"{node_id}-re_agent", node_id, "re_agent", "wrapper",
                                   SKIPPED, carried=0,
                                   reason=f"agent read the unpacked payload instead of "
                                          f"the {label_} output"))
        return

    # No recorded input: infer from Stage 4.5's precedence, and say so.
    for key in _INTERPRET_PRECEDENCE:
        data = _dict(r.get(key))
        if not data or not data.get("analysis_success"):
            continue
        if key == "office_analysis" and not data.get("has_macros"):
            continue
        node_id = next(n for _f, k, n, _l in ROUTED_ANALYSERS if k == key)
        label_ = next(lbl for _f, k, _n, lbl in ROUTED_ANALYSERS if k == key)
        edges.append(_edge(f"{node_id}-re_agent", node_id, "re_agent", "decompiled source",
                           OK, carried=1, inferred=True,
                           reason="inferred from the pipeline's precedence; this report "
                                  "does not record the agent's input"))
        edges.append(_edge("ghidra-re_agent", "ghidra", "re_agent", "program", SKIPPED,
                           carried=0, inferred=True,
                           reason=f"agent read the {label_} output, not a Ghidra program"))
        return

    if any(f.get("analysis_success") for f in files):
        edges.append(_edge("ghidra-re_agent", "ghidra", "re_agent", "program", OK,
                           carried=1, inferred=True,
                           reason="which program the agent read is not recorded "
                                  "(report predates llm_interpretation.input)",
                           canonical=_short(ghidra.get("program_name")) if ghidra else None))
    else:
        edges.append(_edge("ghidra-re_agent", "ghidra", "re_agent", "program", ABSENT,
                           reason="report does not record what the agent read"))
