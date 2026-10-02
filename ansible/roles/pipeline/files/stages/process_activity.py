"""Bounded per-process activity summary from CAPE's behaviour log (#406).

The investigation agent's ``get_api_traces`` tool answers from the pipeline's
own report.json (``analyses.report_json``), never from CAPE storage. Until #406
nothing in the pipeline copied CAPE's process list into that report, so the
tool read ``cape.behavior`` -- a key with no producer -- and told the agent
that every analysis had zero processes and zero API calls.

This module is the producer. It runs once, at pipeline time, against CAPE's
full report.json (which extract_cape_intel already loads) and keeps only what
the agent needs: the process tree and how many calls of which kind each
process made. Individual calls and their arguments are NOT kept; CAPE's own
report for task 1275 was 61 MB, 60,089 call entries across 11 processes.

Everything here is attacker-influenced -- process names, command lines and
module paths are chosen by the sample -- so every string is length-capped and
treated as data, and every truncation is recorded next to the value it
truncated. A truncated list must say it is truncated; an agent that sees 64
processes must be able to tell "64" from "the first 64 of 400".

Stdlib only, no I/O: the API test suite executes this file directly to prove
the consumer reads what this producer writes.
"""

from __future__ import annotations

from collections import Counter

#: Bumped when the shape changes, so the consumer can tell old from new.
SCHEMA_VERSION = 1

#: Processes kept, in CAPE's order (first seen). Task 1275 recorded 11.
MAX_PROCESSES = 64
#: Distinct API names kept per process, most-called first. The busiest process
#: in task 1275 used 125 distinct APIs, so this keeps all of them in practice;
#: a rare API is what an analyst filters for, so the cap is set above the
#: observed maximum rather than at a "top N".
MAX_APIS_PER_PROCESS = 200
#: Distinct categories kept per process. CAPE has ~20; task 1275 used 14.
MAX_CATEGORIES = 32

#: Character caps for sample-controlled strings.
MAX_NAME_CHARS = 260
MAX_PATH_CHARS = 520
MAX_CMDLINE_CHARS = 1024
MAX_LABEL_CHARS = 128   # API and category names
MAX_TIMESTAMP_CHARS = 40


def _text(value: object, limit: int) -> tuple[str, bool]:
    """Return (capped string, was_truncated) for an untrusted value.

    NUL is removed because PostgreSQL's jsonb rejects ``\\u0000`` and db_ingest
    stores the whole report as jsonb: one NUL in a sample-chosen command line
    would fail ingestion of the entire analysis.
    """
    if value is None:
        return "", False
    s = value if isinstance(value, str) else str(value)
    s = s.replace("\x00", "")
    if len(s) > limit:
        return s[:limit], True
    return s, False


def _int_or_none(value: object) -> int | None:
    """CAPE writes pids as int; anything else is recorded as unknown, not 0."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _counts(counter: Counter, limit: int) -> tuple[dict[str, int], bool]:
    """Most-common-first dict of at most ``limit`` labels, and whether it was cut."""
    out: dict[str, int] = {}
    for label, n in counter.most_common():
        if len(out) >= limit:
            return out, True
        key, _ = _text(label, MAX_LABEL_CHARS)
        out[key] = out.get(key, 0) + n
    return out, False


def _summarise_process(proc: dict) -> dict:
    calls = proc.get("calls")
    calls = calls if isinstance(calls, list) else []
    apis: Counter = Counter()
    categories: Counter = Counter()
    for call in calls:
        if not isinstance(call, dict):
            continue
        apis[call.get("api") or "?"] += 1
        categories[call.get("category") or "?"] += 1

    truncated_fields: list[str] = []
    name, cut = _text(proc.get("process_name"), MAX_NAME_CHARS)
    if cut:
        truncated_fields.append("name")
    module_path, cut = _text(proc.get("module_path"), MAX_PATH_CHARS)
    if cut:
        truncated_fields.append("module_path")
    environ = proc.get("environ") if isinstance(proc.get("environ"), dict) else {}
    # Same precedence as extract_cape_intel's process_cmdlines.
    command_line, cut = _text(
        environ.get("CommandLine") or proc.get("command_line"), MAX_CMDLINE_CHARS)
    if cut:
        truncated_fields.append("command_line")
    first_seen, _ = _text(proc.get("first_seen"), MAX_TIMESTAMP_CHARS)

    api_counts, apis_cut = _counts(apis, MAX_APIS_PER_PROCESS)
    category_counts, cats_cut = _counts(categories, MAX_CATEGORIES)

    entry = {
        "pid": _int_or_none(proc.get("process_id")),
        "ppid": _int_or_none(proc.get("parent_id")),
        "name": name,
        "module_path": module_path,
        "command_line": command_line,
        "first_seen": first_seen,
        "api_calls": len(calls),
        "categories": category_counts,
        "categories_truncated": cats_cut,
        "apis": api_counts,
        "apis_distinct": len(apis),
        "apis_truncated": apis_cut,
    }
    if truncated_fields:
        entry["truncated_fields"] = truncated_fields
    return entry


def summarize_process_activity(full_report: dict) -> dict | None:
    """Summarise CAPE's ``behavior.processes`` into a bounded, JSON-safe dict.

    Returns None when CAPE's report has no ``behavior.processes`` list at all,
    so the key is absent and the consumer says "not recorded". An empty list is
    different -- CAPE ran and observed nothing -- and is returned as a summary
    with ``process_count`` 0, because that IS what CAPE recorded (usually lost
    instrumentation; see detonation_health).

    ``process_count`` and ``api_calls_total`` always cover every process CAPE
    recorded, including any dropped by ``MAX_PROCESSES``. ``api_calls_total``
    counts call entries exactly as detonation_health does, so the two agree.
    """
    behavior = full_report.get("behavior") if isinstance(full_report, dict) else None
    if not isinstance(behavior, dict):
        return None
    procs = behavior.get("processes")
    if not isinstance(procs, list):
        return None
    procs = [p for p in procs if isinstance(p, dict)]

    kept = [_summarise_process(p) for p in procs[:MAX_PROCESSES]]
    total_calls = sum(
        len(p["calls"]) if isinstance(p.get("calls"), list) else 0 for p in procs)
    return {
        "schema": SCHEMA_VERSION,
        "source": "CAPE report.json behavior.processes",
        "process_count": len(procs),
        "api_calls_total": total_calls,
        "processes": kept,
        "processes_truncated": len(procs) > MAX_PROCESSES,
        "processes_omitted": max(0, len(procs) - MAX_PROCESSES),
        "limits": {
            "max_processes": MAX_PROCESSES,
            "max_apis_per_process": MAX_APIS_PER_PROCESS,
            "max_categories": MAX_CATEGORIES,
            "max_command_line_chars": MAX_CMDLINE_CHARS,
        },
    }
