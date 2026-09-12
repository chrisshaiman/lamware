#!/usr/bin/env python3
"""Score a pipeline report: did this sample produce what it SHOULD have?

Run it over any set of reports:

    score_report.py /opt/pipeline/reports/r5_*/report.json

Exits non-zero if any report is SUSPECT, so it works as a gate.

Separate from the run driver on purpose. The driver's inline check has been wrong
three times, each time in the same direction — it read one field and called
everything else OK:

  run 4  read llm_interpretation.error only, so six samples whose 404 sat in
         llm_interpretation.analysis.error were reported OK (#590)
  run 5  flagged EMPTY-analysis without asking WHY interpret produced nothing,
         so unclassified_25d18a2b — where Ghidra finds no PE files and interpret
         is correctly never invoked — came out as a false positive

The distinction that matters is not "is there an analysis" but "should there
have been one". Those are different questions and only the second is a verdict.
"""
import json
import sys
from pathlib import Path

#: A backstop, not the primary rule. monitor_injection_failed_pids is the direct
#: signal; this catches the under-instrumented run that produces no warning.
#:
#:     quasarrat, task 1103      1 process   2,344 api calls   -> observed 17
#:     xworm, healthy run        1 process  24,132 api calls   -> observed 17
#:     quasarrat, task 1117      1 process   4,114 api calls   (injection failed)
#:     quasarrat, tasks 1118-21  6-7 procs  49k-92k api calls
#:
#: process_count alone cannot separate the first two, which is why the rule is on
#: call volume. 5,000 sits an order of magnitude below every healthy run observed
#: and above both known bad ones.
#:
#: Still provisional and still derived from a handful of runs — state it rather
#: than hide it. The durable version of this test is comparative, the same sample
#: across runs, but that needs more than one report and this file scores one.
#:
#: KNOWN GAP, measured rather than assumed. Partial instrumentation loss clears
#: every rule in this file:
#:
#:     task 1109 salat     33,971 calls, 10 procs   (clean runs: 78-92k, 14-15)
#:     task 1090 formbook  32,764 calls,  8 procs   (clean runs: 47-56k, 10)
#:
#: Both lost processes mid-run and both sit far above this threshold. Raising it
#: is not the fix — 33,971 is a perfectly healthy total for a quieter sample, and
#: vanished_pids cannot separate them either, since every CLEAN salat run carries
#: one as well. Only a per-sample baseline distinguishes these, so a run still
#: needs comparing against its own history before its numbers are averaged.
QUIET_DETONATION_API_CALLS = 5000


def score(report: dict) -> tuple[str, str]:
    """(verdict, detail). verdict is OK, SKIPPED or SUSPECT."""
    cape = report.get("cape") or {}
    if cape.get("status") in ("error", None) and not cape.get("malscore"):
        return "SUSPECT", f"cape status={cape.get('status')}"

    # Did CAPE actually OBSERVE the sample? observed_behaviour is only a
    # measurement when it did (#518).
    #
    # Direct signal first. CAPE names the processes it injected into but never
    # heard back from, and each one is payload behaviour that happened and went
    # unrecorded — in the quasarrat repro, 45-90k api calls of it. This is not an
    # inference from output volume, so it fires even when the lost child would
    # have pushed the total above any threshold.
    det = cape.get("detonation") or {}
    lost = det.get("monitor_injection_failed_pids") or []
    if lost:
        return "SUSPECT", (
            f"lost instrumentation: CAPE injected {len(lost)} process(es) "
            f"{lost} that never loaded the monitor — their behaviour is missing "
            f"from this report, so the score understates the sample")

    # The heuristic stays as a backstop for the failure mode that produces no
    # warning at all: task 1103 was under-instrumented with an empty
    # monitor_injection_failed_pids.
    calls = det.get("api_calls_total")
    if calls is not None and calls < QUIET_DETONATION_API_CALLS:
        # Say WHY where the log allows it. A process the poller found missing,
        # with no exit hook, is the task-1103 shape and reads very differently
        # from a sample that ran briefly and exited.
        vanished = det.get("vanished_pids") or []
        why = (f" — pid(s) {vanished} vanished with no exit call"
               if vanished and not det.get("clean_exit_pids") else "")
        return "SUSPECT", (f"detonation looks quiet: {calls} api calls across "
                           f"{det.get('process_count')} process(es), "
                           f"{det.get('monitors_loaded')} monitor(s) loaded"
                           f"{why} — too little was observed for the score to "
                           f"mean anything")

    gh = report.get("ghidra") or {}
    li = report.get("llm_interpretation") or {}
    an = li.get("analysis") or {}

    # Did interpret have anything to work on? Ghidra failing or not triggering is
    # a property of the SAMPLE, not a pipeline fault — unclassified_25d18a2b is a
    # 56MB blob with no PE inside, so "no analysis" is the correct outcome.
    ghidra_usable = bool(gh.get("triggered")) and not gh.get("error")

    err = li.get("error") or an.get("error")   # BOTH levels — run 4's lesson
    if err:
        return "SUSPECT", f"interpret error: {str(err)[:70]}"
    if li.get("timed_out"):
        return "SUSPECT", "interpret timed out"
    if not an:
        if not ghidra_usable:
            reason = gh.get("error") or ("not triggered" if not gh.get("triggered") else "?")
            return "SKIPPED", f"interpret not applicable (ghidra: {str(reason)[:50]})"
        return "SUSPECT", "ghidra produced output but interpret returned no analysis"
    return "OK", f"{li.get('tool_calls_used')} tool calls / {li.get('duration_seconds')}s"


def main() -> None:
    rc = 0
    for path in sys.argv[1:]:
        p = Path(path)
        try:
            v, detail = score(json.loads(p.read_text()))
        except Exception as e:  # noqa: BLE001
            v, detail = "SUSPECT", f"unreadable: {type(e).__name__}: {e}"
        label = p.parent.name
        print(f"  {label:34} {v:8} {detail}")
        if v == "SUSPECT":
            rc = 1
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
