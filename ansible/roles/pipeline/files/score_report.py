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

#: A backstop, not the primary rule. The tier (see score()) is the primary
#: signal; this catches a run that died before hollowing anything, where there is
#: no tier evidence to read because nothing got far enough to be lost.
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
    det = cape.get("detonation") or {}

    # Tier-based verdict. The old rule rejected any run that lost a hollowed
    # child, which discarded ~40% of runs — and was wrong, because a PARTIAL run
    # is not deficient data, it is data from a different measurement condition:
    #
    #   CLEAN     signatures 34.3 +/- 0.7    both children traced
    #   PARTIAL   signatures 32.2 +/- 0.4    one traced, one lost
    #   ALL-LOST  signatures 20.8 +/- 0.4    neither traced
    #
    # Within a tier the instrument is near-deterministic (+/-0.5). ACROSS tiers
    # the means differ by enough that pooling them produces the +/-15-25 "noise
    # floor" that made #518 unanswerable — two back-to-back batches of the same
    # sample averaged 53.5 and 45.7 purely because their tier mix differed.
    #
    # So PARTIAL is USABLE and must be kept, but its tier must be recorded so
    # analysis compares like with like. Only ALL-LOST and NO-HOLLOW are rejected:
    # in those, the payload behaviour was never observed at all.
    tier = det.get("tier")
    lost = det.get("lost_pids") or det.get("monitor_injection_failed_pids") or []
    if tier == "ALL-LOST":
        return "SUSPECT", (
            f"no payload observed: the sample hollowed {len(det.get('hollowed_pids') or [])} "
            f"child process(es) {lost} and CAPE instrumented none of them, so this "
            f"run measures the launcher only (#606)")
    if tier == "NO-HOLLOW":
        return "SUSPECT", (
            "sample never reached its hollowing stage — it died during startup, "
            "so there is no payload behaviour in this report to measure")

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
