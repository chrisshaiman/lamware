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

#: A detonation this quiet did not happen. Provisional, and derived from n=3
#: rather than a principled floor — state it rather than hide it:
#:
#:     quasarrat, failed run     1 process   2,344 api calls   -> observed 17
#:     xworm, healthy run        1 process  24,132 api calls   -> observed 17
#:     quasarrat, healthy run    6 processes ~48,000 api calls -> observed 55
#:
#: process_count alone cannot separate those first two, which is why the rule is
#: on call volume. 5,000 sits an order of magnitude below every healthy run
#: observed and twice the only failed one. The durable version of this test is
#: comparative — the same sample across runs — but that needs more than one
#: report, and this file scores one.
QUIET_DETONATION_API_CALLS = 5000


def score(report: dict) -> tuple[str, str]:
    """(verdict, detail). verdict is OK, SKIPPED or SUSPECT."""
    cape = report.get("cape") or {}
    if cape.get("status") in ("error", None) and not cape.get("malscore"):
        return "SUSPECT", f"cape status={cape.get('status')}"

    # Did the sample actually run? observed_behaviour is only a measurement when
    # it did. A run where the sample died before spawning scores a low number that
    # looks like a result and is not one (#518).
    det = cape.get("detonation") or {}
    calls = det.get("api_calls_total")
    if calls is not None and calls < QUIET_DETONATION_API_CALLS:
        return "SUSPECT", (f"detonation looks failed: {calls} api calls across "
                           f"{det.get('process_count')} process(es) — the sample "
                           f"probably died before doing anything")

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
