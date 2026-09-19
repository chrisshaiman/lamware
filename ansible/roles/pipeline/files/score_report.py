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

# (QUIET_DETONATION_API_CALLS removed — see score() for why a global
# call-volume threshold cannot work across this corpus.)


def score(report: dict) -> tuple[str, str]:
    """(verdict, detail). verdict is OK, SKIPPED or SUSPECT."""
    cape = report.get("cape") or {}
    if cape.get("status") in ("error", None) and not cape.get("malscore"):
        return "SUSPECT", f"cape status={cape.get('status')}"

    # Did CAPE actually OBSERVE the sample? observed_behaviour is only a
    # measurement when it did (#518).
    det = cape.get("detonation") or {}

    # Tier is RECORDED but no longer used to reject, because there is no global
    # definition of a failed run. Measured across ~230 runs of nine samples:
    #
    #   NO-HOLLOW  means "died before hollowing" for quasarrat, and simply
    #              "does not hollow" for salat, latrodectus, unclassified,
    #              xworm and agenttesla -- 5 of 9 samples, 100% false positives
    #   ALL-LOST   is fatal for quasarrat (observed 26 vs 54) and harmless for
    #              cobaltstrikebeacon, which is ALL-LOST in 12 of 13 runs while
    #              scoring the most stable in the corpus (90.1 +/- 2.5), because
    #              39 other processes carry its payload
    #   PARTIAL    is equivalent to CLEAN on signatures for both samples that
    #              produce it (27.6 vs 27.8; 32.7 vs 34.0)
    #
    # An earlier version of this file rejected NO-HOLLOW and ALL-LOST globally.
    # That would have failed every run of five samples. The tier is real and
    # worth recording -- it is what made #518 tractable -- but whether a given
    # tier means failure is a property of the sample, not of the tier.
    #
    # Rejection now needs a per-sample baseline (#606). Until that exists this
    # file deliberately does NOT reject on tier: a rule that fires on healthy
    # data is worse than no rule, because it trains the operator to ignore it.
    tier = det.get("tier")
    if tier:
        report.setdefault("_notes", []).append(f"detonation tier: {tier}")

    # The global call-volume backstop was removed with the tier rules, for the
    # same reason: measured across the corpus, "normal" spans four orders of
    # magnitude and the 5,000-call threshold rejected healthy samples.
    #
    #   769fc3a0     0 calls   normal (7 runs, the sample never executes)
    #   latrodectus  266       normal
    #   agenttesla   3,741     normal
    #   salat        90,225    normal
    #   quasarrat    2,344     DEAD -- but indistinguishable from the above
    #                          without knowing what quasarrat usually does
    #
    # Separating a dead run from a quiet sample needs that sample's own history,
    # and this file scores one report. That history exists for the ten-sample
    # eval corpus and CANNOT exist for the production feed, where every sample
    # arrives from MalwareBazaar seen exactly once. So detonation gating belongs
    # in the eval path, not here (#606).
    #
    # Triage is unharmed by the loss this would have caught: a run that loses
    # its hollowed children still yields malscore, family detection and usually
    # config extraction, because those come from memory scanning rather than the
    # API trace. Trace completeness is a measurement concern.

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
