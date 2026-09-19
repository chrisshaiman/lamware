# The two instruments

lamware measures two different things, and conflating them is how six weeks went
into a "noise floor" that turned out not to be noise. Each has one command.

| | `make eval` | `make detonate` |
|---|---|---|
| **asks** | is the model reading the binary correctly? | how much does the observation itself vary? |
| **input** | each corpus sample's **frozen** `report.json` | a sample, detonated N times |
| **detonates** | no | **yes — live malware** |
| **varies** | the LLM arm | nothing; the sample and guest are held fixed |
| **code** | `lamware_eval` | `lamware_detonate` |

They are not interchangeable and neither substitutes for the other. `make eval`
re-runs only the interpretation stage against a stored report, so it cannot see
a detonation problem at all. `make detonate` never invokes the model, so it
cannot see an interpretation problem.

## Why `lamware_detonate` exists

It did not, until 2026-09-18. `lamware_eval` has been committed and tested since
July, and it never detonates — so "run this sample N times and tell me how much
the observation varies" had no code path.

Every #518 batch was therefore a fresh shell script on the sandbox: **thirteen
of them between 2026-09-04 and 2026-09-17**. They diverged, because each one
started from whichever previous script was nearest to hand rather than from what
the last one had learned. Only the final script pinned the guest, and by then
tasks 1132 and 1133 had been discarded for silently running on `office`.

The invariants those scripts accumulated are now executable and mutation-tested
(`pipeline/tests/test_detonation_batch.py`), which is the only form in which
that knowledge survives the next rewrite.

## Reading a detonation scorecard

Output is stratified by **detonation tier**, which records how many of the
sample's hollowed child processes CAPE actually managed to instrument:

    CLEAN      every hollowed child traced
    PARTIAL    some traced, some lost
    ALL-LOST   none traced
    NO-HOLLOW  the sample never hollowed anything

**The pooled mean across tiers is not a measurement.** It is the artefact that
produced #518's apparent ±15–25 variance: two back-to-back batches of the same
sample on the same host averaged 53.5 and 45.7 purely because their CLEAN /
PARTIAL mix differed. Within a tier the same instrument is near-deterministic —
about ±0.5 on ~33, roughly 2% relative. The scorecard therefore prints the
pooled figure only alongside the strata, and labels it explicitly whenever more
than one tier is present.

Tier is a property of **our observation**, not of the sample. The malware
behaves identically every run; parent API counts are byte-identical across runs.

## What a tier does NOT mean

A tier is not a verdict, and there is no global rule that turns one into a
failure. Measured across ~230 runs of nine samples:

* `NO-HOLLOW` means "died before hollowing" for quasarrat and simply "does not
  hollow" for salat, latrodectus, xworm, agenttesla and one unclassified sample
  — five of nine, 100% false positives.
* `ALL-LOST` is fatal for quasarrat (26 observed vs 54) and **harmless** for
  cobaltstrikebeacon, which is ALL-LOST in 12 of 13 runs while being the most
  stable sample in the corpus (90.1 ± 2.5), because 39 other processes carry its
  payload.
* "Normal" API-call volume spans four orders of magnitude across the corpus, so
  no single call-count floor separates a dead run from a quiet sample.

Global gating on tier or call volume was shipped in #607 and reverted in #609
for exactly this reason. **A rule that fires on healthy data is worse than no
rule, because it trains the operator to ignore it.**

## Eval corpus vs production feed

This is the structural line, not a stylistic one:

**Eval corpus** — ten known samples, run repeatedly. A per-sample history exists,
so "is this run valid?" is answerable, tier gating is possible in principle
(#606), and a thesis claim can be made.

**Production feed** — novel samples from MalwareBazaar, each seen once. No
per-sample history can exist, so no baseline and no validity test are possible.
Tier is recorded as **metadata only** and never gates anything. Its output is
triage — IOCs, config extraction, severity — which is useful without any thesis.

The consequence is worth stating plainly: **a thesis claim can only be made on
the eval corpus.** The production feed generates triage output and interesting
samples, not evidence.

`score_report.py` therefore records the tier and does not reject on it. Detonation
gating, if it ever lands, belongs on the eval path where a baseline can exist.

## Safety

`make detonate` runs live malware. It is deliberately foreground and
operator-typed: it starts a one-shot systemd unit and **enables nothing**, so
nothing in this path can arm a recurring or unattended detonation. The
auto-feeder is a separate thing and is never started or enabled without being
asked for explicitly.

Both commands run under systemd on the sandbox rather than over the ssh session,
because a multi-hour job must survive a disconnect — an earlier attempt used
`nohup … &` inside an ssh command, was killed by a signal partway through a
5.5-hour batch, and left a truncated log with an untouched report and no error
anywhere.
