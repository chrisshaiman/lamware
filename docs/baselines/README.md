# Evasion baselines, before and after the 2026-09-04 guest rebuild

> **The result recorded here has been WITHDRAWN.** It was reported as a null.
> It is not a null; it is an unusable measurement. Three of the six post-rebuild
> runs contain samples CAPE failed to instrument, and those runs were averaged
> in as data. See "Why the result was withdrawn" below. The experiment needs to
> be re-run with the screening described at the end.

A guest-image rebuild is a one-way door. These files record what the images
built **2026-05-06** allowed the sandbox to observe, captured **2026-09-01**
before any rebuild, because that measurement cannot be retaken afterwards
(#517).

They are committed here rather than left on the host for the obvious reason:
the host is the thing about to change.

## What was decided before the comparison existed

The primary metric is `observed_behaviour` — signatures + payloads extracted +
injected PIDs. Evasion, when it works, makes a sample do **less** in front of
us, so more observed behaviour after a rebuild is the predicted effect.

**Less would be a real negative result and must be reported as one.** Choosing a
metric after seeing the after-numbers is how a result becomes unfalsifiable,
which is the same discipline the held-out MITRE key exists to enforce (#491).

Anti-VM signature names are recorded and deliberately **not scored**: a sample
checking for a VM says nothing about whether it found one, and counting those
would measure the question rather than the answer (#478).

That pre-registration held up. What failed is upstream of it: the metric assumes
the numbers going in are measurements of the sample, and for several runs they
were measurements of the sandbox losing track of it.

## Totals

| corpus | samples | observed_behaviour |
|---|---|---|
| native-pe | 5 | 232 |
| dotnet | 5 | 207 |

## What was originally reported

| corpus | pre | run1 | run2 | run3 | post mean | sd | change |
|---|---|---|---|---|---|---|---|
| native-pe | 232 | 238 | 244 | 216 | 232.7 | 14.7 | +0.7 |
| dotnet | 207 | 188 | 146 | 192 | 175.3 | 25.5 | -31.7 |

Reported as a null on the grounds that +0.7 against sd 14.7 is nothing and
-31.7 against sd 25.5 is about 1.2 standard deviations on n=3.

## Why the result was withdrawn

`observed_behaviour` is only a measurement when CAPE actually observed the
sample. In several of these runs it did not, and the resulting low score was
averaged in as though it were a quiet detonation.

A controlled reproduction settled the mechanism. Five back-to-back quasarrat
detonations on an idle host (tasks 1117-1121) showed the sample behaving
**identically every time**: it hollows two child processes, `CreateProcessW`
succeeds, and the parent runs 4,112-4,118 API calls before a clean
`NtTerminateProcess`. One run in five still collapsed:

| task | api calls | processes | payloads | what happened |
|---|---|---|---|---|
| 1117 | 4,114 | 1 | 3 | both children injected, **neither loaded the monitor** |
| 1118 | 49,574 | 6 | 14 | — |
| 1119 | 89,165 | 7 | 11 | — |
| 1120 | 91,880 | 7 | 24 | — |
| 1121 | 87,217 | 7 | 24 | — |

Task 1117 is not a sample that did little. It is 45,000-90,000 API calls of
payload behaviour that happened and was never recorded. The guest Application
event log holds no crash record, so this is lost instrumentation, not a dead
sample.

CAPE says so directly:

```
WARNING: Monitor injection attempted but failed for process 3092
WARNING: Monitor injection attempted but failed for process 6680
```

A pid enters `INJECT_LIST` when the monitor DLL is injected
(`analyzer/windows/analyzer.py:1412`) and leaves it when that DLL reports back
`LOADED` (`:1099`). Whatever is still in the list at `complete()` was injected
into and never heard from. Against a process the sample is concurrently
hollowing, that callback is a race, and it is lost roughly one time in five.

Corpus-wide the warning appears in **91 of 1115** analyses (8.2%), but it is not
evenly spread — tasks 1000-1049, the window these baselines come from, run at
**34.8%**.

### There is a second mechanism

Task 1103 lost its payload with **no warning at all**. Its trace stops dead
inside .NET JIT warmup, ten silent seconds pass, the queued memory dump is
reported as `doesn't exist anymore`, and CAPE's poller then finds the process
missing. CAPE words the two cases differently and the distinction is the signal:

- `Process with pid N has terminated` — the `NtTerminateProcess` hook fired. A
  real exit the monitor witnessed. All five repro runs logged this.
- `Process with pid N appears to have terminated` — the poller found it gone,
  with no exit call. Task 1103 logged this and nothing else.

**What ends the process in this second mode is still unknown.** Guest event-log
capture (`evtx`) was enabled afterwards (#598), so the next occurrence should
say whether Windows recorded a crash.

### Which cells are affected

Matching the recorded per-sample process counts back to the CAPE tasks:

| run | total | bad cell | task | signal |
|---|---|---|---|---|
| dotnet run1 | 188 | formbook 52 (8 procs, others 10) | 1090 | 2 vanished, no exit hook |
| dotnet run2 | **146** | warzonerat 30 (1 proc, others 2) | 1102 | **injection failed x2** |
| dotnet run2 | | quasarrat 17 (1 proc, others 6-7) | 1103 | vanished mid-JIT |
| dotnet run3 | 192 | — clean — | | |
| native run1 | 238 | — clean — | | |
| native run2 | 244 | — clean — | | |
| native run3 | **216** | salat 26 (10 procs, others 14-15) | 1109 | under-instrumented |

The two lowest runs are exactly the two runs carrying instrumentation failures,
and dotnet run2's two failures are consecutive tasks. The spread the original
write-up called a noise floor is substantially this.

## What the earlier "noise floor" section got wrong

It reported that per-sample spread tracks magnitude, concluded the instrument
could not resolve better than ~25%, and offered that as the more useful finding.
The observation was real; the explanation was not. Quiet samples are reproducible
because they spawn no children to lose — latrodectus is one process and varies by
zero. Active samples vary because the child processes carrying their payload are
what goes missing.

**That correction is partial and should not be over-read.** Per-sample injection
failure rates do NOT track the spread ordering: quasarrat has the widest spread
(17-56) but one of the lowest failure rates (8.3%), while salat's worst run shows
no injection warning at all. Instrumentation loss explains the specific collapsed
cells above. It is not established as a complete account of the variance.

Likewise, no corrected effect size is offered here. An attempt to measure the
association across the corpus found only 11 samples with both a failed and a
clean run, with ratios spanning 0.06 to 6.79 — too sparse and too noisy to
support any number. The withdrawn result is withdrawn, not replaced.

## The asymmetry that cannot be fixed

"After" has three measurements. "Before" has one, on images that no longer exist
— the one-way door #517 was written about.

This is now worse than it first looked. The post-rebuild runs can at least be
screened for instrumentation failure after the fact, because their analyses are
still on disk. The single pre-rebuild number cannot be re-screened in any way
that would let it be compared, and its salat cell already looks anomalous (6
processes against 14-15 in the clean post-rebuild runs) without any way to
resolve why.

Worth knowing before designing the next one: capture the before-side at least
three times, screen every run, or accept that only large effects will ever be
readable.

## Retaking it after a rebuild

```
python3 /opt/pipeline/evasion_baseline.py \
    --corpus /opt/pipeline/eval/corpus-native.json \
    --out /opt/pipeline/baselines/native-post-rebuild.json
```

Run it as a user that can read `/var/lib/libvirt/images` — the tool refuses to
write a baseline that cannot say which images it describes.

The comparison is only meaningful if the same samples are detonated on the new
images first. These numbers come from stored reports, so the after-capture needs
fresh detonations of the same corpus, not a re-read of the same reports.

**Screen every run before averaging it.** The pipeline now records the three
signals above in `cape.detonation` and `score_report.py` fails a report that
carries them:

- `monitor_injection_failed_pids` — non-empty means behaviour is missing from
  this report, whatever the totals look like
- `vanished_pids` with an empty `clean_exit_pids` — the task-1103 shape
- `api_calls_total` below `QUIET_DETONATION_API_CALLS` — the backstop for a run
  that produces neither signal

A run containing any flagged sample is not a measurement and must be re-detonated
rather than averaged. Discarding it silently would reintroduce exactly the bias
this correction exists to remove, so record which runs were dropped and why.

### What this screening does NOT catch

Validated against the real reports, the rules above flag the catastrophic cells
(1102, 1103, 1117) and **miss the partial ones**:

| task | calls | procs | same sample, clean runs | flagged? |
|---|---|---|---|---|
| 1109 salat | 33,971 | 10 | 78k-92k, 14-15 procs | no |
| 1090 formbook | 32,764 | 8 | 47k-56k, 10 procs | no |

Both lost processes mid-run, both stayed far above the 5,000-call backstop, and
neither logged an injection failure. `vanished_pids` cannot separate them either
— every clean salat run carries one too, so a rule on it would fire constantly.

What identifies them is comparative: 34k against that sample's own 78-92k. A
scorer that reads one report cannot see that, so **screening a single report is
not sufficient** and the per-sample cross-run comparison still has to be done by
hand before averaging. Closing that gap properly needs a baseline of per-sample
call volume, which does not exist yet.
