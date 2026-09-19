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

## The guest is pinned, and recorded

Both CAPE guests are tagged `x64` in `kvm.conf`, so tags alone select neither.
`clean` has a pinned custom CPU model; `office` has host-passthrough plus Office
installed. Until 2026-09-18 the production pipeline submitted `tags=['x64']`
with no machine, so CAPE used whichever guest was free and **the report recorded
nowhere which one ran the sample**.

Submissions now pin explicitly — Office documents to the office guest (derived
from triage's routing tags), everything else to `clean` — and every report
carries `cape.machine_requested` and `cape.machine_ran_on`, read back from CAPE
rather than assumed. A disagreement is recorded as `machine_pin_warning` instead
of passing silently.

## Memory dumps and the Volatility stage

`pipeline_cape_memory_dump` is **true**. Volatility needs a full-VM RAM dump and
is the only thing that reads one.

### The stage was dead from 2026-09-16 to 2026-09-18, and the cause was a reaper

Every analysis in that window reported

    {"triggered": true, "error": "memory dump not found"}

with zero plugins. Either side of it:

    r5_* (2026-09-10/11)        triggered=true  error=none  plugins=7
    verify_salat (2026-09-18)   triggered=true  error=...   plugins=0

The obvious suspect was `memory_dump = off`, set in `cuckoo.conf` on 2026-09-16
during the disk-exhaustion response. **That was a red herring.** CAPE's gate is

    if not self.cfg.cuckoo.memory_dump and not self.task.memory:
        return

so a per-task `memory=1` overrides the global setting, and the pipeline was
sending one. Verified empirically: with the config still `off`, task 1248
produced an 8 GB dump.

The actual cause was `cape-janitor.service` — a host-only, untracked unit added
on 2026-09-16 at 21:07 for the #518 batches, sweeping every 120 seconds and
deleting **every** `memory.dmp` it found, unconditionally. Its own header said
so: *"reaping them is always safe here; reaping them is NOT safe if Volatility
is ever enabled."* It was correct for those batches, which submitted straight to
CAPE and never read a dump. It was catastrophic for the pipeline, which reads
one a few minutes after it is written.

Stopping that unit is the whole fix; the dump reappeared on the next analysis.

The lesson is not "the janitor was wrong". It is that a tool built for one
measurement mode was left running into another, where its stated precondition no
longer held — and the failure surfaced as a string that read like CAPE
misbehaving. The stage now distinguishes **disabled** (a skip naming the switch)
from **requested but absent** (a loud error saying where it looked), so the next
occurrence names itself.

### What reaps the dumps

`delete_memdump = no`, so CAPE never reclaims one itself. Exactly one thing
does, and it is deliberately not the pipeline:

**`cape-storage-maintenance`** — the ansible-managed cron in the cape role,
hourly at :15, `find storage/analyses -name memory.dmp -mmin +60 -delete`. It
runs as `cape`, the user that owns the storage.

A dump therefore lives at most ~61 minutes. The Volatility stage's 45-minute
alarm starts about 3 minutes after the dump is written, so the consumer finishes
~48 minutes in with 12 minutes to spare. A test asserts that inequality rather
than trusting it.

#### The pipeline must NOT delete dumps

This is a security boundary, not an oversight. `analyses/<id>` is
`cape:lamware drwxr-s---` with an ACL granting `lamware` `r-x`, and deleting a
file requires write on the **directory** — so `pipeline` cannot, and must not.

It has been added and removed twice:

    8f126ee  2026-05-09  pipeline deletes the dump after Volatility
    daaa7c3  2026-05-15  removed -- "crosses the security boundary between
                         pipeline and cape users"
    #611     2026-09-19  added back; failed with PermissionError on every run

The second time, a standing comment saying exactly this sat fifty lines below
the new code and did not prevent it. `test_pipeline_does_not_delete_cape_storage`
is the version that can: it walks the AST for any `unlink`/`rmtree`/`remove`
touching CAPE storage.

**If the disk fills, change the cron's schedule or age threshold.** Do not move
deletion across the boundary.

#### And never a short-interval unconditional sweeper

`cape-janitor.service` — host-only, untracked, every 120 seconds, deleting every
`memory.dmp` it found — is what killed the Volatility stage from 2026-09-16 to
2026-09-18. Its own header said *"reaping them is NOT safe if Volatility is ever
enabled."* It has been removed from the host.

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

## The guest is pinned, and recorded

Both CAPE guests are tagged `x64` in `kvm.conf`, so tags alone select neither.
`clean` has a pinned custom CPU model; `office` has host-passthrough plus Office
installed. Until 2026-09-18 the production pipeline submitted `tags=['x64']`
with no machine, so CAPE used whichever guest was free and **the report recorded
nowhere which one ran the sample**.

Submissions now pin explicitly — Office documents to the office guest (derived
from triage's routing tags), everything else to `clean` — and every report
carries `cape.machine_requested` and `cape.machine_ran_on`, read back from CAPE
rather than assumed. A disagreement is recorded as `machine_pin_warning` instead
of passing silently.

## Memory dumps and the Volatility stage

`pipeline_cape_memory_dump` is **true**. Volatility needs a full-VM RAM dump and
is the only thing that reads one.

### The stage was dead from 2026-09-16 to 2026-09-18, and the cause was a reaper

Every analysis in that window reported

    {"triggered": true, "error": "memory dump not found"}

with zero plugins. Either side of it:

    r5_* (2026-09-10/11)        triggered=true  error=none  plugins=7
    verify_salat (2026-09-18)   triggered=true  error=...   plugins=0

The obvious suspect was `memory_dump = off`, set in `cuckoo.conf` on 2026-09-16
during the disk-exhaustion response. **That was a red herring.** CAPE's gate is

    if not self.cfg.cuckoo.memory_dump and not self.task.memory:
        return

so a per-task `memory=1` overrides the global setting, and the pipeline was
sending one. Verified empirically: with the config still `off`, task 1248
produced an 8 GB dump.

The actual cause was `cape-janitor.service` — a host-only, untracked unit added
on 2026-09-16 at 21:07 for the #518 batches, sweeping every 120 seconds and
deleting **every** `memory.dmp` it found, unconditionally. Its own header said
so: *"reaping them is always safe here; reaping them is NOT safe if Volatility
is ever enabled."* It was correct for those batches, which submitted straight to
CAPE and never read a dump. It was catastrophic for the pipeline, which reads
one a few minutes after it is written.

Stopping that unit is the whole fix; the dump reappeared on the next analysis.

The lesson is not "the janitor was wrong". It is that a tool built for one
measurement mode was left running into another, where its stated precondition no
longer held — and the failure surfaced as a string that read like CAPE
misbehaving. The stage now distinguishes **disabled** (a skip naming the switch)
from **requested but absent** (a loud error saying where it looked), so the next
occurrence names itself.

### What reaps the dumps

`delete_memdump = no`, so CAPE never reclaims one itself. Two things do:

**The backstop** is the ansible-managed `cape-storage-maintenance` cron in the
cape role — hourly at :15, `find storage/analyses -name memory.dmp -mmin +60
-delete`. It has been there all along. A dump therefore lives at most ~61
minutes, and the Volatility stage's 45-minute alarm starts about 3 minutes after
the dump is written, so the consumer finishes ~48 minutes in with 12 minutes to
spare.

**The primary path** is the pipeline itself: `reap_memory_dump` runs as soon as
the Volatility stage finishes, success or failure. That holds peak usage at one
dump (8.6 GB) rather than up to two hours' worth.

What must not come back is `cape-janitor.service` — a host-only, untracked
120-second sweep that deleted every `memory.dmp` it found, unconditionally. It
was correct for the #518 batches, which submitted straight to CAPE and never
read a dump, and its own header said so: *"reaping them is NOT safe if
Volatility is ever enabled"*. It would delete the dump out from under a stage
allowed to run for 45 minutes. It has been removed from the host.

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
