# Evasion baselines, before and after the 2026-09-04 guest rebuild

A guest-image rebuild is a one-way door. These files record what the images
built **2026-05-06** allowed the sandbox to observe, captured **2026-09-01**
before any rebuild, because that measurement cannot be retaken afterwards
(#517).

They are committed here rather than left on the host for the obvious reason:
the host is the thing about to change.

The three post-rebuild captures sit alongside them. **The result is a null** —
see "The result" below.

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

## Totals

| corpus | samples | observed_behaviour |
|---|---|---|
| native-pe | 5 | 232 |
| dotnet | 5 | 207 |

## The result: no detectable change, either corpus

Three post-rebuild runs on the images built 2026-09-04, detonated fresh. The
pre-rebuild column is the single committed measurement from the 2026-05-06
images; those are gone, so it has no error bars and never will.

| corpus | pre | run1 | run2 | run3 | post mean | sd | change |
|---|---|---|---|---|---|---|---|
| native-pe | 232 | 238 | 244 | 216 | 232.7 | 14.7 | **+0.7** |
| dotnet | 207 | 188 | 146 | 192 | 175.3 | 25.5 | **-31.7** |

native-pe is +0.7 against sd 14.7 — no effect. dotnet is -31.7 against sd 25.5,
about 1.2 standard deviations on n=3, which is not significant by any reasonable
test.

**The prediction recorded before the data — that a less-detectable guest would
show MORE observed behaviour — is not supported. Neither is the opposite.**

Reported as a null rather than as the -31.7, because two runs were enough to
convince the author that native-pe was "stable and up" at +6 then +12, and the
third came in at 216. Runs 1 and 2 agreed by chance.

## What the noise is made of

Per-sample spread tracks magnitude almost exactly:

| sample | value | spread across 3 runs |
|---|---|---|
| latrodectus | 13 | 0 |
| agenttesla | 13 | 0 |
| xworm | 17 | 0 |
| formbook | 52-69 | 17 |
| warzonerat | 30-51 | 21 |
| salat | 26-50 | 24 |
| quasarrat | 17-56 | 38 |

Quiet samples are perfectly reproducible. Active ones swing by up to half their
value, and the totals are dominated by them, so a corpus total near 200 carries
a noise floor of +/-15 to 25.

**Only an effect larger than roughly 25% would have been visible at all.** That
is the more useful finding than the null: as configured, the instrument cannot
resolve the effect this experiment was designed to look for. A future version
needs either many more samples, or a metric whose variance does not scale with
the value being measured.

## The asymmetry that cannot be fixed

"After" now has three measurements. "Before" has one, on images that no longer
exist -- the one-way door #517 was written about. Even a tight post-rebuild band
is being compared against a single point, so if pre-rebuild variance resembled
what is measured here, the comparison was never going to resolve a modest effect.

Worth knowing before designing the next one: capture the before-side at least
three times, or accept that only large effects will ever be readable.

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
