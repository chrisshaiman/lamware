# Pre-rebuild evasion baselines

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

## Totals

| corpus | samples | observed_behaviour |
|---|---|---|
| native-pe | 5 | 232 |
| dotnet | 5 | 207 |

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
