# Family attribution — the evidence behind ADR-019

Moved out of [ADR-019](DECISIONS.md#adr-019-family-attribution-is-not-a-capability-metric-for-the-re-stage)
on 2026-10-05 so the ADR states the decision and this file carries the measurements and the
literature check. The text below is the ADR's original Context section, unchanged.

The eval harness reports `family_guess` against `mb_family` on every cell, and that
column has been read as a quality signal. Measured against real corpora it is not one.

Three independent measurements, all on the deployed pipeline:

- **qwen scores 0/14** on family identification against MalwareBazaar labels
  (post-#321 sweep, both depths, all 7 samples).
- **The Claude reference scores 0/7** on the same samples. When a frontier model and a
  35B local model both score zero, the metric is the suspect, not the models.
- **MalwareBazaar's own labels disagree with the reference on every sample** —
  raccoonstealer/njrat, icedid/bumblebee, emotet/smokeloader, warmcookie/orcus. There is
  no agreement anywhere to anchor on.

**Checked against the published literature** (2026-08-10 — the argument above is reasoning
from our own data and deserved an outside check). It both supports and *narrows* the
conclusion:

- The MOTIF paper measures **AVClass at 46.78%** accuracy and **AV majority voting at
  62.10%** against its expert ground truth ([arXiv:2111.15031](https://arxiv.org/abs/2111.15031)).
  The tooling whose output becomes MalwareBazaar-style labels is under 50% accurate. Our
  0/14 is therefore as much a statement about the labels as about the models — and this
  is the **strongest support for this ADR**, stronger than the packing argument.
- Packing does degrade static classification: one AV vendor loses 19% accuracy on packed
  files, and static approaches are broadly sensitive to packing and obfuscation.

But the naive packing claim is **too strong and must not be repeated**:

- Supervised classifiers *do* achieve high accuracy on packed samples — MaliCage reports
  **91.66%** on real packed malware (97.8% with GAN augmentation).
- One study found near-zero correlation (0.015 binary, 0.0001 family) between packing
  prevalence and classification accuracy. "Packing destroys family ID" is not a law.

The distinction that matters is **what is classified, and how**. Those results come from
supervised models over **byte-level and structural features** — entropy, byte histograms,
section characteristics, import tables — against a **closed set** of known families. That
is a different task from an LLM reading **decompiled code** and naming a family from an
**open set of 454+**, which is what this stage does. A packer stub is generic *as source
code* while remaining statistically distinctive *as bytes*: a DNN can exploit the latter,
a decompiler-reading model cannot.

So the structural claim, correctly scoped: **the signals available to an LLM reading
decompiled code — distinctive string constants, config markers, custom crypto constants,
characteristic import combinations — do not survive packing**, even though byte-level
statistical signals do. Confirmed on the MOTIF corpus (#368): of 29 samples, 14 yield no
strings matching the interest filter, and the most opaque export 2 imports across 4
functions.

A corollary worth keeping: if family ID is ever wanted as a *product* feature rather than
a metric, the viable route is a supervised byte-level classifier over a closed family
set — not this stage.

The same structure explains why published threat-report IOCs cannot ground this stage
either (#314): **0 of 9** icedid samples and **0 of 2** azorult samples contained any
literal from their own linked reports — C2 domains, drop paths, `regsvr32`, `certutil`.
The reports describe runtime behaviour; static analysis sees the packer.

Real-world family attribution uses YARA over unpacked or memory-dumped samples,
behavioural signatures from detonation, config extraction after unpacking, and network
IOCs. None of those are decompilation of a packer.

There is also a contamination problem that cannot be engineered away. MOTIF has been
public since 2021, its md5→family mappings are in `motif_dataset.jsonl`, and the
underlying vendor reports are indexed web content. Any model trained on public data has
plausibly seen them. The exploitable vector is not hashes — the model never sees one —
but **memorised code patterns from published analyses**, which is indistinguishable from
genuine recognition. That is equally true of a human analyst who has read the same
writeups. "Name the family" therefore conflates analysis with recall and cannot separate
them.
