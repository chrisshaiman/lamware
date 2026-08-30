# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""What a scorecard was run against, stamped onto the scorecard (#486).

`render_scorecard` opened with an operator-supplied `--label` and nothing else.
Two runs whose numbers mean entirely different things were textually
indistinguishable, and the output path was derived from that same label, so the
second silently destroyed the first.

That is the mechanism that lets a confound go unnoticed rather than a defect in
itself, and there were two live examples when this was written:

  #478  every scorecard produced before the INetSim DNS fix measured samples
        that could not resolve a domain. Not comparable to anything after.
  #490  three corpus samples had a Ghidra pairing that opened nothing, so their
        cells measured a dead tool layer. Repaired on 2026-08-29 — before and
        after are different corpora wearing the same name.

Everything here is read, never computed: a stamp that guesses is worse than no
stamp. A field that cannot be read is reported as unknown rather than omitted,
because "we did not record this" and "this did not apply" are different claims.
"""
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

#: Where the deploy records what it shipped. Written by the Ansible run itself,
#: so it describes the code that produced the reports rather than the code in
#: whatever checkout happens to be nearby.
DEPLOY_PROVENANCE = Path("/opt/lamware/deploy-provenance.json")

#: Guest images age out. CAPE's own guidance is 90 days; past that a sample can
#: behave differently for reasons that have nothing to do with the sample, which
#: makes any comparison spanning a rebuild unsound. Recorded as the image's
#: MTIME, which is a proxy for its build date and labelled as one.
GUEST_IMAGE_DIR = Path("/var/lib/libvirt/images")
GUEST_IMAGE_STALE_DAYS = 90


def corpus_identity(corpus_path: str, samples_run: list[str] | None = None) -> dict:
    """Which corpus, and which of it actually ran.

    The manifest hash covers the file's bytes, so adding, removing or re-pointing
    a sample changes it. `samples_run` is recorded separately because a filtered
    run (`--samples`) is a different corpus from the manifest it came from, and
    a pilot on one sample must not be mistaken later for a sweep over twelve.
    """
    path = Path(corpus_path)
    out: dict = {"corpus_path": str(path)}
    try:
        raw = path.read_bytes()
    except OSError as e:
        out["corpus_sha256"] = f"unreadable: {e.__class__.__name__}"
        out["corpus_samples"] = None
    else:
        out["corpus_sha256"] = hashlib.sha256(raw).hexdigest()[:16]
        try:
            out["corpus_samples"] = len(json.loads(raw).get("samples") or [])
        except ValueError:
            out["corpus_samples"] = None
    if samples_run is not None:
        out["samples_run"] = sorted(s[:12] for s in samples_run)
    return out


def deployed_code(path: Path = DEPLOY_PROVENANCE) -> dict:
    """The commit the pipeline was running when these reports were produced."""
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        return {"pipeline_sha": "unknown", "deployed_at": "unknown"}
    out = {"pipeline_sha": str(d.get("sha", "unknown"))[:12],
           "deployed_at": d.get("deployed_at", "unknown")}
    # A deploy from a dirty tree shipped something no commit describes, so the
    # sha above is not a full answer and the scorecard should say so (#384).
    if d.get("dirty"):
        out["pipeline_dirty"] = True
    return out


def guest_images(image_dir: Path = GUEST_IMAGE_DIR, now: datetime | None = None) -> list:
    """Age of each detonation guest image, oldest first.

    An aged guest changes sample behaviour silently, which confounds any
    comparison spanning a rebuild — the same shape as the llama.cpp restart
    problem, one layer down. Reported as age in days rather than a pass/fail so
    a reader can judge it against their own threshold.
    """
    now = now or datetime.now(UTC)
    out = []
    try:
        images = sorted(image_dir.glob("*.qcow2"))
    except OSError:
        return out
    for img in images:
        try:
            mtime = datetime.fromtimestamp(img.stat().st_mtime, UTC)
        except OSError:
            continue
        age = (now - mtime).days
        out.append({"image": img.name, "mtime": mtime.date().isoformat(),
                    "age_days": age, "stale": age > GUEST_IMAGE_STALE_DAYS})
    return sorted(out, key=lambda i: -i["age_days"])


def gather(corpus_path: str, samples_run: list[str] | None = None) -> dict:
    """Everything the scorecard should be able to say about its own inputs."""
    prov = corpus_identity(corpus_path, samples_run)
    prov.update(deployed_code())
    prov["guest_images"] = guest_images()
    return prov


def render(prov: dict | None) -> str:
    """The provenance block, for the top of a scorecard.

    Rendered even when fields are unknown. A scorecard with no block at all is
    the state this exists to end, and one that quietly drops the fields it could
    not read would be the same thing with extra steps.
    """
    if not prov:
        return ""
    lines = ["## Provenance\n",
             f"- corpus: `{prov.get('corpus_path')}`"
             f" sha256:`{prov.get('corpus_sha256')}`"
             f" ({prov.get('corpus_samples')} sample(s) in manifest)"]
    run = prov.get("samples_run")
    if run is not None:
        lines.append(f"- samples run ({len(run)}): {', '.join(run) or 'none'}")
    dirty = " **(deployed from a dirty tree)**" if prov.get("pipeline_dirty") else ""
    lines.append(f"- pipeline: `{prov.get('pipeline_sha')}`"
                 f" deployed {prov.get('deployed_at')}{dirty}")
    for img in prov.get("guest_images") or []:
        flag = " **STALE**" if img.get("stale") else ""
        lines.append(f"- guest image `{img['image']}`: built {img['mtime']},"
                     f" {img['age_days']} days old{flag}")
    return "\n".join(lines) + "\n"
