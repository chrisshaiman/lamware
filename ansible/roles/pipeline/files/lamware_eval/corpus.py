# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Benchmark corpus manifest: known-family samples with persisted Ghidra projects."""
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CorpusSample:
    sha256: str
    mb_family: str
    corpus_dir: str
    analyst_label: str | None = None


def load_corpus(path: str) -> list[CorpusSample]:
    """Load + validate the corpus manifest. Raises ValueError on a malformed entry."""
    data = json.loads(Path(path).read_text())
    samples = []
    for i, e in enumerate(data.get("samples", [])):
        for field in ("sha256", "mb_family", "corpus_dir"):
            if not e.get(field):
                raise ValueError(f"corpus entry {i} missing required field: {field}")
        samples.append(CorpusSample(e["sha256"], e["mb_family"], e["corpus_dir"],
                                    e.get("analyst_label")))
    return samples


def filter_samples(samples: list[CorpusSample], selectors: str) -> list[CorpusSample]:
    """Narrow a corpus to the entries matching any comma-separated selector.

    A selector matches a sha256 prefix or a family name (both case-insensitive), so
    `--samples raccoonstealer` and `--samples 982a0d1b` both pick the same entry.

    Raises on a selector that matches nothing: a probe aimed at one sample must fail
    loudly rather than silently run the whole corpus (or nothing) because a name was
    misspelled — a multi-hour local sweep is an expensive way to discover a typo.
    """
    wanted = [s.strip().lower() for s in selectors.split(",") if s.strip()]
    if not wanted:
        return samples

    out: list[CorpusSample] = []
    for sel in wanted:
        hits = [s for s in samples
                if s.sha256.lower().startswith(sel) or s.mb_family.lower() == sel]
        if not hits:
            known = sorted({f"{s.mb_family}/{s.sha256[:8]}" for s in samples})
            raise ValueError(f"--samples selector matched nothing: {sel!r}. Known: {known}")
        for h in hits:
            if h not in out:
                out.append(h)
    return out
