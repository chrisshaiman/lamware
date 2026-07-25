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
