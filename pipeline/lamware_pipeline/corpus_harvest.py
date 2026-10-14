# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Keep analyses that produced correlation findings past the 7-day cleanup.

The eval corpus needs samples whose reports carry cross-tool correlations
(#420, #426), and finding them takes detonations: about 1 in 10 of the October
intake batch produced any. The nightly cleanup deleted every report directory
after 7 days whatever it held, and re-detonating later does not bring a finding
back — Salat produced one on 2026-09-28 and none on 2026-10-12. So a correlated
report had to be promoted within the week or it was gone.

This runs first in the nightly cleanup. It asks the database which analyses
produced findings (#423 made that a query) and writes:

    keep.txt        report directory names the cleanup must skip
    candidates.tsv  the same rows with what an operator needs to pick from

Both are written beside the reports, never inside one: a report directory holds
attacker-influenced content, and a marker file there could be planted by a
sample to keep itself on disk.

Exit status is non-zero on any failure, and the cleanup then deletes nothing
that night. Keeping an expired report is cheap; deleting the one correlated
report of the week is not.

    python -m lamware_pipeline.corpus_harvest --reports-dir D --out-dir H \\
        [--keep-days 60] [--max-keep 40]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from lamware_shared.task_ids import is_safe_task_id

from lamware_pipeline.correlation_base_rate import KEEP_CANDIDATES

#: Rules whose findings tie behaviour to code, which is what #420 needs. A lone
#: shellcode_self_modified on one PID is the common case and the thinnest one.
_RICH_RULES = frozenset({"injection_corroborated", "dropped_file_loaded"})


@dataclass(frozen=True)
class Candidate:
    task_id: str
    sha256: str
    created_at: _dt.datetime
    cape_task_id: int | None
    family_guess: str
    findings: int
    rules: tuple[str, ...]

    @property
    def priority(self) -> bool:
        """Worth promoting first: several findings, or a rule that links to code."""
        return self.findings >= 3 or bool(_RICH_RULES & set(self.rules))


def select(rows: list[tuple], reports_dir: Path, keep_days: int,
           now: _dt.datetime) -> list[Candidate]:
    """The candidates whose report directory still exists and is young enough to keep.

    `keep_days` bounds the disk this can hold: a report nobody promoted in that
    time goes back to the normal cleanup.
    """
    cutoff = now - _dt.timedelta(days=keep_days)
    out = []
    for task_id, sha256, created_at, cape_task_id, family, findings, rules in rows:
        # The same one-path-segment rule as every other task_id path join
        # (lamware_shared.task_ids): 12 hex characters by default, or a label
        # such as `v661_5b4f596d3cf5` for a manual run.
        if not is_safe_task_id(task_id):
            continue
        if created_at < cutoff:
            continue
        d = reports_dir / task_id
        if d.is_symlink() or not d.is_dir():
            continue
        out.append(Candidate(task_id, sha256 or "", created_at, cape_task_id,
                             (family or "").replace("\t", " ").replace("\n", " ")[:60],
                             int(findings), tuple(rules or ())))
    return out


def cap(cands: list[Candidate], max_keep: int) -> list[Candidate]:
    """At most `max_keep` of them, priority first, then newest.

    The disk bound. The host had 69 GB free on 2026-10-14, a correlated report is
    0.25-0.8 GB (Lumma 246 MB, 42b9c406 768 MB), and a feeder running in idle
    time could find several a day: an age limit alone could fill the disk. What
    falls off the end returns to the normal 7-day cleanup.
    """
    ranked = sorted(cands, key=lambda c: (not c.priority, -c.created_at.timestamp(), c.task_id))
    return ranked[:max(max_keep, 0)]


def _write_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o640)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write(cands: list[Candidate], kept: list[Candidate], out_dir: Path) -> None:
    """candidates.tsv lists every eligible report and whether the cap kept it, so
    what is about to be lost is visible; keep.txt names only the kept ones.
    candidates.tsv is written first, so a keep.txt the cleanup acts on always has
    the rows that explain it beside it."""
    kept_ids = {c.task_id for c in kept}
    rows = ["task_id\tkept\tpriority\tfindings\trules\tcape_task\tcreated_at\tsha256"
            "\tfamily_guess"]
    for c in sorted(cands, key=lambda c: (c.task_id not in kept_ids, not c.priority,
                                          -c.findings, c.task_id)):
        rows.append("\t".join([
            c.task_id, "yes" if c.task_id in kept_ids else "no",
            "yes" if c.priority else "no", str(c.findings), ",".join(c.rules),
            str(c.cape_task_id or ""), c.created_at.strftime("%Y-%m-%dT%H:%MZ"),
            c.sha256, c.family_guess]))
    _write_atomic(out_dir / "candidates.tsv", "\n".join(rows) + "\n")
    _write_atomic(out_dir / "keep.txt", "".join(f"{c.task_id}\n" for c in kept))


def fetch() -> list[tuple]:
    """KEEP_CANDIDATES against the analysis database, as db_ingest connects."""
    import psycopg2

    from lamware_pipeline.config import PipelineConfig

    cfg = PipelineConfig.load(os.environ.get("LAMWARE_PIPELINE_CONFIG",
                                             "/opt/pipeline/config.json"))
    password = os.environ.get("PIPELINE_DB_PASSWORD", "")
    if not password:
        raise RuntimeError("PIPELINE_DB_PASSWORD is not set")
    conn = psycopg2.connect(host=cfg.db_host, port=cfg.db_port, dbname=cfg.db_name,
                            user=cfg.db_user, password=password)
    try:
        conn.set_session(readonly=True)
        with conn.cursor() as cur:
            cur.execute(KEEP_CANDIDATES)
            return cur.fetchall()
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--reports-dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--keep-days", type=int, default=60)
    ap.add_argument("--max-keep", type=int, default=40)
    args = ap.parse_args(argv)
    try:
        args.out_dir.mkdir(mode=0o750, exist_ok=True)
        cands = select(fetch(), args.reports_dir, args.keep_days,
                       _dt.datetime.now(_dt.UTC))
        kept = cap(cands, args.max_keep)
        write(cands, kept, args.out_dir)
    except Exception as e:  # any failure must stop the cleanup, so say what it was
        print(f"corpus_harvest: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"corpus_harvest: keeping {len(kept)} of {len(cands)} correlated report(s), "
          f"{sum(c.priority for c in kept)} priority")
    return 0


if __name__ == "__main__":
    sys.exit(main())
