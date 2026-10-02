# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Promote a finished pipeline analysis into the eval corpus.

    python -m lamware_eval.promote <report_dir> --family X \\
        --corpus-root /opt/pipeline/eval-corpus [--manifest path] [--replace] [--dry-run]

Until this existed, promotion was done by hand on the host, and the hand copy
went wrong in the ways the corpus tests now remember: a refresh that copied
`report.json` and not the project, so the report pointed at a run directory the
7-day cleanup later deleted (#631); a pre-#490 project whose canonical program
was not in it; a #644-affected sample. Since #648/#655 a report holds ONE
PROJECT PER PROGRAM, so "copy report.json and project/" is no longer even the
right shape.

What a promotion does, in order, and why each step refuses rather than warns:

1. Plans the copy from `ghidra.analyzed_files`: every program with
   `analysis_success` and `in_project` not False, plus the canonical
   `ghidra.project_dir`/`program_name`, plus the program
   `llm_interpretation.input` says production's agent read. A program the
   pipeline already knows is missing from its project is not promoted; one the
   eval needs and cannot have is a refusal.
2. Copies `report.json` and each `<subdir>/project` into a staging directory
   beside the destination. Report directories hold attacker-influenced content,
   so the copy never follows a symlink, never copies a special file and refuses
   either outright — a Ghidra project has no reason to contain one.
3. Rewrites every string in the report that names the old report directory.
   Paths into what was copied point at the corpus copy; paths into what was not
   (CAPE injection buffers, the Volatility VAD dump, production's audit trail)
   become null and are listed under `_corpus_promotion.unpromoted`. The paths are
   found by walking the JSON, not from a list of keys, and any survivor fails.
4. Checks every promoted program is in its copied project's `~index.dat`, using
   the pipeline's own `record_project_presence` (#655).
5. Runs the #634 family-label leak check over the promoted report, and refuses
   a sample whose evidence names its family. Also refuses if the corpus path —
   which is itself named after the family — reaches the agent's init payload.
6. Moves the staged copy into place. An existing corpus dir is never overwritten
   without --replace, and never deleted: it moves to `archive/<name>.<UTC stamp>`.
7. Writes the manifest entry atomically.
"""
from __future__ import annotations

import argparse
import copy
import datetime as _dt
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from stages.ghidra import _project_programs, record_project_presence
from stages.interpret import without_host_paths

from lamware_eval.runner import family_label_leak, init_payload_for

#: Lowercase family token. No `_` (it separates family from sha8 in the directory
#: name) and nothing that could walk out of the corpus root.
_FAMILY_RE = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

#: Ansible ships these from the repo and overwrites the host copy on deploy.
_ANSIBLE_OWNED_MANIFESTS = frozenset({"corpus-native.json", "corpus-dotnet.json"})


class PromotionError(Exception):
    """A reason this report must not enter the corpus."""


@dataclass
class Program:
    """One Ghidra program to promote, and the project directory that holds it."""

    name: str
    rel_project: str          # relative to the report dir, e.g. "pe_a314d7708b70/project"
    why: str


@dataclass
class Plan:
    report_dir: Path
    dest: Path
    sha256: str
    family: str
    report: dict
    programs: list[Program] = field(default_factory=list)

    @property
    def projects(self) -> list[str]:
        return sorted({p.rel_project for p in self.programs})


# --------------------------------------------------------------------------- paths


def _rel_inside(path: str, root: Path) -> str | None:
    """`path` relative to `root` if it is lexically inside it, else None.

    Lexical on purpose: the report records the paths it wrote, and a symlinked
    component is caught separately by `_safe_dir`. `realpath` here would follow
    exactly the links this module exists to refuse.
    """
    p = os.path.normpath(path)
    r = os.path.normpath(str(root))
    if p == r:
        return ""
    if p.startswith(r + os.sep):
        return p[len(r) + 1:]
    return None


def _safe_dir(root: Path, rel: str) -> Path:
    """`root/rel`, after checking no component of it is a symlink or a non-directory."""
    cur = root
    for part in Path(rel).parts:
        if part in ("..", "."):
            raise PromotionError(f"refusing path with {part!r} component: {rel}")
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            raise PromotionError(f"project directory does not exist: {cur}") from None
        if stat.S_ISLNK(st.st_mode):
            raise PromotionError(f"refusing to follow symlink in report dir: {cur}")
        if not stat.S_ISDIR(st.st_mode):
            raise PromotionError(f"expected a directory, found something else: {cur}")
    return cur


def _project_rel_for(af: dict, report_dir: Path) -> str:
    """Where this analyzed file's project lives, relative to the report dir.

    Mirrors `record_project_presence`: `host_output_dir/project`, or the report
    dir's own `project/` for results that predate per-program directories.
    """
    base = af.get("host_output_dir")
    if not base:
        return "project"
    rel = _rel_inside(base, report_dir)
    if rel is None:
        raise PromotionError(
            f"{(af.get('program_name') or '?')[:16]}: host_output_dir is outside the "
            f"report dir and would not be promoted with it: {base}")
    return str(Path(rel) / "project") if rel else "project"


# --------------------------------------------------------------------------- plan


def _sha256_of(report: dict) -> str:
    sha = ((report.get("triage") or {}).get("hashes") or {}).get("sha256") or ""
    sha = str(sha).lower()
    if not _SHA256_RE.match(sha):
        raise PromotionError(
            f"report has no valid triage.hashes.sha256 ({sha!r}); pass --sha256")
    return sha


def plan_promotion(report_dir: Path, family: str, corpus_root: Path,
                   sha256: str | None = None) -> Plan:
    """Work out what to copy and where. Reads only; raises PromotionError to refuse."""
    report_dir = Path(os.path.abspath(report_dir))
    if not _FAMILY_RE.match(family or ""):
        raise PromotionError(
            f"--family must be a lowercase token like 'formbook' (no '_', '/', '.'): {family!r}")
    report_path = report_dir / "report.json"
    try:
        st = os.lstat(report_path)
    except FileNotFoundError:
        raise PromotionError(f"no report.json in {report_dir}") from None
    if not stat.S_ISREG(st.st_mode):
        raise PromotionError(f"report.json is not a regular file: {report_path}")
    report = json.loads(report_path.read_text())

    sha = (sha256 or "").lower() or _sha256_of(report)
    if not _SHA256_RE.match(sha):
        raise PromotionError(f"not a sha256: {sha!r}")
    dest = Path(os.path.abspath(corpus_root)) / f"{family}_{sha[:8]}"
    plan = Plan(report_dir, dest, sha, family, report)

    ghidra = report.get("ghidra") or {}
    files = [af for af in (ghidra.get("analyzed_files") or []) if isinstance(af, dict)]
    by_name: dict[str, Program] = {}

    def add(name: str, rel: str, why: str) -> None:
        if Path(rel).name != "project":
            # record_project_presence looks for <host_output_dir>/project, so any
            # other layout would be checked against the wrong index.
            raise PromotionError(f"{name[:16]}: project dir is not named 'project': {rel}")
        if name in by_name:
            if by_name[name].rel_project != rel:
                raise PromotionError(
                    f"{name[:16]} is claimed by two projects: "
                    f"{by_name[name].rel_project} and {rel}")
            return
        by_name[name] = Program(name, rel, why)

    for af in files:
        name = af.get("program_name")
        if af.get("analysis_success") and name and af.get("in_project") is not False:
            add(name, _project_rel_for(af, report_dir), "analyzed_files")

    canon_dir, canon_name = ghidra.get("project_dir"), ghidra.get("program_name")
    if canon_dir and canon_name:
        rel = _rel_inside(canon_dir, report_dir)
        if rel is None:
            raise PromotionError(
                f"ghidra.project_dir is outside the report dir — this report was "
                f"already pointing somewhere else (#631): {canon_dir}")
        lost = [af for af in files if af.get("program_name") == canon_name
                and af.get("in_project") is False]
        if lost:
            raise PromotionError(
                f"canonical program {canon_name[:16]} is recorded in_project=false; "
                f"the eval would hand the agent a program its project cannot open (#490)")
        add(canon_name, rel, "canonical")

    # What production's agent read. For a routed sample this is not the canonical
    # program, and a corpus without it cannot reproduce the production run.
    read = ((report.get("llm_interpretation") or {}).get("input") or {})
    read_name = read.get("program_name") if isinstance(read, dict) else None
    if read_name and read_name not in by_name:
        known = [af for af in files if af.get("program_name") == read_name]
        if known:
            raise PromotionError(
                f"llm_interpretation.input names {read_name[:16]}, which production's "
                f"agent read, but it is not promotable (in_project="
                f"{known[0].get('in_project')!r}, analysis_success="
                f"{known[0].get('analysis_success')!r})")
    elif read_name:
        by_name[read_name].why += "+production_input"

    plan.programs = sorted(by_name.values(), key=lambda p: (p.rel_project, p.name))
    for rel in plan.projects:
        _safe_dir(report_dir, rel)
    return plan


# --------------------------------------------------------------------------- copy


def _copy_tree_no_links(src: Path, dst: Path) -> int:
    """Copy a directory of regular files and directories. Returns files copied.

    Refuses symlinks, hardlinked files and special files instead of skipping
    them: a Ghidra project contains none, so one being there means the
    directory is not what the pipeline wrote, and a silent skip would promote a
    project with a hole in it.
    """
    count = 0
    os.makedirs(dst, exist_ok=False)
    os.chmod(dst, stat.S_IMODE(os.lstat(src).st_mode) & 0o770 | 0o700)
    for entry in sorted(os.scandir(src), key=lambda e: e.name):
        s, d = Path(entry.path), dst / entry.name
        st = os.lstat(s)
        if stat.S_ISLNK(st.st_mode):
            raise PromotionError(f"refusing to follow symlink in report dir: {s}")
        if stat.S_ISDIR(st.st_mode):
            count += _copy_tree_no_links(s, d)
        elif stat.S_ISREG(st.st_mode):
            _copy_file_no_links(s, d)
            count += 1
        else:
            raise PromotionError(f"refusing special file in report dir: {s}")
    return count


def _copy_file_no_links(src: Path, dst: Path) -> None:
    # O_NOFOLLOW closes the gap between the lstat above and this open.
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fin:
        st = os.fstat(fin.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PromotionError(f"refusing non-regular file: {src}")
        if st.st_nlink > 1:
            raise PromotionError(f"refusing hardlinked file in report dir: {src}")
        with open(dst, "xb") as fout:
            shutil.copyfileobj(fin, fout, 1 << 20)
    os.chmod(dst, stat.S_IMODE(st.st_mode) & 0o660 | 0o600)


# --------------------------------------------------------------------------- rewrite


def rewrite_paths(report: dict, old: Path, new: Path,
                  copied: list[str]) -> tuple[list[str], dict[str, str]]:
    """Point every old-report-dir path in `report` at the corpus copy, in place.

    Returns (json paths rewritten, {json path: relative path} nulled). A path
    into something that was copied is rewritten; a path into anything else is
    nulled, because pointing it at a corpus location that does not exist would
    be a worse lie than saying nothing. Prose that merely mentions the old dir is
    rewritten textually.
    """
    old_s, new_s = os.path.normpath(str(old)), os.path.normpath(str(new))
    rewritten: list[str] = []
    nulled: dict[str, str] = {}

    def kept(rel: str) -> bool:
        if rel in ("", "report.json"):
            return True
        for c in copied:
            cdir = os.path.dirname(c)     # host_output_dir of that project
            if rel == c or rel.startswith(c + "/") or (cdir and rel == cdir):
                return True
        return False

    def fix(value: str, where: str):
        # A whole-value path, not a sentence that happens to start with one.
        is_path = value.startswith(old_s) and not any(c.isspace() for c in value)
        rel = _rel_inside(value, old) if is_path else None
        if rel is not None:
            if kept(rel):
                rewritten.append(where)
                return os.path.join(new_s, rel) if rel else new_s
            nulled[where] = rel
            return None
        if re.search(re.escape(old_s) + r"(?=/|\b|$)", value):
            rewritten.append(where)
            return re.sub(re.escape(old_s) + r"(?=/|\b|$)", new_s, value)
        return value

    def walk(obj, where: str):
        if isinstance(obj, dict):
            for k in list(obj):
                if isinstance(k, str) and old_s in k:
                    raise PromotionError(f"report key names the report dir: {where}.{k}")
                v = obj[k]
                sub = f"{where}.{k}"
                if isinstance(v, str):
                    obj[k] = fix(v, sub)
                else:
                    walk(v, sub)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                sub = f"{where}[{i}]"
                if isinstance(v, str):
                    obj[i] = fix(v, sub)
                else:
                    walk(v, sub)

    walk(report, "")
    return rewritten, nulled


def remaining_old_paths(obj, old: Path, where: str = "") -> list[str]:
    """Every JSON path whose key or value still mentions `old`."""
    old_s = os.path.normpath(str(old))
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if old_s in str(k):
                hits.append(f"{where}.{k} (key)")
            hits += remaining_old_paths(v, old, f"{where}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += remaining_old_paths(v, old, f"{where}[{i}]")
    elif isinstance(obj, str) and old_s in obj:
        hits.append(where)
    return hits


# --------------------------------------------------------------------------- checks


def check_index(plan: Plan, root: Path) -> list[str]:
    """Programs absent from their project's ~index.dat under `root` (staged or source).

    Uses the pipeline's own presence check on copies of the analyzed_files
    records, re-pointed at `root`, so a promoted project is held to exactly the
    standard Stage 4 holds a fresh one to.
    """
    missing: list[str] = []
    probes = []
    for p in plan.programs:
        host = root / p.rel_project
        probes.append({"program_name": p.name, "analysis_success": True,
                       "host_output_dir": str(host.parent)})
    record_project_presence(probes, root)
    for p, probe in zip(plan.programs, probes):
        if probe.get("in_project") is not True:
            held = _project_programs(root / p.rel_project)
            state = "index unreadable" if held is None else f"index holds {sorted(held)[:4]}"
            missing.append(f"{p.name[:16]} not in {p.rel_project} ({state})")
    return missing


def leak_check(report: dict, family: str, dest: Path) -> tuple[bool | None, list[str]]:
    """(#634 result, refusals). The corpus dir is named after the family, so a
    rewritten path reaching the agent's payload would hand it the label too."""
    leak = family_label_leak(report, family)
    refusals = []
    if leak:
        refusals.append(f"evidence names the family {family!r} (#634)")
    init, _modality, _src = init_payload_for(report)
    if str(dest) in json.dumps(without_host_paths(init)):
        refusals.append("the corpus path (named after the family) reaches the agent's init payload")
    return leak, refusals


# --------------------------------------------------------------------------- manifest


def manifest_entry(plan: Plan) -> dict:
    return {"sha256": plan.sha256, "mb_family": plan.family, "corpus_dir": str(plan.dest)}


def update_manifest(path: Path, plan: Plan, promoted_from: str, when: str) -> str:
    """Add or update this sample's entry, atomically. Returns 'added' or 'updated'.

    Fields an operator added to an existing entry (analyst_label, role, notes)
    are kept; only the fields promotion owns are overwritten.
    """
    if path.exists():
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or not isinstance(data.get("samples"), list):
            raise PromotionError(f"{path} is not a {{'samples': [...]}} manifest")
        mode = stat.S_IMODE(path.stat().st_mode)
    else:
        data, mode = {"samples": []}, 0o640
    entry = {**manifest_entry(plan), "promoted_from": promoted_from, "promoted_at": when}
    action = "added"
    for e in data["samples"]:
        if isinstance(e, dict) and e.get("sha256", "").lower() == plan.sha256:
            e.update(entry)
            action = "updated"
            break
    else:
        data["samples"].append({**entry, "analyst_label": None})
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data, indent=2) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return action


# --------------------------------------------------------------------------- driver


@dataclass
class Result:
    dest: Path
    programs: list[Program]
    files_copied: int
    rewritten: list[str]
    nulled: dict[str, str]
    leak: bool | None
    archived: Path | None = None
    manifest_action: str | None = None
    dry_run: bool = False


def promote(report_dir: Path, family: str, corpus_root: Path, *,
            manifest: Path | None = None, replace: bool = False,
            dry_run: bool = False, sha256: str | None = None,
            now: _dt.datetime | None = None) -> Result:
    """Promote `report_dir` into `corpus_root`. Raises PromotionError to refuse."""
    corpus_root = Path(os.path.abspath(corpus_root))
    plan = plan_promotion(report_dir, family, corpus_root, sha256)
    now = now or _dt.datetime.now(_dt.UTC)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")

    if plan.dest.exists() and not replace:
        raise PromotionError(f"{plan.dest} exists; pass --replace to archive it and promote")

    # Rewrite and check on a copy first, so a dry run reports every refusal a real
    # run would hit, and a real run refuses before copying gigabytes.
    report = copy.deepcopy(plan.report)
    rewritten, nulled = rewrite_paths(report, plan.report_dir, plan.dest, plan.projects)
    left = remaining_old_paths(report, plan.report_dir)
    if left:
        raise PromotionError(f"old report-dir paths survive the rewrite: {left[:5]}")
    leak, refusals = leak_check(report, family, plan.dest)
    if refusals:
        raise PromotionError("; ".join(refusals))
    report["_corpus_promotion"] = {
        # The run's NAME, not its path: no string in a promoted report points
        # into the old report dir, which is what makes "none remain" checkable.
        "promoted_from": plan.report_dir.name, "promoted_at": stamp,
        "programs": [{"program_name": p.name, "project": p.rel_project, "why": p.why}
                     for p in plan.programs],
        "unpromoted": nulled,
    }
    missing = check_index(plan, plan.report_dir)
    if missing:
        raise PromotionError("program(s) missing from their project index: " + "; ".join(missing))

    if dry_run:
        return Result(plan.dest, plan.programs, 0, rewritten, nulled, leak, dry_run=True)

    corpus_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".promote-{plan.dest.name}-", dir=corpus_root))
    try:
        files = 0
        for rel in plan.projects:
            src = _safe_dir(plan.report_dir, rel)
            dst = staging / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            files += _copy_tree_no_links(src, dst)
        missing = check_index(plan, staging)
        if missing:
            raise PromotionError("program(s) missing from the COPIED project index: "
                                 + "; ".join(missing))
        (staging / "report.json").write_text(json.dumps(report, indent=2, default=str))
        os.chmod(staging / "report.json", 0o640)
        files += 1

        archived = None
        if plan.dest.exists():
            archived = corpus_root / "archive" / f"{plan.dest.name}.{stamp}"
            if archived.exists():
                raise PromotionError(f"archive target already exists: {archived}")
            archived.parent.mkdir(parents=True, exist_ok=True)
            os.rename(plan.dest, archived)
        try:
            os.rename(staging, plan.dest)
        except OSError:
            if archived is not None:
                os.rename(archived, plan.dest)
            raise
    except BaseException:
        # Only ever our own staging dir: nothing that existed before is removed.
        shutil.rmtree(staging, ignore_errors=True)
        raise

    action = None
    if manifest is not None:
        action = update_manifest(Path(manifest), plan, str(plan.report_dir), stamp)
    return Result(plan.dest, plan.programs, files, rewritten, nulled, leak,
                  archived=archived, manifest_action=action)


def _summary(r: Result, manifest: Path | None) -> str:
    lines = [f"{'DRY RUN — ' if r.dry_run else ''}promote -> {r.dest}"]
    lines.append(f"  programs: {len(r.programs)}")
    for p in r.programs:
        lines.append(f"    {p.name[:16]}  {p.rel_project}  ({p.why})")
    if not r.dry_run:
        lines.append(f"  files copied: {r.files_copied}")
    lines.append(f"  paths rewritten: {len(r.rewritten)}")
    for w in r.rewritten:
        lines.append(f"    {w}")
    lines.append(f"  paths nulled (not promoted): {len(r.nulled)}")
    for w, rel in r.nulled.items():
        lines.append(f"    {w} -> was {rel}")
    lines.append("  leak check (#634): " + {True: "LEAKS", False: "clean",
                                             None: "not checkable (non-discriminative family)"}[r.leak])
    if r.archived:
        lines.append(f"  previous corpus dir archived -> {r.archived}")
    if manifest is not None:
        lines.append(f"  manifest {manifest}: {r.manifest_action or 'would be written'}")
        if manifest.name in _ANSIBLE_OWNED_MANIFESTS:
            lines.append("  WARNING: Ansible ships this manifest from the repo and will "
                         "overwrite it on deploy; add the entry to "
                         f"ansible/roles/pipeline/files/eval/{manifest.name} too.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m lamware_eval.promote",
                                 description=__doc__.split("\n\n")[0])
    ap.add_argument("report_dir", type=Path)
    ap.add_argument("--family", required=True)
    ap.add_argument("--corpus-root", type=Path, required=True)
    ap.add_argument("--manifest", type=Path)
    ap.add_argument("--sha256", help="override triage.hashes.sha256")
    ap.add_argument("--replace", action="store_true",
                    help="archive an existing corpus dir to <root>/archive/ and promote")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    try:
        r = promote(a.report_dir, a.family, a.corpus_root, manifest=a.manifest,
                    replace=a.replace, dry_run=a.dry_run, sha256=a.sha256)
    except PromotionError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 1
    print(_summary(r, a.manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
