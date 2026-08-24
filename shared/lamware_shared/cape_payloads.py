# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Locating the payloads CAPE extracted during detonation (#377).

CAPE writes extracted content into several per-task directories, and which one
a payload lands in depends on how CAPE obtained it:

  ``CAPE/``      payloads CAPE's own extractors carved out — unpacked modules
                 and config blobs. The highest-value material for static
                 analysis, because it is the *unpacked* form.
  ``files/``     files the sample wrote to disk during detonation.
  ``procdump/``  process memory dumps.
  ``dropped/``   the historical name for ``files/``. Retained because other
                 CAPE configurations still populate it.

Both the Ghidra stage and the investigation agent used to look **only** in
``dropped/``. On this deployment ``dropped/`` is empty in 1017 of 1017
analyses, so both features returned "nothing here" for every analysis ever
run, while 420 of those 1017 had PE payloads sitting in the directories
neither looked at.

Anything that needs CAPE payloads goes through this module, so the callers
cannot drift apart from each other — or from CAPE — again.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import NamedTuple

from lamware_shared.task_ids import is_safe_task_id

log = logging.getLogger(__name__)

CAPE_STORAGE = Path("/opt/CAPEv2/storage/analyses")

#: Searched in this order — most-refined extraction first, so a caller that
#: truncates to the first N files keeps the highest-value payloads.
PAYLOAD_SUBDIRS: tuple[str, ...] = ("CAPE", "files", "procdump", "dropped")

#: Below this, a "payload" is a stub, an empty carve, or a config fragment.
MIN_PAYLOAD_BYTES = 1024

#: Ghidra on a 78MB process dump runs for hours and produces nothing usable.
#: Callers that hand files to a decompiler should pass this as ``max_bytes``.
MAX_ANALYSABLE_BYTES = 32 * 1024 * 1024

_SHA256_NAME = re.compile(r"^[0-9a-f]{64}$")


class PayloadAccessError(OSError):
    """Cape's storage is present but this process cannot read it.

    Deliberately NOT folded into "no payloads found". A caller that reports
    the two identically tells the operator the sample extracted nothing, when
    the truth is that nobody was able to look — which is the failure #377 was
    about in the first place. "I cannot tell" has to be its own answer.
    """


class Payload(NamedTuple):
    """One file CAPE extracted, and which directory it came from."""

    path: Path
    source: str
    size: int


def payload_dirs(task_id: str | int | None,
                 storage: Path = CAPE_STORAGE) -> list[Path]:
    """Return the existing payload directories for a Cape task, in priority order.

    Returns ``[]`` for a missing task ID or a task with no payload directories
    at all — an empty list is "nothing was extracted", not an error.

    Raises :class:`PayloadAccessError` if Cape's storage cannot be read. Note
    that ``Path.is_dir()`` does not swallow ``EACCES`` (its ``_ignore_error``
    covers ENOENT/ENOTDIR/EBADF/ELOOP only), so this is a real condition and
    not a theoretical one: on a deployment where the service user cannot
    traverse ``storage/``, every call lands here.
    """
    if task_id is None or task_id == "":
        return []
    if not is_safe_task_id(str(task_id)):
        # An unsafe value is "nothing was extracted", consistent with the
        # missing-ID case above: this function's contract is a list of existing
        # directories, and a value that cannot name one has none. Logged rather
        # than raised because PayloadAccessError means "Cape's storage cannot be
        # read", which is a different claim.
        log.warning("Ignoring unsafe task_id %r for payload discovery", task_id)
        return []
    base = storage / str(task_id)
    dirs: list[Path] = []
    for name in PAYLOAD_SUBDIRS:
        candidate = base / name
        try:
            if candidate.is_dir():
                dirs.append(candidate)
        except PermissionError as exc:
            raise PayloadAccessError(
                f"Cannot read Cape storage at {candidate} — "
                f"payload discovery is blocked by filesystem permissions, "
                f"so whether this task extracted anything is unknown"
            ) from exc
        except OSError:
            continue
    return dirs


def find_payloads(task_id: str | int | None,
                  *,
                  storage: Path = CAPE_STORAGE,
                  min_bytes: int = MIN_PAYLOAD_BYTES,
                  max_bytes: int | None = None,
                  pe_only: bool = False) -> list[Payload]:
    """Collect payloads across every CAPE extraction directory for a task.

    Ordered by :data:`PAYLOAD_SUBDIRS`, then by filename within each directory,
    so the result is stable across calls — the investigation agent hands out
    positional indices and must be able to resolve the same index twice.

    CAPE names extracted files after their SHA-256, so the same payload can
    appear in two directories. Those are deduplicated, keeping the
    higher-priority copy. Names that are not hashes are never deduplicated:
    only content-addressed names prove two paths hold the same bytes.

    Propagates :class:`PayloadAccessError` rather than returning ``[]``, so an
    unreadable storage tree cannot masquerade as an empty one.
    """
    found: list[Payload] = []
    seen_hashes: set[str] = set()

    for directory in payload_dirs(task_id, storage):
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_file():
                    continue
                size = entry.stat().st_size
                if size < min_bytes:
                    continue
                if max_bytes is not None and size > max_bytes:
                    continue
                if _SHA256_NAME.match(entry.name):
                    if entry.name in seen_hashes:
                        continue
                    seen_hashes.add(entry.name)
                if pe_only and not _has_mz_header(entry):
                    continue
            except OSError:
                continue
            found.append(Payload(path=entry, source=directory.name, size=size))

    return found


def find_pe_payloads(task_id: str | int | None,
                     *,
                     storage: Path = CAPE_STORAGE,
                     max_bytes: int | None = MAX_ANALYSABLE_BYTES) -> list[Payload]:
    """Payloads carrying an ``MZ`` header, for tools that need a loadable PE.

    Note the deliberate omission: ``CAPE/`` also holds raw code regions with no
    PE header (a carve starting at ``55 8b ec`` is a function prologue, not an
    image). Those are real unpacked code but Ghidra cannot load them without an
    explicit language spec, so they are out of scope here rather than silently
    mis-analysed. Use :func:`find_payloads` to see everything.
    """
    return find_payloads(task_id, storage=storage,
                         max_bytes=max_bytes, pe_only=True)


def _has_mz_header(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False
