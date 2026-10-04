"""
Bounded, non-raising byte reads of attacker-supplied files (ADR-021, #677).

The pipeline routes samples by peeking at their bytes: an MZ check, the CLR
directory of a PE header, a fixed-pattern scan for the PyInstaller cookie.
ADR-021 allows exactly that in the orchestrator — fixed-offset peeks, bounded
byte ranges, fixed-pattern scans — and nothing that parses a format. Every one
of those reads takes a path the sample (or CAPE's extraction of it) controls,
and a read that raises out of Stage 4 loses the sample's whole analysis: the
stage is not wrapped, so the exception ends run_pipeline (#171, #673's class).

What #677's probe found before this module existed:

- a FIFO where a file was expected hung every peek forever (open() blocks for a
  writer that never comes);
- an EACCES on the parent directory raised PermissionError out of
  ``Path.exists()``, which sat outside the peeks' ``try``;
- the PyInstaller check and the embedded-.NET carve read the WHOLE file, so a
  2 GiB file raised MemoryError (not OSError, so not caught) under a 1 GiB limit.

So every read here: opens without blocking and refuses anything that is not a
regular file (checked on the open descriptor, not the path, so there is no
window to swap it); reads at most a stated number of bytes; and returns
``None`` — "could not look", which callers treat as "not this type" — with the
reason logged, instead of raising.

Symlinks ARE followed: CAPE's ``analyses/<id>/binary`` is a symlink into
``storage/binaries``, and refusing it would make the original sample invisible.
"""

import logging
import os
import stat
from collections.abc import Iterator
from pathlib import Path

log = logging.getLogger("pipeline")

# Read size for streaming scans. Memory held by a scan is about one chunk plus
# the overlap, whatever the file's size.
CHUNK = 1 << 20

# The most bytes any fixed-pattern scan reads from one file. On the host
# (2026-10-03) the largest file any scan here reads was a 192,897,024-byte
# Volatility procdump; the largest sample 92,618,994 bytes. 256 MiB covers both
# whole, so the cap changes no answer on any file observed — it only stops a
# file built to exhaust memory or time.
SCAN_CAP = 256 << 20


def open_regular(path: Path | str):
    """Open ``path`` for binary reading if it is a regular file, else ``None``.

    O_NONBLOCK makes opening a FIFO return immediately instead of waiting for a
    writer; the fstat on the descriptor then rejects it (and directories,
    devices, sockets). The flag has no effect on reads of a regular file.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except (OSError, ValueError, TypeError) as e:
        log.info(f"  peek: cannot open {path}: {e}")
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            log.info(f"  peek: {path} is not a regular file (mode {stat.filemode(st.st_mode)}); not reading it")
            os.close(fd)
            return None
        return os.fdopen(fd, "rb")
    except OSError as e:
        os.close(fd)
        log.info(f"  peek: cannot stat {path}: {e}")
        return None


def read_head(path: Path | str, n: int) -> bytes | None:
    """The first ``n`` bytes of ``path`` (fewer if it is shorter), or ``None``
    when it cannot be read as a regular file."""
    fh = open_regular(path)
    if fh is None:
        return None
    try:
        with fh:
            return fh.read(n)
    except OSError as e:
        log.info(f"  peek: read of {path} failed: {e}")
        return None


def regular_size(path: Path | str) -> int | None:
    """Size of ``path`` if it is a regular file (symlinks followed), else ``None``."""
    try:
        st = os.stat(path)
    except (OSError, ValueError) as e:
        log.info(f"  peek: cannot stat {path}: {e}")
        return None
    return st.st_size if stat.S_ISREG(st.st_mode) else None


def iter_chunks(fh, cap: int, overlap: int) -> Iterator[tuple[int, bytes]]:
    """Yield ``(offset, bytes)`` windows over the first ``cap`` bytes of ``fh``.

    Consecutive windows share ``overlap`` bytes, so a pattern of up to
    ``overlap + 1`` bytes that straddles a read boundary is still seen whole.
    ``offset`` is the absolute file offset of the window's first byte.
    """
    carry = b""
    pos = 0
    while pos < cap:
        block = fh.read(min(CHUNK, cap - pos))
        if not block:
            return
        window = carry + block
        yield pos - len(carry), window
        pos += len(block)
        carry = window[-overlap:] if overlap else b""


def contains(path: Path | str, pattern: bytes, cap: int | None = None,
             tail: int = 0) -> tuple[bool | None, bool]:
    """Whether ``pattern`` starts within the first ``cap`` bytes of ``path``.

    Reads at most ``cap + len(pattern) - 1`` bytes from the head, so a pattern
    straddling the cap is still seen whole. Returns ``(found, capped)``.
    ``found`` is ``None`` when the file could not be read. ``capped`` is True
    when the file is longer than that, so part of it was never scanned; the
    caller records that. ``cap`` defaults to SCAN_CAP, read at call time.
    ``tail`` > 0 also scans the last ``tail`` bytes of a capped file — for
    markers that live at the end of a file, such as the PyInstaller cookie.
    """
    cap = SCAN_CAP if cap is None else cap
    head = cap + len(pattern) - 1
    fh = open_regular(path)
    if fh is None:
        return None, False
    try:
        with fh:
            for _, window in iter_chunks(fh, head, len(pattern) - 1):
                if pattern in window:
                    return True, False
            if not fh.read(1):
                return False, False
            # Longer than the head scan.
            if tail > 0:
                size = os.fstat(fh.fileno()).st_size
                # Patterns starting before `cap` were seen whole above.
                fh.seek(max(cap, size - tail))
                if pattern in fh.read(tail):
                    return True, True
            return False, True
    except OSError as e:
        log.info(f"  peek: read of {path} failed: {e}")
        return None, False
