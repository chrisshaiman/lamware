# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Writes into a report directory that cannot be redirected by a planted link.

Report directories are group-writable by every lamware member, and analysis
containers hand output back into them. Either can leave a symlink where the
pipeline is about to write — at the file itself, or at any directory on the
way to it — and a plain ``open(path, "w")`` follows it, writing attacker-chosen
bytes (a CAPE injection buffer is the sample's own memory) to wherever it
points, as the pipeline user.

Everything here is relative to a trusted ``root`` (the report directory, which
the pipeline itself created) and opens every component below it with
``O_NOFOLLOW``: a link anywhere on the path is an error, not a redirection.
Files are written to a fresh ``O_EXCL`` temp name and ``os.replace``d into
place, so the target is replaced, never written through, and never left half
written.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_dir(root: Path, rel_parts: tuple[str, ...], *, create: bool) -> int:
    """An fd for root/rel_parts, refusing a link at any component below root."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in rel_parts:
            if part in ("", ".", ".."):
                raise ValueError(f"refusing path component {part!r}")
            if create:
                try:
                    os.mkdir(part, 0o2770, dir_fd=fd)
                except FileExistsError:
                    pass
            nxt = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _split(path: Path, root: Path) -> tuple[tuple[str, ...], str]:
    rel = Path(path).relative_to(root)      # ValueError if path is not under root
    if not rel.parts:
        raise ValueError(f"{path} is the root itself")
    return rel.parts[:-1], rel.parts[-1]


def write_bytes(path: Path, data: bytes, *, root: Path, mode: int = 0o640,
                fsync: bool = True) -> None:
    """Atomically replace ``path`` (under ``root``) with ``data``.

    Missing directories between ``root`` and ``path`` are created. Raises
    OSError (ELOOP/ENOTDIR) if any component below ``root`` is a link.
    """
    dirs, name = _split(path, root)
    dfd = _open_dir(Path(root), dirs, create=True)
    try:
        tmp = f".{name}.{secrets.token_hex(8)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                     dir_fd=dfd)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                if fsync:
                    os.fsync(f.fileno())
            os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            raise
    finally:
        os.close(dfd)


def write_text(path: Path, text: str, *, root: Path, mode: int = 0o640,
               fsync: bool = True) -> None:
    write_bytes(path, text.encode("utf-8"), root=root, mode=mode, fsync=fsync)


def append_text(path: Path, text: str, *, root: Path, mode: int = 0o640) -> None:
    """Append to ``path`` (under ``root``), refusing a link at any component."""
    dirs, name = _split(path, root)
    dfd = _open_dir(Path(root), dirs, create=True)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, mode,
                     dir_fd=dfd)
        try:
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
