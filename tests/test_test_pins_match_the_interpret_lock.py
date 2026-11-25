"""The pipeline's [test] extra pins the SDK the interpret container ships.

The tests that import interpret-ghidra.py exercise the container's code, so they must
run on the container's anthropic and httpx. An unpinned `anthropic>=0.40` let CI pick
a release built on httpx2, which rejects the container's httpx.Client (#876). Parsed
with tomllib and the lock's own `name==version` lines; no regex over prose.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "ansible/roles/interpret/files/requirements.lock"
PINNED = ("anthropic", "httpx")


def _lock_versions() -> dict[str, str]:
    out = {}
    for line in LOCK.read_text().splitlines():
        head = line.split(" ", 1)[0]
        if "==" in head and not line.startswith((" ", "#")):
            name, ver = head.split("==", 1)
            out[name.lower()] = ver
    return out


def test_the_test_extra_pins_the_interpret_containers_sdk():
    extra = tomllib.loads((ROOT / "pipeline/pyproject.toml").read_text())[
        "project"]["optional-dependencies"]["test"]
    pins = {r.split("==", 1)[0].lower(): r.split("==", 1)[1] for r in extra if "==" in r}
    lock = _lock_versions()
    for name in PINNED:
        assert name in lock, f"{name} is not in {LOCK.name}"
        assert pins.get(name) == lock[name], (
            f"pipeline[test] has {name}=={pins.get(name)}, the interpret lock has {lock[name]}")
