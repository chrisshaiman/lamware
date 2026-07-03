# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The root VERSION file is the single source of truth for the project version.

Every package manifest must match it. This test fails CI if any of them drift,
so bumping the version is: edit VERSION, then update the manifests until this
passes. There is no build-system magic (the api package uses a non-standard
legacy backend), just an enforced invariant.
"""
import json
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

PYPROJECTS = [
    REPO_ROOT / "shared" / "pyproject.toml",
    REPO_ROOT / "pipeline" / "pyproject.toml",
    REPO_ROOT / "api" / "pyproject.toml",
]
PACKAGE_JSON = REPO_ROOT / "frontend" / "package.json"


def canonical_version() -> str:
    return (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()


def test_version_file_is_valid_semver():
    v = canonical_version()
    parts = v.split(".")
    assert len(parts) == 3, f"VERSION must be MAJOR.MINOR.PATCH, got {v!r}"
    assert all(p.isdigit() for p in parts), f"VERSION parts must be numeric, got {v!r}"


def test_python_manifests_match_version_file():
    expected = canonical_version()
    for manifest in PYPROJECTS:
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        got = data["project"]["version"]
        assert got == expected, (
            f"{manifest.relative_to(REPO_ROOT)} version {got!r} != VERSION {expected!r}"
        )


def test_frontend_package_json_matches_version_file():
    expected = canonical_version()
    data = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    assert data["version"] == expected, (
        f"frontend/package.json version {data['version']!r} != VERSION {expected!r}"
    )
