# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every container image a role pulls is pinned by digest, not by a tag.

On 2026-10-21 a malicious LiteLLM release was published to PyPI and Docker.
The litellm role pulled `ghcr.io/berriai/litellm:main-latest` on every deploy;
by that day the tag already pointed at a newer image than the host ran, so the
next deploy would have installed whatever upstream had published, into the
container that holds the API keys. Ollama floated on `:latest` the same way.

Parses every role's defaults and asserts each `*_image` value is
`<registry>/<repo>@sha256:<64 hex>`. Keycloak was the one exception until #812
pinned it too; KNOWN_UNPINNED stays, empty, for the next image that needs its own
PR and rollback plan before it can be pinned. Only a deploy observes what the
host actually runs; this keeps the repo from asking for a moving target.
"""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROLES = Path(__file__).resolve().parents[1] / "ansible" / "roles"
DIGEST = re.compile(r"\A[a-z0-9.\-]+(:[0-9]+)?/[a-z0-9._/\-]+@sha256:[0-9a-f]{64}\Z")
KNOWN_UNPINNED: dict[str, str] = {}


def _image_vars():
    out = []
    for f in sorted(ROLES.glob("*/defaults/main.yml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for k, v in data.items():
            if k.endswith("_image") and isinstance(v, str) and "/" in v:
                out.append((f.parent.parent.name, k, v.strip()))
    return out


def test_the_scan_finds_the_images_it_is_meant_to_guard():
    names = {k for _, k, _ in _image_vars()}
    assert {"litellm_image", "llamacpp_image", "keycloak_image"} <= names, names


@pytest.mark.parametrize("role,var,value", _image_vars(), ids=lambda x: str(x)[:40])
def test_image_is_pinned_by_digest(role, var, value):
    if var in KNOWN_UNPINNED:
        pytest.skip(f"{var} is a known exception, tracked in {KNOWN_UNPINNED[var]}")
    assert DIGEST.match(value), f"{role}: {var} = {value!r} is not pinned by digest"


def test_the_exception_list_does_not_outlive_its_reason():
    """An image pinned since it was listed must leave the list, or it hides a regression."""
    values = {k: v for _, k, v in _image_vars()}
    for var in KNOWN_UNPINNED:
        assert not DIGEST.match(values[var]), f"{var} is pinned now; remove it from KNOWN_UNPINNED"
