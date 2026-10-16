# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Each frontend build replaces the serving directory; it is not merged into it (#731).

`ansible.builtin.copy` never deletes. The serving directory held every bundle
and source map built since June, so turning source maps off in the build
changed nothing nginx served: the current bundle's map from the previous build
was still beside it. Structural, a memory of that deploy: it parses the role's
tasks and checks that the build is staged next to the live directory and
swapped in by rename. Only a deploy observes the property itself (no `.map`
under the served directory, 404 for the old map URL).
"""
from pathlib import Path

import yaml

TASKS = Path(__file__).resolve().parents[1] / "ansible/roles/frontend/tasks/main.yml"


def _tasks() -> list[dict]:
    return yaml.safe_load(TASKS.read_text())


def _dist_copies() -> list[dict]:
    out = []
    for t in _tasks():
        c = t.get("ansible.builtin.copy") or t.get("copy")
        if isinstance(c, dict) and "src/dist" in str(c.get("src", "")):
            out.append(c)
    return out


def test_the_build_is_staged_beside_the_live_directory_not_copied_into_it():
    copies = _dist_copies()
    assert copies, "the task that copies the built dist was not found"
    for c in copies:
        dest = str(c["dest"]).rstrip("/")
        assert dest != "{{ frontend_dist_dir }}", "copied straight into the live directory"
        assert dest.startswith("{{ frontend_dist_dir }}."), dest


def test_the_staged_build_is_swapped_into_place_by_rename():
    swaps = [t for t in _tasks()
             if "mv {{ frontend_dist_dir }}.new {{ frontend_dist_dir }}"
             in str(t.get("ansible.builtin.shell") or t.get("shell") or "")]
    assert len(swaps) == 1
