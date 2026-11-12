# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every recursive ansible.builtin.file task sets follow: false.

`follow` defaults to true, and with `recurse: true` Ansible applies owner, group
and mode to the target of each symlink it meets (measured with ansible-core 2.21:
files outside the tree changed through links inside it; with follow: false they
did not).

Structural because the property is a parameter; security-test check 17 watches
the effect on the host.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TASK_FILES = sorted((ROOT / "ansible").glob("**/tasks/*.yml"))


def _walk(tasks):
    for t in tasks or []:
        if isinstance(t, dict):
            yield t
            for k in ("block", "rescue", "always"):
                yield from _walk(t.get(k))


def _recursive_file_tasks():
    for f in TASK_FILES:
        for t in _walk(yaml.safe_load(f.read_text())):
            for key in ("ansible.builtin.file", "file"):
                p = t.get(key)
                if isinstance(p, dict) and p.get("recurse") in (True, "yes", "true"):
                    yield f.relative_to(ROOT), t.get("name", "?"), p


def test_there_are_recursive_file_tasks_to_check():
    assert len(list(_recursive_file_tasks())) >= 5, "the walker found nothing; it is broken"


@pytest.mark.parametrize("where,name,params", list(_recursive_file_tasks()),
                         ids=lambda v: str(v)[:60] if not isinstance(v, dict) else "")
def test_recursive_file_task_does_not_follow_links(where, name, params):
    assert params.get("follow") is False, f"{where}: {name!r} recurses with follow left on"
