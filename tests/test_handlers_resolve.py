# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every `notify:` must name a handler that exists.

Written after clobbering four handler files in one session by writing where I
should have appended. The worst was roles/frontend: overwriting it removed
`Reload nginx`, which THREE tasks notify -- nginx config changes would have
stopped being applied, silently, because Ansible does not fail on a missing
handler by default in older behaviour and the tasks still report changed.

Ansible resolves handlers per-role, so a name notified in roles/X must be
defined in roles/X (or be a global handler in the play). This checks the
role-local case, which is all of ours.
"""
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLES = sorted(p for p in (ROOT / "ansible" / "roles").iterdir() if p.is_dir())


def _notifies(role: Path) -> set[str]:
    out: set[str] = set()
    for f in (role / "tasks").glob("*.yml"):
        try:
            tasks = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        except yaml.YAMLError:
            continue
        for t in tasks:
            if not isinstance(t, dict):
                continue
            n = t.get("notify")
            if isinstance(n, str):
                out.add(n)
            elif isinstance(n, list):
                out |= {x for x in n if isinstance(x, str)}
            for blk in ("block", "rescue", "always"):
                for sub in (t.get(blk) or []):
                    if isinstance(sub, dict):
                        m = sub.get("notify")
                        if isinstance(m, str):
                            out.add(m)
                        elif isinstance(m, list):
                            out |= {x for x in m if isinstance(x, str)}
    return out


def _handlers(role: Path) -> set[str]:
    out: set[str] = set()
    for f in (role / "handlers").glob("*.yml"):
        try:
            hs = yaml.safe_load(f.read_text(encoding="utf-8")) or []
        except yaml.YAMLError:
            continue
        for h in hs:
            if isinstance(h, dict) and h.get("name"):
                out.add(h["name"])
                # a handler can itself notify another handler
                n = h.get("notify")
                if isinstance(n, str):
                    out.add(n) if False else None
    return out


@pytest.mark.parametrize("role", ROLES, ids=lambda p: p.name)
def test_every_notified_handler_exists(role):
    missing = _notifies(role) - _handlers(role)
    assert not missing, (
        f"roles/{role.name} notifies handlers that do not exist: {sorted(missing)} "
        f"(defined: {sorted(_handlers(role))})")


def test_the_scan_finds_real_notifies():
    """A parser that silently returned nothing would make every case above pass.
    frontend and kvm are known to notify handlers."""
    found = {r.name: _notifies(r) for r in ROLES if _notifies(r)}
    assert len(found) >= 3, f"only found notifies in {list(found)} - parser broken?"
    assert "Reload nginx" in _notifies(ROOT / "ansible" / "roles" / "frontend")


def test_handlers_that_chain_to_other_handlers_resolve_too():
    """roles/kvm's apparmor reload notifies a second handler; a chain that names
    something absent fails at run time, not at parse time."""
    for role in ROLES:
        for f in (role / "handlers").glob("*.yml"):
            hs = yaml.safe_load(f.read_text(encoding="utf-8")) or []
            names = {h["name"] for h in hs if isinstance(h, dict) and h.get("name")}
            for h in hs:
                if isinstance(h, dict) and isinstance(h.get("notify"), str):
                    assert h["notify"] in names, (
                        f"roles/{role.name}: handler {h['name']!r} notifies "
                        f"{h['notify']!r}, which is not defined there")
