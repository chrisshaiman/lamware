# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""nginx died at boot binding an address WireGuard had not created yet.

On the 2026-09-02 reboot:

    nginx: [emerg] bind() to 10.200.0.1:80 failed (99: Cannot assign requested address)

`nginx -t` passed and starting it by hand afterwards worked, so the config was
never wrong -- it lost a race against wg-quick@wg0. Untreated this recurs on
EVERY boot, and the symptom is a dead public site with a healthy-looking config,
which is a slow thing to diagnose.
"""
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "frontend"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text(encoding="utf-8"))


def _dropin():
    for t in TASKS:
        c = t.get("ansible.builtin.copy")
        if isinstance(c, dict) and "nginx.service.d" in str(c.get("dest", "")):
            return t
    return None


def test_a_dropin_orders_nginx_after_wireguard():
    t = _dropin()
    assert t, "nothing orders nginx after wg-quick"
    content = t["ansible.builtin.copy"]["content"]
    assert "After=wg-quick@wg0.service" in content


def test_it_wants_rather_than_requires_the_tunnel():
    """Requires would take nginx down whenever the tunnel restarts for its own
    reasons. Ordering is what was missing, not a hard dependency."""
    content = _dropin()["ansible.builtin.copy"]["content"]
    assert "Wants=wg-quick@wg0.service" in content
    assert "Requires=" not in content


def test_a_lost_race_still_self_heals():
    """After= orders against wg-quick FINISHING, which is not identical to the
    address being usable. Restart=on-failure means a residual race costs seconds
    rather than a person noticing the site is down."""
    content = _dropin()["ansible.builtin.copy"]["content"]
    assert "Restart=on-failure" in content
    assert "RestartSec=" in content


def test_the_dropin_directory_is_created_first():
    """copy does not create parent directories; without this the task fails on a
    host that has never had a drop-in."""
    names = [str(t.get("name", "")) for t in TASKS]
    mk = next(i for i, n in enumerate(names) if "drop-in directory" in n)
    order = next(i for i, t in enumerate(TASKS)
                 if isinstance(t.get("ansible.builtin.copy"), dict)
                 and "nginx.service.d" in str(t["ansible.builtin.copy"].get("dest", "")))
    assert mk < order


def test_systemd_is_reloaded_so_the_dropin_takes_effect():
    """A unit file systemd has not re-read changes nothing, and the failure is
    invisible until the next reboot -- which is the exact event this fixes."""
    assert _dropin().get("notify") == "Reload systemd and restart nginx"
    hs = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    h = next(x for x in hs if x["name"] == "Reload systemd and restart nginx")
    assert h["ansible.builtin.systemd_service"].get("daemon_reload") is True


def test_the_pre_existing_reload_handler_survived():
    """Three tasks notify `Reload nginx`. I overwrote this file while adding the
    handler above; losing it would stop every nginx config change being applied."""
    hs = yaml.safe_load((ROLE / "handlers" / "main.yml").read_text(encoding="utf-8"))
    assert "Reload nginx" in [h["name"] for h in hs]
