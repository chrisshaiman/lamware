# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""What nginx serves is root's, and no service account builds it (V10).

Whoever can replace what nginx serves runs JavaScript in every signed-in
browser. The site used to be built as cape in a cape-owned tree, and served from
a directory inside it. Security-test check 22 runs its checker (the same file as
checks 20 and 21) against fixture `nginx -T` output and real directories here.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()
_START = "cat > \"$ROOTJOBS_PY\" <<'PYEOF'\n"
CHECKER = SMOKE[SMOKE.index(_START) + len(_START):SMOKE.index("\nPYEOF\n")]
FRONTEND = ROOT / "ansible/roles/frontend"
TASKS = yaml.safe_load((FRONTEND / "tasks/main.yml").read_text())
DEFAULTS = yaml.safe_load((FRONTEND / "defaults/main.yml").read_text())


def _served(tmp: Path, conf: str) -> tuple[int, list[str]]:
    f = tmp / "nginx-T.txt"
    f.write_text(conf)
    env = {"PATH": "/usr/bin:/bin", "TRUSTED_UID": str(os.getuid()), "NGINX_T_FILE": str(f)}
    out = subprocess.run([sys.executable, "-I", "-c", CHECKER, "served"], capture_output=True,
                         text=True, env=env, timeout=30, check=True).stdout
    seen = int(next(ln for ln in out.splitlines() if ln.startswith("PARSED ")).split()[1])
    return seen, [ln[4:] for ln in out.splitlines() if ln.startswith("BAD ")]


@pytest.fixture
def site(tmp_path: Path) -> Path:
    base = tmp_path / "www"
    (base / "lamware" / "assets").mkdir(parents=True)
    (base / "lamware" / "index.html").write_text("<html>")
    (base / "lamware" / "assets" / "app.js").write_text("x")
    for d in (tmp_path, base, base / "lamware", base / "lamware" / "assets"):
        os.chmod(d, 0o755)
    for f in (base / "lamware" / "index.html", base / "lamware" / "assets" / "app.js"):
        os.chmod(f, 0o644)
    return base / "lamware"


def _conf(*roots: str) -> str:
    body = "\n".join(f"        root {r};" for r in roots)
    return f"# configuration file /etc/nginx/sites-enabled/lamware.conf:\nserver {{\n{body}\n}}\n"


def test_a_clean_tree_passes(site, tmp_path):
    assert _served(tmp_path, _conf(str(site))) == (1, [])


def test_a_group_writable_file_is_flagged(site, tmp_path):
    os.chmod(site / "assets" / "app.js", 0o664)
    seen, bad = _served(tmp_path, _conf(str(site)))
    assert seen == 1 and len(bad) == 1 and "app.js" in bad[0], bad


def test_a_link_in_the_tree_is_flagged(site, tmp_path):
    os.symlink("/etc/hostname", site / "assets" / "x.js")
    _, bad = _served(tmp_path, _conf(str(site)))
    assert len(bad) == 1 and bad[0].endswith(" link"), bad


def test_a_writable_ancestor_is_flagged(site, tmp_path):
    """The V10 shape: the served directory is fine, the one above it is not."""
    os.chmod(site.parent, 0o775)
    _, bad = _served(tmp_path, _conf(str(site)))
    assert len(bad) == 1 and bad[0].startswith(f"{site} -> {site.parent} "), bad


def test_a_missing_root_is_judged_by_its_nearest_existing_ancestor(site, tmp_path):
    os.chmod(site.parent, 0o777)
    _, bad = _served(tmp_path, _conf(str(site.parent / "not-yet")))
    assert len(bad) == 1 and f"-> {site.parent} " in bad[0], bad


def test_alias_and_several_roots_are_all_checked_and_comments_are_not(site, tmp_path):
    other = tmp_path / "acme"
    other.mkdir(mode=0o777)
    os.chmod(other, 0o777)
    conf = _conf(str(site)) + f"    # root /nonexistent;\n    location /x {{ alias {other}; }}\n"
    conf = conf.replace(f"location /x {{ alias {other}; }}", f"\n        alias {other};\n")
    seen, bad = _served(tmp_path, conf)
    assert seen == 2
    assert len(bad) == 1 and str(other) in bad[0], bad


def test_no_served_path_is_reported_as_blind_by_the_shell(tmp_path):
    seen, bad = _served(tmp_path, "server { listen 80; }\n")
    assert (seen, bad) == (0, [])
    block = SMOKE[SMOKE.index('echo "[22/22]'):]
    assert 'fail "served-tree probe is blind' in block


# --- the role ----------------------------------------------------------------------

def _named(name: str) -> dict:
    return next(t for t in TASKS if isinstance(t, dict) and t.get("name") == name)


def _all_tasks() -> list[dict]:
    out = []
    for t in TASKS:
        out.append(t)
        for key in ("block", "always", "rescue"):
            out.extend(t.get(key, []))
    return out


def test_no_task_runs_as_or_hands_files_to_cape():
    text = yaml.safe_dump(TASKS)
    assert "cape" not in text
    assert "frontend_user" not in text and "frontend_install_dir" not in text


def test_the_build_runs_as_the_build_user_only():
    builds = [t for t in _all_tasks() if "npm" in str(t.get("ansible.builtin.command", ""))]
    assert len(builds) == 2
    for t in builds:
        assert t["become_user"] == "{{ frontend_build_user }}", t["name"]
    u = _named("Create the frontend build user")["ansible.builtin.user"]
    assert u["system"] is True and u["shell"] == "/usr/sbin/nologin"


def test_the_serving_tree_is_outside_the_build_tree_and_the_retired_tree():
    dist, build, old = (DEFAULTS[k] for k in ("frontend_dist_dir", "frontend_build_dir", "frontend_retired_dir"))
    for other in (build, old):
        assert not dist.startswith(other.rstrip("/") + "/") and dist != other
    parent = _named("Create the parent of the serving directory (root's)")["ansible.builtin.file"]
    assert parent["owner"] == "root" and parent["mode"] == "0755"
    stage = _named("Stage the new build beside the serving directory")["ansible.builtin.copy"]
    assert stage["owner"] == "root" and stage["group"] == "root"


def test_nginx_serves_the_serving_tree():
    """Raw template text: it needs Ansible's ipaddr filter to render. The site's
    root is the variable, and nothing names the retired tree."""
    raw = (FRONTEND / "templates/lamware-nginx.conf.j2").read_text()
    roots = {ln.strip()[len("root "):].rstrip(";").strip() for ln in raw.splitlines()
             if ln.strip().startswith("root ") and "{{" in ln}
    assert roots == {"{{ frontend_dist_dir }}"}
    assert DEFAULTS["frontend_retired_dir"] not in raw


def test_build_output_with_a_link_is_refused(tmp_path):
    """Run the role's own refusal command against a fixture build output."""
    t = _named("Refuse build output that holds anything but files and directories")
    dist = tmp_path / "src" / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("x")
    cmd = Environment().from_string(t["ansible.builtin.command"]["cmd"]).render(frontend_build_dir=str(tmp_path))

    def refused() -> bool:
        r = subprocess.run(cmd.split(), capture_output=True, text=True)
        return bool(Environment().from_string("{{ " + t["failed_when"] + " }}").render(
            frontend_dist_odd={"rc": r.returncode, "stdout": r.stdout}) == "True")

    assert not refused()
    os.symlink("/etc/hostname", dist / "assets" / "leak.txt")
    assert refused()


def test_the_old_tree_goes_only_after_nginx_has_moved():
    names = [t.get("name") for t in TASKS]
    flush = next(i for i, t in enumerate(TASKS) if t.get("ansible.builtin.meta") == "flush_handlers")
    guard = names.index("Confirm nginx no longer serves from the old tree")
    remove = names.index("Remove the old frontend tree")
    assert flush < guard < remove
    assert names.index("Replace the serving directory with the new build") < flush
    assert _named("Remove the old frontend tree")["ansible.builtin.file"] == {
        "path": "{{ frontend_retired_dir }}", "state": "absent"}
