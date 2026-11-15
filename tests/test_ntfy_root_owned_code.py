# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The notifier's code is root's, and its token is not in the code (V12).

Root runs ntfy_notify.py (the network monitor) and ntfy_enqueue.py (lamware-aide,
the AWS forwarder's alert unit), so whoever owns that code runs as root. It was
the notify user's. Now the code is root-owned, the notify user writes only its
data directory, and the topic and token live in a file only the senders read.
"""
from __future__ import annotations

import getpass
import grp
import json
import os
import subprocess
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
NTFY = ROOT / "ansible" / "roles" / "ntfy-alerts"
TASKS = yaml.safe_load((NTFY / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((NTFY / "defaults" / "main.yml").read_text(encoding="utf-8"))


def _task(name: str) -> dict:
    return next(t for t in TASKS if isinstance(t, dict) and t.get("name") == name)


def _render(name: str, **over) -> str:
    env = jinja2.Environment()  # noqa: S701 — rendering Python and units, not HTML
    env.filters["bool"] = lambda v: v if isinstance(v, bool) else str(v).lower() in ("true", "yes", "1")
    env.filters["mandatory"] = lambda v: v
    vars_ = {**DEFAULTS, "ntfy_topic": "topic-SENTINEL", "ntfy_token": "tk_SENTINEL",
             "pipeline_db_password": "x", "litellm_master_key": "x", **over}
    return env.from_string((NTFY / "templates" / name).read_text()).render(**vars_)


def _module(secrets: Path) -> dict:
    ns: dict = {}
    exec(compile(_render("ntfy_notify.py.j2", ntfy_secrets_file=str(secrets),  # noqa: S102
                         ntfy_enabled=True),
                 "ntfy_notify.py", "exec"), ns)
    return ns


# --- the token is not in the code ----------------------------------------------

def test_the_rendered_module_carries_neither_topic_nor_token():
    src = _render("ntfy_notify.py.j2")
    assert "topic-SENTINEL" not in src
    assert "tk_SENTINEL" not in src


def test_the_module_sends_with_what_the_secrets_file_holds(tmp_path):
    secrets = tmp_path / "ntfy.json"
    secrets.write_text(json.dumps({"topic": "abc", "token": "tk_1"}))
    ns = _module(secrets)
    sent = {}

    class _Resp:
        status_code = 200

    ns["requests"].post = lambda url, data=None, headers=None, timeout=None: (
        sent.update(url=url, headers=headers) or _Resp())
    assert ns["send_alert"]("t", "m") is True
    assert sent["url"].endswith("/abc")
    assert sent["headers"]["Authorization"] == "Bearer tk_1"


@pytest.mark.parametrize("content", [None, "not json", "[]", '{"token": "x"}'])
def test_an_unreadable_secrets_file_disables_sending_without_raising(tmp_path, content):
    """An alerting shim must not take down its caller (#347): a caller that cannot
    read the file gets False, not an exception, and nothing is posted."""
    secrets = tmp_path / "ntfy.json"
    if content is not None:
        secrets.write_text(content)
    ns = _module(secrets)
    ns["requests"].post = lambda *a, **k: pytest.fail("posted without a topic")
    assert ns["send_alert"]("t", "m") is False


def test_the_secrets_file_is_written_root_owned_and_unprinted():
    t = _task("Write the ntfy topic and token (root and the notify user only)")
    c = t["ansible.builtin.copy"]
    assert c["dest"] == "{{ ntfy_secrets_file }}"
    assert c["owner"] == "root" and c["group"] == "{{ ntfy_user }}" and c["mode"] == "0640"
    assert t["no_log"] is True and t["diff"] is False
    env = jinja2.Environment()  # noqa: S701
    env.filters["to_json"] = json.dumps  # what Ansible's filter does
    rendered = env.from_string(c["content"]).render(ntfy_topic="a", ntfy_token="b")
    assert json.loads(rendered) == {"topic": "a", "token": "b"}
    acl = _task("Let auto-feeder read the ntfy topic and token (ACL)")["ansible.posix.acl"]
    assert acl["entity"] == "auto-feeder" and acl["permissions"] == "r"


def test_the_secrets_file_is_outside_the_root_only_etc_lamware():
    """/etc/lamware is root 0700 (networking's libvirt definitions); the role
    creates its parent 0755 and must not be the one to loosen that."""
    assert Path(DEFAULTS["ntfy_secrets_file"]).parent != Path("/etc/lamware")


# --- the code is root's ---------------------------------------------------------

def test_every_file_the_role_deploys_into_the_code_directory_is_roots():
    deployed = [t for t in TASKS if isinstance(t, dict)
                for mod in ("ansible.builtin.template", "ansible.builtin.copy")
                if mod in t and str(t[mod]["dest"]).startswith("{{ ntfy_install_dir }}")]
    assert len(deployed) == 4, [t["name"] for t in deployed]
    for t in deployed:
        body = t.get("ansible.builtin.template") or t["ansible.builtin.copy"]
        assert body["owner"] == "root", t["name"]
        assert int(body["mode"], 8) & 0o022 == 0, f"{t['name']}: group/other writable"


def test_the_code_directory_is_roots_and_not_group_writable():
    d = _task("Create the ntfy-alerts code directory (root-owned)")["ansible.builtin.file"]
    assert d["path"] == "{{ ntfy_install_dir }}"
    assert d["owner"] == "root"
    assert int(d["mode"], 8) & 0o7022 == 0, d["mode"]


def test_the_notify_user_writes_only_its_data_directory():
    unit = _render("lamware-digest.service.j2")
    rw = [ln.split("=", 1)[1] for ln in unit.splitlines() if ln.startswith("ReadWritePaths=")]
    assert rw == [DEFAULTS["ntfy_data_dir"]]
    err = next(ln for ln in unit.splitlines() if ln.startswith("StandardError="))
    assert err == f"StandardError=append:{DEFAULTS['ntfy_data_dir']}/digest.err"


def test_the_digest_writes_its_output_to_the_data_directory():
    src = _render("daily-digest.py.j2")
    assert f'DATA_DIR = Path("{DEFAULTS["ntfy_data_dir"]}")' in src
    assert 'DIGEST_FILE = DATA_DIR / "latest-digest.json"' in src
    assert 'RotatingFileHandler(str(DATA_DIR / "digest.log")' in src


def test_the_api_reads_the_digest_where_the_digest_writes_it():
    from ast import AnnAssign, parse, walk
    tree = parse((ROOT / "api" / "app" / "config.py").read_text())
    default = next(n.value.value for n in walk(tree)
                   if isinstance(n, AnnAssign) and getattr(n.target, "id", "") == "digest_file")
    assert default == f"{DEFAULTS['ntfy_data_dir']}/latest-digest.json"


def test_the_aide_log_rule_follows_the_digest_log():
    rules = (ROOT / "ansible" / "roles" / "hardening" / "files" / "98_lamware_logs").read_text()
    lines = [ln for ln in rules.splitlines() if "digest" in ln and not ln.startswith("#")]
    assert lines == [DEFAULTS["ntfy_data_dir"].replace(".", "\\.") + "/digest\\.log$ f ActLog"]


# --- the migration ---------------------------------------------------------------

def test_the_move_carries_the_digest_output_over_once(tmp_path):
    """Run the role's own move script against a fake code and data directory."""
    code, data = tmp_path / "code", tmp_path / "data"
    code.mkdir()
    data.mkdir()
    (code / "digest.log").write_text("old log\n")
    (code / "latest-digest.json").write_text("{}\n")
    (code / "ntfy_notify.py").write_text("# code stays\n")
    (data / "digest.err").write_text("already moved\n")
    (code / "digest.err").write_text("stale copy\n")
    os.symlink("/etc/passwd", code / "digest.log.1")

    script = jinja2.Template(_task("Move the digest's output files to the data directory")
                             ["ansible.builtin.shell"]).render(
        ntfy_install_dir=str(code), ntfy_data_dir=str(data), ntfy_user=getpass.getuser())
    script = script.replace("-g lamware", f"-g {grp.getgrgid(os.getgid()).gr_name}")

    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "moved 3"
    assert (data / "digest.log").read_text() == "old log\n"
    assert (data / "latest-digest.json").read_text() == "{}\n"
    assert (data / "digest.err").read_text() == "already moved\n", "an existing file was overwritten"
    assert not (code / "digest.log").exists() and not (code / "digest.err").exists()
    assert (code / "ntfy_notify.py").exists()
    assert (code / "digest.log.1").is_symlink() and not (data / "digest.log.1").exists(), (
        "a link was followed")
    assert oct((data / "digest.log").stat().st_mode & 0o777) == "0o640"

    again = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert again.stdout.strip() == "moved 0"
