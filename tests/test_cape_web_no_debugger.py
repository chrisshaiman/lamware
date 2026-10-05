"""cape-web must not run Werkzeug's interactive debugger.

Structural, and a memory of a defect rather than a test of the host: CAPE cannot
run here, so nothing local can observe which server cape-web starts. The host
check is behavioural (the debugger's own resource URL must stop answering 200);
see the PR. These parse the role's YAML and assert on values.

cape2.sh's unit starts `manage.py runserver_plus`, and in the installed
django-extensions the DebuggedApplication wrap does not depend on Django's DEBUG,
so DEBUG = False alone would not have removed it. The role replaces ExecStart
with a drop-in instead.
"""

import configparser
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = yaml.safe_load((ROOT / "ansible" / "roles" / "cape" / "tasks" / "main.yml").read_text())


def _task(name: str) -> dict:
    (task,) = [t for t in TASKS if t.get("name") == name]
    return task


def _dropin() -> tuple[str, configparser.ConfigParser]:
    copy = _task("Run cape-web without the Werkzeug debugger")["ansible.builtin.copy"]
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    # systemd allows a key twice (ExecStart= then ExecStart=...); keep the last.
    parser.read_string(copy["content"])
    return copy["dest"], parser


def test_the_dropin_replaces_execstart_without_runserver_plus():
    dest, unit = _dropin()
    assert dest.startswith("/etc/systemd/system/cape-web.service.d/") and dest.endswith(".conf")
    exec_start = unit["Service"]["ExecStart"]
    assert "runserver_plus" not in exec_start
    argv = exec_start.split()
    assert argv[argv.index("manage.py") + 1] == "runserver"
    assert "--insecure" in argv and "--noreload" in argv


def test_the_dropin_clears_the_packaged_execstart_first():
    """Without an empty ExecStart= first, systemd rejects a second ExecStart for a
    simple service, or (for oneshot) runs both."""
    copy = _task("Run cape-web without the Werkzeug debugger")["ansible.builtin.copy"]
    lines = [ln.strip() for ln in copy["content"].splitlines()]
    starts = [ln for ln in lines if ln.startswith("ExecStart=")]
    assert starts[0] == "ExecStart=" and len(starts) == 2


def test_the_dropin_keeps_the_wireguard_bind():
    _, unit = _dropin()
    task = _task("Run cape-web without the Werkzeug debugger")
    assert task["vars"]["cape_web_bind"] == (
        "{{ wireguard_address | ansible.utils.ipaddr('address') }}:{{ cape_api_port }}")
    assert "manage.py runserver {{ cape_web_bind }} " in unit["Service"]["ExecStart"]


def test_the_dropin_directory_is_created_before_the_copy():
    names = [t.get("name") for t in TASKS]
    assert names.index("Create the cape-web drop-in directory") < names.index(
        "Run cape-web without the Werkzeug debugger")


def test_django_debug_is_turned_off_in_local_settings():
    li = _task("Turn Django DEBUG off for the CAPE web UI")["ansible.builtin.lineinfile"]
    assert li["path"].endswith("/web/web/local_settings.py")
    assert li["line"] == "DEBUG = False"


def test_both_take_effect_before_the_ordered_restart():
    names = [t.get("name") for t in TASKS]
    reload_at = names.index("Reload systemd after cape2.sh installs unit files")
    start_at = names.index("Start Cape web and processor")
    for n in ("Run cape-web without the Werkzeug debugger", "Turn Django DEBUG off for the CAPE web UI"):
        assert names.index(n) < reload_at < start_at
