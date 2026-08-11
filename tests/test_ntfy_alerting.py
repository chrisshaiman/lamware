# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The ntfy alerting path: six ways it was failing quietly (#347-#353).

Every one of these shares a shape — the alerting system reporting healthy while
not alerting, or alerting when told not to:

  #347  the module was deployed group `pipeline` while its only non-root
        consumer runs as `auto-feeder`. It imported anyway, via a stale
        group-readable .pyc, and the `except ImportError` around it cannot
        catch the PermissionError a redeploy would produce.
  #348  a digest cron orphaned under a previous owner fired nightly and failed,
        invisible to a role that manages crons per user.
  #349  `{% if ntfy_enabled %}` tests the STRING, so `-e ntfy_enabled=false`
        rendered alerts ON.
  #350  the two AIR-GAP BREACH alerts hardcoded the ntfy path while six other
        call sites templated it.
  #351  the digest cron was gated on ntfy_enabled, so disabling push
        notifications also froze the dashboard.
  #353  doubled log lines, an optional DB password, an inert `cd /tmp`.
"""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"
NTFY = ROLES / "ntfy-alerts"
TASKS = yaml.safe_load((NTFY / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((NTFY / "defaults" / "main.yml").read_text(encoding="utf-8"))
NOTIFY_T = (NTFY / "templates" / "ntfy_notify.py.j2").read_text(encoding="utf-8")
DIGEST_T = (NTFY / "templates" / "daily-digest.py.j2").read_text(encoding="utf-8")
MONITOR_T = (ROLES / "network-monitor" / "templates"
             / "network-monitor.sh.j2").read_text(encoding="utf-8")
SMOKE_T = (ROLES / "security-test" / "templates"
           / "security-smoke-test.sh.j2").read_text(encoding="utf-8")
FEEDER_T = (ROLES / "auto-feeder" / "templates"
            / "auto-feeder.py.j2").read_text(encoding="utf-8")


def _code_only(src: str) -> str:
    """Strip comment lines so an absence check cannot match the prose.

    Both absence assertions below failed on first run by matching the comment
    that explains the removal — "# No StreamHandler (#353)" satisfies
    `"StreamHandler" not in src` being False. Same trap as #336's guards; the
    fix is to look at code, not at the file.
    """
    out = []
    for line in src.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped.startswith("{#"):
            continue
        out.append(line.split("  #")[0])
    return "\n".join(out)


def test_the_comment_stripper_works():
    """Guards the guard — positive and negative control."""
    assert "No StreamHandler" not in _code_only(DIGEST_T)
    assert "RotatingFileHandler(" in _code_only(DIGEST_T)


def _task(name_fragment: str) -> dict:
    for t in TASKS:
        if name_fragment.lower() in (t.get("name") or "").lower():
            return t
    raise AssertionError(f"no task matching {name_fragment!r}")


# ---------------------------------------------------------------------------
# #349 — truthiness. The one with a measured wrong answer.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expect_enabled", [
    ("false", False), ("False", False), ("no", False), ("0", False),
    (False, False), (True, True), ("true", True), ("yes", True),
])
def test_ntfy_enabled_renders_from_the_VALUE_not_the_string(value, expect_enabled):
    """`-e ntfy_enabled=false` arrives as the string "false", which is non-empty
    and therefore truthy. Measured before the fix: naked_if=True."""
    env = jinja2.Environment()
    env.filters["bool"] = _ansible_bool
    out = env.from_string(NOTIFY_T).render(
        ntfy_url="https://ntfy.sh", ntfy_topic="t", ntfy_enabled=value)
    assert f"NTFY_ENABLED = {expect_enabled}" in out, (
        f"ntfy_enabled={value!r} rendered the wrong state")


@pytest.mark.parametrize("value,expect", [("false", "false"), (False, "false"),
                                          ("true", "true"), (True, "true")])
def test_the_smoke_test_also_tests_the_value(value, expect):
    """security-test.yml has no `when: ntfy_enabled` to catch the mistake
    downstream, so there it fails silently — the smoke test starts pushing
    alerts the operator disabled."""
    env = jinja2.Environment()
    env.filters["bool"] = _ansible_bool
    out = env.from_string(SMOKE_T).render(
        security_test_api_url="", security_test_keycloak_url="",
        security_test_domain="", security_test_install_dir="/opt/st",
        ntfy_url="https://ntfy.sh", ntfy_topic="t", ntfy_enabled=value)
    assert f"NTFY_ENABLED={expect}" in out


def _ansible_bool(v):
    """Ansible's `bool` filter, close enough for template rendering."""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "yes", "on", "1", "y")


def test_no_template_tests_ntfy_enabled_bare():
    """A bare `{% if ntfy_enabled %}` anywhere is the bug returning."""
    for name, src in (("ntfy_notify", NOTIFY_T), ("smoke", SMOKE_T)):
        for m in re.finditer(r"\{[%{]-?\s*(?:if\s+)?ntfy_enabled([^%}]*)", src):
            tail = m.group(1)
            assert "bool" in tail, (
                f"{name}: ntfy_enabled used without | bool -> {m.group(0)!r}")


# ---------------------------------------------------------------------------
# #347 — the module must be readable by the user that imports it
# ---------------------------------------------------------------------------

def test_the_module_group_matches_the_directory():
    """The directory is pipeline:lamware 0750 so auto-feeder (in lamware) can
    traverse it. Deploying the module group `pipeline` meant it could reach the
    file and not read it."""
    d = _task("Create ntfy-alerts directory")["ansible.builtin.file"]
    m = _task("Deploy ntfy notification module")["ansible.builtin.template"]
    assert d["group"] == "lamware"
    assert m["group"] == "lamware", (
        "the module is group-restricted more tightly than the directory that "
        "exists to make it reachable")


def test_the_digest_script_is_reachable_too():
    assert _task("Deploy daily digest script")["ansible.builtin.template"]["group"] \
        == "lamware"


def test_the_import_guard_catches_more_than_ImportError():
    """PermissionError is an OSError. `except ImportError` lets it terminate
    auto-feeder at startup instead of degrading to ntfy_alert = None."""
    code = _code_only(FEEDER_T)
    start = code.index("from ntfy_notify import")
    block = code[start:code.index("ntfy_alert = None", start) + 40]
    assert "except Exception" in block, (
        f"an alerting shim must not be able to take down its caller: {block!r}")
    assert "except ImportError:" not in block


def test_the_module_template_suppresses_diff():
    """ntfy_topic is the only access control on a public relay (#352), and
    --diff prints the rendered body."""
    assert _task("Deploy ntfy notification module").get("diff") is False


# ---------------------------------------------------------------------------
# #351 — the dashboard must not depend on push notifications
# ---------------------------------------------------------------------------

def test_the_digest_cron_is_gated_on_the_digest_setting_alone():
    """ntfy_enabled is a DELIVERY setting; latest-digest.json is generated DATA
    the dashboard reads. send_alert already no-ops when disabled."""
    install = _task("Install daily digest cron")
    remove = _task("Remove daily digest cron")
    assert "ntfy_enabled" not in install["when"], (
        f"digest generation still coupled to push delivery: {install['when']!r}")
    assert "ntfy_digest_enabled" in install["when"]
    assert "ntfy_enabled" not in remove["when"]


# ---------------------------------------------------------------------------
# #348 — orphaned schedules
# ---------------------------------------------------------------------------

def test_former_cron_owners_are_cleaned_up():
    """`ansible.builtin.cron` is per user, so an entry under a previous owner is
    invisible to both the install and remove tasks."""
    assert "cape" in DEFAULTS["ntfy_digest_former_cron_users"], (
        "cape held this cron before the role moved to pipeline and its copy "
        "failed nightly from at least 2026-08-04")
    t = _task("Remove orphaned digest cron")
    assert t["ansible.builtin.cron"]["state"] == "absent"
    assert "ntfy_digest_former_cron_users" in str(t.get("loop"))


def test_the_outcome_is_asserted_not_just_the_removal_list():
    """The list only covers owners someone thought to name. A job that changed
    hands again would be scheduled twice, silently — which is how #348 hid."""
    t = _task("Assert exactly one crontab")
    assert t.get("changed_when") is False
    assert "daily-digest.py" in t["ansible.builtin.shell"]
    assert "failed_when" in t


# ---------------------------------------------------------------------------
# #350 — the breach alerts must not hardcode the path
# ---------------------------------------------------------------------------

def test_no_literal_ntfy_path_survives_rendering():
    """Rendered, not source: the template legitimately contains the literal
    inside `default('/opt/ntfy-alerts')`. What must not appear is a call site
    that ignores the variable."""
    rendered = jinja2.Environment().from_string(MONITOR_T).render(
        management_interface="enp3s0f0", network_monitor_detonation_bridge="virbr-det",
        network_monitor_install_dir="/opt/network-monitor",
        network_monitor_pause_file="/opt/network-monitor/paused",
        ntfy_install_dir="/CUSTOM/ntfy", cape_user="cape")
    assert "/opt/ntfy-alerts" not in rendered, (
        "a call site still hardcodes the default install dir")
    assert "/CUSTOM/ntfy/ntfy_notify.py" in rendered


def test_the_breach_alerts_specifically_are_templated():
    """These two are the reason this matters: the call is `2>/dev/null || true`,
    so a wrong path fails silently and the breach never reaches a phone."""
    breach = [ln for ln in MONITOR_T.splitlines() if "NETWORK BREACH" in ln]
    assert len(breach) == 2, f"expected 2 breach alerts, found {len(breach)}"
    for ln in breach:
        idx = MONITOR_T.index(ln)
        call = MONITOR_T[max(0, idx - 200):idx]
        assert "ntfy_install_dir" in call, (
            "an AIR-GAP BREACH alert still hardcodes its ntfy path")


# ---------------------------------------------------------------------------
# #353 — digest hygiene
# ---------------------------------------------------------------------------

def test_the_db_password_is_mandatory_like_its_neighbour():
    """An empty default rendered clean, deployed clean, and failed at 20:00 as a
    connection error — one line above `litellm_master_key | mandatory`."""
    assert "pipeline_db_password | mandatory" in DIGEST_T
    assert "pipeline_db_password | default" not in DIGEST_T


def test_logging_has_exactly_one_writer_for_digest_log():
    """The RotatingFileHandler owns digest.log. A StreamHandler plus a cron
    redirect into the same file duplicated every line and raced the rollover."""
    code = _code_only(DIGEST_T)
    assert "RotatingFileHandler" in code
    assert "StreamHandler" not in code
    job = _task("Install daily digest cron")["ansible.builtin.cron"]["job"]
    assert ">> " not in job.replace("2>> ", ""), (
        f"cron still redirects stdout into the handler's file: {job!r}")


def test_the_cron_does_not_cd_into_a_world_writable_directory():
    """`cd /tmp` was inert for path resolution and actively harmful for imports:
    it puts a world-writable directory first on sys.path (#371)."""
    job = _task("Install daily digest cron")["ansible.builtin.cron"]["job"]
    assert "cd /tmp" not in job, f"still cds into /tmp: {job!r}"


def test_stderr_is_still_captured_somewhere():
    """Dropping the redirect must not mean losing a crash that happens before
    logging is configured."""
    job = _task("Install daily digest cron")["ansible.builtin.cron"]["job"]
    assert "2>>" in job or "2>" in job, f"stderr goes nowhere: {job!r}"
