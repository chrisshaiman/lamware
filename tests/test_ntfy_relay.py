"""Alerts from pipeline-uid processes are queued as data and delivered by a relay (#729).

The pipeline user has no DNS and no egress, so the daily digest and the spool
runner's quarantine alerts — both run as pipeline — failed on every attempt
after the egress lockdown, into a log nobody reads. The digest moved to its own
user; the spool runner now writes a file into a drop box that a path unit
delivers as that user.

These tests render and RUN the real enqueue and relay scripts against a real
directory. The relay's inputs are written by the pipeline user, which handles
hostile samples, so most of them are about what the relay refuses.
"""
from __future__ import annotations

import configparser
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
NTFY = ROOT / "ansible" / "roles" / "ntfy-alerts"
TASKS = yaml.safe_load((NTFY / "tasks" / "main.yml").read_text())
DEFAULTS = yaml.safe_load((NTFY / "defaults" / "main.yml").read_text())


def _render(name: str, **over) -> str:
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    vars_ = {**DEFAULTS, **over}
    return env.from_string((NTFY / "templates" / name).read_text()).render(**vars_)


@pytest.fixture
def box(tmp_path):
    d = tmp_path / "dropbox"
    d.mkdir()
    return d


@pytest.fixture
def enqueue(tmp_path, box):
    path = tmp_path / "ntfy_enqueue.py"
    path.write_text(_render("ntfy_enqueue.py.j2", ntfy_dropbox_dir=str(box)))
    return path


@pytest.fixture
def relay(tmp_path, box, monkeypatch):
    """The rendered relay, loaded with a stub ntfy_notify that records sends."""
    sent: list[dict] = []
    stub = types.ModuleType("ntfy_notify")

    def send_alert(title, message, priority="default", tags="", click=""):
        sent.append({"title": title, "message": message,
                     "priority": priority, "tags": tags})
        return relay.ok
    stub.send_alert = send_alert
    monkeypatch.setitem(sys.modules, "ntfy_notify", stub)
    ns: dict = {"__name__": "ntfy_relay_under_test"}
    src = _render("ntfy_relay.py.j2", ntfy_dropbox_dir=str(box),
                  ntfy_install_dir=str(tmp_path))
    exec(compile(src, "ntfy_relay.py", "exec"), ns)  # noqa: S102
    relay.ns, relay.sent, relay.ok = ns, sent, True
    return relay


def _queue(enqueue: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(enqueue), *args],
                          capture_output=True, text=True, timeout=30)


def _alerts(box: Path) -> list[str]:
    return sorted(p.name for p in box.iterdir() if p.name.startswith("alert-"))


# --- the round trip ----------------------------------------------------------

def test_a_queued_alert_is_delivered_once_and_removed(enqueue, relay, box):
    r = _queue(enqueue, "Pipeline Failure", "sample 1234 quarantined",
               "--priority", "high", "--tags", "warning")
    assert r.returncode == 0, r.stderr
    assert len(_alerts(box)) == 1
    counts = relay.ns["run"](str(box))
    assert counts == {"sent": 1, "failed": 0, "rejected": 0, "dropped": 0}
    assert relay.sent == [{"title": "Pipeline Failure",
                           "message": "sample 1234 quarantined",
                           "priority": "high", "tags": "warning"}]
    assert list(box.iterdir()) == []


def test_enqueue_is_atomic_and_readable_by_the_relay_user(enqueue, box):
    """The caller runs under umask 077; the relay is another user."""
    r = subprocess.run(["bash", "-c", f"umask 077; {sys.executable} {enqueue} t m"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    names = [p.name for p in box.iterdir()]
    assert len(names) == 1 and names[0].startswith("alert-"), names   # no .alert- tmp left
    assert (box / names[0]).stat().st_mode & 0o777 == 0o644


def test_enqueue_reports_failure_when_it_cannot_queue(tmp_path):
    path = tmp_path / "e.py"
    path.write_text(_render("ntfy_enqueue.py.j2", ntfy_dropbox_dir=str(tmp_path / "nope")))
    r = _queue(path, "t", "m")
    assert r.returncode == 1 and "could not queue" in r.stderr


def test_a_failed_send_is_logged_and_does_not_loop(enqueue, relay, box, capfd):
    relay.ok = False
    _queue(enqueue, "t", "m")
    counts = relay.ns["run"](str(box))
    assert counts["failed"] == 1
    assert _alerts(box) == [], "a failed alert left in place re-triggers the path unit forever"
    assert "NOT DELIVERED" in capfd.readouterr().err


# --- what the relay refuses -----------------------------------------------------

def _write(box: Path, name: str, data) -> Path:
    p = box / name
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return p


@pytest.mark.parametrize("payload", [
    "not json",
    json.dumps(["a", "list"]),
    json.dumps({"title": 1, "message": "m"}),
    json.dumps({"title": "t"}),
])
def test_malformed_alerts_are_set_aside_unsent(relay, box, payload):
    _write(box, "alert-1-1.json", payload)
    counts = relay.ns["run"](str(box))
    assert counts["rejected"] == 1 and relay.sent == []
    assert _alerts(box) == [], "a rejected file must leave the glob or the path unit loops"
    assert (box / ".rejected-alert-1-1.json").exists()


def test_an_oversized_alert_is_refused(relay, box):
    max_bytes = DEFAULTS["ntfy_relay_max_bytes"]
    _write(box, "alert-1-1.json", {"title": "t", "message": "x" * (max_bytes + 10)})
    assert relay.ns["run"](str(box))["rejected"] == 1 and relay.sent == []


def test_a_symlink_is_never_followed(relay, box, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"title": "leaked", "message": "contents"}))
    (box / "alert-1-1.json").symlink_to(secret)
    counts = relay.ns["run"](str(box))
    assert counts["rejected"] == 1 and relay.sent == []
    assert secret.exists(), "setting the link aside must not touch its target"


def test_a_directory_cannot_make_the_path_unit_loop(relay, box):
    d = box / "alert-1-1.json"
    d.mkdir()
    (d / "inner").write_text("x")
    relay.ns["run"](str(box))
    assert _alerts(box) == [], "a non-file left matching alert-*.json fires the relay forever"


def test_a_name_outside_the_pattern_is_set_aside(relay, box):
    _write(box, "alert-../../x.json".replace("/", "_"), {"title": "t", "message": "m"})
    relay.ns["run"](str(box))
    assert relay.sent == [] and _alerts(box) == []


def test_fields_are_capped_and_priority_and_tags_allowlisted(relay, box):
    _write(box, "alert-1-1.json", {"title": "T" * 500, "message": "M" * 9000,
                                   "priority": "max; rm -rf /", "tags": "Bad Tags!"})
    relay.ns["run"](str(box))
    (got,) = relay.sent
    assert len(got["title"]) == 120 and len(got["message"]) == 2000
    assert got["priority"] == "default" and got["tags"] == ""


def test_a_flood_is_cut_off_and_reported(relay, box):
    limit = DEFAULTS["ntfy_relay_max_per_run"]
    for i in range(limit + 7):
        _write(box, f"alert-{i:06d}-1.json", {"title": f"t{i}", "message": "m"})
    counts = relay.ns["run"](str(box))
    assert counts["sent"] == limit and counts["dropped"] == 7
    assert relay.sent[-1]["title"] == "Alerts dropped"
    assert _alerts(box) == []


# --- deployment shape ------------------------------------------------------------

def _task(name: str) -> dict:
    return next(t for t in TASKS if isinstance(t, dict) and t.get("name") == name)


def test_the_drop_box_admits_pipeline_but_only_to_create():
    f = _task("Create the alert drop box")["ansible.builtin.file"]
    assert f["group"] == "pipeline" and f["mode"] == "1730"
    assert f["owner"] == "{{ ntfy_user }}"


def test_the_path_unit_fires_only_on_finished_alerts():
    cp = configparser.ConfigParser()
    cp.read_string(_render("lamware-notify-relay.path.j2"))
    assert cp["Path"]["PathExistsGlob"].endswith("/alert-*.json")
    assert cp["Path"]["Unit"] == "lamware-notify-relay.service"


def test_the_relay_runs_as_the_notify_user_and_can_write_only_the_drop_box():
    cp = configparser.ConfigParser()
    cp.read_string(_render("lamware-notify-relay.service.j2"))
    svc = cp["Service"]
    assert svc["User"] == DEFAULTS["ntfy_user"]
    assert svc["ProtectSystem"] == "strict"
    assert svc["ReadWritePaths"] == DEFAULTS["ntfy_dropbox_dir"]
    assert svc["NoNewPrivileges"] == "yes"


def test_no_pipeline_owned_sender_is_left():
    """The cron and every deployed file belong to the notify user now."""
    cron = _task("Install daily digest cron job")["ansible.builtin.cron"]
    assert cron["user"] == "{{ ntfy_user }}"
    assert "pipeline" in DEFAULTS["ntfy_digest_former_cron_users"], (
        "the pipeline crontab entry must be removed, or it keeps firing and failing")
    for name in ("Deploy ntfy notification module", "Deploy daily digest script",
                 "Deploy the alert enqueue script (run by pipeline-uid callers)",
                 "Deploy the alert relay"):
        assert _task(name)["ansible.builtin.template"]["owner"] == "{{ ntfy_user }}", name


def test_a_pipeline_owned_bytecode_cache_is_removed():
    """A cache pipeline can write, in a directory the notify user imports from,
    would let pipeline run code as a user with egress."""
    t = _task("Remove a bytecode cache the notify user does not own")
    assert t["ansible.builtin.file"]["state"] == "absent"
    assert "pw_name != ntfy_user" in str(t["when"])


def test_the_spool_runner_queues_rather_than_sends():
    runner = (ROOT / "ansible" / "roles" / "api" / "templates"
              / "pipeline-spool-run.sh.j2").read_text()
    assert "ntfy_enqueue.py" in runner
    code = "\n".join(ln for ln in runner.splitlines() if not ln.lstrip().startswith("#"))
    assert "ntfy_notify.py" not in code, "a pipeline-uid process cannot reach ntfy"
