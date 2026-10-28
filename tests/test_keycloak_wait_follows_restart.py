"""The Keycloak readiness wait must run after any queued restart.

Structural test: the ordering of a handler flush against a task is not
observable outside a live play. On 2026-10-27 the unit changed, the wait
passed against the old container, the handler restarted Keycloak at
end-of-play, and security-test probed it mid-startup.
"""

from pathlib import Path

import yaml

TASKS = Path(__file__).resolve().parents[1] / "ansible/roles/keycloak/tasks/main.yml"


def _tasks() -> list[dict]:
    return yaml.safe_load(TASKS.read_text())


def _index(pred) -> int:
    for i, task in enumerate(_tasks()):
        if pred(task):
            return i
    raise AssertionError("task not found")


def _is_unit_template(task: dict) -> bool:
    tmpl = task.get("ansible.builtin.template") or {}
    return tmpl.get("dest") == "/etc/systemd/system/keycloak.service"


def _is_flush(task: dict) -> bool:
    return task.get("ansible.builtin.meta") == "flush_handlers"


def _is_wait(task: dict) -> bool:
    uri = task.get("ansible.builtin.uri") or {}
    return "/health/ready" in str(uri.get("url", ""))


def test_unit_change_notifies_restart() -> None:
    task = _tasks()[_index(_is_unit_template)]
    assert task.get("notify") == "Restart Keycloak"


def test_handlers_flush_between_unit_change_and_readiness_wait() -> None:
    unit, wait = _index(_is_unit_template), _index(_is_wait)
    flushes = [i for i, t in enumerate(_tasks()) if _is_flush(t)]
    assert any(unit < f < wait for f in flushes), (
        "the readiness wait runs before the queued restart; flush handlers first"
    )
