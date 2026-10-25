# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The ollama role removes Ollama; it must never deploy it again.

Ollama was retired on 2026-10-25 once #431 was answered: its short summaries
were its 4,096-token default context filling up, and nothing has called it since
#643. The host evidence is the deploy's own assertion (nothing listening on
11434) and the absent unit, image and model store. This structural test exists
because a revert of the teardown, or a copy-paste from the old role, would
reinstall a 23 GB model server with no caller, and nothing on the host would
flag a server that answers.
"""
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parents[1] / "ansible" / "roles" / "ollama"
TASKS = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())


def _modules(task: dict) -> dict:
    return {k: v for k, v in task.items() if "." in k}


def test_no_task_starts_enables_or_installs_ollama():
    for task in TASKS:
        for module, args in _modules(task).items():
            name = task.get("name", "")
            if module == "ansible.builtin.systemd" and isinstance(args, dict):
                assert args.get("state") in (None, "stopped"), name
                assert args.get("enabled") in (None, False), name
            assert module not in ("ansible.builtin.template", "ansible.builtin.copy",
                                  "ansible.builtin.get_url"), f"{name}: installs a file"
            if module == "ansible.builtin.command":
                cmd = args if isinstance(args, str) else str(args)
                assert "pull" not in cmd and "podman run" not in cmd, f"{name}: {cmd}"


def test_unit_file_and_model_store_are_removed():
    removed = {_modules(t)["ansible.builtin.file"]["path"]
               for t in TASKS
               if isinstance(_modules(t).get("ansible.builtin.file"), dict)
               and _modules(t)["ansible.builtin.file"].get("state") == "absent"}
    assert "/etc/systemd/system/ollama.service" in removed, removed
    assert "{{ ollama_install_dir }}" in removed, removed


def test_the_role_has_no_handlers_or_templates_left():
    assert not (ROLE / "handlers").exists()
    assert not (ROLE / "templates").exists()
