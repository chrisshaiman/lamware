# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every module under stages/ is in the pipeline role's copy list.

The role ships stage modules by an explicit loop, not by directory. A module
added to the repo but not to the loop exists in every test run and is missing
on the host -- #325 landed as a no-op exactly that way. #406 adds
stages/process_activity.py, which stages/cape.py imports at module load, so a
missed entry would take the whole CAPE stage down on the host while the suite
stays green.

Structural, because the only other observer is a deploy. The YAML is parsed
and the loop compared as a set; nothing is matched as text.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "ansible/roles/pipeline/tasks/main.yml"
STAGES = ROOT / "ansible/roles/pipeline/files/stages"


def _shipped_stage_modules() -> set[str]:
    tasks = yaml.safe_load(TASKS.read_text())
    loops = [t.get("loop") for t in tasks
             if isinstance(t, dict)
             and (t.get("ansible.builtin.copy") or {}).get("src") == "stages/{{ item }}"]
    assert len(loops) == 1, f"expected one stages copy task, found {len(loops)}: the probe is broken"
    return set(loops[0])


def test_every_stage_module_ships():
    on_disk = {p.name for p in STAGES.glob("*.py")}
    shipped = _shipped_stage_modules()
    assert "cape.py" in shipped, "the probe is broken"
    assert on_disk - shipped == set(), f"in the repo but never deployed: {sorted(on_disk - shipped)}"
    assert shipped - on_disk == set(), f"deployed but missing from the repo: {sorted(shipped - on_disk)}"
