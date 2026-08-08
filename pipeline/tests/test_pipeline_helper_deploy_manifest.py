# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every importable pipeline helper must actually be deployed.

The pipeline role copies top-level helpers by an EXPLICIT list, so adding a module
to `roles/pipeline/files/` does nothing on its own. On 2026-08-08 that landed #318
as a no-op: `attack_check.py` and `attack_catalog.json` were merged, the deploy ran
from the right commit with `dirty: false`, and neither file reached the host.

The provenance marker said `sha: 0839e8e` — the exact commit containing them. It
was telling the truth: that commit deployed. Nothing copied the files, because
nothing was asked to. Provenance answers "which code ran", never "did this file
arrive", which is why it could not catch this and this test can.

#319 landed in the same deploy only because it MODIFIED an already-listed file.
Same PR batch, same tags, opposite outcome — the difference was invisible until a
host check went looking for the artifact rather than the commit.

This is #262's shape (a feature spanning code and deploy manifest, half-landing
silently) with the halves inside a single role.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"
TASKS = ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml"

# Deployed by their own tasks, not the top-level helper loop.
_ELSEWHERE = {
    "run-pipeline.py", "db_ingest.py", "generate-report.py", "ioc_extract.py",
    "pipeline_status.py", "backfill_relationships.py", "llm_ab_summary.py",
    "re_ab_labels.json",
}


def _deployed_names() -> set[str]:
    """Every filename the role copies, from any task in it.

    Deliberately scans the WHOLE task file rather than one loop: a helper moved to
    a different task is still deployed, and a guard that only knows about one loop
    would fail on a correct refactor.
    """
    text = TASKS.read_text(encoding="utf-8")
    return set(re.findall(r"[\w./-]+\.(?:py|json)", text))


def _importable_helpers() -> set[str]:
    """Top-level modules and data files in the role's files/ directory."""
    out = set()
    for p in FILES.iterdir():
        if p.is_dir() or p.name.startswith(("_", ".")):
            continue
        if p.suffix in (".py", ".json"):
            out.add(p.name)
    return out


def test_every_helper_module_is_in_the_deploy_manifest():
    """THE regression. #318 merged, deployed, and was absent from the host."""
    missing = sorted(_importable_helpers() - _deployed_names() - _ELSEWHERE)
    assert not missing, (
        f"these files exist in roles/pipeline/files/ but no task copies them, so "
        f"they will merge and deploy as a silent no-op: {missing}. Add them to the "
        f"helper loop in tasks/main.yml, or to _ELSEWHERE if another task handles "
        f"them.")


def test_attack_check_and_its_catalog_are_both_deployed():
    """Named explicitly because they are useless apart.

    `attack_check` with no catalog reports every ID as `unknown_id`, which reads as
    'nothing to see' — a check that cannot run looking like a check that passed.
    """
    deployed = _deployed_names()
    assert "attack_check.py" in deployed
    assert "attack_catalog.json" in deployed


def test_the_manifest_guard_would_catch_a_new_module():
    """Guards the guard: prove the set difference is live, not vacuous."""
    fake = "definitely_not_deployed_helper.py"
    assert fake not in _deployed_names()
    assert fake in ((_importable_helpers() | {fake}) - _deployed_names() - _ELSEWHERE)


def test_elsewhere_entries_still_exist():
    """A stale exemption would silently re-open the hole it was carved for."""
    present = _importable_helpers()
    stale = sorted(n for n in _ELSEWHERE if n not in present)
    assert not stale, (
        f"_ELSEWHERE names files that no longer exist: {stale}. Remove them, or the "
        f"exemption list starts hiding real gaps.")
