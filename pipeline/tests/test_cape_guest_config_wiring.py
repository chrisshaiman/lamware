# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pin has to survive the whole chain: defaults -> template -> config -> call.

A knob that exists in the dataclass but is never rendered into config.json, or
rendered but never passed to submit_to_cape, is a knob wired to nothing -- and
it would read as "configurable" in review while the production path stayed
exactly as broken as before.
"""
import ast
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"
sys.path.insert(0, str(FILES))

from lamware_pipeline.config import PipelineConfig  # noqa: E402

DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "pipeline" / "defaults" / "main.yml").read_text())
TEMPLATE = (ROOT / "ansible" / "roles" / "pipeline"
            / "templates" / "config.json.j2").read_text()
RUN_PIPELINE = ast.parse((FILES / "run-pipeline.py").read_text())

NEW_KEYS = ("cape_machine", "cape_office_machine", "cape_memory_dump")


def test_the_dataclass_accepts_the_new_keys():
    for k in NEW_KEYS:
        assert k in PipelineConfig.model_fields, f"{k} missing from PipelineConfig"


def test_an_older_config_json_still_loads():
    """These are defaulted on purpose: a host whose config.json predates them
    must keep working rather than crash every stage at import."""
    for k in NEW_KEYS:
        assert PipelineConfig.model_fields[k].default is not None, (
            f"{k} has no default, so an existing config.json would fail to load")


def test_the_guest_defaults_are_the_safe_ones():
    assert DEFAULTS["pipeline_cape_machine"] == "clean"
    assert DEFAULTS["pipeline_cape_office_machine"] == "office"


def test_memory_dumps_are_on_because_volatility_cannot_run_without_one():
    assert DEFAULTS["pipeline_cape_memory_dump"] is True


def test_every_key_is_rendered_into_config_json():
    for k in NEW_KEYS:
        assert f'"{k}"' in TEMPLATE, f"{k} is never written to config.json"
        assert f"pipeline_{k}" in TEMPLATE, f"{k} is not fed from the role default"


def _call_keywords(tree, func_name):
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == func_name):
            return {kw.arg for kw in node.keywords}
    return None


def test_run_pipeline_passes_the_pin_to_the_api():
    kws = _call_keywords(RUN_PIPELINE, "submit_to_cape")
    assert kws is not None, "run-pipeline no longer calls submit_to_cape"
    assert "machine" in kws, "the submission is unpinned again"
    assert "memory_dump" in kws, "memory dumping is not driven by config"


def test_run_pipeline_derives_the_machine_rather_than_hardcoding_one():
    """Hardcoding `clean` at the call site would send Office documents to a guest
    with no Office installed."""
    assert _call_keywords(RUN_PIPELINE, "derive_machine") is not None or any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "derive_machine" for n in ast.walk(RUN_PIPELINE)), (
        "run-pipeline does not derive the guest from the routing tags")


def test_volatility_is_told_whether_a_dump_was_requested():
    kws = _call_keywords(RUN_PIPELINE, "run_volatility")
    assert kws is not None and "memory_dump_requested" in kws, (
        "the Volatility stage cannot tell 'disabled' from 'CAPE failed'")


# --- dumps and their reapers are ONE decision ------------------------------

def _memdump_reaper_cron():
    """The cron task that reaps memory dumps, found by PARSING the role.

    Not by grepping. The string "cape-storage-maintenance" also appears in a
    comment above an unrelated task ("renaming this task to ..."), so a
    substring check still passes after the cron itself is renamed away. A
    mutation sweep caught exactly that.
    """
    tasks = yaml.safe_load(
        (ROOT / "ansible" / "roles" / "cape" / "tasks" / "main.yml").read_text())
    for t in tasks:
        if not isinstance(t, dict):
            continue
        cron = t.get("ansible.builtin.cron")
        if not isinstance(cron, dict) or cron.get("state") == "absent":
            continue
        if "memory.dmp" in str(cron.get("job") or ""):
            return cron
    return None


def test_enabling_dumps_requires_a_backstop_reaper_to_exist():
    """A dump is ~8 GB and conf/memory.conf sets delete_memdump=no, so CAPE
    never reclaims one. Turning dumps on without a reaper is what filled the
    disk and silently stopped CAPE scheduling below freespace=50000."""
    if not DEFAULTS["pipeline_cape_memory_dump"]:
        return
    cron = _memdump_reaper_cron()
    assert cron is not None, "memory dumps are enabled but no cron reaps memory.dmp"
    assert "-mmin" in str(cron["job"]), "the reaper no longer reaps by age"


def test_pipeline_does_not_delete_cape_storage():
    """The pipeline user must not reclaim dumps. This is a security boundary.

    analyses/<id> is cape:lamware drwxr-s--- with an ACL granting lamware r-x.
    Deleting a file needs write on the DIRECTORY, so `pipeline` cannot -- and
    deliberately must not. Cleanup belongs to the cape-owned cron.

    This has now been added and removed TWICE:

        8f126ee  2026-05-09  pipeline deletes the dump after Volatility
        daaa7c3  2026-05-15  removed: "crosses the security boundary between
                             pipeline and cape users"
        #611     2026-09-19  added back; failed with PermissionError on every
                             run, silently, while reading as belt-and-braces

    A standing comment saying "do not do this" sat fifty lines below the second
    attempt and did not prevent it. This test is the version that can.
    """
    src = (FILES / "run-pipeline.py").read_text()
    for node in ast.walk(RUN_PIPELINE):
        if not isinstance(node, ast.Call):
            continue
        name = (node.func.attr if isinstance(node.func, ast.Attribute)
                else getattr(node.func, "id", ""))
        if name in ("unlink", "rmtree", "remove", "reap_memory_dump"):
            seg = ast.get_source_segment(src, node) or ""
            assert "CAPEv2" not in seg and "memory" not in seg.lower(), (
                f"run-pipeline deletes CAPE storage: {seg!r}. Cleanup belongs "
                f"to the cape-owned cron -- see daaa7c3.")


def test_the_cape_owned_cron_is_the_only_reaper():
    """Removing the pipeline path only works if the cron actually exists."""
    cron = _memdump_reaper_cron()
    assert cron is not None, "no reaper at all: dumps would accumulate at ~8.6 GB each"
    assert cron.get("user") in ("cape", "{{ cape_user }}"), (
        f"the reaper must run as the user that OWNS the storage, not {cron.get('user')!r}")


def test_the_reaper_grace_exceeds_the_volatility_stage_timeout():
    """The 120-second sweeper that killed this stage deleted dumps a stage was
    still allowed to be reading. Any reaper must outlast that stage.

    run-pipeline arms signal.alarm(2700) -- 45 minutes -- and the dump is
    roughly 3 minutes old when the stage starts.
    """
    cron = _memdump_reaper_cron()
    assert cron is not None, "no memory.dmp reaper to check"
    m = re.search(r"memory\.dmp'\s+-mmin\s+\+(\d+)", str(cron["job"]))
    assert m, f"cannot find the reaper's age threshold in: {cron['job']}"
    grace_min = int(m.group(1))

    alarm = re.search(r"signal\.alarm\((\d+)\)", (FILES / "run-pipeline.py").read_text())
    assert alarm, "the Volatility stage timeout is gone"
    stage_timeout_min = int(alarm.group(1)) / 60

    assert grace_min > stage_timeout_min, (
        f"reaper deletes dumps at {grace_min}m but the Volatility stage may run "
        f"for {stage_timeout_min:.0f}m -- it would delete one mid-read")
