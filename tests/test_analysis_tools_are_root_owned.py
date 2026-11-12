# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""ADR-025 for the analysis tools: code is root's, the pipeline owns data only.

In these roles only the runtime data directories may be pipeline-owned; the
install directory, build context, wrappers and rules are root-owned and only
readable by the pipeline (group lamware). Structural, because ownership is a
task parameter; security-test check 14 asks the kernel on the host.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = {  # role: paths that may stay the pipeline's
    "ghidra": {"{{ item }}"},           # the data-directories loop (output, projects)
    "volatility": {"{{ item }}", "{{ volatility_install_dir }}/cache"},
    "triage": {"{{ item }}"},
    "interpret": {"{{ interpret_install_dir }}/ab-results"}, "office-macro-analysis": set(), "powershell-analysis": set(),
    "python-sandbox": set(),
    "pcap-analysis": {"{{ item }}"}, "go-analysis": {"{{ item }}"},
    "java-analysis": {"{{ item }}"}, "dotnet-analysis": {"{{ item }}"},
    "pdf-generation": {"{{ item }}"}, "pyinstaller-analysis": {"{{ item }}"},
    "screenshot-analysis": {"{{ item }}"},
}
DATA_LOOP_NAME = "Create the data directories (pipeline's; ADR-025)"


def _walk(tasks):
    for t in tasks or []:
        if isinstance(t, dict):
            yield t
            for k in ("block", "rescue", "always"):
                yield from _walk(t.get(k))


def _owned(role):
    for t in _walk(yaml.safe_load((ROOT / f"ansible/roles/{role}/tasks/main.yml").read_text())):
        for mod, p in t.items():
            if isinstance(p, dict) and p.get("owner") == "pipeline":
                yield t, p.get("dest") or p.get("path")


@pytest.mark.parametrize("role", sorted(DATA))
def test_only_data_directories_are_pipeline_owned(role):
    for task, path in _owned(role):
        assert path in DATA[role], f"{role}: {task.get('name')!r} gives pipeline {path}"
        if path == "{{ item }}":
            assert task.get("name") == DATA_LOOP_NAME
            assert all("/build" not in str(i) and "rules" not in str(i) for i in task["loop"])


@pytest.mark.parametrize("role", sorted(DATA))
def test_the_build_context_is_taken_back_without_following_links(role):
    tasks = list(_walk(yaml.safe_load((ROOT / f"ansible/roles/{role}/tasks/main.yml").read_text())))
    take = [t["ansible.builtin.file"] for t in tasks
            if isinstance(t.get("ansible.builtin.file"), dict)
            and str(t["ansible.builtin.file"].get("path", "")).endswith("/build")
            and t["ansible.builtin.file"].get("recurse")]
    assert take and take[0]["owner"] == "root" and take[0]["follow"] is False


def test_build_inputs_are_copied_root_owned():
    seen = []
    for f in ("image.yml", "image_base.yml"):
        for t in _walk(yaml.safe_load((ROOT / "ansible/roles/build-fetch/tasks" / f).read_text())):
            p = t.get("ansible.builtin.copy")
            # Only what lands in the build context; lamware-fetch keeps its own staging.
            if isinstance(p, dict) and "hb_build_dir" in str(p.get("dest", "")):
                assert p.get("owner") == "root", f"{f}: {t.get('name')}"
                seen.append(f)
    assert sorted(set(seen)) == ["image.yml", "image_base.yml"], seen


def test_sample_feeder_gives_its_user_nothing_but_read_on_the_config():
    """The auto-feeder (another user) acts on the feeder's config and seen-hash
    file, so the feeder user may own neither, nor the script or directory."""
    tasks = list(_walk(yaml.safe_load((ROOT / "ansible/roles/sample-feeder/tasks/main.yml").read_text())))
    for t in tasks:
        for mod, p in t.items():
            if isinstance(p, dict) and "owner" in p:
                assert p["owner"] == "root", f"{t.get('name')!r} owner {p['owner']}"
    acl = [t["ansible.posix.acl"] for t in tasks if "ansible.posix.acl" in t]
    assert len(acl) == 1 and acl[0]["permissions"] == "r" and acl[0]["path"].endswith("config.json")

