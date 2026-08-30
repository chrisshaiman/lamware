# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cape resolved every sample's domains from our own infrastructure (#497).

`cuckoo.conf [processing] resolve_dns` was left at CAPE's default of `on`, so
`modules/processing/network.py:554` called `_dns_gethostbyname` for every domain
a sample queried and wrote the answer into `domains[].ip`. The analysis host has
a working resolver, so those lookups left the box.

Two consequences, and the second is the one that lasts:

  OPSEC   an operator watching authoritative DNS for their own C2 domain sees a
          query from our egress shortly after each detonation.

  TRUTH   the address reached the report as an observation. 242 of the 338
          ipv4-addr IOCs in the database came from our resolver rather than from
          the detonation, and the PDF rendered "domain → ip" under a heading
          reading "Contacted Domains".

Nobody chose it. It is a default, and its output looks exactly like ordinary
report data, which is why it survived since the platform was built.
"""
import ast
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CAPE_TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "cape" / "tasks" / "main.yml").read_text(
        encoding="utf-8"))
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"


def _ini_tasks() -> list[dict]:
    return [t["community.general.ini_file"] for t in CAPE_TASKS
            if isinstance(t, dict)
            and isinstance(t.get("community.general.ini_file"), dict)]


# --- the setting ---


def test_host_side_dns_resolution_is_turned_off():
    """Parsed from the task, not grepped: this repo's comments discuss
    resolve_dns at length and a text search would find it either way."""
    matches = [t for t in _ini_tasks() if t.get("option") == "resolve_dns"]
    assert matches, "nothing manages resolve_dns"
    for t in matches:
        assert t["section"] == "processing", t
        assert str(t["value"]).lower() in {"off", "no", "false", "0"}, t
        assert t["path"].endswith("cuckoo.conf"), t


def test_the_setting_is_managed_so_it_cannot_drift_back():
    """A CAPE upgrade rewrites conf/ from conf/default/, where the default is
    `on`. Setting it once by hand would be undone by the next upgrade with no
    sign that it had been."""
    task = next(t for t in CAPE_TASKS
                if isinstance(t, dict)
                and isinstance(t.get("community.general.ini_file"), dict)
                and t["community.general.ini_file"].get("option") == "resolve_dns")
    assert task.get("notify"), "the processor keeps its config until restarted"


# --- the report must not present our resolver's answer as an observation ---


def _calls_in(path: Path, func: str) -> list[ast.Call]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [n for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == func]


def test_no_ipv4_ioc_is_minted_from_a_host_side_lookup():
    """An IOC list is a list of things this sample did. An address it never
    contacted does not belong in it however it is labelled — which is why this
    asserts the call is gone rather than that its wording changed."""
    calls = _calls_in(FILES / "ioc_extract.py", "add_ioc")
    resolved = [c for c in calls
                if len(c.args) >= 4 and isinstance(c.args[3], ast.JoinedStr)
                and any(isinstance(v, ast.Constant) and "Resolved from" in str(v.value)
                        for v in c.args[3].values)]
    assert not resolved, [c.lineno for c in resolved]

    plain = [c for c in calls
             if len(c.args) >= 4 and isinstance(c.args[3], ast.Constant)
             and "Resolved from" in str(c.args[3].value)]
    assert not plain, [c.lineno for c in plain]


def test_the_domain_itself_is_still_an_ioc():
    """The domain WAS queried by the sample. Only the address beside it came
    from us, so the fix must not throw the observation away with it."""
    src = (FILES / "ioc_extract.py").read_text(encoding="utf-8")
    calls = _calls_in(FILES / "ioc_extract.py", "add_ioc")
    kinds = {c.args[0].value for c in calls
             if c.args and isinstance(c.args[0], ast.Constant)}
    assert "domain-name" in kinds
    assert "Contacted domain" in src


def _domains_loop(path: Path) -> ast.For:
    """The `for` node that iterates the report's `domains` list.

    Scoped by AST rather than by a line window or a text search. My first
    attempt at these two tests used both and failed on its own evidence: the
    line window overran into the `hosts` loop, where reading `ip` is correct
    because a contacted host IS an observation, and the text search matched the
    arrow inside the comment explaining why the arrow was removed. Grepping
    source finds the prose about the fix as readily as the fix.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        it = ast.dump(node.iter)
        if "'domains'" in it or "Name(id='domains'" in it:
            return node
    raise AssertionError(f"no loop over domains in {path.name}")


@pytest.mark.parametrize("consumer", ["ioc_extract.py", "generate-report.py"])
def test_nothing_reads_the_ip_beside_a_domain(consumer):
    """The field stays in the report — old reports have it, and deleting data is
    not this fix's job — but nothing may present it as sandbox behaviour."""
    loop = _domains_loop(FILES / consumer)
    reads = [n for n in ast.walk(loop)
             if isinstance(n, ast.Constant) and n.value == "ip"]
    assert not reads, f"{consumer} still reads domains[].ip at {[n.lineno for n in reads]}"


def test_the_hosts_loop_is_left_alone():
    """A contacted host IS an observation. The fix must not sweep it up: my
    first version of the test above did exactly that."""
    src = (FILES / "ioc_extract.py").read_text(encoding="utf-8")
    assert "Contacted host" in src
    calls = _calls_in(FILES / "ioc_extract.py", "add_ioc")
    kinds = [c.args[0].value for c in calls
             if c.args and isinstance(c.args[0], ast.Constant)]
    assert "ipv4-addr" in kinds, "observed IPs are still IOCs"
