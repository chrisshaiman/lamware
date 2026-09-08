# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Detect a container that is Up and serving nothing (#580).

The local model was unreachable for six days. Every status-shaped signal was
green -- `podman ps` said "Up 6 days", the unit was active with zero restarts,
`ss` showed the port LISTENing, `podman top` showed the process alive, and
run-pipeline exited 0. The socket was held by conmon and nothing forwarded,
because a stale CNI DNAT rule left by a container removed during the podman
outage (#576) shadowed the live rule and aimed every connection at an IP that
no longer existed.

The one signal that disagreed was CPU time: 53 seconds over six days.

Neither `podman network reload --all` nor restarting the unit clears an orphan
rule -- podman only regenerates rules for containers it still knows about, and
a restart appends the new rule BEHIND the stale one.
"""
import re
from pathlib import Path

import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_SRC = (ROOT / "ansible" / "roles" / "podman" / "templates"
              / "check-podman-ports.sh.j2").read_text(encoding="utf-8")
PODMAN_TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "podman" / "tasks" / "main.yml").read_text(encoding="utf-8"))
LLAMA_TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "llama-cpp" / "tasks" / "main.yml").read_text(encoding="utf-8"))

RENDERED = Environment().from_string(SCRIPT_SRC).render(
    ntfy_url="https://ntfy.example", ntfy_topic="lamware",
    ntfy_token="tok", podman_port_probe_timeout=10)


def _named(tasks, fragment):
    for t in tasks:
        if fragment.lower() in (t.get("name") or "").lower():
            return t
    raise AssertionError(f"no task matching {fragment!r}")


def test_the_template_renders_and_is_valid_shell():
    """It contains ${...} and Go-template braces adjacent to Jinja's own, which
    is how the first two drafts died -- once on ${'#'}arr[@], once on a comment
    that itself contained a Jinja print tag."""
    import subprocess, tempfile
    f = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
    f.write(RENDERED); f.close()
    r = subprocess.run(["bash", "-n", f.name], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_the_container_id_pattern_tolerates_escaped_quotes():
    """iptables -S prints the comment with BACKSLASH-ESCAPED quotes:

        --comment "dnat name: \\"podman\\" id: \\"abc123\\""

    A pattern anchored on `id: "` matches nothing, so the loop body never runs
    and the check passes on every input -- including a deliberately injected
    orphan rule. That is exactly what the first version did."""
    m = re.search(r"grep -oP '([^']+)'", RENDERED)
    assert m, "no id-extraction pattern found"
    pattern = m.group(1)
    assert "\\\\?" in pattern or '\\"' in pattern, (
        f"pattern {pattern!r} will not match iptables' escaped quotes")

    # and prove it against real iptables -S output
    import subprocess
    sample = r'-A CNI-HOSTPORT-DNAT -p tcp -m comment --comment "dnat name: \"podman\" id: \"fad5c553\"" -j CNI-DN-X'
    got = subprocess.run(["grep", "-oP", pattern], input=sample,
                         capture_output=True, text=True).stdout.strip()
    assert got == "fad5c553", f"pattern extracted {got!r} from a real rule line"


def test_reachability_is_probed_not_inferred():
    """`podman ps` reported Up for the whole outage. The check must open a
    connection."""
    assert "/dev/tcp/" in RENDERED, "nothing actually connects to the published port"


def test_orphan_rules_are_compared_against_live_containers():
    assert "podman ps -a" in RENDERED and "CNI-HOSTPORT-DNAT" in RENDERED


def test_the_alert_cannot_fail_silently():
    """A bare `curl -s` swallows a 403 and exits 0, giving a notification
    channel that reports healthy while delivering nothing (#336, #343, #352)."""
    assert "--fail-with-body" in RENDERED
    assert "Authorization: Bearer" in RENDERED


def test_the_check_runs_between_deploys():
    """A deploy-time check would have passed on 2026-09-01 and told us nothing
    for the six days that followed."""
    cron = _named(PODMAN_TASKS, "Run the podman port health check")
    assert "ansible.builtin.cron" in cron


def test_llama_cpp_liveness_asks_the_model_to_generate():
    """Reading status passes during the outage; only a request fails."""
    gen = _named(LLAMA_TASKS, "Ask the model to actually generate")
    uri = gen["ansible.builtin.uri"]
    assert uri["method"] == "POST"
    assert "chat/completions" in uri["url"]


def test_llama_cpp_failure_stops_the_deploy():
    a = _named(LLAMA_TASKS, "Fail when the model is not actually serving")["ansible.builtin.assert"]
    conditions = " ".join(str(c) for c in a["that"])
    assert "llamacpp_generate.status" in conditions, "the generation result is not asserted"
    assert "llamacpp_models.status" in conditions
