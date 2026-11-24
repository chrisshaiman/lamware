# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""lamware-container: podman's profile plus upstream's stacked-peer fix, nothing else (ADR-032).

The drift test renders the vendored containers/common v0.57.4 template (the one
noble's podman 4.9.3 embeds) with our name, adds exactly the lines of
container-libs PR #919, and requires our profile to match line for line. So the
copy cannot quietly diverge from what upstream reviewed. Security-test check 26's
own shell block is run against stub podman/systemctl and fake label files.
"""
from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible/roles/podman"
PROFILE = (ROLE / "files/lamware-container").read_text()
TEMPLATE_GO = ROOT / "tests/fixtures/containers-common-v0.57.4-apparmor_linux_template.go.txt"
TASKS = yaml.safe_load((ROLE / "tasks/main.yml").read_text())
NAME = "lamware-container"
PR919 = {  # inserted after the line in the key, verbatim from the merged PR
    "signal (send,receive) peer={name},": [
        "# With AppArmor 5.0+, child processes get a stacked profile.",
        "signal (send,receive) peer={name}//&*,"],
    "ptrace (trace,read) peer={name},": [
        "# With AppArmor 5.0+, child processes get a stacked profile.",
        "ptrace (trace,read) peer={name}//&*,"],
}


def _norm(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _render_upstream(name: str) -> list[str]:
    src = TEMPLATE_GO.read_text()
    body = src[src.index("defaultProfileTemplate = `") + len("defaultProfileTemplate = `"):]
    body = body[:body.index("`")]
    # podman's defaults: Imports = tunables/global, InnerImports = abstractions/base.
    body = re.sub(r"\{\{range \$value := \.Imports\}\}\s*\{\{\$value\}\}\s*\{\{end\}\}",
                  "#include <tunables/global>", body)
    body = re.sub(r"\{\{range \$value := \.InnerImports\}\}\s*\{\{\$value\}\}\s*\{\{end\}\}",
                  "#include <abstractions/base>", body)
    body = re.sub(r"\{\{if ge \.Version \d+\}\}|\{\{end\}\}", "", body)  # AppArmor 4.0.1 >= both gates
    body = body.replace("{{.Name}}", name)
    assert "{{" not in body, body
    out = []
    for ln in _norm(body):
        out.append(ln)
        for anchor, extra in PR919.items():
            if ln == anchor.format(name=name):
                out.extend(e.format(name=name) for e in extra)
    return out


def test_the_vendored_template_is_the_one_podman_4_9_3_embeds():
    digest = hashlib.sha256(TEMPLATE_GO.read_bytes()).hexdigest()
    assert digest == "6bb0364148a7d039762bd698aeb99f89d641cca945cf0335bdd772551b0091f6"


def test_the_profile_is_the_upstream_template_plus_pr_919_only():
    ours = _norm(PROFILE)
    # Our header is comment lines above the first #include; everything after must match.
    ours = ours[ours.index("#include <tunables/global>"):]
    assert ours == _render_upstream(NAME)


def test_the_drift_test_catches_an_extra_rule():
    """Guards the guard: a one-line change must not survive the comparison."""
    ours = _norm(PROFILE.replace("  umount,\n", "  umount,\n  mount,\n"))
    ours = ours[ours.index("#include <tunables/global>"):]
    assert ours != _render_upstream(NAME)


def test_only_the_stacked_rules_are_added():
    added = [ln for ln in _norm(PROFILE) if "//&" in ln and not ln.startswith("#")]
    assert added == [f"signal (send,receive) peer={NAME}//&*,", f"ptrace (trace,read) peer={NAME}//&*,"]


# --- the role -------------------------------------------------------------------------

def _task(name):
    return next(t for t in TASKS if isinstance(t, dict) and t.get("name") == name)


def test_root_podmans_default_is_lamware_container_and_rootless_can_read_the_config():
    d = _task("Create podman's system configuration drop-in directory")["ansible.builtin.file"]
    assert (d["path"], d["mode"]) == ("/etc/containers/containers.conf.d", "0755")
    c = _task("Make lamware-container root podman's default AppArmor profile")
    body = c["ansible.builtin.copy"]
    assert body["mode"] == "0644"
    assert re.search(r'^\[containers\]\napparmor_profile = "lamware-container"$', body["content"], re.M)
    assert c["notify"] == "Restart root containers"


def test_the_profile_is_installed_loaded_and_restarts_the_root_containers():
    inst = _task("Install the lamware-container AppArmor profile")
    assert inst["ansible.builtin.copy"]["dest"] == "/etc/apparmor.d/lamware-container"
    assert inst["notify"] == "Restart root containers"
    load = _task("Load the lamware-container profile into the kernel")
    assert load["ansible.builtin.command"] == "apparmor_parser -r -W /etc/apparmor.d/lamware-container"
    assert "'lamware-container (enforce)' not in podman_aa_loaded.stdout_lines" in load["when"]
    handlers = yaml.safe_load((ROLE / "handlers/main.yml").read_text())
    h = next(x for x in handlers if x["name"] == "Restart root containers")
    assert set(h["ansible.builtin.command"].split()[2:]) == {"litellm.service", "llama-cpp.service", "keycloak.service"}


def test_the_deploy_probe_requires_the_profile_and_a_delivered_signal():
    p = _task("Prove a root container gets the profile and can signal its own child")
    fw = p["failed_when"]
    assert "search('^lamware-container')" in fw and "'signal-delivered' not in" in fw


# --- check 26, run for real ---------------------------------------------------------

SMOKE = (ROOT / "ansible/roles/security-test/templates/security-smoke-test.sh.j2").read_text()


def _check26() -> str:
    env = jinja2.Environment()  # noqa: S701 - shell, not HTML
    env.filters["bool"] = bool
    out = env.from_string(SMOKE).render()
    return out[out.index('echo "[26/27]'):out.index('echo "[27/27]')]


def _run26(tmp: Path, *, loaded=True, labels=("lamware-container//&unconfined (enforce)",) * 3,
           ours="lamware-container//&unconfined (enforce)\ndelivered", upstream="", version="4.9.3") -> str:
    bindir = tmp / "bin"
    bindir.mkdir()
    procdir = tmp / "proc"
    procdir.mkdir()
    names = [f"c{i}" for i in range(len(labels))]
    for i, lbl in enumerate(labels):
        (procdir / str(100 + i)).write_text(lbl + "\n")
    (tmp / "profiles").write_text(("lamware-container (enforce)\n" if loaded else "") + "other (enforce)\n")
    (tmp / "ours").write_text(ours)
    (tmp / "up").write_text(upstream)
    inspect = "\n".join(f'  {n}) echo {100 + i} ;;' for i, n in enumerate(names))
    (bindir / "podman").write_text(f"""#!/bin/bash
case "$1" in
  ps) printf '%s\\n' {' '.join(names)} ;;
  inspect) case "${{@: -1}}" in
{inspect}
  esac ;;
  version) echo {version} ;;
  run) if [[ " $* " == *" --security-opt "* ]]; then cat {tmp}/up; else cat {tmp}/ours; fi ;;
esac
""")
    (bindir / "systemctl").write_text("#!/bin/bash\necho 'path=/usr/bin/podman ; argv[]=/usr/bin/podman run ghcr.io/x/y@sha256:1 ;'\n")
    for f in bindir.iterdir():
        f.chmod(0o755)
    body = (_check26().replace("/sys/kernel/security/apparmor/profiles", str(tmp / "profiles"))
            .replace('"/proc/$pid/attr/current"', f'"{procdir}/$pid"'))
    script = 'pass() { echo "PASS: $1"; }\nfail() { echo "FAIL: $1"; }\n' + body
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": f"{bindir}:/usr/bin:/bin"}).stdout


def test_check26_passes_and_says_whether_the_copy_is_still_needed(tmp_path):
    out = _run26(tmp_path)
    assert "PASS: root containers: 3 under lamware-container" in out, out
    assert "podman's own profile refuses them" in out


def test_check26_notes_when_podmans_own_profile_works(tmp_path):
    out = _run26(tmp_path, upstream="delivered")
    assert "PASS" in out and "podman's own profile also delivers signals" in out, out


@pytest.mark.parametrize("kw, want", [
    ({"loaded": False}, "profile is not loaded"),
    ({"labels": ()}, "probe is blind"),
    ({"labels": ("lamware-container (enforce)", "containers-default-0.57.4-apparmor1//&unconfined (enforce)")},
     "not under lamware-container: c1:[containers-default"),
    ({"ours": "lamware-container//&unconfined (enforce)\nsh: can't kill"}, "cannot signal its own child"),
    ({"ours": "containers-default-0.57.4-apparmor1 (enforce)\ndelivered"}, "cannot signal its own child"),
    ({"version": "5.4.0"}, "podman is 5.4.0, but lamware-container was copied from 4.9.3"),
])
def test_check26_fails_each_way_it_should(tmp_path, kw, want):
    out = _run26(tmp_path, **kw)
    assert "FAIL" in out and want in out, out


def test_the_restart_waits_for_all_three_services_before_the_play_moves_on():
    """The first deploy restarted Keycloak and the security test probed it mid-start."""
    handlers = yaml.safe_load((ROLE / "handlers/main.yml").read_text())
    names = [h["name"] for h in handlers]
    wait = next(h for h in handlers if h.get("listen") == "Restart root containers")
    assert names.index("Restart root containers") < names.index(wait["name"])
    urls = " ".join(wait["loop"])
    for frag in ("/health/liveliness", "llamacpp_port", "/auth/health/ready"):
        assert frag in urls, frag
    assert wait["until"] == "podman_root_ready.status == 200" and wait["retries"] * wait["delay"] >= 120
