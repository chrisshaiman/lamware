# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pipeline user runs its images from a store it cannot write (ADR-025 phase 3).

Behavioural where something can run here: the `lamware-podman` helper is rendered
and executed against a recording podman stub (it must refuse to run without the
read-only store, and otherwise hand podman a throwaway graph root, the read-only
store as an additional image store, and an empty config directory, then remove
the throwaway store).

Structural for the rest, because it is deploy wiring no local run reaches (the
host evidence is security-test check 18 and the helper's own `close` probe):
every place the pipeline user starts a container goes through the helper; every
pipeline podman call in the shared build pins the protected store; the build is
always followed by `close`; the role runs before any image is built; check 18's
image list is exactly the set of images the roles build.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible/roles"
ROLE = ROLES / "image-store"
SHARED = ROLES / "build-fetch/tasks"
DEFAULTS = yaml.safe_load((ROLE / "defaults/main.yml").read_text())


def _resolved_defaults(**over) -> dict:
    data = {**DEFAULTS, **over}
    env = Environment(undefined=StrictUndefined)
    for _ in range(4):
        data = {k: env.from_string(v).render(**data) if isinstance(v, str) else v
                for k, v in data.items()}
    return data


def _render(template: str, **over) -> str:
    src = (ROLE / "templates" / template).read_text()
    return Environment(undefined=StrictUndefined, keep_trailing_newline=True) \
        .from_string(src).render(**_resolved_defaults(**over))


# --------------------------------------------------------------------------
# lamware-podman, executed
# --------------------------------------------------------------------------

STUB = r'''#!/bin/bash
python3 - "$@" <<'PY'
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps({"argv": sys.argv[1:],
                        "xdg": os.environ.get("XDG_CONFIG_HOME"),
                        "xdg_listing": sorted(os.listdir(os.environ["XDG_CONFIG_HOME"]))
                        if os.path.isdir(os.environ.get("XDG_CONFIG_HOME", "")) else None}) + "\n")
argv = sys.argv[1:]
if argv[:1] == ["unshare"]:      # podman unshare runs its command
    import subprocess; subprocess.run(argv[1:])
PY
'''


def _run_helper(tmp_path: Path, *, store_present: bool) -> tuple[subprocess.CompletedProcess, list[dict], Path]:
    ro = tmp_path / "ro"
    ro.mkdir()
    if store_present:
        (ro / "overlay-images").mkdir()
    helper = tmp_path / "lamware-podman"
    helper.write_text(_render("lamware-podman.sh.j2", image_store_ro=str(ro)))
    helper.chmod(0o755)
    stub = tmp_path / "podman"
    stub.write_text(STUB)
    stub.chmod(0o755)
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    log = tmp_path / "log"
    proc = subprocess.run(
        [str(helper), "run", "--rm", "localhost/triage:latest"],
        env={**os.environ, "LAMWARE_PODMAN_BIN": str(stub), "STUB_LOG": str(log),
             "TMPDIR": str(tmpdir), "XDG_CONFIG_HOME": str(tmp_path / "users-own-config")},
        capture_output=True, text=True, timeout=30)
    calls = [json.loads(ln) for ln in log.read_text().splitlines()] if log.exists() else []
    return proc, calls, tmpdir


@pytest.fixture(autouse=False)
def _needs_bash():
    if not shutil.which("bash") or not shutil.which("python3"):
        pytest.skip("bash/python3 not available")


def test_the_helper_refuses_to_run_without_the_read_only_store(tmp_path, _needs_bash):
    """Falling back to the user's own (writable) store would undo the whole change
    silently, so a missing store is an error and podman is never called."""
    proc, calls, _ = _run_helper(tmp_path, store_present=False)
    assert proc.returncode == 125, proc.stderr
    assert calls == []
    assert "not mounted" in proc.stderr


def test_the_helper_runs_from_a_throwaway_store_with_the_read_only_one_added(tmp_path, _needs_bash):
    proc, calls, tmpdir = _run_helper(tmp_path, store_present=True)
    assert proc.returncode == 0, proc.stderr
    run = [c for c in calls if "run" in c["argv"]]
    assert len(run) == 1, calls
    argv = run[0]["argv"]
    opts = dict(zip(argv[0::2], argv[1::2]))
    work = Path(opts["--root"]).parent
    assert work.parent == tmpdir and opts["--runroot"] == str(work / "run")
    assert opts["--storage-driver"] == "overlay"
    assert opts["--storage-opt"] == f"additionalimagestore={tmp_path / 'ro'}"
    # The caller's arguments arrive unchanged, after the store options.
    assert argv[-3:] == ["run", "--rm", "localhost/triage:latest"]
    # Not the user's own config directory, and an empty one.
    assert run[0]["xdg"] == str(work / "config") and run[0]["xdg_listing"] == []
    # The throwaway store is removed (through podman unshare, then plainly).
    assert any(c["argv"][:3] == ["unshare", "rm", "-rf"] for c in calls), calls
    assert list(tmpdir.iterdir()) == []


def test_the_rendered_helpers_parse():
    for t in ("lamware-podman.sh.j2", "lamware-image-store.sh.j2"):
        subprocess.run(["bash", "-n"], input=_render(t), text=True, check=True)


# --------------------------------------------------------------------------
# Every container the pipeline user starts goes through the helper
# --------------------------------------------------------------------------

HELPER = "{{ image_store_lib_dir | default('/usr/local/lib/lamware') }}/lamware-podman"
# Anywhere on a non-comment line, including inside $( ... ), except a quoted
# glob such as network-monitor's 'podman run --rm*' allowlist entry (a pattern it
# matches process lines against, not a container it starts). The helper's own
# path ends in "lamware-podman", which the lookbehind excludes.
_PLAIN = re.compile(r"(?<![\w'-])podman[ \t]+(run|image[ \t]+exists|images|create|start)\b")
_VIA_HELPER = re.compile(re.escape(HELPER) + r"[ \t]+(run|image[ \t]+exists|images)\b")


def _plain_podman(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines()
            if not ln.lstrip().startswith("#") and _PLAIN.search(ln)]


def _root_service(p: Path) -> bool:
    """A systemd unit with no User= runs as root, with root's own podman and
    store (keycloak, litellm, llama-cpp): not the pipeline user's images."""
    text = p.read_text()
    return p.name.endswith(".service.j2") and not re.search(r"^User=", text, re.M)


def test_no_template_starts_a_container_with_plain_podman():
    bad = {p.relative_to(ROLES).as_posix(): hits
           for p in sorted(ROLES.glob("*/templates/*.j2"))
           if not _root_service(p) and (hits := _plain_podman(p.read_text()))}
    assert bad == {}
    # The exemption covers exactly the root services, not a pipeline unit.
    exempt = sorted(p.parent.parent.name for p in ROLES.glob("*/templates/*.j2")
                    if _root_service(p) and _plain_podman(p.read_text()))
    assert exempt == ["keycloak", "litellm", "llama-cpp"], exempt


def test_the_wrappers_were_found_through_the_helper():
    """Guards the guard above: if the helper spelling changed, nothing would be
    'plain podman' and nothing would be checked."""
    users = {p.name for p in ROLES.glob("*/templates/*.j2") if _VIA_HELPER.search(p.read_text())}
    assert len(users) >= 16, sorted(users)
    for name in ("run-triage-wrapper.sh.j2", "run-ghidra-wrapper.sh.j2", "run-sandbox.sh.j2",
                 "run-dotnet-tools.sh.j2", "run-prompt-ab.sh.j2", "security-smoke-test.sh.j2"):
        assert name in users, name


@pytest.mark.parametrize("text", [
    "podman run --rm x\n",
    "  head -c 5 | podman run -i x\n",
    "if ! podman image exists x; then\n",
    'SUBUID=$(cd / && sudo -u "$U" timeout 60 podman run --rm x)\n',
    "exec /usr/bin/podman run x\n",
])
def test_the_plain_podman_detector_catches_a_regression(text):
    assert _plain_podman(text), text


@pytest.mark.parametrize("text", [
    "    'podman run --rm*'\n",
    "# podman run in a comment\n",
    HELPER + " run --rm x\n",
])
def test_the_plain_podman_detector_passes_what_is_not_a_plain_call(text):
    assert not _plain_podman(text), text


def _walk(tasks):
    for t in tasks or []:
        if isinstance(t, dict):
            yield t
            for k in ("block", "rescue", "always"):
                yield from _walk(t.get(k))


def _cmd(t: dict) -> str:
    for mod in ("ansible.builtin.command", "ansible.builtin.shell"):
        body = t.get(mod)
        if body is not None:
            return str(body.get("cmd") if isinstance(body, dict) else body)
    return ""


def test_every_pipeline_podman_task_uses_a_pinned_store():
    """A task that runs podman as the pipeline user either builds into the
    protected store (shared build: hb_pipeline_podman plus its config directory)
    or runs from it (the helper)."""
    seen = 0
    for f in sorted(ROLES.glob("*/tasks/*.yml")):
        for t in _walk(yaml.safe_load(f.read_text())):
            cmd = _cmd(t)
            if t.get("become_user") != "pipeline" or "podman" not in cmd:
                continue
            if re.search(r"\bpodman\s+(--version|unshare|system\s+migrate)\b", cmd):
                continue
            seen += 1
            where = f"{f.relative_to(ROLES)}: {t.get('name')}"
            if "{{ hb_pipeline_podman }}" in cmd:
                assert t.get("environment") == "{{ hb_pipeline_env }}", where
            else:
                assert HELPER in cmd, where
    assert seen == 10, seen


def test_the_shared_build_pins_the_protected_store():
    d = yaml.safe_load((ROLES / "build-fetch/defaults/main.yml").read_text())
    assert d["hb_pipeline_podman"].startswith("podman --root {{ hb_store_graph }} ")
    assert "--runroot {{ hb_store_sealed }}/build-run" in d["hb_pipeline_podman"]
    assert d["hb_pipeline_env"] == {"XDG_CONFIG_HOME": "{{ hb_store_sealed }}/build-config"}
    # The defaults the role resolves to are the image-store role's.
    assert "image_store_graph" in d["hb_store_graph"]
    assert "image_store_sealed_dir" in d["hb_store_sealed"]
    # ...and the role creates both directories for the user.
    paths = [i["path"] for t in _walk(yaml.safe_load((ROLE / "tasks/main.yml").read_text()))
             for i in (t.get("loop") or []) if isinstance(i, dict) and "path" in i]
    for sub in ("build-run", "build-config"):
        assert "{{ image_store_sealed_dir }}/" + sub in paths, sub


def test_every_build_is_followed_by_close():
    tasks = yaml.safe_load((SHARED / "image.yml").read_text())
    cmds = [_cmd(t) for t in tasks]
    assert cmds[0].endswith("/lamware-image-store open")
    (blk,) = [t for t in tasks if "block" in t]
    assert [b.get("ansible.builtin.include_tasks") for b in blk["block"]] == ["image_build.yml"]
    assert [_cmd(a) for a in blk["always"]] == [cmds[0].replace(" open", " close")]
    # Nothing builds outside that block.
    assert not any("podman" in c for c in cmds)


# --------------------------------------------------------------------------
# The role: mount, seal, order
# --------------------------------------------------------------------------

def test_the_store_is_under_a_root_only_parent_and_mounted_read_only():
    d = _resolved_defaults()
    assert Path(d["image_store_graph"]).parent == Path(d["image_store_sealed_dir"])
    assert not Path(d["image_store_ro"]).is_relative_to(d["image_store_sealed_dir"])
    loop = next(t["loop"] for t in _walk(yaml.safe_load((ROLE / "tasks/main.yml").read_text()))
                if t.get("name") == "Create the image store directories")
    sealed = next(i for i in loop if i["path"] == "{{ image_store_sealed_dir }}")
    assert (sealed["owner"], sealed["mode"]) == ("root", "0700")
    mount = _render("image-store.mount.j2", **UNITS)
    opts = dict(ln.split("=", 1) for ln in mount.splitlines() if "=" in ln and not ln.startswith("#"))
    assert opts["What"] == d["image_store_graph"] and opts["Where"] == d["image_store_ro"]
    assert set(opts["Options"].split(",")) == {"bind", "ro"}
    # systemd orders a local mount before local-fs.target on its own; ordering it
    # after as well is a cycle (it was in the first version; systemd-analyze
    # verify on the host found it).
    assert "local-fs.target" not in _unit_deps(mount).get("After", set())


UNITS = {"image_store_ro_unit": "x.mount", "image_store_user_manager": "user@997.service"}


def _unit_deps(text: str) -> dict[str, set[str]]:
    """Unit-section dependency directives, each a set of unit names."""
    deps: dict[str, set[str]] = {}
    for ln in text.splitlines():
        if "=" in ln and not ln.startswith("#"):
            k, v = ln.split("=", 1)
            if k in ("Wants", "Requires", "After", "Before"):
                deps.setdefault(k, set()).update(v.split())
    return deps


def test_the_seal_runs_at_boot_before_the_pipeline_can_start():
    unit = _render("lamware-image-store-seal.service.j2", **UNITS)
    d = _unit_deps(unit)
    assert {"x.mount"} <= d["Requires"] and {"x.mount", "user@997.service"} <= d["After"]
    # Wants pulls the lingering user's manager into the boot transaction; without
    # it logind starts the manager as a separate job and After= orders nothing.
    assert "user@997.service" in d["Wants"]
    assert "pipeline-spool.service" in d["Before"]
    assert re.search(r"^ExecStart=\S+/lamware-image-store close$", unit, re.M)


def test_the_pipeline_users_manager_waits_for_the_read_only_mount():
    """A podman namespace that predates the read-only mount keeps a writable view
    of the store; the lingering user's manager is what starts podman at boot."""
    d = _unit_deps(_render("user-manager-after-mount.conf.j2", **UNITS))
    assert d == {"Wants": {"x.mount"}, "After": {"x.mount"}}
    tasks = list(_walk(yaml.safe_load((ROLE / "tasks/main.yml").read_text())))
    dest = next(t["ansible.builtin.template"]["dest"] for t in tasks
                if (t.get("ansible.builtin.template") or {}).get("src") == "user-manager-after-mount.conf.j2")
    assert dest == "/etc/systemd/system/{{ image_store_user_manager }}.d/lamware-image-store.conf"
    fact = next(t["ansible.builtin.set_fact"] for t in tasks
                if "image_store_user_manager" in (t.get("ansible.builtin.set_fact") or {}))
    assert fact["image_store_user_manager"].startswith("user@{{ ansible_facts.getent_passwd[image_store_user][1] }}")


# Path, socket and timer units order themselves before paths/sockets/timers.target,
# which come before basic.target; a user manager comes after basic.target. A unit
# both after the manager and before one of those is an ordering cycle, which
# systemd breaks at boot by dropping a job of its choosing (the first draft of
# this ordering had exactly that: Before=pipeline-spool.path).
EARLY = (".path", ".socket", ".timer")


def _cycle(deps: dict[str, set[str]]) -> list[str]:
    if not any(u.startswith("user@") for u in deps.get("After", ())):
        return []
    return sorted(u for u in deps.get("Before", ()) if u.endswith(EARLY))


def test_the_seal_ordering_has_no_cycle_through_basic_target():
    assert _cycle(_unit_deps(_render("lamware-image-store-seal.service.j2", **UNITS))) == []


def test_the_cycle_check_catches_the_first_draft():
    assert _cycle({"After": {"user@997.service"}, "Before": {"pipeline-spool.path"}}) == ["pipeline-spool.path"]


def test_close_restarts_the_namespace_then_probes_with_a_control():
    """The order is the finding: a namespace that predates the read-only mount
    keeps a writable view, and a probe without a control reads 'sealed' when
    podman unshare itself is broken."""
    text = _render("lamware-image-store.sh.j2")
    close = text[text.index("  close)"):text.index("  status)")]
    order = [close.index(s) for s in ('chmod 0700 "$SEALED"', "podman system migrate", "probe_writable")]
    assert order == sorted(order)
    probe = text[text.index("probe_writable() {"):text.index("\n}\n", text.index("probe_writable() {"))]
    assert probe.index("$ctl/probe") < probe.index('for d in "$RO" "$GRAPH"')
    assert "podman unshare" in probe.split('for d in "$RO" "$GRAPH"')[1]


def _site_roles() -> list[str]:
    plays = yaml.safe_load((ROOT / "ansible/site.yml").read_text())
    return [r["role"] if isinstance(r, dict) else r for p in plays for r in p.get("roles", [])]


def _image_building_roles() -> set[str]:
    out = set()
    for f in ROLES.glob("*/tasks/main.yml"):
        for t in _walk(yaml.safe_load(f.read_text())):
            inc = t.get("ansible.builtin.include_role") or {}
            if inc.get("name") == "build-fetch" and inc.get("tasks_from") == "image":
                out.add(f.parent.parent.name)
    return out


def test_the_role_runs_before_every_role_that_builds_an_image():
    roles = _site_roles()
    builders = _image_building_roles()
    assert len(builders) == 14, sorted(builders)
    first = min(roles.index(r) for r in builders)
    assert "image-store" in roles and roles.index("image-store") < first


def test_check_18_requires_exactly_the_images_the_roles_build():
    tags = set()
    for f in ROLES.glob("*/tasks/main.yml"):
        for t in _walk(yaml.safe_load(f.read_text())):
            v = t.get("vars") or {}
            if "hb_tag" in v:
                tags.add(v["hb_tag"])
    listed = yaml.safe_load((ROLES / "security-test/defaults/main.yml").read_text())[
        "security_test_pipeline_images"]
    assert len(tags) == 14 and sorted(listed) == sorted(tags)
