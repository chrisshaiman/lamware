# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""libvirt access control limits cape to what CAPE uses, on its own guests (ADR-027).

Behavioural where it can run here: the real polkit rule is rendered and executed
under node against a mock `polkit` object. It must allow root everything, allow cape
exactly the measured permission set on the configured guests, refuse everyone and
everything else, and never return "no decision" for a libvirt action (libvirt's own
defaults refuse snapshot/start/stop to every caller, root included; that is how task
1312 failed during the spike).

Structural for deploy order and wiring, which no local run reaches. The host
evidence is the role's own allowed/refused probe, run as cape after every change,
and security-test check 19.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[1]
KVM = ROOT / "ansible/roles/kvm"
KVM_DEFAULTS = yaml.safe_load((KVM / "defaults/main.yml").read_text())
KVM_TASKS = yaml.safe_load((KVM / "tasks/main.yml").read_text())
KVM_HANDLERS = yaml.safe_load((KVM / "handlers/main.yml").read_text())
GUESTS = [{"name": "clean", "snapshot": "clean"}, {"name": "office", "snapshot": "office"}]

# Permissions that take a file path or change a domain's definition. cape must
# never get one: each is a way to make libvirtd (root) write where cape says.
PATH_TAKING = {"snapshot", "core-dump", "save", "write", "block-write", "migrate",
               "fs-trim", "start", "init-control", "inject-nmi", "send-input",
               "set-password", "open-device", "open-graphics", "pm-control"}


def _rule() -> str:
    src = (KVM / "templates/49-lamware-libvirt.rules.j2").read_text()
    return Environment(undefined=StrictUndefined).from_string(src).render(
        cape_user="cape", cape_guests=GUESTS, **KVM_DEFAULTS)


HARNESS = r"""
const rules = [];
const polkit = { Result: { YES: "yes", NO: "no" }, addRule: f => rules.push(f),
                 log: () => {}, spawn: () => "" };
eval(require("fs").readFileSync(process.argv[2], "utf8"));
const cases = JSON.parse(require("fs").readFileSync(0, "utf8"));
const out = cases.map(([user, id, dom]) => {
    const action = { id: id, lookup: k => (k === "domain_name" ? dom : undefined) };
    for (const r of rules) { const v = r(action, { user: user }); if (v !== undefined) return v; }
    return "undecided";
});
process.stdout.write(JSON.stringify(out));
"""


@pytest.fixture(scope="module")
def decide(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available; the rule is a polkit JavaScript file")
    d = tmp_path_factory.mktemp("polkit")
    (d / "rule.js").write_text(_rule())
    (d / "harness.js").write_text(HARNESS)

    def run(cases):
        p = subprocess.run([node, str(d / "harness.js"), str(d / "rule.js")],
                           input=json.dumps(cases), capture_output=True, text=True, timeout=30)
        assert p.returncode == 0, p.stderr
        return json.loads(p.stdout)
    return run


A = "org.libvirt.api."


def test_cape_gets_exactly_the_measured_set_on_its_guests(decide):
    allowed = [("cape", A + "connect." + p, None) for p in ("getattr", "search-domains")] + \
              [("cape", A + "domain." + p, g) for p in ("getattr", "read", "screenshot", "stop")
               for g in ("clean", "office")]
    assert decide(allowed) == ["yes"] * len(allowed)


@pytest.mark.parametrize("perm", sorted(PATH_TAKING) + ["read-secure", "delete"])
def test_cape_is_refused_anything_else_on_its_guests(decide, perm):
    assert decide([("cape", A + "domain." + perm, "clean")]) == ["no"]


@pytest.mark.parametrize("case", [
    ("cape", A + "domain.read", "lamware-acl-probe"),        # a domain that is not a guest
    ("cape", A + "domain.read", None),                        # no domain name at all
    ("cape", A + "domain.getattr", "clean "),                 # near-miss name
    ("cape", A + "connect.search-networks", None),
    ("cape", A + "network.write", "detonation"),
    ("cape", A + "storage-pool.write", "default"),
    ("cape", A + "node-device.detach", None),
    ("pipeline", A + "domain.read", "clean"),                 # the world-readable read-only socket
    ("pipeline", A + "connect.getattr", None),
    ("lamware-api", A + "domain.getattr", "office"),
    ("ubuntu", A + "domain.stop", "clean"),
])
def test_everything_else_is_refused(decide, case):
    assert decide([list(case)]) == ["no"]


def test_root_is_allowed_everything(decide):
    """With access control on, root is checked too; no rule for root means libvirt's
    defaults, which refuse snapshot/start/stop."""
    cases = [("root", A + x, "clean") for x in ("domain.snapshot", "domain.start", "domain.write",
                                                  "domain.core-dump", "network.write", "connect.write")]
    assert decide(cases) == ["yes"] * len(cases)


def test_no_libvirt_action_is_left_to_the_defaults(decide):
    users = ["root", "cape", "pipeline", "nobody"]
    perms = ["domain.read", "domain.snapshot", "connect.getattr", "secret.read-secure", "domain.save"]
    cases = [(u, A + p, d) for u in users for p in perms for d in ("clean", "other", None)]
    assert "undecided" not in decide(cases)


def test_actions_outside_libvirt_are_not_touched(decide):
    assert decide([("cape", "org.freedesktop.login1.reboot", None),
                   ("pipeline", "org.freedesktop.systemd1.manage-units", None)]) == ["undecided", "undecided"]


def test_the_cape_permission_lists_take_no_path():
    """The defaults are the policy; this keeps a future edit from slipping one in."""
    perms = set(KVM_DEFAULTS["kvm_libvirt_cape_domain_perms"])
    assert perms == {"getattr", "read", "screenshot", "stop"}
    assert not perms & PATH_TAKING
    assert set(KVM_DEFAULTS["kvm_libvirt_cape_connect_perms"]) == {"getattr", "search-domains"}


# --- deploy order and wiring --------------------------------------------------

def _i(fragment: str) -> int:
    for i, t in enumerate(KVM_TASKS):
        if fragment.lower() in (t.get("name") or "").lower():
            return i
    raise AssertionError(f"no kvm task {fragment!r}")


def _h(fragment: str) -> int:
    for i, t in enumerate(KVM_HANDLERS):
        if fragment.lower() in (t.get("name") or "").lower():
            return i
    raise AssertionError(f"no kvm handler {fragment!r}")


def test_the_rule_is_in_place_before_access_control_is_switched_on():
    assert _i("Install the libvirt access rule") < _i("Switch on libvirt access control")
    assert _i("Remove the audit rule") < _i("Apply pending libvirt and CAPE restarts")


def test_the_restart_is_refused_under_a_running_guest():
    """Handlers with `listen` run in file order: list, refuse, then restart."""
    on = KVM_TASKS[_i("Switch on libvirt access control")]
    assert on["notify"] == "Apply libvirt access control"
    order = [_h("List running guests"), _h("Refuse to restart libvirtd"), _h("Restart libvirtd to apply")]
    assert order == sorted(order)
    for n in ("List running guests", "Refuse to restart libvirtd", "Restart libvirtd to apply"):
        assert KVM_HANDLERS[_h(n)]["listen"] == "Apply libvirt access control"
    guard = KVM_HANDLERS[_h("Refuse to restart libvirtd")]["ansible.builtin.assert"]["that"]
    assert "kvm_running_guests.stdout" in str(guard)


def test_the_role_proves_the_rule_with_an_allowed_and_a_refused_call_as_cape():
    allowed = KVM_TASKS[_i("As cape, list domains")]
    refused = KVM_TASKS[_i("As cape, list networks")]
    for t in (allowed, refused):
        assert t["become_user"] == "{{ cape_user }}"
    assert "rc != 0" in allowed["failed_when"] and "kvm_acl_root_view" in allowed["failed_when"]
    assert "rc == 0" in refused["failed_when"] and "access denied" in refused["failed_when"]
    # The restart is flushed before the probes, so they test the running daemon.
    assert _i("Apply pending libvirt and CAPE restarts") < _i("As root, list domains") < _i("As cape, list domains")
    assert KVM_TASKS[_i("Apply pending libvirt and CAPE restarts")]["ansible.builtin.meta"] == "flush_handlers"


def test_no_task_runs_only_when_something_changed():
    """ansible-lint no-handler: those belong in handlers, which is where they are."""
    bad = [t.get("name") for t in KVM_TASKS if "is changed" in str(t.get("when", ""))]
    assert bad == []


def _user_group_tasks(role: str):
    tasks = yaml.safe_load((ROOT / "ansible/roles" / role / "tasks/main.yml").read_text())
    return [t["ansible.builtin.user"] for t in tasks
            if isinstance(t.get("ansible.builtin.user"), dict)
            and t["ansible.builtin.user"].get("name") == "{{ cape_user }}"]


@pytest.mark.parametrize("role", ["kvm", "qemu-patched"])
def test_no_role_puts_cape_in_kvm(role):
    users = _user_group_tasks(role)
    assert users, f"{role}: no task manages cape's groups"
    for u in users:
        assert "kvm" not in str(u.get("groups", "")).split(","), f"{role} adds cape to kvm"


def test_the_kvm_role_takes_cape_out_of_kvm_and_restarts_capes_services():
    gp = KVM_TASKS[_i("Take cape out of the kvm group")]
    assert gp["ansible.builtin.command"] == "gpasswd -d {{ cape_user }} kvm"
    assert "getent_group.kvm" in gp["when"]
    assert gp["notify"] == "Drop the kvm group from cape's processes"
    rs = KVM_HANDLERS[_h("Restart CAPE and cape's user manager")]
    # cape lingers: its user manager runs from boot and hands kvm to its children.
    assert set(rs["loop"]) == {"cape", "cape-processor", "cape-web",
                               "user@{{ ansible_facts.getent_passwd[cape_user][1] }}.service"}
    assert rs["listen"] == "Drop the kvm group from cape's processes"
    assert _h("Read cape's uid") < _h("Restart CAPE and cape's user manager")


def test_guest_images_are_root_owned_and_private():
    tasks = yaml.safe_load((ROOT / "ansible/roles/cape-guests/tasks/main.yml").read_text())
    d = next(t["ansible.builtin.file"] for t in tasks if t.get("name") == "Ensure guest image directory exists")
    assert (d["owner"], d["group"], d["mode"]) == ("root", "root", "0711")
    s = next(t for t in tasks if "Set guest image ownership" in (t.get("name") or ""))
    assert "chmod 0600" in s["ansible.builtin.shell"]


def test_qemu_patched_and_cape_guests_agree_on_the_image_directory():
    """They flipped it 0755/0711 on every deploy; whichever ran last won."""
    tasks = yaml.safe_load((ROOT / "ansible/roles/qemu-patched/tasks/main.yml").read_text())
    t = next(t for t in tasks if (t.get("name") or "").startswith("Fix libvirt directory permissions"))
    modes = {i["path"]: i["mode"] for i in t["loop"]}
    assert modes["/var/lib/libvirt/images"] == "0711"
