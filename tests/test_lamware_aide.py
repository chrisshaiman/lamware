# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""lamware-aide must make AIDE's result reach someone, and keep its baseline current.

The nightly check compared against a baseline from April, failed every night with
about a million differences, and nobody read it. These tests run the real script
with a fake `aide` and a fake alert queue: an unexpected difference must alert and
keep the baseline, expected ones (a detonation, a reboot, ADR-035) must be absorbed
quietly from the same scan, a report that cannot be classified must fail closed, an
error must alert as a failure, and a rebaseline must swap the databases only when
AIDE produced a new one. The expected-differences rules are tested as shipped,
against entries from the host's real reports. The host evidence (a rebaseline and
a check on the sandbox) is in the PR; this is what CI can observe.
"""
import importlib.util
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FILES = ROOT / "ansible" / "roles" / "hardening" / "files"

spec = importlib.util.spec_from_file_location("lamware_aide", FILES / "lamware-aide.py")
aide = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aide)

REPORT = """Start timestamp: 2026-10-26 00:00:01 -0700 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:\t1069382
  Added entries:\t\t3
  Removed entries:\t\t1
  Changed entries:\t\t1

---------------------------------------------------
Added entries:
---------------------------------------------------

f++++++++++++++++: /usr/local/bin/implant
f++++++++++++++++: /usr/local/bin/implant2
d++++++++++++++++: /etc/cron.d/x
---------------------------------------------------
Removed entries:
---------------------------------------------------

f----------------: /etc/sudoers.d/old
---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /usr/bin/sudo
"""


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fake aide (rc and output per test), a captured alert queue, temp databases."""
    state = {"rc": 0, "out": "", "alerts": [], "argv": [], "writes_new": True, "chown": []}
    db, new, prev = tmp_path / "aide.db", tmp_path / "aide.db.new", tmp_path / "aide.db.prev"
    db.write_text("OLD")
    monkeypatch.setattr(aide, "DB", str(db))
    monkeypatch.setattr(aide, "DB_NEW", str(new))
    monkeypatch.setattr(aide, "DB_PREV", str(prev))
    monkeypatch.setattr(aide, "LOCK", str(tmp_path / "lock"))
    monkeypatch.setattr(aide, "REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(aide, "EXPECTED", str(FILES / "expected-differences.conf"))
    monkeypatch.setattr(aide.os, "chown", lambda path, uid, gid: state["chown"].append((path, uid, gid)))

    def fake_run(argv, **kw):
        if argv[1] == aide.ENQUEUE:
            state["alerts"].append({"title": argv[2], "message": argv[3], "priority": argv[5]})
            return subprocess.CompletedProcess(argv, 0, "", "")
        state["argv"].append(argv)
        if "--update" in argv and state["writes_new"]:
            new.write_text("NEW")
        return subprocess.CompletedProcess(argv, state["rc"], state["out"], "")

    monkeypatch.setattr(aide.subprocess, "run", fake_run)
    state.update(db=db, new=new, prev=prev, reports=tmp_path / "reports")
    return state


def test_summary_counts_and_directories():
    s = aide.summarize(REPORT)
    assert (s["added"], s["removed"], s["changed"], s["total"]) == (3, 1, 1, 1069382)
    assert dict(s["top_dirs"])["/usr/local/bin"] == 2


def test_a_clean_check_sends_nothing_and_keeps_the_baseline(env):
    env["rc"] = 0
    assert aide.main(["check"]) == 0
    assert env["alerts"] == []
    # One scan that both compares and writes a new database (ADR-035).
    assert env["argv"][0][:2] == [aide.AIDE, "--update"]
    assert env["db"].read_text() == "OLD" and not env["new"].exists()


def test_an_unexpected_difference_alerts_high_names_it_and_keeps_the_baseline(env):
    env["rc"], env["out"] = 7, REPORT
    assert aide.main(["check"]) == 7          # the unit still shows failed
    [a] = env["alerts"]
    assert a["priority"] == "high" and a["title"] == "AIDE: 5 unexpected differences since the baseline"
    for p in ("/usr/local/bin/implant", "/etc/sudoers.d/old", "/usr/bin/sudo"):
        assert p in a["message"]
    assert env["db"].read_text() == "OLD" and not env["new"].exists()
    assert not env["prev"].exists()


def test_an_aide_error_alerts_as_a_failure(env):
    env["rc"] = 17
    assert aide.main(["check"]) == 17
    [a] = env["alerts"]
    assert a["title"] == "AIDE check failed" and a["priority"] == "high"
    assert env["db"].read_text() == "OLD" and not env["new"].exists()


def test_rebaseline_reports_what_it_absorbs_then_swaps(env):
    env["rc"], env["out"] = 4, REPORT
    assert aide.main(["rebaseline", "--reason", "a deploy"]) == 0
    assert env["argv"][0][:2] == [aide.AIDE, "--update"]
    assert env["db"].read_text() == "NEW" and env["prev"].read_text() == "OLD"
    assert not env["new"].exists()
    assert env["chown"] == [(str(env["db"]), 0, 0)]   # the owner AIDE records next time
    assert env["db"].stat().st_mode & 0o777 == 0o600
    [a] = env["alerts"]
    assert a["priority"] == "low" and "3 added" in a["message"]


def test_rebaseline_keeps_the_old_baseline_when_aide_wrote_nothing(env):
    env["rc"], env["writes_new"] = 17, False
    assert aide.main(["rebaseline"]) != 0
    assert env["db"].read_text() == "OLD"
    assert env["alerts"][0]["title"] == "AIDE baseline NOT renewed"


def test_the_full_report_goes_to_a_file_and_the_journal_gets_the_summary(env, capsys):
    env["rc"], env["out"] = 7, REPORT
    aide.main(["check"])
    [report] = env["reports"].iterdir()
    assert report.read_text() == REPORT
    assert report.stat().st_mode & 0o777 == 0o600
    journal = capsys.readouterr().out
    assert "3 added, 1 removed, 1 changed" in journal and str(report) in journal
    assert "/usr/local/bin/implant2" not in journal   # entries are not journalled
    assert str(report) in env["alerts"][0]["message"]


def test_rebaseline_alert_names_the_report_file(env):
    env["rc"], env["out"] = 4, REPORT
    aide.main(["rebaseline"])
    [report] = env["reports"].iterdir()
    assert str(report) in env["alerts"][0]["message"]


def test_old_reports_are_pruned_to_the_newest(env, monkeypatch):
    env["reports"].mkdir(mode=0o700)
    for i in range(aide.REPORTS_KEPT + 5):
        f = env["reports"] / f"check-old{i:02d}.txt"
        f.write_text("x")
        os.utime(f, (1000 + i, 1000 + i))
    aide.main(["check"])
    names = sorted(p.name for p in env["reports"].iterdir())
    assert len(names) == aide.REPORTS_KEPT
    assert "check-old00.txt" not in names and "check-old34.txt" in names
    assert any(not n.startswith("check-old") for n in names)   # tonight's survived


# --- exclusions: data out, code in ------------------------------------------------
RULES = [re.compile(line[1:]) for line in
         (FILES / "99_lamware_exclusions").read_text().splitlines()
         if line.startswith("!")]


def _excluded(path: str) -> bool:
    # AIDE matches rule regexes anchored at the start of the path.
    return any(r.match(path) for r in RULES)


@pytest.mark.parametrize("path", [
    "/home/pipeline/.local/share/containers/storage/overlay/x",
    "/var/lib/containers/storage/x", "/opt/CAPEv2/storage/analyses/1/binary",
    "/opt/pipeline/reports/abc/report.json", "/data/db/collection-1.wt",
    "/home/cape/.cache/pip/x", "/var/lib/postgresql/16/main/base/1",
    "/var/lib/lamware-aide/reports", "/var/lib/lamware-aide/reports/check-20261026T070000Z.txt",
    # runtime churn measured in a check 7 minutes after a rebaseline
    "/run/user/1000/gnupg/S.keyboxd", "/run/systemd/journal/streams/10:5071847",
    "/tmp/user/0/nuclei906522728/LOG", "/home/ubuntu/.ansible/tmp/ansible-tmp-1/AnsiballZ_command.py",
    "/var/lib/nginx/proxy/7/01", "/var/spool/lamware-notify", "/var/lib/aide/aide.db.new",
    "/var/lib/aide/aide.db.prev", "/etc/suricata/rules/suricata.rules",
    "/opt/network-monitor/status.json", "/var/log/inetsim/service.log",
    # what merge-check's security-test leaves behind
    "/opt/security-test/results/nuclei-20261025-220229.txt", "/root/.cache/nuclei/index.gob",
    "/root/.config/nuclei/.templates-config.json",
    # daily housekeeping, measured in the first real night's check
    "/var/cache/apt-show-versions/apackages-multiarch",
    "/var/lib/systemd/timers/stamp-fwupd-refresh.timer",
    # scheduled jobs' state, from the nightly checks of 2026-10-27 to 11-04
    "/var/lib/apt/lists/security.ubuntu.com_ubuntu_dists_noble-security_InRelease",
    "/var/cache/apt/pkgcache.bin", "/var/cache/apt/archives/linux-image-7.0.0-42-generic.deb",
    "/var/lib/apt/periodic/upgrade-stamp", "/var/lib/PackageKit/transactions.db",
    "/var/lib/update-notifier/updates-available", "/var/cache/swcatalog/cache/en-US-os-catalog.xb",
    "/var/lib/swcatalog/yaml", "/var/cache/fwupd/devices.json",
    "/var/lib/fwupd/metadata/lvfs/firmware.xml.zst", "/run/motd.d/85-fwupd",
    "/var/lib/letsencrypt/.certbot.lock", "/var/cache/man/oldlocal/CACHEDIR.TAG",
    # the first week after that deploy (2026-11-07, 11-08)
    "/var/lib/ubuntu-release-upgrader/release-upgrade-available",
    "/var/lib/rkhunter/db/rkhunter_prop_list.dat",
])
def test_churning_data_is_excluded(path):
    assert _excluded(path)


@pytest.mark.parametrize("path", [
    "/opt/pipeline/venv/bin/python", "/opt/pipeline/run-pipeline.py", "/usr/bin/sudo",
    "/etc/passwd", "/etc/sudoers.d/x", "/home/cape/.ssh/authorized_keys",
    "/home/pipeline/.bashrc", "/home/pipeline/.local/bin/x", "/opt/CAPEv2/conf/cuckoo.conf",
    "/usr/local/sbin/lamware-aide", "/var/lib/aide/aide.db", "/root/.ssh/authorized_keys",
    "/etc/suricata/suricata.yaml", "/etc/suricata/update.yaml", "/opt/network-monitor/monitor.sh",
    "/run/systemd/system/x.service", "/tmp/implant", "/var/lib/lamware-aide",
    "/var/log/sudo.log", "/var/log/account/pacct",
    "/root", "/root/.config/nuclei/config.yaml", "/opt/security-test/run.sh",
    # beside the scheduled jobs' state: what they install or are configured by
    "/etc/apt/sources.list", "/etc/apt/apt.conf.d/50unattended-upgrades",
    "/var/lib/fwupd/pki/x", "/etc/letsencrypt/live/x/privkey.pem",
    "/etc/letsencrypt/renewal/x.conf", "/var/lib/dpkg/status", "/run/motd",
    "/etc/rkhunter.conf", "/usr/bin/rkhunter", "/var/lib/rkhunter/db/rkhunter.dat",
])
def test_code_and_configuration_stay_monitored(path):
    assert not _excluded(path)


# --- rotated logs: this host rotates with dateext + xz -------------------------
LOG_RULES = [line.split()[0] for line in
             (FILES / "98_lamware_logs").read_text().splitlines()
             if line.startswith("/var/log/.+")]


@pytest.mark.parametrize("path", [
    "/var/log/nginx/access.log-20261025", "/var/log/nginx/access.log-20261025.xz",
    "/var/log/syslog-20261018.xz", "/var/log/nginx/error.log-20261022.xz",
])
def test_dated_rotated_logs_get_the_rotation_rule(path):
    assert any(re.match(r + "$" if not r.endswith("$") else r, path) for r in LOG_RULES), LOG_RULES


@pytest.mark.parametrize("path", [
    "/var/log/nginx/access.log", "/var/log/syslog", "/var/log/sudo.log",
    "/var/log/foo-2026.log", "/var/log/x-20261025.sh",
])
def test_live_logs_and_other_files_do_not(path):
    assert not any(re.match(r, path) for r in LOG_RULES), path


# --- logs that logrotate rotates: owner and mode only, and first in line -----------
ROTATED = FILES / "30_lamware_rotated_logs"
ROTATED_RULES = [line.split() for line in ROTATED.read_text().splitlines()
                 if line.startswith("/")]


def test_rotated_log_rules_sort_before_ubuntus_package_rules():
    """AIDE applies the rule from the earliest file. Ubuntu's 31_aide_* give these logs
    ActLog (`growing`); in 98_ these rules never applied (`aide -p`, 2026-11-04)."""
    assert ROTATED.name < "31_aide_"
    tasks = (FILES.parent / "tasks" / "main.yml").read_text()
    assert f"- {ROTATED.name}" in tasks, "the deploy does not install the file"


@pytest.mark.parametrize("path", [
    # every active log in the host's /etc/logrotate.d, enumerated 2026-11-04
    "/var/log/nginx/access.log", "/var/log/nginx/error.log", "/var/log/btmp", "/var/log/wtmp",
    "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log", "/var/log/mail.log",
    "/var/log/cron.log", "/var/log/user.log", "/var/log/dpkg.log", "/var/log/alternatives.log",
    "/var/log/fail2ban.log", "/var/log/numad.log", "/var/log/rkhunter.log", "/var/log/boot.log",
    "/var/log/aptitude", "/var/log/apt/history.log", "/var/log/apt/term.log",
    "/var/log/cloud-init.log", "/var/log/cloud-init-output.log", "/var/log/ubuntu-advantage.log",
    "/var/log/letsencrypt/letsencrypt.log", "/var/log/libvirt/libvirtd.log",
    "/var/log/libvirt/qemu/clean.log", "/var/log/privoxy/logfile",
    "/var/log/unattended-upgrades/unattended-upgrades.log",
    "/var/log/unattended-upgrades/unattended-upgrades-dpkg.log",
    "/var/log/usbguard/usbguard-audit.log",
])
def test_every_rotated_active_log_gets_freqrotlog(path):
    hits = [(r, g) for r, _, g in ROTATED_RULES if re.match(r, path)]
    assert hits and all(g == "FreqRotLog" for _, g in hits), (path, hits)


@pytest.mark.parametrize("path", [
    # rotated copies keep their content (98_), and what is not a rotated log stays out
    "/var/log/nginx/access.log-20261025.xz", "/var/log/syslog-20261018.xz",
    "/var/log/sudo.log", "/var/log/account/pacct", "/var/log/auth.log.bak", "/var/log/nginx/x.log.sh",
])
def test_freqrotlog_does_not_reach_rotated_copies_or_other_files(path):
    assert not any(re.match(r, path) for r, _, _ in ROTATED_RULES), path



# --- the nightly gate: absorb only what a detonation or a reboot changes (ADR-035) -----

def _report(added=(), removed=(), changed=()):
    """An AIDE 0.18 report with these entries; changed entries are (summary, path)."""
    lines = ["Start timestamp: 2026-11-20 00:00:01 -0800 (AIDE 0.18.6)",
             "AIDE found differences between database and filesystem!!", "", "Summary:",
             "  Total number of entries:\t1000",
             f"  Added entries:\t\t{len(added)}", f"  Removed entries:\t\t{len(removed)}",
             f"  Changed entries:\t\t{len(changed)}", ""]
    for title, items in (("Added", [("f++++++++++++++++++", p) for p in added]),
                         ("Removed", [("f------------------", p) for p in removed]),
                         ("Changed", list(changed))):
        if items:
            lines += ["-" * 51, f"{title} entries:", "-" * 51, ""]
            lines += [f"{flags}: {p}" for flags, p in items]
    lines += ["", "-" * 51, "Detailed information about changes:", "-" * 51, "",
              "File: /opt/CAPEv2/log/cuckoo.log", " Size      : 1 | 2"]
    return "\n".join(lines) + "\n"


EXPECTED_RULES = aide.load_expected(str(FILES / "expected-differences.conf"))
SWTPM = "/var/lib/libvirt/swtpm/00000000-0000-4000-8000-000000000000/tpm2/tpm2-00.permall"
# Real entries from the 2026-11-19 check (a detonation night), uuid and sample renamed.
DETONATION = _report(
    added=["/opt/CAPEv2/log/cuckoo.log.2026-11-16", "/opt/CAPEv2/log/process-1322.log",
           "/tmp/cuckoo-tmp", "/tmp/cuckoo-tmp/upload_f_tjpd_s",
           "/tmp/cuckoo-tmp/upload_f_tjpd_s/sample.exe", "/run/libvirt/qemu/swtpm",
           "/var/lib/libvirt/images/windows11-guest.1795065977"],
    removed=["/opt/CAPEv2/log/cuckoo.log.2026-09-16",
             "/var/lib/libvirt/images/windows11-guest.1794790133"],
    changed=[("d =.... mc.. .. . ", "/etc/apparmor.d/libvirt"),
             ("f =.... mci.H.. . ", "/etc/libvirt/qemu/clean.xml"),
             ("f <b... mci.H.. . ", "/opt/CAPEv2/log/cuckoo.log"),
             ("f =...g mci.H.. . ", "/opt/CAPEv2/log/process.log"),
             ("f =.... .c..... . ", "/var/lib/libvirt/images/windows11-guest.qcow2"),
             ("f =.... mci.H.. . ", SWTPM),
             ("d   ...   .n .. . ", "/run/libvirt/qemu")])


def test_the_shipped_rules_load():
    assert len(EXPECTED_RULES) > 20
    assert aide.main(["rules"]) in (0, 1)   # EXPECTED is the host path outside the env fixture


def test_a_detonation_night_is_absorbed_quietly_from_the_same_scan(env):
    env["rc"], env["out"] = 7, DETONATION
    assert aide.main(["check"]) == 0
    assert env["db"].read_text() == "NEW" and env["prev"].read_text() == "OLD"
    assert len(env["argv"]) == 1                       # one scan, no second pass
    [a] = env["alerts"]
    assert a["priority"] == "low" and "16 expected differences absorbed" in a["title"]


def test_the_dev_null_finding_still_alerts_on_a_detonation_night(env):
    """The 11-19 check: /dev/null's owner changed among 30 detonation entries."""
    report = DETONATION.replace("Changed entries:\t\t7", "Changed entries:\t\t8").replace(
        '"d   ...   .n .. . : /run/libvirt/qemu"', "").replace(
        "d   ...   .n .. . : /run/libvirt/qemu",
        "d   ...   .n .. . : /run/libvirt/qemu\nc =..ug    . ..   : /dev/null")
    env["rc"], env["out"] = 7, report
    assert aide.main(["check"]) == 7
    [a] = env["alerts"]
    assert a["priority"] == "high" and a["title"].startswith("AIDE: 1 unexpected")
    assert "/dev/null" in a["message"] and "cuckoo" not in a["message"]
    assert env["db"].read_text() == "OLD" and not env["new"].exists()


@pytest.mark.parametrize("section, flags, path", [
    ("Changed", "c =..ug    . ..   ", "/dev/null"),                         # 11-19
    ("Changed", "f =.... .c..H.. . ", "/var/lib/libvirt/images/windows11-guest.qcow2"),
    ("Changed", "f =..p. mci.H.. . ", "/etc/libvirt/qemu/clean.xml"),        # mode
    ("Changed", "f =...u mci.H.. . ", SWTPM),                                # owner
    ("Changed", "! =.... mci.H.. . ", "/opt/CAPEv2/log/cuckoo.log"),         # type
    ("Changed", "f =.... mci.H..C. ", "/run/libvirt/qemu/x"),                # capabilities
    ("Added", "f++++++++++++++++++", "/run/systemd/system/evil.service"),
    ("Added", "f++++++++++++++++++", "/run/systemd/transient/evil.service"),
    ("Added", "f++++++++++++++++++", "/run/credentials/x.service/key"),
    ("Changed", "f =.... mci.H.. . ", "/run/credentials/x.service/key"),
    ("Changed", "f =.... mc..H.. . ", "/var/lib/cloud/instances/" + "0" * 8 + "-0000-4000-8000-" + "0" * 12 + "/scripts/part-001"),
    ("Changed", "f =.... mci.H.. . ", "/var/spool/postfix/etc/resolv.conf"),
    ("Added", "f++++++++++++++++++", "/root/flow-measure/flow-20261118T071143.json"),
    ("Changed", "f =.... mc..H.. . ", "/opt/CAPEv2/data/yara/index_memory.yarc"),
    ("Added", "f++++++++++++++++++", "/opt/CAPEv2/log/../../../usr/bin/x"),
])
def test_these_are_never_absorbed(section, flags, path):
    assert not aide.is_expected((section, flags, path), EXPECTED_RULES)


@pytest.mark.parametrize("section, flags, path", [
    ("Added", "f++++++++++++++++++",
     "/run/systemd/transient/libpod-" + "a" * 64 + ".scope"),
    ("Changed", "f =.... mci.H.. . ", "/run/systemd/system/netplan-ovs-cleanup.service"),
    ("Changed", "l.=.... mci.  .   ", "/var/spool/postfix/etc/localtime"),
    ("Changed", "ll=....    .  .   ", "/dev/disk/by-id/nvme-x-part1"),
    ("Changed", "f =.... mci.... . ", "/run/credentials/x.service/key"),
    ("Added", "b++++++++++++++++++", "/dev/nvme1n1p5"),
])
def test_reboot_and_runtime_entries_are_absorbed(section, flags, path):
    assert aide.is_expected((section, flags, path), EXPECTED_RULES)


def test_a_report_that_does_not_add_up_fails_closed(env):
    env["rc"], env["out"] = 7, DETONATION.replace("Added entries:\t\t7", "Added entries:\t\t9")
    assert aide.main(["check"]) == 7
    [a] = env["alerts"]
    assert a["priority"] == "high" and "NOT CLASSIFIED" in a["message"]
    assert env["db"].read_text() == "OLD" and not env["new"].exists()


def test_missing_rules_fail_closed(env, monkeypatch):
    monkeypatch.setattr(aide, "EXPECTED", str(env["db"].parent / "absent.conf"))
    env["rc"], env["out"] = 7, DETONATION
    assert aide.main(["check"]) == 7
    [a] = env["alerts"]
    assert a["priority"] == "high" and "expected-differences rules" in a["message"]
    assert env["db"].read_text() == "OLD"


@pytest.mark.parametrize("line", ["allow X cm /x", "allow C qq /x", "permit C cm /x", "allow C cm"])
def test_a_malformed_rule_is_refused(tmp_path, line):
    f = tmp_path / "r.conf"
    f.write_text(line + "\n")
    with pytest.raises(ValueError):
        aide.load_expected(str(f))


def test_no_allow_rule_lets_owner_mode_or_capabilities_change_except_cape_logs():
    for action, _sections, letters, rx in EXPECTED_RULES:
        if action != "allow":
            continue
        risky = letters & set("YpugAXSEC")
        if rx.pattern == r"/opt/CAPEv2/log/(cuckoo|process)\.log":
            assert risky == {"g"}, risky
        else:
            assert not risky, (rx.pattern, risky)


def test_the_deploy_installs_and_validates_the_rules():
    import yaml
    tasks = yaml.safe_load((ROOT / "ansible/roles/hardening/tasks/main.yml").read_text())
    by_name = {t.get("name"): t for t in tasks if isinstance(t, dict)}
    inst = by_name["Install the expected-differences rules"]["ansible.builtin.copy"]
    assert (inst["src"], inst["dest"]) == ("expected-differences.conf", aide.EXPECTED)
    names = list(by_name)
    assert names.index("Install lamware-aide") < names.index("Validate the expected-differences rules")
    assert by_name["Validate the expected-differences rules"]["ansible.builtin.command"] == \
        "/usr/local/sbin/lamware-aide rules"


@pytest.mark.parametrize("flags, letters", [
    ("c =..ug    . ..   ", {"u", "g"}),                 # /dev/null, 2026-11-19
    ("f <b... mci.H.. . ", {"Z", "b", "m", "c", "i", "H"}),
    ("ll=....    .  .   ", {"l"}),                      # a udev disk link
    ("d   ...   .n .. . ", {"n"}),
    ("! =.... mc..... . ", {"Y", "m", "c"}),
    # Constructed, not from a report: capabilities, the 18th and last column.
    ("".join("C" if i == 17 else "f" if i == 0 else "." for i in range(18)), {"C"}),
])
def test_summary_columns_are_read_by_position(flags, letters):
    """Strings from the host's reports: one column off reads an owner change as
    something else, which is exactly the mistake a test fixture made once."""
    assert aide.changed_letters(flags) == letters
