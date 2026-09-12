# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The analysis window must outlast the samples' payload stage (#518).

CAPE's default analysis timeout is 200s. Measured across three runs of the same
three samples, every one begins its payload stage at 179-206s:

    quasarrat   r3 child spawns 205s | r4 process died 197s | r5 spawns 206s
    warzonerat  r3 spawns 203s       | r4 spawns 203s       | r5 spawns 203s
    salat       r3 spawns 179s       | r4 179s              | r5 179s, died 201s

So the window closed exactly where the behaviour started, and whether a sample's
children were captured came down to a few seconds of jitter. quasarrat scored
55, 17, 45 on IDENTICAL images. Those low runs were read as measurement noise and
averaged in, giving observed_behaviour a +/-15-25 noise floor that left the
experiment unable to resolve its own question.

A timeout at or below the observed payload window is not a performance tuning
choice; it silently costs measurements.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "cape" / "defaults" / "main.yml").read_text(encoding="utf-8"))
TASKS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "cape" / "tasks" / "main.yml").read_text(encoding="utf-8"))

#: The latest payload-stage start observed across the three #518 corpus runs.
OBSERVED_PAYLOAD_STAGE_S = 206


def test_the_window_outlasts_the_observed_payload_stage():
    """Not merely longer — long enough to OBSERVE the payload once it starts.
    A window ending the moment the child spawns records the spawn and nothing
    after it, which is what warzonerat's r4 run was: child announced at 203s,
    one process in the report."""
    t = DEFAULTS["cape_analysis_timeout"]
    assert t >= OBSERVED_PAYLOAD_STAGE_S * 1.5, (
        f"cape_analysis_timeout={t}s against a payload stage starting at "
        f"{OBSERVED_PAYLOAD_STAGE_S}s — the window closes on the behaviour and "
        f"capture becomes a coin flip")


def test_the_timeout_is_managed_by_ansible():
    """It lived only in /opt/CAPEv2/conf/cuckoo.conf, unmanaged, so a CAPE
    reinstall would silently restore 200s and the flakiness with it."""
    names = [t.get("name", "") for t in TASKS]
    idx = next((i for i, n in enumerate(names) if "analysis timeout" in n.lower()), None)
    assert idx is not None, "no task sets the analysis timeout"
    task = TASKS[idx]
    ini = task.get("community.general.ini_file")
    assert ini, "the timeout is not set via ini_file"
    assert ini["section"] == "timeouts" and ini["option"] == "default"
    assert "cape_analysis_timeout" in str(ini["value"]), \
        "the timeout is hardcoded rather than driven by the role variable"


def test_changing_it_restarts_cape():
    """cuckoo.conf is read at startup; without the handler the running daemon
    keeps the old window and the deploy reports success."""
    names = [t.get("name", "") for t in TASKS]
    idx = next(i for i, n in enumerate(names) if "analysis timeout" in n.lower())
    assert "Restart Cape services" in str(TASKS[idx].get("notify", "")), \
        "changing the analysis timeout does not restart Cape, so it takes no effect"
