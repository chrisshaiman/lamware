# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Guard the interpret container timeout against reasoning-on local RE runs.

The podman --timeout SIGKILLs the interpret container mid-run, and the failure
presents as "exited without final result" rather than a timeout, so it reads as
a model/plumbing bug. Measured local runtimes that must fit underneath it:

  qwen3.6 agentic RE, 10 tool calls   333s   (2026-07-23 spike)
  + PR #180 two-phase synthesis       ~9-10min/sample
  25-cycle arm at ~33s/turn           ~825s

360s (the historical default, sized for cloud Claude at ~150s/sample) is below
all of those. This asserts a floor with headroom rather than an exact value, so
the timeout can be tuned without churning the test.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULTS = ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml"
WRAPPER = (ROOT / "ansible" / "roles" / "interpret" / "templates"
           / "run-interpret-wrapper.sh.j2")

# Slowest expected local arm (~825s) plus margin for cold-load and synthesis.
MIN_TIMEOUT_SECONDS = 1200


def _configured_timeout() -> int:
    m = re.search(r'^interpret_container_timeout:\s*"?(\d+)"?',
                  DEFAULTS.read_text(), re.MULTILINE)
    assert m, "interpret_container_timeout not found in role defaults"
    return int(m.group(1))


def test_timeout_accommodates_reasoning_on_local_re():
    t = _configured_timeout()
    assert t >= MIN_TIMEOUT_SECONDS, (
        f"interpret_container_timeout={t}s SIGKILLs reasoning-on local RE "
        f"(25-cycle arm is ~825s); need >= {MIN_TIMEOUT_SECONDS}s"
    )


def test_wrapper_uses_the_configured_timeout():
    """The wrapper must read the var, not hardcode a value."""
    assert "--timeout={{ interpret_container_timeout }}" in WRAPPER.read_text()
