# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The #205 import coverage must not be able to switch itself off silently.

De-templating `interpret-ghidra.py` bought one thing above all: the agentic Ghidra RE
loop — the most complex and most security-relevant module in the repo — can finally be
IMPORTED by a test instead of only grepped as text. `test_interpret_config_defaults.py`
does exactly that, and it is the only test that does.

It opens with:

    pytest.importorskip("anthropic", reason="pip install './pipeline[test]'")

which is correct for a local checkout without the extras, and is also a switch that can
turn the whole thing off without saying so. Drop `anthropic` from `pipeline[test]`, or
change CI's install line, and that module SKIPS. Every assertion in it stops running,
CI stays green, and the coverage #205 was opened to create is gone with no signal.

That is the failure mode this repo keeps rediscovering: `| mandatory` that could not
fire because a role default satisfied it (#238); `smoke-setup` reporting "ready" because
`playwright install` exits 0 without a working browser (#269). A guard that can be
disabled silently is worse than no guard, because it stops anyone looking again.

So: assert the two things the skip depends on. Neither can change without a red test.
"""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pipeline" / "pyproject.toml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
IMPORTING_TEST = Path(__file__).parent / "test_interpret_config_defaults.py"

# What the container script imports at module scope. Importing it for real requires
# these present; stubbing them would only prove it imports against a fake.
REQUIRED_EXTRAS = ("anthropic", "httpx")


def _test_extra() -> list[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return data.get("project", {}).get("optional-dependencies", {}).get("test", [])


def test_test_extra_declares_what_the_import_needs():
    """Without these, the only test that imports the container script skips."""
    declared = " ".join(_test_extra())
    missing = [pkg for pkg in REQUIRED_EXTRAS if pkg not in declared]
    assert not missing, (
        f"pipeline[test] no longer declares {missing}. That is not a packaging detail: "
        f"test_interpret_config_defaults.py opens with importorskip('anthropic'), so "
        f"dropping it makes the ONLY test that imports interpret-ghidra.py skip "
        f"silently while CI stays green — deleting the #205 coverage with no signal.")


def test_ci_installs_the_test_extra():
    """Declaring the extra is useless if CI does not install it."""
    ci = CI.read_text(encoding="utf-8")
    assert re.search(r"pipeline\[test\]", ci), (
        "CI must install ./pipeline[test]; without it the interpret-import test skips "
        "and #205's coverage silently disappears from every run.")


def test_the_importing_test_still_imports_for_real():
    """Guard the mechanism, not just its dependencies.

    Rewriting that test to read the file as text — the pattern every OTHER interpret
    test uses — would leave this file's assertions passing while the actual import
    coverage was gone. So check it still loads the module.
    """
    src = IMPORTING_TEST.read_text(encoding="utf-8")
    assert "spec_from_file_location" in src and "exec_module" in src, (
        "test_interpret_config_defaults.py must still IMPORT interpret-ghidra.py "
        "(spec_from_file_location + exec_module). Source-text assertions cannot catch "
        "an ImportError, a syntax error, or a bad module-scope constant — which is the "
        "coverage #205 existed to add.")


def test_the_skip_reason_tells_you_how_to_fix_it():
    """A skip nobody can action is how this silently becomes permanent."""
    src = IMPORTING_TEST.read_text(encoding="utf-8")
    match = re.search(r"importorskip\([^)]*\)", src, re.S)
    assert match, "expected an importorskip guarding the real import"
    assert "pipeline[test]" in match.group(0), (
        "the skip reason should name the install that fixes it, so a local run that "
        "skips is obviously fixable rather than looking like a pass")
