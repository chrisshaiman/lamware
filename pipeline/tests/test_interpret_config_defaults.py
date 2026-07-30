# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""#205: the interpret container script is plain Python, and these tests can reach it.

For as long as it was `interpret-ghidra.py.j2`, ~2,900 lines of tool dispatch, message
construction, result capping and synthesis had ZERO test reach — nothing could import a
Jinja template. A syntax error in it surfaced when podman built the image on the host,
not in CI.

It carried exactly nine Jinja scalars for that price. They now ship as JSON written by
the role at deploy time.

These tests are deliberately about the SEAM, not the analysis logic: that the module
imports at all, that it survives a missing config file (the property that makes it
importable), that it does not swallow a corrupt one, and that the fallbacks cannot drift
away from the ansible defaults they mirror.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "interpret"
SCRIPT = ROLE / "files" / "interpret-ghidra.py"
CONFIG_TEMPLATE = ROLE / "templates" / "interpret-config.json.j2"
ROLE_DEFAULTS = ROLE / "defaults" / "main.yml"
CONTAINERFILE = ROLE / "templates" / "Containerfile.j2"
TASKS = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")

pytest.importorskip("anthropic", reason="pip install './pipeline[test]'")


def _load_module(config_path: str | None):
    """Import the container script under a given INTERPRET_CONFIG.

    Loaded under a private module name so it never collides with anything else in
    sys.modules, and removed afterwards so nothing leaks into later test modules —
    the failure mode that got the WebSocket tests excluded from CI (#214).
    """
    name = "_interpret_under_test"
    prev_env = os.environ.get("INTERPRET_CONFIG")
    if config_path is None:
        os.environ.pop("INTERPRET_CONFIG", None)
    else:
        os.environ["INTERPRET_CONFIG"] = config_path
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.modules.pop(name, None)
        if prev_env is None:
            os.environ.pop("INTERPRET_CONFIG", None)
        else:
            os.environ["INTERPRET_CONFIG"] = prev_env


def test_the_script_is_not_a_template_anymore():
    assert SCRIPT.exists(), "interpret-ghidra.py should live in the role's files/ dir"
    assert not (ROLE / "templates" / "interpret-ghidra.py.j2").exists(), (
        "the .j2 must be gone, or the role can ship a stale templated copy alongside it")
    body = SCRIPT.read_text(encoding="utf-8")
    assert "{{" not in body and "{%" not in body, (
        "a surviving Jinja marker is a Python syntax error that only appears at "
        "container-build time")


def test_it_imports_with_no_config_file_present():
    """The property that makes the module testable at all."""
    mod = _load_module("/nonexistent/interpret-config.json")
    assert mod.DEFAULT_CONFIG == mod._BUILTIN_DEFAULTS


def test_deployed_config_overrides_the_builtins(tmp_path):
    cfg = tmp_path / "interpret-config.json"
    cfg.write_text(json.dumps({"model": "local-qwen", "max_tool_calls": 30}))
    mod = _load_module(str(cfg))
    assert mod.DEFAULT_CONFIG["model"] == "local-qwen"
    assert mod.DEFAULT_CONFIG["max_tool_calls"] == 30
    # untouched keys still come from the builtins
    assert mod.DEFAULT_CONFIG["max_strings"] == mod._BUILTIN_DEFAULTS["max_strings"]


def test_a_corrupt_config_warns_instead_of_silently_using_fallbacks(tmp_path, capsys):
    """A deploy that writes broken JSON must not look like a healthy run.

    Falling back silently would run the whole analysis on the wrong model or tool budget
    and report success — the same silent-degradation shape as the llama.cpp flag that was
    accepted and ignored.
    """
    cfg = tmp_path / "interpret-config.json"
    cfg.write_text("{ this is not json")
    mod = _load_module(str(cfg))
    assert mod.DEFAULT_CONFIG == mod._BUILTIN_DEFAULTS
    assert "WARNING" in capsys.readouterr().err


def _role_default(name: str) -> str:
    m = re.search(rf"^{name}:\s*\"?([^\"\n#]+)\"?", ROLE_DEFAULTS.read_text(encoding="utf-8"),
                  re.MULTILINE)
    assert m, f"{name} missing from the role defaults"
    return m.group(1).strip()


def test_builtin_fallbacks_do_not_drift_from_the_role_defaults():
    """The fallbacks mirror ansible; a mirror nobody checks is a second source of truth.

    Without this, editing defaults/main.yml would leave the builtins silently stale, and
    they are exactly what a developer sees when reading the script.
    """
    mod = _load_module("/nonexistent/interpret-config.json")
    for key, var in [
        ("model", "interpret_model"),
        ("escalation_threshold", "interpret_escalation_threshold"),
        ("escalation_model", "interpret_escalation_model"),
        ("max_output_tokens", "interpret_max_output_tokens"),
        ("max_tool_calls", "interpret_max_tool_calls"),
        ("max_tool_calls_per_turn", "interpret_max_tool_calls_per_turn"),
        ("max_imports", "interpret_max_imports"),
        ("max_strings", "interpret_max_strings"),
        ("max_string_length", "interpret_max_string_length"),
    ]:
        expected = _role_default(var)
        actual = str(mod._BUILTIN_DEFAULTS[key])
        assert actual == expected, (
            f"builtin fallback {key}={actual} has drifted from {var}={expected}")


def test_every_scalar_the_template_used_is_still_shipped():
    """The config template must carry all nine, or a value silently reverts to a fallback."""
    tmpl = CONFIG_TEMPLATE.read_text(encoding="utf-8")
    for var in ("interpret_model", "interpret_escalation_threshold", "interpret_escalation_model",
                "interpret_max_output_tokens", "interpret_max_tool_calls",
                "interpret_max_tool_calls_per_turn", "interpret_max_imports",
                "interpret_max_strings", "interpret_max_string_length"):
        assert var in tmpl, f"{var} is no longer shipped to the container"


def test_the_role_copies_the_script_and_templates_the_config():
    assert "src: interpret-ghidra.py\n" in TASKS, "the script must be copied, not templated"
    assert "src: interpret-config.json.j2" in TASKS, "the config must still be rendered"


def test_the_image_actually_contains_the_config():
    """The script reads the config from beside itself; the COPY is what puts it there."""
    dockerfile = CONTAINERFILE.read_text(encoding="utf-8")
    assert "COPY interpret-config.json /opt/interpret-config.json" in dockerfile, (
        "without this the container falls back to builtins and ignores the role's values")


def test_the_script_compiles_standalone():
    """Catches in CI what previously only failed when podman built the image."""
    r = subprocess.run([sys.executable, "-m", "py_compile", str(SCRIPT)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
