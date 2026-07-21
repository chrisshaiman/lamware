# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guard: the single-shot backend knob is wired to exactly the 3 pilot paths."""
from pathlib import Path

TEMPLATE = (Path(__file__).resolve().parents[2]
            / "ansible" / "roles" / "interpret" / "templates" / "interpret-ghidra.py.j2")


def test_ss_client_defined_from_backend_flag():
    text = TEMPLATE.read_text(encoding="utf-8")
    assert 'ss_client = summary_client if config.get("single_shot_backend") == "local" else client' in text


def test_exactly_three_pilot_paths_use_ss_client():
    text = TEMPLATE.read_text(encoding="utf-8")
    # .NET, Go, PowerShell — and only those — route through ss_client.
    assert text.count("ss_client.messages.create(") == 3
