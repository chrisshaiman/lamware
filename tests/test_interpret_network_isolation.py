# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static regression guard: the interpret container must run --network=none.

Reverting to --network=host would re-expose the adversary-facing LLM container to the
host network namespace (Postgres/Keycloak/internet). Cheap CI gate; the runtime probe
(interpret role verify task) proves the isolation actually holds at deploy time.
"""
from pathlib import Path

WRAPPER = (
    Path(__file__).resolve().parents[1]
    / "ansible" / "roles" / "interpret" / "templates" / "run-interpret-wrapper.sh.j2"
)


def test_interpret_wrapper_uses_network_none():
    text = WRAPPER.read_text()
    assert "--network=none" in text, "interpret container must run --network=none"
    assert "--network=host" not in text, "interpret container must NOT use --network=host"
