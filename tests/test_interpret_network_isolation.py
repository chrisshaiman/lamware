# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static regression guard: the interpret container must run --network=none.

Reverting to --network=host would re-expose the adversary-facing LLM container to the
host network namespace (Postgres/Keycloak/internet). Cheap CI gate; the runtime probe
(interpret role verify task) proves the isolation actually holds at deploy time.
"""
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
WRAPPER = _ROOT / "ansible" / "roles" / "interpret" / "templates" / "run-interpret-wrapper.sh.j2"
SOCKET_UNIT = _ROOT / "ansible" / "roles" / "litellm" / "templates" / "litellm-socket.service.j2"


def test_interpret_wrapper_uses_network_none():
    text = WRAPPER.read_text()
    assert "--network=none" in text, "interpret container must run --network=none"
    assert "--network=host" not in text, "interpret container must NOT use --network=host"


def test_interpret_base_url_does_not_imply_a_reachable_tcp_endpoint():
    # The base URL host is cosmetic (all requests route over LITELLM_UDS). It must NOT look
    # like a reachable host TCP endpoint, which would silently work again if someone restored
    # --network=host. A non-resolvable .invalid host fails closed instead.
    text = WRAPPER.read_text()
    assert "litellm.invalid" in text, "base URL host should be a non-resolvable dummy (fail-closed)"
    assert 'LITELLM_BASE_URL="http://127.0.0.1' not in text, (
        "base URL must not imply a reachable TCP LiteLLM endpoint"
    )


def test_litellm_socket_dir_is_group_gated():
    # The socket directory must be 0750 root:pipeline, not world-traversable — so only the
    # pipeline group + root (the legitimate set) can reach the socket, not every local user.
    text = SOCKET_UNIT.read_text()
    assert "Group=pipeline" in text, "socket RuntimeDirectory must be pipeline-group-owned"
    assert "RuntimeDirectoryMode=0750" in text, "socket dir must be 0750 (not world-traversable)"
