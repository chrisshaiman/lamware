# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Network-isolation probe for the interpret container (--network=none).

Run inside a throwaway --network=none probe container at deploy. Asserts the container
CAN reach LiteLLM via the bind-mounted Unix socket AND CANNOT reach any host TCP
service / the internet. Exit 0 = isolation holds; nonzero = regression.
"""
import os
import socket
import sys

import httpx

fails = []

# (1) MUST reach LiteLLM over the Unix socket.
try:
    key = os.environ.get("LITELLM_API_KEY", "")
    client = httpx.Client(transport=httpx.HTTPTransport(uds="/run/litellm.sock"), timeout=10)
    resp = client.get("http://litellm/health", headers={"Authorization": f"Bearer {key}"})
    if resp.status_code != 200:
        fails.append(f"LiteLLM /health via socket returned {resp.status_code}, expected 200")
except Exception as exc:  # noqa: BLE001 - probe reports any failure to reach LiteLLM
    fails.append(f"could not reach LiteLLM over the socket: {exc!r}")

# (2) MUST NOT reach host TCP services / the internet (no netns under --network=none).
for host, port in [("127.0.0.1", 5432), ("1.1.1.1", 443)]:
    try:
        socket.create_connection((host, port), timeout=3).close()
        fails.append(f"REACHED {host}:{port} — network isolation breached")
    except OSError:
        pass  # expected: unreachable

if fails:
    print("ISOLATION PROBE FAILED:", file=sys.stderr)
    for line in fails:
        print("  -", line, file=sys.stderr)
    sys.exit(1)
print("isolation probe OK: LiteLLM reachable via socket; host services unreachable")
