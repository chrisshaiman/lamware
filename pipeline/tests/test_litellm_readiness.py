# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Guard the LiteLLM deploy readiness probe against the /health fan-out trap.

LiteLLM's /health endpoint issues a LIVE inference call to every entry in
model_list. With local Ollama models registered (qwen3:32b ~20GB,
gpt-oss:20b ~13GB) that cold-loads tens of gigabytes and blocks well past any
sane probe timeout — measured >120s on 2026-07-24 — so an otherwise healthy
container retry-loops the deploy to failure.

/health/readiness checks the process plus DB/cache only, with no backend
fan-out, and answers immediately. Same root cause as the netcheck.py fix in
799ec17; this guards the ansible role so the fix does not regress a third time.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LITELLM_TASKS = ROOT / "ansible" / "roles" / "litellm" / "tasks" / "main.yml"


def _probe_urls() -> list[str]:
    """Every litellm health URL referenced by the role's readiness tasks."""
    text = LITELLM_TASKS.read_text()
    return re.findall(r"url:\s*\"[^\"]*litellm_port\s*\}\}(/health[^\"]*)\"", text)


def test_readiness_probes_exist():
    urls = _probe_urls()
    assert urls, "no litellm health probe URLs found - did the role move?"


def test_readiness_never_uses_bare_health():
    """A bare /health probe hangs on backend cold-load and fails the deploy."""
    for url in _probe_urls():
        assert url != "/health", (
            "litellm readiness probe uses bare /health, which fans out a live "
            "inference call to every model_list entry and blocks on local-model "
            "cold-load. Use /health/readiness."
        )


def test_readiness_uses_readiness_endpoint():
    urls = _probe_urls()
    assert all(u.startswith("/health/readiness") for u in urls), urls
