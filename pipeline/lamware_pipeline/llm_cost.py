# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A run's LLM cost from LiteLLM's own records (ADR-037).

The interpret container puts the LiteLLM call id of every model call into the stage's
`usage` block (`usage["litellm_call_ids"]`). After the last LLM stage the orchestrator
calls `resolve_run_cost(report, fetch)`: each id is looked up in LiteLLM's spend log
(`GET /spend/logs?request_id=<id>`), retried for a while because LiteLLM writes the
log in batches, and the sum goes into `report["llm_cost"]`.

The result is complete only when every stage that used tokens carried call ids and
every id resolved. Anything less is recorded, never guessed, and db_ingest then prices
the run from its rate table as before.
"""
from __future__ import annotations

import http.client
import json
import socket
import time
import urllib.parse
from collections.abc import Callable

#: Report sections whose `usage` the LLM stages write (db_ingest prices the same ones).
SECTIONS = ("llm_interpretation", "executive_summary", "evasion_analysis", "visual_analysis")
TOKEN_KEYS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


def _usages(report: dict) -> list[tuple[str, dict]]:
    out = []
    for name in SECTIONS:
        section = report.get(name)
        usage = section.get("usage") if isinstance(section, dict) else None
        if isinstance(usage, dict):
            out.append((name, usage))
    pe = report.get("plain_english_usage")
    if isinstance(pe, dict):
        out.append(("plain_english", pe))
    return out


def _has_tokens(usage: dict) -> bool:
    return any(isinstance(usage.get(k), (int, float)) and usage.get(k) > 0 for k in TOKEN_KEYS)


def call_ids(report: dict) -> tuple[list[str], list[str]]:
    """(every call id in the report, the stages that used tokens but carried none)."""
    ids: list[str] = []
    unidentified: list[str] = []
    for name, usage in _usages(report):
        found = [i for i in usage.get("litellm_call_ids") or [] if isinstance(i, str) and i]
        if found:
            ids.extend(i for i in found if i not in ids)
        elif _has_tokens(usage):
            unidentified.append(name)
    return ids, unidentified


def resolve_run_cost(report: dict, fetch: Callable[[str], float | None], *,
                     deadline_s: float = 180.0, poll_s: float = 10.0,
                     clock: Callable[[], float] = time.monotonic,
                     sleep: Callable[[float], None] = time.sleep) -> dict:
    """`report["llm_cost"]`: LiteLLM's recorded cost of every call this run made.

    `fetch(call_id)` returns the call's recorded spend in dollars, or None while the
    spend log does not have it yet. Unresolved ids are retried until `deadline_s`.
    """
    ids, unidentified = call_ids(report)
    spend: dict[str, float] = {}
    end = clock() + deadline_s
    while True:
        for cid in ids:
            if cid not in spend:
                value = fetch(cid)
                if value is not None:
                    spend[cid] = float(value)
        if len(spend) == len(ids) or clock() >= end:
            break
        sleep(poll_s)
    unresolved = [cid for cid in ids if cid not in spend]
    return {
        "source": "litellm",
        "usd": round(sum(spend.values()), 6),
        "calls": len(ids),
        "resolved": len(spend),
        "unresolved_call_ids": unresolved,
        "stages_without_call_ids": unidentified,
        "complete": not unresolved and not unidentified,
    }


class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP over a Unix socket. The standard library has none, and the pipeline venv
    carries no httpx."""

    def __init__(self, socket_path: str, timeout: float):
        super().__init__("litellm", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


def litellm_spend_fetcher(socket_path: str, api_key: str,
                          timeout_s: float = 15.0) -> Callable[[str], float | None]:
    """fetch(call_id) over LiteLLM's spend log, for resolve_run_cost.

    Over LiteLLM's Unix socket, the one the interpret container already uses: the
    pipeline user's egress rules drop TCP to LiteLLM's port, by design, and this path
    needs no change to them (measured 2026-11-25: TCP timed out, the socket answered).
    The log is keyed by LiteLLM's call id; a missing row (not written yet) or an
    unreachable proxy is None, so the caller retries and then records it unresolved.
    """
    def fetch(call_id: str) -> float | None:
        path = "/spend/logs?" + urllib.parse.urlencode({"request_id": call_id})
        conn = _UnixHTTPConnection(socket_path, timeout_s)
        try:
            conn.request("GET", path, headers={"Authorization": f"Bearer {api_key}"})
            resp = conn.getresponse()
            if resp.status != 200:
                return None
            rows = json.loads(resp.read())
        except (OSError, ValueError, http.client.HTTPException):
            return None
        finally:
            conn.close()
        rows = rows if isinstance(rows, list) else (rows or {}).get("data", [])
        matched = [r for r in rows if isinstance(r, dict)
                   and call_id in (r.get("request_id"), r.get("litellm_call_id"))]
        if not matched:
            return None
        return sum(float(r.get("spend") or 0.0) for r in matched)

    return fetch
