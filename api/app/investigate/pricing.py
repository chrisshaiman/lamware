# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The investigation panel's prices, from LiteLLM (ADR-037, ADR-038).

The panel used to price turns from MODEL_COSTS, a hand-kept table, and offered only
the models in it. Now both come from LiteLLM's own price map, the one its spend log
bills from: GET /v1/model/info with the panel's scoped key lists every model that key
may call, with its per-token prices.

A model counts as PRICED only when LiteLLM states both input and output prices. A
model with no stated price would otherwise be recorded as $0.00, indistinguishable
from a free one, and investigation_cost_alert_usd (an alert, not a cap) would never
notice its spend. A local model is free by declaration: give its LiteLLM entry
input_cost_per_token: 0 and output_cost_per_token: 0.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import NamedTuple

import httpx

from ..config import settings

log = logging.getLogger(__name__)

CACHE_SECONDS = 600


class Price(NamedTuple):
    input: float
    output: float


_lock = threading.Lock()
_cache: tuple[float, dict[str, Price]] | None = None


def _fetch() -> dict[str, Price]:
    resp = httpx.get(f"{settings.litellm_url}/v1/model/info",
                     headers={"Authorization": f"Bearer {settings.litellm_investigate_key}"},
                     timeout=10.0)
    resp.raise_for_status()
    prices: dict[str, Price] = {}
    for entry in resp.json().get("data", []):
        info = entry.get("model_info") or {}
        cin, cout = info.get("input_cost_per_token"), info.get("output_cost_per_token")
        if isinstance(cin, (int, float)) and isinstance(cout, (int, float)) and cin >= 0 and cout >= 0:
            prices[entry["model_name"]] = Price(float(cin), float(cout))
    return prices


def prices() -> dict[str, Price]:
    """LiteLLM's prices by model name, cached for CACHE_SECONDS.

    If LiteLLM cannot be read, the last prices read are used; with none, the result
    is empty, so no model counts as priced and the panel offers none (fails closed).
    """
    global _cache
    with _lock:
        now = time.monotonic()
        if _cache and now - _cache[0] < CACHE_SECONDS:
            return _cache[1]
        try:
            fresh = _fetch()
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("LiteLLM prices unavailable (%s); using %s",
                        type(exc).__name__, "the last prices read" if _cache else "none")
            return _cache[1] if _cache else {}
        _cache = (now, fresh)
        return fresh


def clear_cache() -> None:
    global _cache
    with _lock:
        _cache = None
