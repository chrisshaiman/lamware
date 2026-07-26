# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# LLM spend tracking endpoint.
#
# Proxies to LiteLLM's /spend/logs API on localhost:4000 and aggregates
# per-request cost data into model breakdowns, daily totals, and cache
# efficiency metrics. Supplements the basic cost_today/cost_week/cost_total
# from the stats endpoint with richer operational data.

import logging
from collections import defaultdict
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Depends, Query

from ..auth import AuthContext, require_auth
from ..config import settings

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/spend", tags=["spend"])


@router.get("")
async def get_spend_summary(
    days: int = Query(default=30, ge=1, le=90, description="Days of history"),
    auth: AuthContext = Depends(require_auth),
) -> dict:
    """
    Aggregate LLM spend data from LiteLLM proxy.

    Returns per-model cost breakdown, daily cost series, token usage,
    and cache efficiency metrics.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{settings.litellm_url}/spend/logs",
                headers={"Authorization": f"Bearer {settings.litellm_key}"},
            )
            resp.raise_for_status()
            logs = resp.json()
    except Exception as e:
        # Log it. Swallowing this bare is how the endpoint reported $0 rather than
        # "broken" for as long as it read the wrong env vars — a zero here is
        # indistinguishable from genuinely free local inference, so the failure has to
        # say so somewhere.
        log.warning("LiteLLM spend API unreachable at %s: %s: %s",
                    settings.litellm_url, type(e).__name__, e)
        return {
            "error": f"Could not reach LiteLLM spend API: {type(e).__name__}",
            "by_model": [],
            "by_day": [],
            "totals": {
                "total_cost": 0,
                "total_requests": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "cache_hits": 0,
                "cache_misses": 0,
            },
        }

    if not isinstance(logs, list):
        logs = []

    # Filter to requested date range
    cutoff = datetime.now(UTC).timestamp() - (days * 86400)
    filtered = []
    for entry in logs:
        start_str = entry.get("startTime", "")
        if not start_str:
            continue
        try:
            ts = datetime.fromisoformat(start_str.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            continue
        if ts >= cutoff:
            filtered.append(entry)

    # Aggregate by model
    model_agg: dict[str, dict] = defaultdict(lambda: {
        "cost": 0.0,
        "requests": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_tokens": 0,
        "cache_read_tokens": 0,
    })

    # Aggregate by day
    day_agg: dict[str, dict] = defaultdict(lambda: {
        "cost": 0.0,
        "requests": 0,
    })

    total_cost = 0.0
    total_requests = 0
    total_input = 0
    total_output = 0
    total_cache_creation = 0
    total_cache_read = 0

    for entry in filtered:
        model = entry.get("model", "unknown")
        cost = entry.get("spend", 0) or 0
        prompt_tokens = entry.get("prompt_tokens", 0) or 0
        completion_tokens = entry.get("completion_tokens", 0) or 0

        # Extract cache stats from metadata
        meta = entry.get("metadata", {}) or {}
        additional = meta.get("additional_usage_values", {}) or {}
        prompt_details = additional.get("prompt_tokens_details", {}) or {}
        cache_creation = prompt_details.get("cache_creation_tokens", 0) or 0
        # Also check top-level additional_usage_values for cache_read
        cache_read = additional.get("cache_read_input_tokens", 0) or 0

        # Day key
        start_str = entry.get("startTime", "")
        try:
            day_key = start_str[:10]  # "2026-06-02"
        except (TypeError, IndexError):
            day_key = "unknown"

        model_agg[model]["cost"] += cost
        model_agg[model]["requests"] += 1
        model_agg[model]["input_tokens"] += prompt_tokens
        model_agg[model]["output_tokens"] += completion_tokens
        model_agg[model]["cache_creation_tokens"] += cache_creation
        model_agg[model]["cache_read_tokens"] += cache_read

        day_agg[day_key]["cost"] += cost
        day_agg[day_key]["requests"] += 1

        total_cost += cost
        total_requests += 1
        total_input += prompt_tokens
        total_output += completion_tokens
        total_cache_creation += cache_creation
        total_cache_read += cache_read

    by_model = sorted(
        [
            {"model": model, **data}
            for model, data in model_agg.items()
        ],
        key=lambda x: x["cost"],
        reverse=True,
    )

    by_day = sorted(
        [
            {"date": day, **data}
            for day, data in day_agg.items()
        ],
        key=lambda x: x["date"],
    )

    return {
        "by_model": by_model,
        "by_day": by_day,
        "totals": {
            "total_cost": round(total_cost, 4),
            "total_requests": total_requests,
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "cache_creation_tokens": total_cache_creation,
            "cache_read_tokens": total_cache_read,
        },
    }
