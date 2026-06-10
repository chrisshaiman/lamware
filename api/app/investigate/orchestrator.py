# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# LLM conversation orchestrator for the investigation agent.
#
# run_conversation_turn() drives one full turn: it sends messages to the
# LiteLLM proxy (OpenAI-compatible streaming API), yields SSE-shaped event
# dicts as an async generator, dispatches tool calls via execute_tool(), and
# loops until the model produces a final text response.
#
# The messages list is MUTATED in place — assistant and tool messages are
# appended after each LLM call so the router can persist the full history
# after the generator is exhausted.
#
# Event types yielded:
#   token        — {"content": str}           streaming text fragment
#   tool_call    — {"tool": str, "args": dict}
#   tool_result  — {"tool": str, "result": dict}
#   pin_proposal — {"proposal": dict}         when pin_finding returns status=proposed
#   done         — {"input_tokens": int, "output_tokens": int,
#                   "cost": float, "tool_calls_used": int}
#   error        — {"message": str}

import asyncio
import json
import logging
from typing import AsyncGenerator

import httpx

from ..config import settings
from .tools import TOOL_DEFINITIONS, execute_tool

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cost table — USD per token (input / output)
# ---------------------------------------------------------------------------

MODEL_COSTS: dict[str, dict[str, float]] = {
    "claude-sonnet-4-6": {"input": 3e-6, "output": 15e-6},
    "claude-opus-4-6": {"input": 5e-6, "output": 25e-6},
    "claude-haiku-4-5": {"input": 1e-6, "output": 5e-6},
}

# ---------------------------------------------------------------------------
# Pure helpers — unit-testable without httpx or asyncio
# ---------------------------------------------------------------------------


def parse_stream_line(line: str) -> dict | None:
    """Parse one SSE line from the LLM stream into a chunk dict, or None.

    Returns None for blank lines, non-data lines, and the [DONE] sentinel.
    Returns None (and logs a warning) on JSON decode errors so the caller
    can skip the line without crashing.
    """
    if not line.startswith("data: "):
        return None
    payload = line[len("data: "):]
    if payload.strip() == "[DONE]":
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        log.warning("Skipping malformed SSE line: %r", line[:200])
        return None


class ToolCallAccumulator:
    """Accumulate streaming tool-call deltas into complete tool-call blocks.

    OpenAI streaming splits tool calls across many chunks. The index field
    identifies which tool call a delta belongs to — a new entry appears when
    function.name is present; subsequent deltas append arguments fragments.
    Parallel tool calls interleave by index so we key by index, not position.
    """

    def __init__(self) -> None:
        # keyed by delta index (int)
        self._calls: dict[int, dict] = {}

    def add_delta(self, delta_tool_calls: list[dict]) -> None:
        """Process one chunk's tool_calls delta list."""
        for delta in delta_tool_calls:
            idx = delta.get("index", 0)
            fn = delta.get("function") or {}

            if idx not in self._calls:
                # First chunk for this index — initialise the entry.
                # id may not be present on every delta; fall back to empty str
                self._calls[idx] = {
                    "id": delta.get("id") or "",
                    "name": fn.get("name") or "",
                    "arguments": fn.get("arguments") or "",
                }
            else:
                # Subsequent chunks — accumulate
                if delta.get("id"):
                    self._calls[idx]["id"] = delta["id"]
                if fn.get("name"):
                    self._calls[idx]["name"] += fn["name"]
                if fn.get("arguments"):
                    self._calls[idx]["arguments"] += fn["arguments"]

    def blocks(self) -> list[dict]:
        """Return complete tool-call blocks sorted by index.

        Each block: {"id": str, "name": str, "arguments": str}
        """
        return [self._calls[i] for i in sorted(self._calls)]

    def __bool__(self) -> bool:
        return bool(self._calls)


# ---------------------------------------------------------------------------
# OpenAI tool format conversion
# ---------------------------------------------------------------------------

def _build_openai_tools() -> list[dict]:
    """Convert TOOL_DEFINITIONS (Claude input_schema) to OpenAI tools format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in TOOL_DEFINITIONS
    ]


# ---------------------------------------------------------------------------
# Main async generator
# ---------------------------------------------------------------------------


async def run_conversation_turn(
    messages: list[dict],
    system_prompt: str,
    model: str,
    session,          # sqlmodel.Session — kept untyped to avoid import at top level
    report: dict,
    analysis_id: int,
) -> AsyncGenerator[dict, None]:
    """Drive one full conversation turn, yielding SSE-shaped event dicts.

    IMPORTANT: `messages` is mutated in place — assistant and tool messages
    are appended so the router can persist the full conversation history after
    this generator is exhausted.

    Yields event dicts: {"event": <type>, "data": <dict>}
    """
    openai_tools = _build_openai_tools()
    total_input_tokens = 0
    total_output_tokens = 0
    tool_calls_used = 0

    async with httpx.AsyncClient(timeout=300.0) as client:
        while True:
            # Build the request body
            body = {
                "model": model,
                "messages": [{"role": "system", "content": system_prompt}] + messages,
                "tools": openai_tools,
                "max_tokens": 4096,
                "stream": True,
                "stream_options": {"include_usage": True},
            }

            # --- Streaming call ---
            accumulated_text = ""
            accumulator = ToolCallAccumulator()
            call_failed = False

            try:
                async with client.stream(
                    "POST",
                    f"{settings.litellm_url}/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.litellm_key}",
                        "Content-Type": "application/json",
                    },
                    content=json.dumps(body),
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        chunk = parse_stream_line(line)
                        if chunk is None:
                            continue

                        # Capture usage (usually on the final usage-only chunk)
                        usage = chunk.get("usage")
                        if usage:
                            total_input_tokens += usage.get("prompt_tokens", 0)
                            total_output_tokens += usage.get("completion_tokens", 0)

                        # Guard: choices may be empty on the usage-only chunk
                        choice = (chunk.get("choices") or [{}])[0]
                        delta = choice.get("delta") or {}

                        # Text token
                        content = delta.get("content")
                        if content:
                            accumulated_text += content
                            yield {"event": "token", "data": {"content": content}}

                        # Tool-call delta
                        tc_deltas = delta.get("tool_calls")
                        if tc_deltas:
                            accumulator.add_delta(tc_deltas)

            except httpx.HTTPStatusError as exc:
                log.error("LiteLLM HTTP error: %s", exc)
                yield {"event": "error", "data": {"message": f"LLM API error: {exc.response.status_code}"}}
                return
            except httpx.RequestError as exc:
                log.error("LiteLLM request error: %s", exc)
                yield {"event": "error", "data": {"message": f"LLM request failed: {exc}"}}
                return

            # --- Decide what to do with the response ---
            tool_blocks = accumulator.blocks()

            if not tool_blocks:
                # Final text response — append to messages and break
                messages.append({"role": "assistant", "content": accumulated_text})
                break

            # --- Tool loop ---
            # Enforce per-turn cap before executing anything
            if tool_calls_used + len(tool_blocks) > settings.investigation_max_tool_calls_per_turn:
                log.warning(
                    "Tool call limit (%d) exceeded in turn — stopping",
                    settings.investigation_max_tool_calls_per_turn,
                )
                yield {
                    "event": "error",
                    "data": {
                        "message": (
                            f"Tool call limit ({settings.investigation_max_tool_calls_per_turn}) "
                            "exceeded for this turn."
                        ),
                    },
                }
                messages.append({
                    "role": "assistant",
                    "content": (
                        f"I have reached the tool call limit "
                        f"({settings.investigation_max_tool_calls_per_turn} per turn) and cannot "
                        "continue this turn. Please start a new message to continue."
                    ),
                })
                break

            # Append the assistant message with tool_calls in OpenAI format
            assistant_msg: dict = {
                "role": "assistant",
                "content": accumulated_text or None,
                "tool_calls": [
                    {
                        "id": blk["id"],
                        "type": "function",
                        "function": {
                            "name": blk["name"],
                            "arguments": blk["arguments"],
                        },
                    }
                    for blk in tool_blocks
                ],
            }
            messages.append(assistant_msg)

            # Execute each tool call
            for blk in tool_blocks:
                tool_name = blk["name"]
                call_id = blk["id"]
                raw_args = blk["arguments"]

                # Parse JSON arguments — invalid JSON becomes empty dict
                try:
                    args = json.loads(raw_args) if raw_args.strip() else {}
                except json.JSONDecodeError:
                    log.warning(
                        "Tool %s received invalid JSON args: %r — using {}",
                        tool_name, raw_args[:200],
                    )
                    args = {}

                yield {"event": "tool_call", "data": {"tool": tool_name, "args": args}}

                # execute_tool is sync and may block up to 130s (Ghidra) — offload
                result = await asyncio.to_thread(
                    execute_tool, tool_name, args, session, report, analysis_id
                )

                # Emit pin_proposal event when pin_finding returns a proposal
                if tool_name == "pin_finding" and result.get("status") == "proposed":
                    yield {"event": "pin_proposal", "data": {"proposal": result}}

                yield {"event": "tool_result", "data": {"tool": tool_name, "result": result}}

                # Append tool result message
                messages.append({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "content": json.dumps(result),
                })

                tool_calls_used += 1

            # Loop back to call the LLM again with tool results

    # Compute cost
    costs = MODEL_COSTS.get(model, {"input": 0.0, "output": 0.0})
    cost = (
        total_input_tokens * costs["input"]
        + total_output_tokens * costs["output"]
    )

    yield {
        "event": "done",
        "data": {
            "input_tokens": total_input_tokens,
            "output_tokens": total_output_tokens,
            "cost": round(cost, 6),
            "tool_calls_used": tool_calls_used,
        },
    }
