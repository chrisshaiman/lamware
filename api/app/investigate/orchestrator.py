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
from collections.abc import AsyncGenerator

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
# Thread-safe tool execution helper
# ---------------------------------------------------------------------------


def _execute_tool_with_own_session(tool_name: str, args: dict, report: dict, analysis_id: int) -> dict:
    """Tool DB reads get their own session — SQLAlchemy sessions must not
    cross threads, and the request session stays free for stream persistence.

    execute_tool is sync and may block up to 130s (Ghidra); it is called via
    asyncio.to_thread. The request-scoped Session must never be passed into a
    thread — create a short-lived session here instead.
    """
    from sqlmodel import Session

    from ..database import engine
    try:
        with Session(engine) as tool_session:
            return execute_tool(tool_name, args, tool_session, report, analysis_id)
    except Exception as e:  # noqa: BLE001 - must not escape; see below
        # Session construction happens OUTSIDE execute_tool's try, so an
        # unreachable engine or an exhausted pool raised here, propagated through
        # asyncio.to_thread, and escaped the tool loop. By then the assistant
        # message carrying `tool_calls` is already in `messages`, so the turn ends
        # with a tool call that has no matching `role: "tool"` reply — a malformed
        # conversation the provider rejects, from a transient DB blip.
        #
        # execute_tool promises "always returns a JSON-safe dict, never raises".
        # That promise only held for the dispatch it wraps, not for getting a
        # session in the first place. Same disclosure rule as execute_tool: full
        # detail to the server log, exception TYPE only to the model, so a DSN or
        # host name cannot ride out in an error string.
        log.exception("Tool %s failed before dispatch", tool_name)
        return {"error": f"{tool_name} failed ({type(e).__name__})"}


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
    # Checked once, up front: without a key every turn 401s, and the retry/stream
    # error path reports that as an upstream failure rather than as missing deploy
    # config. There is no default key to fall back on by design (#238).
    if not settings.litellm_key:
        log.error("LAMWARE_LITELLM_KEY is not set — investigation agent cannot "
                  "authenticate to LiteLLM. Written by lamware-api.env.j2 from the "
                  "vault variable litellm_master_key.")
        yield {"event": "error",
               "data": {"message": "LiteLLM key not configured (LAMWARE_LITELLM_KEY)"}}
        return

    openai_tools = _build_openai_tools()
    total_input_tokens = 0
    total_output_tokens = 0
    tool_calls_used = 0
    errored = False

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

            try:
                async with client.stream(
                    "POST",
                    f"{settings.litellm_url}/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.litellm_key}",
                        "Content-Type": "application/json",
                    },
                    content=json.dumps(body, default=str),
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

            # Both handlers BREAK rather than return. The router persists the
            # assistant message and the session's token/cost columns only in its
            # `done` branch, so returning here threw away everything the earlier
            # rounds had already produced: the prose the analyst watched stream,
            # and the tokens they were billed for. Breaking falls through to the
            # cost computation and the `done` yield below, which is also what
            # puts the partial answer into the next turn's rebuilt history —
            # without it the transcript holds two consecutive user messages.
            except httpx.HTTPStatusError as exc:
                log.error("LiteLLM HTTP error: %s", exc)
                yield {"event": "error", "data": {"message": f"LLM API error: {exc.response.status_code}"}}
                errored = True
                break
            except httpx.RequestError as exc:
                # Full detail (which can include the internal proxy URL) goes to
                # the server log only; the client gets a generic message.
                log.error("LiteLLM request error: %s", exc)
                yield {"event": "error", "data": {"message": "LLM request failed (proxy unreachable)"}}
                errored = True
                break

            # --- Decide what to do with the response ---
            tool_blocks = accumulator.blocks()

            if not tool_blocks:
                # Final text response — append to messages and break
                #
                # No prompt-influence keyword scan here (unlike the pipeline's check_prompt_influence).
                # That scan guards the pipeline's maliciousness VERDICT ("benign"/"not malicious"). The
                # investigation agent emits no verdict — it is analyst-driven Q&A, output-only (pin_finding
                # returns "proposed"; maliciousness is decided upstream). There is no verdict to protect, so a
                # keyword scan over conversational text would be noisy and actionless. The agent path's controls
                # are containment (no-net/read-only/cap-drop), output-only pins, analyst-auth, and execute_tool
                # arg validation (see tool_validators.py).
                messages.append({"role": "assistant", "content": accumulated_text})
                break

            # --- Tool loop ---
            # Cap is all-or-nothing per batch: if this batch would exceed the limit,
            # none of it executes — keeps history coherent vs partially-executed batches.
            if tool_calls_used + len(tool_blocks) > settings.investigation_max_tool_calls_per_turn:
                log.warning(
                    "Tool call limit (%d) exceeded in turn — stopping",
                    settings.investigation_max_tool_calls_per_turn,
                )
                synthetic_text = (
                    f"I have reached the tool call limit "
                    f"({settings.investigation_max_tool_calls_per_turn} per turn) and cannot "
                    "continue this turn. Please start a new message to continue."
                )
                # Yield the synthetic text as a token event so the router's
                # accumulated assistant_content includes it before the break.
                yield {"event": "token", "data": {"content": synthetic_text}}
                yield {
                    "event": "error",
                    "data": {
                        "message": (
                            f"Tool call limit ({settings.investigation_max_tool_calls_per_turn}) "
                            "exceeded for this turn."
                        ),
                    },
                }
                messages.append({"role": "assistant", "content": synthetic_text})
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
                # to a thread. Each call gets its own short-lived DB session via
                # _execute_tool_with_own_session; SQLAlchemy sessions must not
                # cross thread boundaries.
                result = await asyncio.to_thread(
                    _execute_tool_with_own_session, tool_name, args, report, analysis_id
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
            # A turn that ended on an upstream failure still reports `done` so its
            # work is persisted, so `done` alone no longer means "the model
            # finished". Callers that care about completeness read this.
            "partial": errored,
        },
    }
