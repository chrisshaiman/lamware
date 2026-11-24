#!/usr/bin/env python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A loopback stand-in for a model: valid, fixed replies to every LLM stage (ADR-036).

The `stub` LLM profile points every LLM stage here, through LiteLLM's `stub` alias,
so a run exercises the whole pipeline in minutes, for free and deterministically:
permission phases (ADR-031) and the coverage corpus need every stage to *run*, not
to analyse well. It proves the plumbing, not that a real model can drive the tools.

It speaks one API, Anthropic Messages (POST /v1/messages, streaming or not, and
/v1/messages/count_tokens). The pipeline's OpenAI-wire calls reach it too: LiteLLM
translates them for an `anthropic/` alias. What it answers:

  1. A forced tool_choice ("tool" or "any"): that tool (or the first), with
     arguments built from the tool's JSON schema.
  2. Tools offered and no tool_result yet in the conversation: one call to the
     first tool, so the agent's tool path runs once.
  3. Otherwise text. If the system prompt lists its output keys ("Respond with a
     JSON object containing:" then "- key: description" lines), a JSON object with
     those keys, typed from each description. Without such a list, a short prose
     reply.

Every reply carries a usage block (CLAUDE.md section 10). Strings are never empty,
because some stages treat an empty field as a failed analysis. Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

log = logging.getLogger("llm-stub")
STUB_TEXT = "stub"
MAX_DEPTH = 6
MAX_BODY = 64 * 1024 * 1024

# --------------------------------------------------------------------- schema fill


def fill(schema: Any, depth: int = 0, defs: dict | None = None) -> Any:
    """A minimal value that satisfies a JSON schema: enums take their first value,
    arrays get one item (or minItems), objects get every listed property."""
    if not isinstance(schema, dict) or depth > MAX_DEPTH:
        return STUB_TEXT
    defs = defs if defs is not None else {**schema.get("$defs", {}), **schema.get("definitions", {})}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/"):
        return fill(defs.get(ref.rsplit("/", 1)[-1], {}), depth + 1, defs)
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        return schema["enum"][0]
    for key in ("anyOf", "oneOf", "allOf"):
        options = [o for o in schema.get(key) or [] if isinstance(o, dict) and o.get("type") != "null"]
        if options:
            return fill(options[0], depth + 1, defs)
    if "default" in schema and schema["default"] not in (None, "", [], {}):
        return schema["default"]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")
    if kind is None:
        kind = "object" if "properties" in schema else "array" if "items" in schema else "string"
    if kind == "string":
        n = max(int(schema.get("minLength") or 0), len(STUB_TEXT))
        return (STUB_TEXT * n)[:n] if schema.get("maxLength") is None else STUB_TEXT[: max(1, schema["maxLength"])]
    if kind == "integer":
        return int(schema.get("minimum", 0) or 0)
    if kind == "number":
        return float(schema.get("minimum", 0) or 0)
    if kind == "boolean":
        return False
    if kind == "array":
        n = max(1, int(schema.get("minItems") or 0))
        return [fill(schema.get("items", {}), depth + 1, defs) for _ in range(n)]
    if kind == "object":
        props = schema.get("properties") or {}
        return {k: fill(v, depth + 1, defs) for k, v in props.items()}
    return STUB_TEXT


# -------------------------------------------------------------- prompt-derived reply

_LIST_MARK = re.compile(r"(must contain|containing)\s*:\s*\Z", re.I)   # one line at a time
_BULLET = re.compile(r"-\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)\Z")
_OBJ_KEYS = re.compile(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:')
_ENUM = re.compile(r'"([^"]+)"\s*\|')


def value_for(description: str) -> Any:
    """A value typed from a prompt's description of one output key."""
    d = description.strip()
    low = d.lower()
    if low.startswith("list"):
        brace = d.find("{")
        if brace != -1:
            keys = _OBJ_KEYS.findall(d[brace: d.find("}", brace) + 1 or None])
            return [{k: STUB_TEXT for k in keys}] if keys else [STUB_TEXT]
        return [STUB_TEXT]
    enum = _ENUM.match(d)
    if enum:
        return enum.group(1)
    if low.startswith(("integer", "int ", "number", "float")):
        return 0
    if low.startswith(("boolean", "bool", "true", "false")):
        return False
    return STUB_TEXT


def keys_from_prompt(system_text: str) -> dict[str, Any]:
    """The keys a prompt's "... containing:" list asks for, each with a typed value."""
    out: dict[str, Any] = {}
    listing = False
    for line in system_text.splitlines():
        if _LIST_MARK.search(line):
            listing, out = True, {}
            continue
        if not listing:
            continue
        m = _BULLET.match(line.strip())
        if m:
            out[m.group(1)] = value_for(m.group(2))
        elif out and line.strip() and not line.startswith((" ", "\t")):
            listing = False
    return out


def system_text(body: dict) -> str:
    sysp = body.get("system")
    if isinstance(sysp, str):
        return sysp
    if isinstance(sysp, list):
        return "\n".join(b.get("text", "") for b in sysp if isinstance(b, dict))
    return ""


# -------------------------------------------------------------------------- answer


def _has_tool_result(messages: list) -> bool:
    for m in messages or []:
        content = m.get("content") if isinstance(m, dict) else None
        if isinstance(content, list) and any(isinstance(b, dict) and b.get("type") == "tool_result"
                                             for b in content):
            return True
    return False


def _approx_tokens(obj: Any) -> int:
    return max(1, len(json.dumps(obj, default=str)) // 4)


def answer(body: dict) -> dict:
    """The full (non-streamed) Messages response for a request body."""
    tools = [t for t in body.get("tools") or [] if isinstance(t, dict) and t.get("name")]
    choice = body.get("tool_choice") or {}
    forced = isinstance(choice, dict) and choice.get("type") in ("tool", "any")
    seed = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:16]
    if tools and (forced or not _has_tool_result(body.get("messages"))):
        tool = next((t for t in tools if t["name"] == choice.get("name")), tools[0]) \
            if isinstance(choice, dict) else tools[0]
        content = [{"type": "tool_use", "id": f"toolu_stub_{seed}", "name": tool["name"],
                    "input": fill(tool.get("input_schema") or {})}]
        stop = "tool_use"
    else:
        keys = keys_from_prompt(system_text(body))
        text = json.dumps(keys) if keys else (
            "This is a stub reply from the lamware test backend. No model analysed this sample.")
        content = [{"type": "text", "text": text}]
        stop = "end_turn"
    return {
        "id": f"msg_stub_{seed}", "type": "message", "role": "assistant",
        "model": body.get("model") or "stub", "content": content,
        "stop_reason": stop, "stop_sequence": None,
        "usage": {"input_tokens": _approx_tokens(body.get("messages")) + _approx_tokens(body.get("system")),
                  "output_tokens": _approx_tokens(content),
                  "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0},
    }


def sse_events(msg: dict) -> list[tuple[str, dict]]:
    """The Anthropic streaming events that build `msg`."""
    start = {**msg, "content": [], "stop_reason": None,
             "usage": {**msg["usage"], "output_tokens": 1}}
    events: list[tuple[str, dict]] = [("message_start", {"type": "message_start", "message": start})]
    for i, block in enumerate(msg["content"]):
        if block["type"] == "text":
            events += [("content_block_start", {"type": "content_block_start", "index": i,
                                                "content_block": {"type": "text", "text": ""}}),
                       ("content_block_delta", {"type": "content_block_delta", "index": i,
                                                "delta": {"type": "text_delta", "text": block["text"]}})]
        else:
            events += [("content_block_start", {"type": "content_block_start", "index": i,
                                                "content_block": {**block, "input": {}}}),
                       ("content_block_delta", {"type": "content_block_delta", "index": i,
                                                "delta": {"type": "input_json_delta",
                                                          "partial_json": json.dumps(block["input"])}})]
        events.append(("content_block_stop", {"type": "content_block_stop", "index": i}))
    events += [("message_delta", {"type": "message_delta",
                                  "delta": {"stop_reason": msg["stop_reason"], "stop_sequence": None},
                                  "usage": {"output_tokens": msg["usage"]["output_tokens"]}}),
               ("message_stop", {"type": "message_stop"})]
    return events


# -------------------------------------------------------------------------- server


class StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"   # a streamed body ends at connection close
    server_version = "llm-stub"
    sys_version = ""

    def version_string(self) -> str:
        # No trailing space: LiteLLM's h11 refuses "Server: llm-stub " (see anthropic-wif).
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        log.info("event=http %s", format % args)

    def _json(self, status: int, obj: dict) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path.split("?")[0] in ("/health", "/v1/health"):
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "llm-stub"}})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._json(413, {"type": "error", "error": {"type": "request_too_large", "message": "llm-stub"}})
            return
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"type": "error", "error": {"type": "invalid_request_error",
                                                        "message": "llm-stub: body is not JSON"}})
            return
        if path == "/v1/messages/count_tokens":
            self._json(200, {"input_tokens": _approx_tokens(body.get("messages"))})
            return
        if path != "/v1/messages":
            self._json(404, {"type": "error", "error": {"type": "not_found_error",
                                                        "message": f"llm-stub serves /v1/messages, not {path}"}})
            return
        msg = answer(body)
        log.info("event=answered model=%s stream=%s stop=%s tools=%d", msg["model"],
                 bool(body.get("stream")), msg["stop_reason"], len(body.get("tools") or []))
        if not body.get("stream"):
            self._json(200, msg)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for name, data in sse_events(msg):
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11436)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s %(message)s")
    if not ipaddress.ip_address(args.host).is_loopback:
        log.error("event=config_error refusing a non-loopback listen address %s", args.host)
        return 2
    server = ThreadingHTTPServer((args.host, args.port), StubHandler)
    server.daemon_threads = True
    log.info("event=listening host=%s port=%d", args.host, args.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
