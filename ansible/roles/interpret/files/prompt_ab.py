# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Paired A/B of PROMPT VARIANTS against one fixed transcript.

Sibling of llm_ab_re.py, and deliberately the other axis. `llm_ab_re.py` replays the
agentic loop once per MODEL, so each arm generates its own transcript — fine for
comparing models, useless for comparing prompts, because the thing you changed and the
conversation it ran against both moved at once.

This holds the transcript fixed and varies only the final user message. That is the
only way to attribute a difference to the prompt.

Runs INSIDE the interpret container so the transport is the production one: same image,
same anthropic client over the bind-mounted LiteLLM socket, same CACHED_SYSTEM and TOOLS
blocks that interpret-ghidra.py itself builds. A probe that constructs its own client is
measuring its own plumbing.

Built for #260 ("does /no_think empty phase 2a?"), which turned on a distinction no
cheaper method could make: the model generated ~2,000 tokens in every arm, so token
counts said "not empty" while the actual question was whether any of them were VISIBLE
TEXT rather than an empty thinking block. Hence the block-level reporting.

## Transcript source

Rebuilt from a run's `llm_audit/tool_calls.json` — real decompilation, real strings, at
real scale. #260's original probe used one paragraph repeated 40x, and "thin input a
model might reasonably decline to summarise" turned out to be exactly the confound: the
failure did not reproduce against a real investigation.

The rebuild is lossy in one known way: the audit log records tool calls and results but
not the model's prose BETWEEN them, so the transcript carries tool_use/tool_result
blocks without interstitial assistant text. Both arms get the byte-identical transcript,
so it is a paired comparison and the gap cancels. It would matter only if that missing
prose is what changes the model's willingness to answer.

## Usage (from the host, via run-prompt-ab)

    run-prompt-ab --audit /path/to/tool_calls.json \
                  --model local-qwen-llamacpp-re-s42 \
                  --suffix ' /no_think' --repeats 2

`--suffix` defines arm B; arm A is always the bare prompt. Prefer a SEEDED model alias
(#222): without one, sampling variance swamps the effect — measured spread across seeds
on the same arm and sample was 3.3x in wall-clock.

Costs one full prompt evaluation for the first request; every later arm reuses the KV
prefix, since only the final message differs. Measured at 58k tokens: 68 minutes cold,
then ~6 seconds per subsequent arm.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from typing import Any

CONTAINER_SCRIPT = "/opt/interpret-ghidra.py"

DEFAULT_INIT = (
    "You are reverse-engineering a Windows PE sample in Ghidra. Investigate its "
    "capabilities, network behaviour and configuration using the available tools, "
    "then report what it does."
)


def load_container_module(path: str = CONTAINER_SCRIPT):
    """Import interpret-ghidra.py for its system prompt, tools and client builder.

    Its `main()` is behind a `__name__` guard and it has no top-level side effects, so
    loading it is inert. Taking CACHED_SYSTEM and TOOLS from the real module rather
    than restating them is the point: a restated copy drifts, and a drifted prompt
    silently makes the arms incomparable to production.
    """
    spec = importlib.util.spec_from_file_location("_interpret_for_ab", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rebuild_transcript(audit: list[dict], init_text: str = DEFAULT_INIT) -> list[dict]:
    """Anthropic-format transcript from an audit log of {tool, args, result}.

    Every tool_use MUST be answered by a tool_result with a matching id or the API
    rejects the next request outright, so ids are generated in lockstep here rather
    than reused from the log (which does not record them).
    """
    messages: list[dict[str, Any]] = [{"role": "user", "content": init_text}]
    for index, entry in enumerate(audit):
        call_id = f"toolu_replay{index:04d}"
        messages.append({"role": "assistant", "content": [{
            "type": "tool_use",
            "id": call_id,
            "name": entry.get("tool", "unknown"),
            "input": entry.get("args") or {},
        }]})
        payload = entry.get("result", entry.get("error", ""))
        messages.append({"role": "user", "content": [{
            "type": "tool_result",
            "tool_use_id": call_id,
            "content": json.dumps(payload, default=str),
        }]})
    return messages


def describe(response) -> dict:
    """Block-level summary of one response.

    Reports text and thinking SEPARATELY because that distinction is the whole reason
    this exists. #260's failure was `0 content blocks, stop=end_turn` while the model
    was still generating — so output-token counts, wall-clock and stop_reason all look
    healthy in the exact case being investigated. Only the block split separates a real
    answer from an empty one.
    """
    blocks = list(getattr(response, "content", []) or [])
    text = "".join(getattr(b, "text", "") for b in blocks
                   if getattr(b, "type", "") == "text")
    thinking = "".join(getattr(b, "thinking", "") for b in blocks
                       if getattr(b, "type", "") == "thinking")
    usage = getattr(response, "usage", None)
    return {
        "blocks": len(blocks),
        "block_types": ",".join(sorted({getattr(b, "type", "?") for b in blocks})) or "-",
        "text_chars": len(text),
        "thinking_chars": len(thinking),
        "stop_reason": getattr(response, "stop_reason", "?"),
        "in_tok": getattr(usage, "input_tokens", None),
        "out_tok": getattr(usage, "output_tokens", None),
        "text_head": text[:200].replace("\n", " "),
    }


def summarise(rows: list[dict], arm_names: list[str]) -> list[str]:
    """Per-arm verdict, with generation RATE rather than raw wall-clock.

    Wall-clock alone is misleading and was the substance of #260's error: the original
    "154s -> 115s, no loss of substance" reading vanished once normalised. Measured,
    the two arms generated at 5.01 and 5.03 tok/s — identical — and the entire time
    difference was one arm choosing to emit 406 more tokens. Reporting tok/s alongside
    wall-clock makes that visible instead of inviting the same conclusion twice.
    """
    out = ["", "=== verdict ==="]
    for arm in arm_names:
        mine = [r for r in rows if r["arm"] == arm]
        if not mine:
            continue
        empty = sum(1 for r in mine if r["text_chars"] == 0)
        texts = sorted(r["text_chars"] for r in mine)
        walls = sorted(r["wall"] for r in mine)
        rates = [r["out_tok"] / r["wall"] for r in mine
                 if r.get("out_tok") and r.get("wall")]
        rate = f"{sum(rates) / len(rates):.2f} tok/s" if rates else "n/a"
        out.append(f"  {arm:<22} empty {empty}/{len(mine)}   "
                   f"median text {texts[len(texts) // 2]:,} chars   "
                   f"median wall {walls[len(walls) // 2]:.1f}s   gen {rate}")
    return out


def build_client(module, api_key: str):
    import anthropic
    kwargs: dict[str, Any] = {"api_key": api_key, "timeout": module.LLM_TIMEOUT_S}
    base = os.environ.get("LITELLM_BASE_URL", "")
    if base:
        kwargs["base_url"] = base
    uds = os.environ.get("LITELLM_UDS", "")
    if uds:
        kwargs["http_client"] = module._uds_client(uds)
    return anthropic.Anthropic(**kwargs)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--audit", default="/opt/audit.json",
                    help="llm_audit/tool_calls.json to rebuild the transcript from")
    ap.add_argument("--model", default="local-qwen-llamacpp-re-s42",
                    help="model alias; prefer a SEEDED one so sampling is controlled")
    ap.add_argument("--prompt", default=None,
                    help="final user message (defaults to phase 2a's, read from the "
                         "container script so it cannot drift)")
    ap.add_argument("--suffix", default=" /no_think",
                    help="appended to form arm B; arm A is the bare prompt")
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--max-tokens", type=int, default=8192)
    ap.add_argument("--out", default="/opt/out/prompt_ab_results.json")
    args = ap.parse_args()

    api_key = os.environ.get("LITELLM_API_KEY", "")
    if not api_key:
        print("ERROR: LITELLM_API_KEY is not set. Forward it by NAME "
              "(`-e LITELLM_API_KEY`), never inline in argv — /proc/<pid>/cmdline is "
              "world-readable (#238).", file=sys.stderr)
        return 2

    module = load_container_module()
    with open(args.audit) as fh:
        audit = json.load(fh)
    messages = rebuild_transcript(audit)

    base_prompt = args.prompt or (
        "Based on your investigation, summarize your findings and state your "
        "conclusion in prose: malware family, capabilities, MITRE techniques, and "
        "notable code-level IOCs. Do not output JSON.")
    arms = [("bare", base_prompt),
            (f"+{args.suffix.strip()}", base_prompt + args.suffix)]

    size = len(json.dumps(messages, default=str))
    print(f"  transcript : {len(audit)} tool calls, {len(messages)} messages, "
          f"{size:,} chars")
    print(f"  model      : {args.model}   repeats: {args.repeats}")
    print(f"  arms       : {', '.join(name for name, _ in arms)}\n")

    client = build_client(module, api_key)
    header = (f"  {'arm':<22} {'rep':<4} {'wall':>9} {'blocks':>7} {'types':<16} "
              f"{'text':>7} {'think':>7} {'stop':<12} {'in_tok':>8}")
    print(header)
    print("  " + "-" * (len(header) - 2))

    rows: list[dict] = []
    for rep in range(1, args.repeats + 1):
        # Arms interleave within a repeat so server-side drift — cache state, thermal —
        # lands on both rather than on whichever ran last.
        for arm_name, prompt in arms:
            started = time.time()
            try:
                response = module.create_message(
                    client, model=args.model, max_tokens=args.max_tokens,
                    system=module.CACHED_SYSTEM, tools=module.TOOLS,
                    messages=messages + [{"role": "user", "content": prompt}])
                row = describe(response)
                row["error"] = None
            except Exception as exc:  # noqa: BLE001 - a failed arm is a result
                row = {"blocks": 0, "block_types": "ERROR", "text_chars": 0,
                       "thinking_chars": 0, "stop_reason": type(exc).__name__,
                       "in_tok": None, "out_tok": None,
                       "text_head": str(exc)[:200], "error": str(exc)[:400]}
            row.update({"arm": arm_name, "rep": rep, "wall": time.time() - started})
            rows.append(row)
            print(f"  {arm_name:<22} {rep:<4} {row['wall']:>8.1f}s {row['blocks']:>7} "
                  f"{row['block_types']:<16} {row['text_chars']:>7} "
                  f"{row['thinking_chars']:>7} {str(row['stop_reason']):<12} "
                  f"{str(row['in_tok']):>8}")

    print("\n  === opening of each response ===")
    for row in rows:
        print(f"  [{row['arm']} rep{row['rep']}] "
              f"{row['text_head'] or '(EMPTY — no text block)'}")
    print("\n".join(summarise(rows, [name for name, _ in arms])))

    try:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as fh:
            json.dump(rows, fh, indent=2, default=str)
        print(f"\n  results -> {args.out}")
    except OSError as exc:
        print(f"  [!] could not write {args.out}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
