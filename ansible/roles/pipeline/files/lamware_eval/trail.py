# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Read a run's forensic trail and print the timeline.

Written because reconstructing one qwen@30 run by hand cost an hour and produced three
wrong conclusions on the way. Everything this prints was derived manually from a
llama.cpp container log on 2026-07-28; the point is that it should never need deriving
again.

    python -m lamware_eval.trail <path/to/*.trail.jsonl>

Reads a trail written by stages.interpret.TurnTrail. Tolerates a truncated final line —
a SIGKILLed run can leave a partial write, and refusing to parse the file at that point
would defeat its purpose.
"""
import json
import sys
from pathlib import Path

# A turn costing more than this is worth calling out. The 2026-07-28 run had two turns
# over 20 minutes that together were 55 of its 86 minutes of model time.
SLOW_TURN_SECONDS = 300


def load(path: str | Path) -> list[dict]:
    """Parse the trail, skipping a partial final line rather than failing on it."""
    rows = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            # Only ever legitimate for the LAST line, where a kill interrupted the write.
            print(f"  [!] skipping unparseable line (likely a partial final write): "
                  f"{line[:60]!r}", file=sys.stderr)
    return rows


def summarise(rows: list[dict]) -> dict:
    tools = [r for r in rows if r.get("event") == "tool"]
    by_phase: dict[str, float] = {}
    for a, b in zip(rows, rows[1:]):
        by_phase[a.get("phase", "?")] = by_phase.get(a.get("phase", "?"), 0.0) + (
            b.get("t", 0) - a.get("t", 0))
    by_tool: dict[str, dict] = {}
    for r in tools:
        e = by_tool.setdefault(r.get("tool", "?"), {"calls": 0, "bytes": 0})
        e["calls"] += 1
        e["bytes"] += r.get("result_bytes", 0)
    return {
        "events": len(rows),
        "tool_calls": len(tools),
        "total_result_bytes": tools[-1]["cumulative_result_bytes"] if tools else 0,
        "seconds_by_phase": by_phase,
        "by_tool": by_tool,
        "completed": any(r.get("event") == "final" for r in rows),
        "killed": any(r.get("event") == "container_exited_without_final" for r in rows),
    }


def render(rows: list[dict]) -> str:
    out = ["", "=== timeline ===",
           "   t(min)  phase      event      detail"]
    prev_t = 0.0
    for r in rows:
        t = r.get("t", 0)
        gap = t - prev_t
        prev_t = t
        detail = ""
        if r.get("event") == "tool":
            detail = (f"{r.get('tool')} -> {r.get('result_bytes', 0):,}B "
                      f"(cum {r.get('cumulative_result_bytes', 0):,}B)")
            if r.get("error"):
                detail += f"  ERROR: {r['error'][:60]}"
        elif r.get("event") == "status":
            detail = r.get("message", "")[:70]
        elif r.get("event") == "final":
            detail = (f"tool_calls={r.get('tool_calls_used')} "
                      f"analysis={'yes' if r.get('has_analysis') else 'NO'}")
        else:
            detail = ", ".join(f"{k}={v}" for k, v in r.items()
                               if k not in ("seq", "t", "phase", "event"))[:70]
        flag = "  <-- SLOW" if gap >= SLOW_TURN_SECONDS else ""
        out.append(f"  {t/60:7.1f}  {r.get('phase','?'):<9} {r.get('event','?'):<10} "
                   f"{detail}{flag}")

    s = summarise(rows)
    out += ["", "=== summary ===",
            f"  events           : {s['events']}",
            f"  tool calls       : {s['tool_calls']}",
            f"  tool result bytes: {s['total_result_bytes']:,}",
            f"  completed        : {s['completed']}",
            f"  killed mid-run   : {s['killed']}", ""]
    out.append("  time by phase:")
    for phase, secs in s["seconds_by_phase"].items():
        out.append(f"    {phase:<10} {secs/60:7.1f} min")
    out.append("")
    out.append("  by tool (calls / bytes returned):")
    for tool, e in sorted(s["by_tool"].items(), key=lambda kv: -kv[1]["bytes"]):
        out.append(f"    {tool:<22} {e['calls']:3d} calls  {e['bytes']:>10,}B")
    return "\n".join(out)


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    rows = load(sys.argv[1])
    if not rows:
        print("  (empty trail — the run died before its first event)")
        raise SystemExit(1)
    print(render(rows))


if __name__ == "__main__":
    main()
