"""
Stage 4.5: LLM Interpretation — agentic Claude analysis of Ghidra output.

The orchestrator brokers JSON lines between two containers:
  - interpret container (--network=none; reaches LiteLLM via a bind-mounted Unix
    socket, no host network namespace) holds the Claude conversation
  - Ghidra tool container (--network=none) executes per-query

Tool arguments are validated via regex whitelist before reaching Ghidra.

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import os
import re
import subprocess
import time
from pathlib import Path

from lamware_shared.tool_validators import GHIDRA_ARG_VALIDATORS, validate_ghidra_args

PROMPT_INFLUENCE_KEYWORDS = ["benign", "not malicious", "false positive", "harmless", "safe to run"]

# Local models (small active-param MoE) derail on the full ~200-function list —
# they describe the JSON instead of analyzing. Returning only the top-N functions
# by xref_count keeps the model investigating (probe-validated: 15 works, 200
# derails). Also trims noise + token cost for the cloud model. Applies to both.
LIST_FUNCTIONS_CAP = 15


def cap_list_functions(result: dict, cap: int = LIST_FUNCTIONS_CAP) -> dict:
    """Trim a list_functions result to the top-`cap` functions by xref_count.

    No-op unless the result is the expected {'count', 'functions': [...]} shape
    with more than `cap` entries. Adds a note so the model knows more exist.
    """
    if not isinstance(result, dict):
        return result
    funcs = result.get("functions")
    if not isinstance(funcs, list) or len(funcs) <= cap:
        return result
    total = len(funcs)
    top = sorted(funcs, key=lambda f: f.get("xref_count", 0) if isinstance(f, dict) else 0,
                 reverse=True)[:cap]
    return {**result, "functions": top, "count": len(top),
            "note": f"showing top {len(top)} of {total} functions by xref_count"}


# Tool results are appended to the transcript verbatim and never fall out of it, so
# every oversized body is re-paid on every subsequent turn. The 2026-07-27 depth probe
# died at 20 tool calls with 46,216 tokens against a 32k window.
#
# Measured from that run's tool_calls.json (20 calls, raccoonstealer): 83,259 chars of
# tool output ~= 20,814 tokens, i.e. 45% of the context. 8 results exceeded 6000 chars
# and EVERY one was decompile_function, clustered tightly at ~9,000 chars.
#
# That clustering is why the cap is 12000 and not lower: ~9 KB is the TYPICAL decompiled
# body for this corpus, not an outlier, and trimming every function by a third to save
# ~12% of context is a bad trade against analysis quality. This targets genuine outliers
# only. Raising --ctx-size is the dominant lever; this is the secondary one.
#
# Starting value — tune with the cycle sweep once depth is no longer context-bound.
TOOL_RESULT_CHAR_CAP = 12000


def _marker(omitted: str) -> str:
    """Explicit truncation notice. Never truncate silently.

    A model that receives half a function assumes it saw all of it and makes claims
    about code it was never shown — which the grounding metric then scores as
    fabrication when the HARNESS, not the model, dropped the evidence.
    """
    return (f"\n...[TRUNCATED: {omitted}. Use get_strings_at or decompile a narrower "
            f"target if you need the rest — do not assume the remainder is empty.]")


def cap_tool_result(result: dict, cap: int = TOOL_RESULT_CHAR_CAP) -> dict:
    """Bound the TOTAL serialized size of a tool result before it enters the transcript.

    The previous version capped only `isinstance(value, str)` fields, so a LIST-valued
    result passed through entirely uncapped — `get_strings_at` was measured returning
    **49,613 bytes against a 12,000-char cap**, and the turn that carried it cost 33.4
    minutes of a 180-minute run (#242). Many short string fields whose total was large
    escaped equally.

    Budgeting is total, not per field, because the cost that matters is what the whole
    result adds to the transcript — and it is paid on every later turn, since prompt-eval
    rate falls from 66 to 8.6 tok/s as context grows.

    Small scalar fields are reserved FIRST so a huge `code` or `strings` field cannot
    starve the metadata (status, address, count) that tells the model what it is looking
    at. Lists are trimmed by dropping whole elements — cutting mid-element would emit
    malformed entries the model would try to interpret.

    No-op on results already within budget, so cloud-model behaviour is unchanged.
    """
    if not isinstance(result, dict):
        return result

    def size(value: object) -> int:
        return len(value) if isinstance(value, str) else len(json.dumps(value, default=str))

    # The bookkeeping has to be budgeted too. Two bugs came from not doing that: the
    # per-field truncation markers alone overshot a 2,000-char cap by 3,300 when many
    # fields were trimmed, and the `note` was appended AFTER budgeting, so the result
    # landed over cap and a second pass kept growing it.
    NOTE_ALLOWANCE = 400
    MIN_USEFUL_FIELD = 200  # below this, a fragment plus a marker is worse than nothing
    METADATA_CHARS = 200    # a string this short is a label, not a payload

    def is_payload(key: str, value: object) -> bool:
        # `note` is bookkeeping — never re-truncate it as payload, or capping an
        # already-capped result mangles its own explanation.
        if key == "note":
            return False
        if isinstance(value, list):
            return True
        # Short strings are metadata too: "address": "0x0041b500", "status": "ok".
        # Classifying them as payload meant a tight budget could truncate the very
        # labels that make a truncated result interpretable.
        return isinstance(value, str) and len(value) > METADATA_CHARS

    big = {k: v for k, v in result.items() if is_payload(k, v)}
    small = {k: v for k, v in result.items() if k not in big}

    # Metadata first — it is tiny and it is what makes a truncated result interpretable.
    remaining = cap - NOTE_ALLOWANCE - sum(size(v) for v in small.values())
    out: dict = dict(small)
    notes: list[str] = []
    omitted_fields: list[str] = []

    for key, value in big.items():
        if remaining < MIN_USEFUL_FIELD:
            # Budget gone. Emit nothing rather than a marker per field — the markers
            # were themselves the overrun. One collective note covers them.
            out[key] = [] if isinstance(value, list) else ""
            omitted_fields.append(key)
            continue
        if isinstance(value, str):
            if len(value) <= remaining:
                out[key] = value
                remaining -= len(value)
            else:
                budget = remaining
                out[key] = value[:budget] + _marker(f"{len(value) - budget} more characters")
                notes.append(f"{key}: truncated to {budget} chars")
                remaining = 0
        else:  # list — drop whole elements; a partial element is malformed input
            kept: list = []
            for item in value:
                item_size = size(item)
                if item_size <= remaining:
                    kept.append(item)
                    remaining -= item_size
                else:
                    break
            dropped = len(value) - len(kept)
            out[key] = kept
            if dropped:
                notes.append(f"{key}: kept {len(kept)} of {len(value)} items, "
                             f"{dropped} dropped")

    if omitted_fields:
        notes.append(f"omitted entirely (budget exhausted): {', '.join(omitted_fields)}")
    if notes:
        combined = "; ".join(filter(None, [result.get("note"),
                                           "TRUNCATED — " + "; ".join(notes)]))
        out["note"] = combined[:NOTE_ALLOWANCE]
    elif "note" in result:
        out["note"] = result["note"]
    return out


def validate_tool_args(tool_name: str, args: dict) -> str | None:
    """Validate a pipeline tool call. Preserves the prior Unknown-tool behavior."""
    if tool_name not in GHIDRA_ARG_VALIDATORS:
        return f"Unknown tool: {tool_name}"
    return validate_ghidra_args(tool_name, args)


def ghidra_unavailable_error(analysis_type: str | None) -> str:
    """Error returned to the LLM when it calls a Ghidra tool with no project.

    Non-native analysis paths (script/office/.NET/…) build init payloads with
    no project_dir — no Ghidra project exists for them. Without this guard the
    broker shelled out `run-ghidra --tool "" ""`, and every call failed with a
    confusing "realpath: '': No such file or directory" that polluted the
    final narrative. Tell the LLM plainly, and tell it to stop trying.
    """
    return (
        f"No Ghidra project is available for this analysis "
        f"(analysis_type={analysis_type or 'unknown'}). Ghidra tools only work "
        "for natively analyzed PE/ELF binaries. Do not retry Ghidra tools; "
        "base your analysis on the data already provided."
    )


class TurnTrail:
    """Append-as-it-happens forensic record of an agentic RE run.

    The existing audit log is written once, at the end, from an in-memory list. Any run
    that is SIGKILLed — which is every run that exhausts the container budget, i.e.
    exactly the runs worth understanding — leaves an EMPTY llm_audit directory.

    Reconstructing the 2026-07-28 qwen@30 run therefore meant hand-parsing the
    llama.cpp container log and reverse-engineering its undocumented `MMM.SS.mmm`
    timestamps from token rates. That produced three wrong conclusions before the right
    one: blaming LRU cache misses, then reporting `reprocessed = (1 - sim_best) x ctx`
    as a finding when it is an identity, then attributing 94 minutes to Ghidra when it
    was a single cancelled synthesis request that logged no summary line.

    So: one JSON object per event, flushed immediately. A killed run keeps everything up
    to the moment it died, which is the point.

    Deliberately orchestrator-side. The container would give richer data but needs an
    image rebuild to change; this needs only a pipeline deploy, so it can be iterated on.
    """

    # Status text the container emits when the tool loop ends and synthesis begins.
    # Phase matters: the cancelled run spent 90 of its 180 minutes in synthesis, and
    # nothing in the record distinguished that from loop time.
    _SYNTHESIS_MARKERS = ("requesting final analysis", "Hit max tool calls")

    def __init__(self, path: Path, started: float) -> None:
        self.path = path
        self.started = started
        self.seq = 0
        self.phase = "loop"
        self.cumulative_result_bytes = 0
        self._broken = False
        # Full tool output goes in sibling files rather than inline: a decompiled body
        # is ~9KB and would make the JSONL unreadable, but a byte COUNT is not evidence.
        # "What did the model actually see?" is the question chain-of-custody asks, and
        # only the content answers it.
        self.results_dir = path.parent / "results"

    def _write(self, row: dict) -> None:
        """Never let instrumentation break the run it is instrumenting."""
        if self._broken:
            return
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, default=str) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except Exception as e:  # noqa: BLE001
            self._broken = True
            print(f"    [!] turn trail disabled ({type(e).__name__}: {e})")

    def event(self, kind: str, **fields) -> None:
        self.seq += 1
        row = {
            "seq": self.seq,
            "t": round(time.time() - self.started, 2),
            "phase": self.phase,
            "event": kind,
        }
        row.update(fields)
        self._write(row)

    def _dump_result(self, result: object) -> str | None:
        """Persist a tool result verbatim and return its path.

        Verbatim and untruncated: this is the record of what the model was shown, so
        trimming it here would defeat the purpose — and the cap that shapes what the
        model sees has already been applied by the time this is called.
        """
        if self._broken or result is None:
            return None
        try:
            self.results_dir.mkdir(parents=True, exist_ok=True)
            path = self.results_dir / f"{self.seq + 1:04d}.json"
            with path.open("w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, default=str)
                fh.flush()
                os.fsync(fh.fileno())
            return str(path)
        except Exception as e:  # noqa: BLE001
            print(f"    [!] could not persist tool result ({type(e).__name__}: {e})")
            return None

    def tool(self, name: str, args: dict, result: object = None,
             error: str | None = None) -> None:
        # Bytes stay because they make context growth visible at a glance — the
        # list-cap bug (#242) showed as a 49,613B row. The full content is written
        # alongside so the row is a pointer to evidence, not a substitute for it.
        size = 0 if result is None else len(json.dumps(result, default=str))
        self.cumulative_result_bytes += size
        self.event("tool", tool=name,
                   args=json.dumps(args, default=str)[:200],
                   result_bytes=size,
                   cumulative_result_bytes=self.cumulative_result_bytes,
                   result_path=self._dump_result(result),
                   error=error)

    def turn(self, msg: dict) -> None:
        """Record what the MODEL produced for a turn — text, reasoning, stop reason.

        Emitted by the container, because the orchestrator cannot see this: the JSON
        protocol between them carries only tool_call/status/final, and the model's text
        and thinking blocks live in the container's `messages` list. Instrumenting
        orchestrator-side captured timing and shape but nothing about HOW the model
        reached its verdict, which is what #197 actually asks for.
        """
        text = msg.get("text") or ""
        thinking = msg.get("thinking") or ""
        self.event("turn",
                   turn_index=msg.get("turn_index"),
                   stop_reason=msg.get("stop_reason"),
                   text_chars=len(text),
                   thinking_chars=len(thinking),
                   tool_calls=msg.get("tool_calls") or [],
                   usage=msg.get("usage") or {},
                   text=text,
                   thinking=thinking)

    def stream_progress(self, msg: dict) -> None:
        """Periodic heartbeat while the model generates.

        llama-server emits nothing during prompt evaluation, so a long turn is
        indistinguishable from a hang from the outside — the 90-minute synthesis looked
        like a stall until the container log was parsed by hand.
        """
        self.event("stream", turn_index=msg.get("turn_index"),
                   output_tokens=msg.get("output_tokens"),
                   thinking_tokens=msg.get("thinking_tokens"))

    def status(self, message: str) -> None:
        if any(marker in message for marker in self._SYNTHESIS_MARKERS):
            self.phase = "synthesis"
        self.event("status", message=message[:300])

    def final(self, msg: dict, duration: float) -> None:
        self.event("final",
                   duration_seconds=round(duration, 1),
                   tool_calls_used=msg.get("tool_calls_used"),
                   model_used=msg.get("model_used"),
                   usage=msg.get("usage", {}),
                   has_analysis=bool(msg.get("analysis")))


def audit_filename(analysis_type: str | None) -> str:
    """Per-invocation audit log filename under llm_audit/.

    run_interpret runs up to three times per pipeline run (main
    interpretation, evasion_analysis, visual_analysis) against the same
    output_dir; a single shared filename meant the last writer — usually a
    tool-less pass — clobbered the real tool log to []. The main native-PE
    pass has no analysis_type and keeps the historical name.
    """
    if not analysis_type:
        return "tool_calls.json"
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", analysis_type)
    return f"tool_calls_{safe}.json"


_STDERR_TAIL_CHARS = 4000


def _drain_stderr(proc) -> str:
    """Read whatever the interpret container wrote to stderr, for the error path.

    stderr is a pipe that nothing read, so when the container died its traceback was
    captured and then thrown away: the 2026-07-27 qwen@30 probe reported only
    "exited without final result" after 18 successful tool calls, with no way to tell
    a crash from an OOM from a clean exit. A failure that cannot be diagnosed costs
    another full run to reproduce — 26 minutes, in that case.

    Returns the tail, since a traceback's last lines are the informative ones. Never
    raises: this runs on the error path, and losing the diagnostic is better than
    replacing the real error with one from the diagnostic itself.
    """
    try:
        if proc.stderr is None or proc.stderr.closed:
            return ""
        text = proc.stderr.read() or ""
    except Exception as e:  # noqa: BLE001 - diagnostics must not mask the real failure
        return f"<could not read container stderr: {type(e).__name__}: {e}>"
    text = text.strip()
    if len(text) > _STDERR_TAIL_CHARS:
        return "...[truncated]\n" + text[-_STDERR_TAIL_CHARS:]
    return text


def run_ghidra_tool(project_dir: str, program_name: str,
                    tool_name: str, tool_args: dict,
                    ghidra_cmd: str, list_functions_cap: int | None = None,
                    result_char_cap: int | None = None) -> dict:
    """Execute a single Ghidra tool call in a container.

    list_functions_cap: when set, trims list_functions output to the top-N by
    xref. Used ONLY for the local backend (small models derail on the full
    ~200-function list); cloud Claude gets the untrimmed list (cap=None).

    result_char_cap: when set, bounds long string fields (decompiled bodies) so a
    single result cannot consume a large share of the context window. Also local-only:
    the cloud model has room the local one does not.
    """
    if not project_dir or not program_name:
        return {"error": ghidra_unavailable_error(None)}
    try:
        result = subprocess.run(
            [ghidra_cmd, "--tool", project_dir, program_name,
             tool_name, json.dumps(tool_args)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            return {"error": result.stderr[:200]}
        parsed = json.loads(result.stdout)
        if tool_name == "list_functions" and list_functions_cap:
            parsed = cap_list_functions(parsed, list_functions_cap)
        if result_char_cap:
            parsed = cap_tool_result(parsed, result_char_cap)
        return parsed
    except subprocess.TimeoutExpired:
        return {"error": "Ghidra tool timeout (120s)"}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON from Ghidra tool",
                "raw": result.stdout[:500] if result else ""}


def check_prompt_influence(analysis: dict) -> bool:
    """Check if LLM response shows signs of prompt injection influence."""
    text = json.dumps(analysis).lower()
    return any(kw in text for kw in PROMPT_INFLUENCE_KEYWORDS)


def run_interpret(ghidra_result: dict, output_dir: Path,
                  interpret_cmd: str, interpret_enabled: bool,
                  interpret_timeout: int, interpret_config: dict,
                  ghidra_cmd: str) -> dict:
    """Run the agentic LLM interpretation loop.

    Starts the interpret container (long-running, stdin/stdout pipes),
    sends Ghidra data, brokers tool calls to Ghidra containers, and
    collects the final analysis.
    """
    if not interpret_enabled:
        return {"enabled": False, "reason": "disabled_by_config"}
    if not Path(interpret_cmd).exists():
        return {"enabled": False, "reason": "interpret_cmd_not_found"}

    project_dir = ghidra_result.get("project_dir", "")
    program_name = ghidra_result.get("program_name", "")

    start_time = time.time()

    # Start interpret container (long-running, communicates via stdin/stdout)
    try:
        proc = subprocess.Popen(
            [interpret_cmd],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as e:
        return {"enabled": True, "error": f"Failed to start interpret container: {e}"}

    # Send init message (bazaar_family passed through for LLM context)
    init_payload = {
        "type": "init",
        "ghidra_data": ghidra_result,
        "config": interpret_config,
    }
    if ghidra_result.get("bazaar_family"):
        init_payload["bazaar_family"] = ghidra_result["bazaar_family"]
    init_msg = json.dumps(init_payload)
    proc.stdin.write(init_msg + "\n")
    proc.stdin.flush()

    # Audit log — filename keyed by analysis_type so the multiple
    # run_interpret invocations per pipeline run don't clobber each other.
    audit_dir = output_dir / "llm_audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_path = audit_dir / audit_filename(ghidra_result.get("analysis_type"))
    tool_call_log = []

    # Forensic trail — appended and fsynced per event so a SIGKILLed run still has one.
    trail = TurnTrail(
        audit_dir / (audit_path.stem + ".trail.jsonl"),
        start_time,
    )
    trail.event("run_start",
                model=interpret_config.get("model"),
                re_backend=interpret_config.get("re_backend"),
                max_tool_calls=interpret_config.get("max_tool_calls"),
                max_tool_calls_per_turn=interpret_config.get("max_tool_calls_per_turn"),
                analysis_type=ghidra_result.get("analysis_type"))

    try:
        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > interpret_timeout:
                proc.stdin.write(json.dumps({"type": "force_final", "reason": "timeout"}) + "\n")
                proc.stdin.flush()
                # Give container 30s to produce final response, then kill
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    pass
                break

            # Read response from interpret container
            line = proc.stdout.readline().strip()
            if not line:
                break

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            msg_type = msg.get("type")

            if msg_type == "final":
                analysis = msg.get("analysis", {})
                duration = time.time() - start_time
                influenced = check_prompt_influence(analysis) if analysis else False

                result = {
                    "enabled": True,
                    "provider": "anthropic",
                    "model_initial": interpret_config["model"],
                    "model_final": msg.get("model_used", interpret_config["model"]),
                    "escalated": msg.get("model_used", "") != interpret_config["model"],
                    "tool_calls_used": msg.get("tool_calls_used", 0),
                    "duration_seconds": round(duration, 1),
                    "possible_prompt_influence": influenced,
                    "analysis": analysis,
                    "usage": msg.get("usage", {}),
                    "audit": {"tool_call_log": str(audit_path)},
                }

                trail.final(msg, duration)

                # Save audit log
                with audit_path.open("w") as f:
                    json.dump(tool_call_log, f, indent=2)

                result["audit"]["turn_trail"] = str(trail.path)
                return result

            elif msg_type == "tool_call":
                tool_name = msg.get("tool", "")
                tool_args = msg.get("args", {})
                print(f"    Tool call: {tool_name}({json.dumps(tool_args)[:80]})")

                # Validate arguments; refuse outright when this analysis has
                # no Ghidra project (non-native paths) instead of shelling out
                # a doomed `run-ghidra --tool "" ""`.
                error = validate_tool_args(tool_name, tool_args)
                if not error and not (project_dir and program_name):
                    error = ghidra_unavailable_error(ghidra_result.get("analysis_type"))
                if error:
                    print(f"    [!] Validation failed: {error}")
                    response = {"type": "tool_error", "tool": tool_name, "error": error}
                    tool_call_log.append({"tool": tool_name, "args": tool_args, "error": error})
                    trail.tool(tool_name, tool_args, error=error)
                else:
                    # Execute Ghidra tool in container. Both caps are local-backend
                    # ONLY — small models derail on the full ~200-function list, and
                    # the local context window is ~30x smaller than the cloud one.
                    # Cloud Claude keeps full, untruncated results.
                    _is_local = interpret_config.get("re_backend") == "local"
                    _lf_cap = LIST_FUNCTIONS_CAP if _is_local else None
                    _rc_cap = TOOL_RESULT_CHAR_CAP if _is_local else None
                    tool_result = run_ghidra_tool(project_dir, program_name,
                                                  tool_name, tool_args, ghidra_cmd,
                                                  _lf_cap, _rc_cap)
                    response = {"type": "tool_result", "tool": tool_name, "result": tool_result}
                    tool_call_log.append({"tool": tool_name, "args": tool_args, "result": tool_result})
                    trail.tool(tool_name, tool_args, result=tool_result)

                proc.stdin.write(json.dumps(response) + "\n")
                proc.stdin.flush()

            elif msg_type == "status":
                print(f"    LLM: {msg.get('message', '')}")
                trail.status(msg.get("message", ""))

            elif msg_type == "turn":
                # The model's own output for a turn. Emitted only by containers built
                # after #197; older images simply never send it, and unknown message
                # types were already ignored here, so this is backward-compatible.
                trail.turn(msg)

            elif msg_type == "stream":
                trail.stream_progress(msg)

    except Exception as e:
        trail.event("loop_error", error=f"{type(e).__name__}: {e}")
        return {"enabled": True,
                "error": f"Interpret loop error: {e}",
                "container_stderr": _drain_stderr(proc)}
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    # The container died without a final message. This is the case the trail exists for:
    # the in-memory audit log is lost, but the trail is already on disk.
    trail.event("container_exited_without_final")
    return {"enabled": True,
            "error": "Interpret container exited without final result",
            "container_stderr": _drain_stderr(proc),
            "audit": {"turn_trail": str(trail.path)}}


def run_summarize(report: dict, interpret_cmd: str, interpret_enabled: bool,
                  interpret_config: dict) -> dict:
    """Generate an executive summary of the full pipeline report.

    Single-shot Claude call (no tools) — sends a condensed version of the
    merged report and gets back a structured summary for analysts.
    """
    if not interpret_enabled:
        return {"enabled": False, "reason": "disabled_by_config"}
    if not Path(interpret_cmd).exists():
        return {"enabled": False, "reason": "interpret_cmd_not_found"}

    try:
        proc = subprocess.Popen(
            [interpret_cmd],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as e:
        return {"enabled": True, "error": f"Failed to start interpret container: {e}"}

    # Send summarize message — use communicate() to avoid deadlock on
    # large reports (42MB+ when malfind/volatility data is included)
    msg = json.dumps({"type": "summarize", "report": report, "config": interpret_config}, default=str)

    try:
        stdout, stderr = proc.communicate(input=msg + "\n", timeout=300)
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"error": "Summary generation timed out (300s)"}
    except Exception as e:
        proc.kill()
        return {"error": f"Summary communication error: {e}"}

    # Parse the last JSON line from stdout (container may emit status lines too)
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
            summary = result.get("summary", {"error": "No summary in response"})
            # Pass through token usage and model for cost tracking
            if "usage" in result:
                summary["usage"] = result["usage"]
            if "model_used" in result:
                summary["model"] = result["model_used"]

            # If parse_final_response hit the fallback, the summary fields
            # (executive_summary, key_findings, etc.) end up inside "narrative"
            # as a raw JSON string. Extract them.
            if "executive_summary" not in summary and "narrative" in summary:
                raw = summary["narrative"]
                # Try full JSON parse (code blocks, bare JSON)
                import re
                cb_match = re.search(r"```(?:json)?\s*\n(.*?)\n\s*```", raw, re.DOTALL)
                if cb_match:
                    try:
                        parsed = json.loads(cb_match.group(1))
                        if isinstance(parsed, dict) and "executive_summary" in parsed:
                            # Preserve usage/model from the outer result
                            if "usage" in summary:
                                parsed["usage"] = summary["usage"]
                            if "model" in summary:
                                parsed["model"] = summary["model"]
                            return parsed
                    except (json.JSONDecodeError, TypeError):
                        pass
                first = raw.find("{")
                last = raw.rfind("}")
                if first != -1 and last > first:
                    try:
                        parsed = json.loads(raw[first:last + 1])
                        if isinstance(parsed, dict) and "executive_summary" in parsed:
                            if "usage" in summary:
                                parsed["usage"] = summary["usage"]
                            if "model" in summary:
                                parsed["model"] = summary["model"]
                            return parsed
                    except (json.JSONDecodeError, TypeError):
                        pass

                # JSON malformed — extract executive_summary value directly
                es_match = re.search(r'"executive_summary"\s*:\s*"', raw)
                if es_match:
                    start = es_match.end()
                    extracted = []
                    i = start
                    while i < len(raw):
                        ch = raw[i]
                        if ch == '\\' and i + 1 < len(raw):
                            next_ch = raw[i + 1]
                            if next_ch == 'n':
                                extracted.append('\n')
                            elif next_ch == '"':
                                extracted.append('"')
                            elif next_ch == '\\':
                                extracted.append('\\')
                            else:
                                extracted.append(ch + next_ch)
                            i += 2
                        elif ch == '"':
                            break
                        else:
                            extracted.append(ch)
                            i += 1
                    if extracted:
                        summary["executive_summary"] = ''.join(extracted)

            return summary
        except json.JSONDecodeError:
            continue

    return {"error": f"No valid JSON in summarize output. stderr: {stderr[:300]}"}


def run_plain_english(report: dict, interpret_cmd: str, interpret_enabled: bool,
                      interpret_config: dict) -> str:
    """Generate a plain English summary for non-technical audiences.

    Returns the summary string, or empty string on failure.
    """
    if not interpret_enabled:
        return ""
    if not Path(interpret_cmd).exists():
        return ""

    summary = report.get("executive_summary", {})
    executive_text = summary.get("executive_summary", "")
    if not executive_text:
        return ""

    try:
        proc = subprocess.Popen(
            [interpret_cmd],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError:
        return ""

    msg = json.dumps({
        "type": "plain_english",
        "executive_summary": executive_text,
        "family": report.get("family", "unknown"),
        "severity": report.get("severity", "unknown"),
        "filename": report.get("sample_name", "unknown"),
        "model": interpret_config.get("plain_english_model",
                                      interpret_config.get("summary_model", "claude-haiku-4-5-20251001")),
        "config": interpret_config,
    }, default=str)

    try:
        stdout, stderr = proc.communicate(input=msg + "\n", timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        return ""
    except Exception:
        proc.kill()
        return ""

    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
            return {
                "summary": result.get("summary", ""),
                "usage": result.get("usage", {}),
                "model": result.get("model_used", ""),
            }
        except json.JSONDecodeError:
            continue
    return {"summary": "", "usage": {}, "model": ""}
