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


def run_ghidra_tool(project_dir: str, program_name: str,
                    tool_name: str, tool_args: dict,
                    ghidra_cmd: str) -> dict:
    """Execute a single Ghidra tool call in a container."""
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
        if tool_name == "list_functions":
            parsed = cap_list_functions(parsed)
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

                # Save audit log
                with audit_path.open("w") as f:
                    json.dump(tool_call_log, f, indent=2)

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
                else:
                    # Execute Ghidra tool in container
                    tool_result = run_ghidra_tool(project_dir, program_name,
                                                  tool_name, tool_args, ghidra_cmd)
                    response = {"type": "tool_result", "tool": tool_name, "result": tool_result}
                    tool_call_log.append({"tool": tool_name, "args": tool_args, "result": tool_result})

                proc.stdin.write(json.dumps(response) + "\n")
                proc.stdin.flush()

            elif msg_type == "status":
                print(f"    LLM: {msg.get('message', '')}")

    except Exception as e:
        return {"enabled": True, "error": f"Interpret loop error: {e}"}
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

    return {"enabled": True, "error": "Interpret container exited without final result"}


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
