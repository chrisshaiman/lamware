# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pipeline side of the agentic .NET path (#646): build the payload, broker the tools.

The tool implementation is stages/dotnet_tools.py, and it never runs here.
ADR-021: agent tools are brokered by the orchestrator and executed in a
sandbox — never in the orchestrator's own process, never answered by the
interpret container itself. This module is the broker for the .NET tools, as
`run_ghidra_tool` is for Ghidra's:

  * `DotnetToolBroker.request` runs ONE request — the first-message map, or one
    tool call — through `run-dotnet-tools` (a python-sandbox container: no
    network, read-only root, no host mounts, memory/pids limits, caps dropped,
    `podman --timeout`), with a pipeline-side subprocess timeout as backstop.
    It never raises: a timeout, an OOM kill, a non-zero exit, oversized or
    unparseable output all come back as `{"error": ...}`, so one failed call
    costs one turn and the run goes on.
  * `build_dotnet_interpret_init` builds the .NET payload for either mode and
    never raises for "agentic": a map the sandbox cannot build falls back to
    the single-shot payload, marked with why.

Why a container per request rather than one per run: a tool call is the only
moment the interpret container reads stdin, so it is the only moment
force_final and the synthesis reserve (#240) reach the agent. Per-call
containers keep every call a separate, bounded, killable unit brokered on that
protocol — exactly the Ghidra tool shape (`run-ghidra --tool`) — at the cost
of a container start and an index rebuild per call.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

from stages import dotnet_tools
from stages.dotnet_tools import DotnetToolLimits, is_agentic_dotnet
from stages.single_shot_init import _source_provenance, build_dotnet_init

log = logging.getLogger(__name__)

DOTNET_MODES = ("agentic", "single_shot")

#: Where the pipeline role installs the wrapper. Production passes the
#: configured path (`InterpretConfig.dotnet_tools_cmd`); this default serves
#: callers with no config (the eval's offline re-scorer, the promotion check),
#: and LAMWARE_DOTNET_TOOLS_CMD overrides it for tests.
DEFAULT_TOOLS_CMD = "/opt/pipeline/run-dotnet-tools"
#: Seconds the container may run (podman --timeout in the wrapper).
DEFAULT_TOOLS_TIMEOUT = 30
#: Added to the container timeout for the pipeline-side backstop: podman's
#: own start and teardown, so the backstop fires only if podman does not.
STARTUP_GRACE_S = 15
#: Largest result accepted from the sandbox, in bytes. The wrapper cuts its
#: output at the same size; a cut result fails to parse and is an error.
MAX_RESULT_BYTES = 1_048_576


def default_tools_cmd() -> str:
    return os.environ.get("LAMWARE_DOTNET_TOOLS_CMD", DEFAULT_TOOLS_CMD)


@lru_cache(maxsize=1)
def _tool_code() -> str:
    """The sandbox's program: dotnet_tools.py's own text, sent with each request."""
    return Path(dotnet_tools.__file__).read_text(encoding="utf-8")


def _failure(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"[:300]


class DotnetToolBroker:
    """Runs .NET tool requests in the sandbox for one decompiled source."""

    def __init__(self, source: str, *, analyser_truncated: bool = False,
                 source_bytes_total: int | None = None,
                 limits: dict | DotnetToolLimits | None = None,
                 cmd: str | None = None, timeout: int | None = None) -> None:
        self.source = source or ""
        self.analyser_truncated = analyser_truncated
        self.source_bytes_total = source_bytes_total
        self.limits = (limits if isinstance(limits, DotnetToolLimits)
                       else DotnetToolLimits.from_config(limits))
        self.cmd = cmd or default_tools_cmd()
        self.timeout = int(timeout or DEFAULT_TOOLS_TIMEOUT)

    @classmethod
    def from_payload(cls, payload: dict, cfg: dict | None = None) -> DotnetToolBroker:
        """For an agentic init payload, configured from an interpret config."""
        cfg = cfg or {}
        return cls(payload.get("decompiled_source", "") or "",
                   analyser_truncated=bool(payload.get("source_truncated_by_analyser")),
                   source_bytes_total=payload.get("source_bytes_total"),
                   limits=cfg.get("dotnet_tool_limits"),
                   cmd=cfg.get("dotnet_tools_cmd"), timeout=cfg.get("dotnet_tools_timeout"))

    def request(self, op: str, **fields) -> dict:
        """One request through the sandbox. Never raises."""
        body = json.dumps({
            "code": _tool_code(), "op": op, "source": self.source,
            "analyser_truncated": self.analyser_truncated,
            "source_bytes_total": self.source_bytes_total,
            "limits": asdict(self.limits), **fields,
        })
        limit = self.timeout + STARTUP_GRACE_S
        try:
            # Its own process group, so the backstop kills the wrapper AND its
            # children (head, podman): killing only the wrapper leaves them
            # holding stdout open, and reading it would wait for them.
            proc = subprocess.Popen([self.cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, start_new_session=True)
        except OSError as e:
            return {"error": f"tool failed: cannot run the sandbox ({_failure(e)})"}
        try:
            stdout, stderr = proc.communicate(body, timeout=limit)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.communicate()
            return {"error": f"tool failed: the sandbox did not answer within {limit}s",
                    "timed_out": True}
        proc = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
        if proc.returncode != 0:
            # 137 = SIGKILL: the memory or pids limit, or podman's own timeout.
            why = ("killed — memory/pids limit or the sandbox timeout"
                   if proc.returncode in (137, -9) else f"exit {proc.returncode}")
            return {"error": f"tool failed: sandbox {why}: "
                             f"{(proc.stderr or '').strip()[-200:]}",
                    "timed_out": proc.returncode in (137, -9)}
        out = proc.stdout or ""
        if len(out.encode("utf-8", "replace")) > MAX_RESULT_BYTES:
            return {"error": f"tool failed: result larger than {MAX_RESULT_BYTES:,} bytes"}
        try:
            result = json.loads(out)
        except json.JSONDecodeError:
            return {"error": f"tool failed: the sandbox returned no JSON "
                             f"({out.strip()[:120]!r})"}
        if not isinstance(result, dict):
            return {"error": "tool failed: the sandbox returned a non-object result"}
        return result

    def call(self, tool: str, args: dict) -> dict:
        """One tool call. A search that runs out of time is the model's pattern,
        so it is answered as one (the eval counts that as a semantic answer,
        not a dead tool layer)."""
        result = self.request("tool", tool=tool, args=args or {})
        if tool == "search_source" and result.pop("timed_out", False):
            return {"error": f"Invalid search pattern: it ran longer than the "
                             f"{self.timeout}s sandbox limit and was stopped. "
                             f"Use a simpler pattern."}
        result.pop("timed_out", None)
        return result


def build_dotnet_agentic_init(dotnet_data: dict, llm_context: dict, cape_sigs: list[str],
                              cfg: dict | None = None) -> dict:
    """The agentic .NET init payload; raises if the sandbox cannot build the map.

    Carries `decompiled_source` IN FULL, for the broker: `agent_payload` in
    stages/interpret.py removes it before the payload reaches the interpret
    container. Everything else is what the agent sees in its first message,
    and all of it that is derived from the source was derived in the sandbox.
    """
    decompilation = dotnet_data.get("decompilation", {}) or {}
    source = decompilation.get("source", "") or ""
    broker = DotnetToolBroker(source, limits=(cfg or {}).get("dotnet_tool_limits"),
                              cmd=(cfg or {}).get("dotnet_tools_cmd"),
                              timeout=(cfg or {}).get("dotnet_tools_timeout"))
    mapped = broker.request("map")
    if "error" in mapped:
        raise RuntimeError(mapped["error"])
    extraction_source = dotnet_data.get("extraction_source")
    deob = dotnet_data.get("deobfuscation") or {}
    return {
        **llm_context,
        "analysis_type": "dotnet",
        "dotnet_mode": "agentic",
        "source_language": "csharp",
        "decompiled_source": source,
        "source_bytes_indexed": len(source),
        **_source_provenance(decompilation),
        "blob_bytes_elided": decompilation.get("blob_bytes_elided"),
        "deobfuscated": bool(deob.get("deobfuscated")),
        "assembly": mapped.get("assembly") or {},
        "table_of_contents": mapped.get("table_of_contents") or {},
        "suspicious_constructs": mapped.get("suspicious_constructs") or {},
        "strings_of_interest": dotnet_data.get("strings_of_interest", []),
        "analysis_success": True,
        "origin": "extraction" if extraction_source else "original",
        "extraction_context": {
            "source_dir": extraction_source["source_dir"],
            "sha256": extraction_source["sha256"],
            "cape_signatures": cape_sigs[:10],
        } if extraction_source else None,
    }


def build_dotnet_interpret_init(dotnet_data: dict, llm_context: dict, cape_sigs: list[str],
                                mode: str, cfg: dict | None = None) -> dict:
    """The .NET init payload for `mode` — the ONE place the choice is made.

    run-pipeline.py and the eval harness both call this, so the eval measures
    what production sends for the same `dotnet_mode` (#380, #667). `cfg` is the
    interpret config: `dotnet_tool_limits`, `dotnet_tools_cmd`,
    `dotnet_tools_timeout`.

    NEVER RAISES for the agentic mode. It runs in Stage 4.5 after CAPE,
    Volatility and Ghidra; an exception here once left main() with no report
    and no DB row (review of #673). Any failure — the sandbox could not build
    the map, timed out, was killed — falls back to the single-shot payload,
    marked `dotnet_agentic_failed` with the reason, and is logged. An unknown
    `mode` is a configuration error and raises; PipelineConfig rejects it at
    startup.
    """
    if mode == "single_shot":
        return build_dotnet_init(dotnet_data, llm_context, cape_sigs)
    if mode != "agentic":
        raise ValueError(f"dotnet_mode must be one of {DOTNET_MODES}, got {mode!r}")
    try:
        return build_dotnet_agentic_init(dotnet_data, llm_context, cape_sigs, cfg)
    except Exception as e:  # noqa: BLE001 - nothing about this sample may end the run
        reason = _failure(e)
        log.warning("agentic .NET init failed, falling back to single-shot: %s", reason)
        init = build_dotnet_init(dotnet_data, llm_context, cape_sigs)
        init["dotnet_agentic_failed"] = reason
        return init


def dotnet_input_record(init: dict, requested_mode: str) -> dict:
    """`llm_interpretation.input` for a .NET run: which path ACTUALLY ran.

    Shared by run-pipeline.py and the eval (whose `kind` is the modality), so
    a fallback is recorded the same way in both: the requested mode, the
    single-shot kind, and why.
    """
    failed = (init or {}).get("dotnet_agentic_failed")
    agentic = is_agentic_dotnet(init) and not failed
    rec = {"kind": "dotnet_agentic" if agentic else "dotnet",
           "dotnet_mode": "agentic" if agentic else "single_shot"}
    if failed:
        rec.update(requested_mode=requested_mode, agentic_failed=failed)
    return rec
