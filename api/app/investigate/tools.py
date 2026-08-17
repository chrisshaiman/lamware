# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Investigation agent tool definitions and implementations.
#
# Each tool is a function taking validated args and returning a JSON-safe
# dict. TOOL_DEFINITIONS provides Claude tool_use schemas. All DB tools are
# read-only SELECTs. Ghidra and sandbox tools shell out to the isolated
# container wrappers. pin_finding returns a proposal only — the analyst
# confirms via a separate endpoint before anything is saved.

import json
import logging
import shlex
import subprocess
from pathlib import Path

from lamware_shared.cape_payloads import (
    Payload,
    PayloadAccessError,
    find_payloads,
    payload_dirs,
)
from sqlalchemy import text
from sqlmodel import Session

from ..config import settings
from .tool_validators import validate_tool_args

log = logging.getLogger(__name__)

CAPE_STORAGE = Path("/opt/CAPEv2/storage/analyses")

TOOL_DEFINITIONS = [
    {
        "name": "search_iocs",
        "description": (
            "Search for an IOC value ACROSS ALL analyses. Returns matching "
            "analyses with family, severity, and source stage. Use to answer 'have "
            "we seen this C2/domain/hash before?'. If you already have an "
            "analysis_id and want that one analysis's IOCs, use get_iocs instead."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "description": "IOC value or substring (IP, domain, hash, URL)",
                },
                "type": {
                    "type": "string",
                    "description": (
                        "Optional IOC type filter "
                        "(ipv4-addr, domain-name, url, file:hashes.SHA-256, mutex, etc.)"
                    ),
                },
            },
            "required": ["value"],
        },
    },
    {
        "name": "search_techniques",
        "description": "Find analyses using a specific MITRE ATT&CK technique.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "MITRE technique ID (e.g., T1055.003)",
                },
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "search_analyses",
        "description": (
            "Search analyses by SHA256 hash, filename, or malware family name. "
            "Returns top 20 matches."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search term"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_network_events",
        "description": (
            "Get DNS, HTTP, and TCP network events recorded during detonation "
            "of an analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "analysis_id": {"type": "integer"},
                "type": {
                    "type": "string",
                    "description": "Filter by event type (dns, http, tcp, udp)",
                },
            },
            "required": ["analysis_id"],
        },
    },
    {
        "name": "get_signatures",
        "description": "Get Cape behavioral signatures for an analysis, sorted by severity.",
        "input_schema": {
            "type": "object",
            "properties": {"analysis_id": {"type": "integer"}},
            "required": ["analysis_id"],
        },
    },
    {
        "name": "get_capabilities",
        "description": "Get LLM-identified malware capabilities for an analysis.",
        "input_schema": {
            "type": "object",
            "properties": {"analysis_id": {"type": "integer"}},
            "required": ["analysis_id"],
        },
    },
    {
        "name": "get_iocs",
        "description": (
            "Get all IOCs for ONE analysis you already have the id for, optionally "
            "filtered by type. To find which analyses contain a specific IOC value, "
            "use search_iocs instead."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "analysis_id": {"type": "integer"},
                "type": {"type": "string"},
            },
            "required": ["analysis_id"],
        },
    },
    {
        "name": "get_sample_lineage",
        "description": (
            "Get dropped/injected file relationships for an analysis sample."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"analysis_id": {"type": "integer"}},
            "required": ["analysis_id"],
        },
    },
    {
        "name": "decompile_function",
        "description": (
            "Decompile a function from the Ghidra project of the current analysis. "
            "Accepts function name or hex address (e.g., 0x00401000)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "get_xrefs_to",
        "description": (
            "Get all CALLERS of a function — cross-references pointing TO it — in "
            "the Ghidra project. Answers 'what invokes this?'. For the opposite "
            "direction (what this function calls), use get_xrefs_from."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "get_xrefs_from",
        "description": (
            "Get all CALLEES of a function — cross-references pointing FROM it — "
            "in the Ghidra project. Answers 'what does this call?'. For the opposite "
            "direction (what invokes it), use get_xrefs_to."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "get_strings_at",
        "description": "Get strings near a memory address in the binary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Hex address (e.g., 0x00402000)",
                },
                "range": {
                    "type": "integer",
                    "description": "Byte range to search (default 4096)",
                },
            },
            "required": ["address"],
        },
    },
    {
        "name": "list_functions",
        "description": (
            "List functions in the binary, with optional wildcard filter "
            "(e.g., *crypt*). Returns names decompile_function accepts — call this "
            "first to find candidates, then decompile the interesting ones."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"filter": {"type": "string"}},
        },
    },
    {
        "name": "get_data_at",
        "description": "Read raw hex bytes at a memory address in the binary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "length": {
                    "type": "integer",
                    "description": "Bytes to read (default 256)",
                },
            },
            "required": ["address"],
        },
    },
    {
        "name": "get_cape_payloads",
        "description": (
            "List payloads dropped/extracted by Cape during dynamic analysis of "
            "this sample. Returns the indices read_payload expects — call this "
            "first if you do not already know a payload_index. Each entry names "
            "its source_dir: CAPE (payloads Cape's extractors unpacked — usually "
            "the most informative), files (written to disk by the sample), or "
            "procdump (process memory dumps)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "read_payload",
        "description": (
            "Read a hex preview (first 4KB) of a specific Cape-extracted payload. "
            "For full payload analysis, use run_python — payloads are mounted at "
            "/data/ in the sandbox."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "payload_index": {
                    "type": "integer",
                    "description": "Index from get_cape_payloads",
                },
            },
            "required": ["payload_index"],
        },
    },
    {
        "name": "get_pcap_summary",
        "description": (
            "Get Zeek/Suricata PCAP analysis results for the CURRENT analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_api_traces",
        "description": (
            "Get Cape API call traces for the CURRENT analysis, optionally "
            "filtered by process name or API name substring."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "process": {"type": "string"},
                "api_filter": {"type": "string"},
            },
            "required": [],
        },
    },
    {
        "name": "run_python",
        "description": (
            "Execute a Python script in an isolated sandbox (no network, "
            f"{settings.sandbox_timeout_seconds}s timeout, {settings.sandbox_memory_mb}MB). "
            "Pre-loaded helpers: "
            "`from helpers.crypto import xor_decrypt, rc4_decrypt, single_byte_xor_scan`; "
            "`from helpers.encoding import b64_decode, b64_variants, hex_to_bytes, "
            "bytes_to_hex, rot13`; "
            "`from helpers.parsing import read_dword_le, read_dword_be, read_qword_le, "
            "extract_strings, pe_overlay_offset, struct_unpack_at`. "
            "Cape payload files for the current analysis are mounted read-only at /data/ "
            "(filenames from get_cape_payloads)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "script": {
                    "type": "string",
                    "description": f"Python script (max {settings.sandbox_max_script_bytes // 1024}KB)",
                },
            },
            "required": ["script"],
        },
    },
    {
        "name": "pin_finding",
        "description": (
            "Propose a significant finding for the analyst to pin: a new IOC, a "
            "technique attribution, or an important observation. The analyst confirms "
            "or dismisses in the UI. Use as soon as you discover something significant "
            "— don't wait until the end."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["ioc", "technique", "note"],
                },
                "value": {
                    "type": "string",
                    "description": (
                        "IOC value, MITRE technique ID, or note text"
                    ),
                },
                "ioc_type": {
                    "type": "string",
                    "description": (
                        "Required when type=ioc: ipv4-addr, domain-name, url, "
                        "file:hashes.SHA-256, mutex, etc."
                    ),
                },
                "context": {
                    "type": "string",
                    "description": "How/why this was found",
                },
            },
            "required": ["type", "value", "context"],
        },
    },
]

# Schema lookup for argument validation (built once from the tool definitions).
_SCHEMA_BY_NAME = {t["name"]: t["input_schema"] for t in TOOL_DEFINITIONS}


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

# Ghidra tool names that shell out to run-ghidra
_GHIDRA_TOOLS = {
    "decompile_function",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_strings_at",
    "list_functions",
    "get_data_at",
}

# Tools answered from the session's own report/CAPE task rather than the DB.
# The database tools take an analysis_id and honour it; these structurally
# cannot, so they no longer advertise one — see execute_tool.
_CURRENT_ANALYSIS_TOOLS = {
    "get_cape_payloads",
    "read_payload",
    "get_pcap_summary",
    "get_api_traces",
}


def execute_tool(
    tool_name: str,
    args: dict,
    session: Session,
    report: dict,
    analysis_id: int,
) -> dict:
    """Dispatch a tool call. Always returns a JSON-safe dict, never raises."""
    try:
        err = validate_tool_args(tool_name, args, _SCHEMA_BY_NAME)
        if err:
            log.warning("Tool %s rejected by arg validation: %s", tool_name, err)
            return {"error": err}

        if tool_name in _GHIDRA_TOOLS:
            return _ghidra_tool(tool_name, args, report)

        db_tools = {
            "search_iocs": _search_iocs,
            "search_techniques": _search_techniques,
            "search_analyses": _search_analyses,
            "get_network_events": _get_network_events,
            "get_signatures": _get_signatures,
            "get_capabilities": _get_capabilities,
            "get_iocs": _get_iocs,
            "get_sample_lineage": _get_sample_lineage,
        }
        if tool_name in db_tools:
            return db_tools[tool_name](args, session)

        # These four answer from `report`, which the router loaded for THIS
        # session's analysis, and from that analysis's CAPE task id. They cannot
        # serve another analysis, so their schemas no longer accept an id. Any
        # model still sending one — from an older transcript, or copied out of a
        # search_* result — is refused rather than quietly handed the session's
        # own data under someone else's id, which is how a false cross-analysis
        # correlation gets made.
        if tool_name in _CURRENT_ANALYSIS_TOOLS:
            requested = args.get("analysis_id")
            if requested is not None and requested != analysis_id:
                return {"error": (
                    f"{tool_name} only serves the current analysis ({analysis_id}); "
                    f"it cannot fetch analysis {requested}. Use the database tools "
                    f"(get_iocs, get_network_events, get_signatures, "
                    f"get_capabilities, get_sample_lineage) for other analyses."
                )}

        if tool_name == "get_cape_payloads":
            return _get_cape_payloads(args, report)
        if tool_name == "read_payload":
            return _read_payload(args, report)
        if tool_name == "get_pcap_summary":
            return _get_pcap_summary(args, report)
        if tool_name == "get_api_traces":
            return _get_api_traces(args, report)
        if tool_name == "run_python":
            return _run_python(args, report)
        if tool_name == "pin_finding":
            return _pin_finding(args)

        return {"error": f"Unknown tool: {tool_name}"}
    except Exception as e:
        # Full detail (which can carry filesystem paths / host info) goes to the
        # server log only; the model/analyst gets the exception type, not its message.
        log.exception("Tool %s failed", tool_name)
        return {"error": f"{tool_name} failed ({type(e).__name__})"}


# ---------------------------------------------------------------------------
# DB tools (read-only SELECTs)
# ---------------------------------------------------------------------------


def _search_iocs(args: dict, session: Session) -> dict:
    # The optional type filter is always bound (NULL = no filter) rather than
    # concatenated, so the query is a single static string — no SQL built from
    # string fragments.
    sql = text(
        """
        SELECT DISTINCT a.id, a.malware_family_guess, a.severity,
               iv.type, iv.value, ai.source_stage
        FROM analysis_iocs ai
        JOIN ioc_values iv ON ai.ioc_id = iv.id
        JOIN analyses a ON ai.analysis_id = a.id
        WHERE iv.value ILIKE :pattern
          AND (:ioc_type IS NULL OR iv.type = :ioc_type)
        ORDER BY a.id DESC LIMIT 50
        """
    )
    params: dict = {
        "pattern": f"%{args['value']}%",
        "ioc_type": args.get("type"),
    }
    rows = session.exec(sql.bindparams(**params)).all()
    return {
        "matches": [
            {
                "analysis_id": r[0],
                "family": r[1],
                "severity": r[2],
                "ioc_type": r[3],
                "ioc_value": r[4],
                "source_stage": r[5],
            }
            for r in rows
        ],
        "count": len(rows),
    }


def _search_techniques(args: dict, session: Session) -> dict:
    sql = text(
        """
        SELECT a.id, a.malware_family_guess, a.severity,
               tv.technique_id, tv.technique_name, tv.tactics, at2.source_stage
        FROM analysis_techniques at2
        JOIN technique_values tv ON at2.technique_id = tv.id
        JOIN analyses a ON at2.analysis_id = a.id
        WHERE tv.technique_id = :tid
        ORDER BY a.id DESC LIMIT 50
        """
    )
    rows = session.exec(sql.bindparams(tid=args["technique_id"])).all()
    return {
        "matches": [
            {
                "analysis_id": r[0],
                "family": r[1],
                "severity": r[2],
                "technique_id": r[3],
                "technique_name": r[4],
                "tactics": r[5],
                "source_stage": r[6],
            }
            for r in rows
        ],
        "count": len(rows),
    }


def _search_analyses(args: dict, session: Session) -> dict:
    sql = text(
        """
        SELECT a.id, s.sha256, s.filename, a.malware_family_guess,
               a.severity, CAST(a.malscore AS FLOAT), a.started_at
        FROM analyses a
        JOIN samples s ON s.id = a.sample_id
        WHERE s.sha256 ILIKE :pattern
           OR s.filename ILIKE :pattern
           OR a.malware_family_guess ILIKE :pattern
        ORDER BY a.started_at DESC LIMIT 20
        """
    )
    rows = session.exec(sql.bindparams(pattern=f"%{args['query']}%")).all()
    return {
        "matches": [
            {
                "analysis_id": r[0],
                "sha256": r[1],
                "filename": r[2],
                "family": r[3],
                "severity": r[4],
                "malscore": r[5],
                "started_at": r[6].isoformat() if r[6] else None,
            }
            for r in rows
        ],
        "count": len(rows),
    }


def _get_network_events(args: dict, session: Session) -> dict:
    # Schema columns: id, analysis_id, event_type, dns_query, dns_type,
    # dns_answers, http_method, http_url, http_host, http_status,
    # http_user_agent, src_ip, src_port, dst_ip, dst_port, timestamp
    # Optional event_type filter bound as NULL = no filter (static query).
    sql = text(
        """
        SELECT event_type, dns_query, dns_type, dns_answers,
               http_method, http_url, http_host, http_status, http_user_agent,
               src_ip, src_port, dst_ip, dst_port, timestamp
        FROM network_events
        WHERE analysis_id = :aid
          AND (:etype IS NULL OR event_type = :etype)
        ORDER BY timestamp ASC NULLS LAST LIMIT 200
        """
    )
    params: dict = {"aid": args["analysis_id"], "etype": args.get("type")}
    rows = session.exec(sql.bindparams(**params)).all()
    return {
        "events": [
            {
                "event_type": r[0],
                "dns_query": r[1],
                "dns_type": r[2],
                "dns_answers": r[3],
                "http_method": r[4],
                "http_url": r[5],
                "http_host": r[6],
                "http_status": r[7],
                "http_user_agent": r[8],
                "src_ip": r[9],
                "src_port": r[10],
                "dst_ip": r[11],
                "dst_port": r[12],
                "timestamp": r[13].isoformat() if r[13] else None,
            }
            for r in rows
        ],
        "count": len(rows),
    }


def _get_signatures(args: dict, session: Session) -> dict:
    # Schema columns: id, analysis_id, name, severity, description, source_stage
    sql = text(
        """
        SELECT name, severity, description, source_stage
        FROM signatures
        WHERE analysis_id = :aid
        ORDER BY severity DESC LIMIT 200
        """
    )
    rows = session.exec(sql.bindparams(aid=args["analysis_id"])).all()
    return {
        "signatures": [
            {
                "name": r[0],
                "severity": r[1],
                "description": r[2],
                "source_stage": r[3],
            }
            for r in rows
        ],
        "count": len(rows),
    }


def _get_capabilities(args: dict, session: Session) -> dict:
    # Schema columns: id, analysis_id, description, source_stage, created_at
    sql = text(
        """
        SELECT description, source_stage
        FROM capabilities
        WHERE analysis_id = :aid
        ORDER BY id ASC LIMIT 500
        """
    )
    rows = session.exec(sql.bindparams(aid=args["analysis_id"])).all()
    return {
        "capabilities": [
            {"description": r[0], "source_stage": r[1]}
            for r in rows
        ],
        "count": len(rows),
    }


def _get_iocs(args: dict, session: Session) -> dict:
    # Optional type filter bound as NULL = no filter (static query).
    sql = text(
        """
        SELECT iv.type, iv.value, ai.source_stage, ai.confidence, ai.context
        FROM analysis_iocs ai
        JOIN ioc_values iv ON ai.ioc_id = iv.id
        WHERE ai.analysis_id = :aid
          AND (:ioc_type IS NULL OR iv.type = :ioc_type)
        ORDER BY iv.type, iv.value LIMIT 500
        """
    )
    params: dict = {"aid": args["analysis_id"], "ioc_type": args.get("type")}
    rows = session.exec(sql.bindparams(**params)).all()
    return {
        "iocs": [
            {
                "type": r[0],
                "value": r[1],
                "source_stage": r[2],
                "confidence": r[3],
                "context": r[4],
            }
            for r in rows
        ],
        "count": len(rows),
    }


def _get_sample_lineage(args: dict, session: Session) -> dict:
    # sample_relationships uses parent_id / child_id (both FK to samples.id)
    # analyses.sample_id links the analysis to its sample
    sql = text(
        """
        SELECT
            p.sha256 AS parent_sha256,
            p.filename AS parent_filename,
            c.sha256 AS child_sha256,
            c.filename AS child_filename,
            sr.relationship,
            sr.context,
            sr.discovered_at
        FROM analyses a
        JOIN sample_relationships sr
            ON sr.parent_id = a.sample_id OR sr.child_id = a.sample_id
        JOIN samples p ON p.id = sr.parent_id
        JOIN samples c ON c.id = sr.child_id
        WHERE a.id = :aid
        ORDER BY sr.discovered_at ASC LIMIT 100
        """
    )
    rows = session.exec(sql.bindparams(aid=args["analysis_id"])).all()
    return {
        "relationships": [
            {
                "parent_sha256": r[0],
                "parent_filename": r[1],
                "child_sha256": r[2],
                "child_filename": r[3],
                "relationship": r[4],
                "context": r[5],
                "discovered_at": r[6].isoformat() if r[6] else None,
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ---------------------------------------------------------------------------
# Cape payload tools
# ---------------------------------------------------------------------------


def _cape_task_id(report: dict) -> str | None:
    """Extract the Cape task ID from the pipeline report JSON."""
    cape = report.get("cape") or {}
    tid = cape.get("id") or cape.get("task_id")
    return str(tid) if tid else None


def _resolve_payloads(report: dict) -> tuple[list[Payload] | None, dict | None]:
    """Return (payloads, None) on success, (None, error_dict) on failure.

    Both payload tools resolve through here, so the index get_cape_payloads
    hands out is the index read_payload resolves. They previously built their
    own lists — one enumerated before filtering out directories, the other
    after, so the two disagreed whenever a non-file entry was present.
    """
    task_id = _cape_task_id(report)
    if not task_id:
        return None, {"error": "No Cape task ID in report — sample may not have been detonated"}
    try:
        payloads = find_payloads(task_id, storage=CAPE_STORAGE)
    except PayloadAccessError as exc:
        # Distinct from "extracted nothing": the agent must not conclude the
        # sample dropped no payloads when the truth is that we could not look.
        log.error("Cape payload access denied for task %s: %s", task_id, exc)
        return None, {"error": (
            "Cape's payload storage is not readable by the API service user, so "
            "whether this sample extracted payloads is unknown — this is a "
            "deployment permission problem, not a property of the sample. "
            "Do not treat it as evidence of nothing being dropped."
        )}
    if not payloads:
        return None, {"error": "Cape extracted no payloads during detonation of this sample"}
    return payloads, None


def _get_cape_payloads(args: dict, report: dict) -> dict:
    payloads, err = _resolve_payloads(report)
    if err:
        return err
    return {
        "payloads": [
            {"index": i, "filename": p.path.name, "size": p.size, "source_dir": p.source}
            for i, p in enumerate(payloads)
        ],
        "count": len(payloads),
        "task_id": _cape_task_id(report),
    }


def _read_payload(args: dict, report: dict) -> dict:
    payloads, err = _resolve_payloads(report)
    if err:
        return err

    idx = args["payload_index"]
    if idx < 0 or idx >= len(payloads):
        return {
            "error": (
                f"payload_index {idx} out of range — "
                f"{len(payloads)} payloads available (0–{len(payloads) - 1})"
            )
        }

    target = payloads[idx].path
    data = target.read_bytes()
    preview = data[:4096]
    return {
        "filename": target.name,
        "size": len(data),
        "hex_preview": preview.hex(),
        "truncated": len(data) > 4096,
    }


def _get_pcap_summary(args: dict, report: dict) -> dict:
    pcap = report.get("pcap_analysis")
    if pcap is None:
        return {"error": "No pcap_analysis key in report — PCAP analysis may not have run"}

    # Cap to 50KB to avoid blowing up LLM context
    raw = json.dumps(pcap)
    if len(raw) > 51200:
        top_keys = {}
        for k, v in pcap.items():
            try:
                size = len(json.dumps(v))
            except (TypeError, ValueError):
                size = f"<unserializable: {type(v).__name__}>"
            top_keys[k] = f"<truncated — {size} bytes>"
        return {
            "note": "pcap_analysis exceeded 50KB — showing top-level keys only",
            "keys": top_keys,
        }
    return {"pcap_analysis": pcap}


def _get_api_traces(args: dict, report: dict) -> dict:
    cape = report.get("cape") or {}
    behavior = cape.get("behavior") or {}
    processes = behavior.get("processes") or []

    proc_filter = (args.get("process") or "").lower()
    api_filter = (args.get("api_filter") or "").lower()

    result = []
    max_processes = 10
    max_calls_per_process = 100

    for proc in processes[:max_processes]:
        proc_name = proc.get("process_name", "") or ""
        if proc_filter and proc_filter not in proc_name.lower():
            continue

        calls = proc.get("calls") or []
        if api_filter:
            calls = [c for c in calls if api_filter in (c.get("api") or "").lower()]

        total_calls = len(calls)
        calls = calls[:max_calls_per_process]

        # Cape call entries may contain bytes/datetime — force JSON-safe via default=str
        safe_calls = json.loads(json.dumps(calls, default=str))

        result.append(
            {
                "process_name": proc_name,
                "pid": proc.get("pid"),
                "total_calls": total_calls,
                "calls_shown": len(safe_calls),
                "calls": safe_calls,
            }
        )

    return {
        "processes": result,
        "process_count": len(result),
    }


# ---------------------------------------------------------------------------
# Python sandbox
# ---------------------------------------------------------------------------


def _run_python(args: dict, report: dict) -> dict:
    script = args["script"]
    if len(script.encode()) > settings.sandbox_max_script_bytes:
        kb = settings.sandbox_max_script_bytes // 1024
        return {"error": f"Script exceeds {kb}KB limit — shorten your script"}

    # shlex.split so that env-var values like "sudo -u pipeline /usr/local/bin/run-sandbox"
    # are split into a proper argv list rather than treated as a single executable name.
    cmd = shlex.split(settings.sandbox_cmd)

    # Mount Cape's extracted payloads if available — nothing extracted is not an
    # error. The whole task directory goes in, not one payload subdir: --data
    # maps to a fixed /data inside the container, so it cannot be repeated, and
    # payloads are spread across CAPE/, files/ and procdump/ (#377). The task
    # directory is still inside run-sandbox's allowlist, and read-only.
    # Mount ONLY the payload directories, each at /data/<name>. The whole task
    # directory used to go in — 76MB of pcaps, memory dumps, evtx and the full
    # Cape report — into the container where LLM-authored code runs, when the
    # sandbox exists to work on payloads (#392). The names match the source
    # directories, so in-container paths are unchanged from that mount.
    #
    # payload_dirs raises on an unreadable storage tree; that must not take down
    # the whole tool, since the sandbox is still useful without a data mount.
    task_id = _cape_task_id(report)
    try:
        data_dirs = payload_dirs(task_id, storage=CAPE_STORAGE) if task_id else []
    except (PayloadAccessError, OSError) as exc:
        log.warning("Cannot read Cape payload dirs for task %s: %s", task_id, exc)
        data_dirs = []
    for d in data_dirs:
        cmd += ["--data-as", f"{d.name}={d}"]

    # Outer backstop = the container's own timeout + 10s margin. The container
    # (run-sandbox, python_sandbox_container_timeout) is the authoritative limit;
    # this just ensures the subprocess can't hang past it.
    outer_timeout = settings.sandbox_timeout_seconds + 10

    try:
        result = subprocess.run(
            cmd,
            input=script,
            capture_output=True,
            text=True,
            timeout=outer_timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Sandbox timed out (>{outer_timeout}s)"}

    out = result.stdout
    err = result.stderr

    # Cap output sizes
    if len(out) > 1_048_576:
        out = out[:1_048_576] + "\n[output truncated at 1MB]"
    if err and len(err) > 10240:
        err = err[:10240] + "\n[stderr truncated at 10KB]"

    response: dict = {"stdout": out, "exit_code": result.returncode}
    if err:
        response["stderr"] = err
    return response


# ---------------------------------------------------------------------------
# Ghidra tools
# ---------------------------------------------------------------------------


def _ghidra_tool(tool_name: str, args: dict, report: dict) -> dict:
    ghidra = report.get("ghidra") or {}
    project_dir = ghidra.get("project_dir")
    program_name = ghidra.get("program_name")

    if not project_dir or not program_name:
        return {
            "error": (
                "Ghidra project not available — either the Ghidra stage did not run "
                "or the project was not persisted in the report"
            )
        }

    if not Path(project_dir).is_dir():
        return {
            "error": (
                f"Ghidra project directory not found on disk: {project_dir}. "
                "The analysis host may differ from the API host."
            )
        }

    # shlex.split so that env-var values like "sudo -u pipeline /usr/local/bin/run-ghidra"
    # are split into a proper argv list rather than treated as a single executable name.
    cmd = shlex.split(settings.ghidra_cmd) + [
        "--tool", project_dir, program_name,
        tool_name,
        json.dumps(args),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=130,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Ghidra tool {tool_name} timed out after 130 seconds"}

    if result.returncode != 0:
        return {
            "error": f"Ghidra exited {result.returncode}",
            "stderr": result.stderr[:4096] if result.stderr else "",
        }

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {
            "error": f"Ghidra returned non-JSON output: {exc}",
            "raw": result.stdout[:2048],
        }


# ---------------------------------------------------------------------------
# pin_finding — proposal only, no DB write
# ---------------------------------------------------------------------------


def _pin_finding(args: dict) -> dict:
    valid_types = {"ioc", "technique", "note"}
    pin_type = args.get("type")
    if pin_type not in valid_types:
        return {
            "error": (
                f"Invalid type '{pin_type}'. Must be one of: "
                + ", ".join(sorted(valid_types))
            )
        }

    if pin_type == "ioc" and not args.get("ioc_type"):
        return {
            "error": (
                "ioc_type is required when type=ioc. "
                "Provide one of: ipv4-addr, domain-name, url, "
                "file:hashes.SHA-256, mutex, etc."
            )
        }

    return {
        "status": "proposed",
        "awaiting_confirmation": True,
        "type": pin_type,
        "value": args["value"],
        "ioc_type": args.get("ioc_type"),
        "context": args["context"],
    }
