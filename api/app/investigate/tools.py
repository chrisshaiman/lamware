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
import subprocess
from pathlib import Path

from sqlalchemy import text
from sqlmodel import Session

from ..config import settings

log = logging.getLogger(__name__)

CAPE_STORAGE = Path("/opt/CAPEv2/storage/analyses")

TOOL_DEFINITIONS = [
    {
        "name": "search_iocs",
        "description": (
            "Search for an IOC value across all analyses. Returns matching analyses "
            "with family, severity, and source stage. Use to answer 'have we seen "
            "this C2/domain/hash before?'"
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
        "description": "Get IOCs for an analysis, optionally filtered by type.",
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
            "Get all callers (cross-references TO) a function in the Ghidra project."
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
            "Get all callees (cross-references FROM) a function in the Ghidra project."
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
            "(e.g., *crypt*)."
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
            "List payloads dropped/extracted by Cape during dynamic analysis "
            "of this sample."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"analysis_id": {"type": "integer"}},
            "required": ["analysis_id"],
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
                "analysis_id": {"type": "integer"},
                "payload_index": {
                    "type": "integer",
                    "description": "Index from get_cape_payloads",
                },
            },
            "required": ["analysis_id", "payload_index"],
        },
    },
    {
        "name": "get_pcap_summary",
        "description": (
            "Get Zeek/Suricata PCAP analysis results for an analysis."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"analysis_id": {"type": "integer"}},
            "required": ["analysis_id"],
        },
    },
    {
        "name": "get_api_traces",
        "description": (
            "Get Cape API call traces for an analysis, optionally filtered by "
            "process name or API name substring."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "analysis_id": {"type": "integer"},
                "process": {"type": "string"},
                "api_filter": {"type": "string"},
            },
            "required": ["analysis_id"],
        },
    },
    {
        "name": "run_python",
        "description": (
            "Execute a Python script in an isolated sandbox (no network, 30s timeout, "
            "256MB). Pre-loaded helpers: "
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
                    "description": "Python script (max 10KB)",
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


def execute_tool(
    tool_name: str,
    args: dict,
    session: Session,
    report: dict,
    analysis_id: int,
) -> dict:
    """Dispatch a tool call. Always returns a JSON-safe dict, never raises."""
    try:
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
        log.exception("Tool %s failed", tool_name)
        return {"error": f"{type(e).__name__}: {e}"}


# ---------------------------------------------------------------------------
# DB tools (read-only SELECTs)
# ---------------------------------------------------------------------------


def _search_iocs(args: dict, session: Session) -> dict:
    sql = text(
        """
        SELECT DISTINCT a.id, a.malware_family_guess, a.severity,
               iv.type, iv.value, ai.source_stage
        FROM analysis_iocs ai
        JOIN ioc_values iv ON ai.ioc_id = iv.id
        JOIN analyses a ON ai.analysis_id = a.id
        WHERE iv.value ILIKE :pattern
        """
        + (" AND iv.type = :ioc_type" if args.get("type") else "")
        + """
        ORDER BY a.id DESC LIMIT 50
        """
    )
    params: dict = {"pattern": f"%{args['value']}%"}
    if args.get("type"):
        params["ioc_type"] = args["type"]
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
    sql = text(
        """
        SELECT event_type, dns_query, dns_type, dns_answers,
               http_method, http_url, http_host, http_status, http_user_agent,
               src_ip, src_port, dst_ip, dst_port, timestamp
        FROM network_events
        WHERE analysis_id = :aid
        """
        + (" AND event_type = :etype" if args.get("type") else "")
        + """
        ORDER BY timestamp ASC NULLS LAST LIMIT 200
        """
    )
    params: dict = {"aid": args["analysis_id"]}
    if args.get("type"):
        params["etype"] = args["type"]
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
        ORDER BY severity DESC
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
        ORDER BY id ASC
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
    sql = text(
        """
        SELECT iv.type, iv.value, ai.source_stage, ai.confidence, ai.context
        FROM analysis_iocs ai
        JOIN ioc_values iv ON ai.ioc_id = iv.id
        WHERE ai.analysis_id = :aid
        """
        + (" AND iv.type = :ioc_type" if args.get("type") else "")
        + """
        ORDER BY iv.type, iv.value LIMIT 500
        """
    )
    params: dict = {"aid": args["analysis_id"]}
    if args.get("type"):
        params["ioc_type"] = args["type"]
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


def _get_cape_payloads(args: dict, report: dict) -> dict:
    task_id = _cape_task_id(report)
    if not task_id:
        return {
            "error": (
                "No Cape task ID in report — sample may not have been detonated"
            )
        }
    dropped = CAPE_STORAGE / task_id / "dropped"
    if not dropped.is_dir():
        return {"payloads": [], "count": 0, "note": "No dropped payloads directory"}
    payloads = [
        {"index": i, "filename": f.name, "size": f.stat().st_size}
        for i, f in enumerate(sorted(dropped.iterdir()))
        if f.is_file()
    ]
    return {"payloads": payloads, "count": len(payloads), "task_id": task_id}


def _read_payload(args: dict, report: dict) -> dict:
    task_id = _cape_task_id(report)
    if not task_id:
        return {
            "error": (
                "No Cape task ID in report — sample may not have been detonated"
            )
        }
    dropped = CAPE_STORAGE / task_id / "dropped"
    if not dropped.is_dir():
        return {"error": "No dropped payloads directory"}

    files = sorted(f for f in dropped.iterdir() if f.is_file())
    idx = args["payload_index"]
    if idx < 0 or idx >= len(files):
        return {
            "error": (
                f"payload_index {idx} out of range — "
                f"{len(files)} payloads available (0–{len(files) - 1})"
            )
        }

    target = files[idx]
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
        top_keys = {k: f"<truncated — {len(json.dumps(v))} bytes>" for k, v in pcap.items()}
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

        result.append(
            {
                "process_name": proc_name,
                "pid": proc.get("pid"),
                "total_calls": total_calls,
                "calls_shown": len(calls),
                "calls": calls,
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
    if len(script.encode()) > 10240:
        return {"error": "Script exceeds 10KB limit — shorten your script"}

    cmd = [settings.sandbox_cmd]

    # Mount dropped payloads if available
    task_id = _cape_task_id(report)
    if task_id:
        dropped = CAPE_STORAGE / task_id / "dropped"
        if dropped.is_dir():
            cmd += ["--data", str(dropped)]

    try:
        result = subprocess.run(
            cmd,
            input=script,
            capture_output=True,
            text=True,
            timeout=40,
        )
    except subprocess.TimeoutExpired:
        return {"error": "Sandbox timed out after 40 seconds"}

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

    cmd = [
        settings.ghidra_cmd,
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
