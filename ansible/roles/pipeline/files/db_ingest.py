"""
Database ingestion — write structured analysis data to PostgreSQL.

Author: Christopher Shaiman
License: Apache 2.0
"""

import os

from lamware_pipeline.config import PipelineConfig
from lamware_pipeline.correlation_rules import correlation_rows
from lamware_pipeline.db import build_insert, build_update
from lamware_pipeline.relationships import write_relationships_safe

# MITRE ATT&CK tactic mapping — maps technique IDs to their tactic phases.
# Covers common techniques seen in malware analysis. Techniques not in this
# dict get no tactics (dashboard shows empty). Expand as needed.
MITRE_TACTICS = {
    "T1007": ["discovery"],
    "T1012": ["discovery"],
    "T1014": ["defense-evasion"],
    "T1016": ["discovery"],
    "T1018": ["discovery"],
    "T1021": ["lateral-movement"],
    "T1027": ["defense-evasion"],
    "T1027.002": ["defense-evasion"],
    "T1033": ["discovery"],
    "T1036": ["defense-evasion"],
    "T1041": ["exfiltration"],
    "T1047": ["execution"],
    "T1053": ["execution", "persistence", "privilege-escalation"],
    "T1055": ["defense-evasion", "privilege-escalation"],
    "T1055.003": ["defense-evasion", "privilege-escalation"],
    "T1055.012": ["defense-evasion", "privilege-escalation"],
    "T1057": ["discovery"],
    "T1059": ["execution"],
    "T1059.001": ["execution"],
    "T1059.003": ["execution"],
    "T1059.005": ["execution"],
    "T1059.006": ["execution"],
    "T1071": ["command-and-control"],
    "T1071.001": ["command-and-control"],
    "T1082": ["discovery"],
    "T1083": ["discovery"],
    "T1095": ["command-and-control"],
    "T1105": ["command-and-control"],
    "T1106": ["execution"],
    "T1112": ["defense-evasion"],
    "T1134": ["defense-evasion", "privilege-escalation"],
    "T1134.001": ["defense-evasion", "privilege-escalation"],
    "T1140": ["defense-evasion"],
    "T1204": ["execution"],
    "T1218": ["defense-evasion"],
    "T1486": ["impact"],
    "T1489": ["impact"],
    "T1490": ["impact"],
    "T1497": ["defense-evasion", "discovery"],
    "T1497.001": ["defense-evasion", "discovery"],
    "T1518": ["discovery"],
    "T1543": ["persistence", "privilege-escalation"],
    "T1547": ["persistence", "privilege-escalation"],
    "T1547.001": ["persistence", "privilege-escalation"],
    "T1548": ["defense-evasion", "privilege-escalation"],
    "T1548.002": ["defense-evasion", "privilege-escalation"],
    "T1553": ["defense-evasion"],
    "T1555": ["credential-access"],
    "T1560": ["collection"],
    "T1562": ["defense-evasion"],
    "T1571": ["command-and-control"],
    "T1573": ["command-and-control"],
    "T1574": ["persistence", "privilege-escalation", "defense-evasion"],
    "T1480": ["defense-evasion"],
    "T1485": ["impact"],
    # T1489/T1490 were re-declared here identically to lines 54-55 — a merge artifact in
    # a hand-maintained table. Behaviour was unaffected (same value), but a duplicate key
    # in a lookup table is one careless edit away from becoming a silent override.
    "T1564": ["defense-evasion"],
    "T1070": ["defense-evasion"],
    "T1070.004": ["defense-evasion"],
    "T1129": ["execution"],
    "T1202": ["defense-evasion"],
    "T1064": ["execution"],
    "T1003": ["credential-access"],
    "T1003.001": ["credential-access"],
    "T1056": ["collection", "credential-access"],
    "T1056.001": ["collection", "credential-access"],
    "T1113": ["collection"],
    "T1115": ["collection"],
    "T1005": ["collection"],
    "T1552": ["credential-access"],
    "T1552.001": ["credential-access"],
    "T1555.003": ["credential-access"],
    "T1078": ["defense-evasion", "initial-access", "persistence", "privilege-escalation"],
    "T1102": ["command-and-control"],
    "T1132": ["command-and-control"],
    "T1568": ["command-and-control"],
    "T1048": ["exfiltration"],
    "T1567": ["exfiltration"],
    "T1010": ["discovery"],
    "T1046": ["discovery"],
    "T1049": ["discovery"],
    "T1069": ["discovery"],
    "T1087": ["discovery"],
    "T1124": ["discovery"],
    "T1135": ["discovery"],
    "T1201": ["discovery"],
    "T1120": ["discovery"],
}


# -------------------------------------------------------------------------
# Configuration (injected by Ansible template)
# -------------------------------------------------------------------------

_CFG = PipelineConfig.load(
    os.environ.get("LAMWARE_PIPELINE_CONFIG", "/opt/pipeline/config.json")
)
DB_HOST = _CFG.db_host
DB_PORT = _CFG.db_port
DB_NAME = _CFG.db_name
DB_USER = _CFG.db_user
DB_PASSWORD = os.environ.get("PIPELINE_DB_PASSWORD", "")


# LLM pricing per million tokens (update when model pricing changes).
# These must match Anthropic's published rates — a drifted entry silently
# mis-states llm_cost_usd on every analysis, and there is no runtime signal that
# it is wrong. test_pricing_table_matches_published_rates guards them.
_LLM_PRICING = {
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-opus-4-6": {"input": 5.00, "output": 25.00},
    "claude-haiku-4-5": {"input": 1.00, "output": 5.00},
    # Local inference has no per-token API cost. These names are matched exactly;
    # the `local-` prefix rule in _price_for_model() is what actually covers the
    # deployed set, which has drifted past this list before (see below).
    "local-qwen": {"input": 0.00, "output": 0.00},
    "local-qwen-strict": {"input": 0.00, "output": 0.00},
    "default": {"input": 3.00, "output": 15.00},
}

# Any model served by the local backend costs nothing per token. Kept as a PREFIX
# rule rather than an enumeration because the enumeration silently fell behind the
# deployment: pipeline_summary_model / pipeline_plain_english_model moved from
# "local-qwen" to "local-qwen-llamacpp" (the Ollama->llama.cpp switch), and the eval
# arms use "local-qwen-llamacpp-re" and "local-qwen-re". None of those were in the
# table, so free local inference fell through to the "default" row and was billed at
# Anthropic Sonnet rates ($3/$15 per Mtok) — ~$0.05 of phantom cost per summary,
# on every run, surfaced in llm_cost_usd and the spend dashboard. The prefix makes
# the whole `local-*` family correct without another name to forget.
_LOCAL_MODEL_PREFIX = "local-"
_ZERO_PRICING = {"input": 0.00, "output": 0.00}


def _price_for_model(model: str) -> dict:
    """Per-Mtok pricing for a model name, resolved fail-loud rather than fail-silent.

    Order: an exact table entry wins; then any `local-*` name is priced at zero
    (local inference has no API cost); only a genuinely unrecognised name reaches
    the `default` row, and that case is announced. An unpriced model silently
    charged at the default rate is exactly how the local-qwen-llamacpp cost was
    wrong on every run with nothing to signal it.
    """
    name = model or "default"
    entry = _LLM_PRICING.get(name)
    if entry is not None:
        return entry
    if name.startswith(_LOCAL_MODEL_PREFIX):
        return _ZERO_PRICING
    print(f"  [!] llm_cost: model {name!r} is not in the pricing table — "
          f"billing at the default ${_LLM_PRICING['default']['input']}/"
          f"${_LLM_PRICING['default']['output']} per Mtok, which may be wrong")
    return _LLM_PRICING["default"]


def _calculate_llm_cost(report: dict) -> float:
    """Calculate total LLM API cost from token usage across all stages.

    Reads usage data from llm_interpretation, executive_summary,
    evasion_analysis, and visual_analysis sections of the report.
    Falls back to $0.50 estimate if no usage data available.
    """
    total_cost = 0.0
    has_usage = False

    # Each section stores usage at the top level of its result dict
    llm_sections = [
        "llm_interpretation",
        "executive_summary",
        "evasion_analysis",
        "visual_analysis",
    ]

    for section_key in llm_sections:
        section = report.get(section_key, {})

        usage = section.get("usage", {})
        if not usage:
            continue

        model = section.get("model_used", section.get("model_final",
                section.get("model", "default")))
        pricing = _price_for_model(model)

        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)

        if input_tokens or output_tokens:
            has_usage = True
            cost = (input_tokens * pricing["input"] / 1_000_000) + \
                   (output_tokens * pricing["output"] / 1_000_000)
            total_cost += cost

    # Plain English summary usage (stored separately at report root)
    pe_usage = report.get("plain_english_usage", {})
    if pe_usage:
        input_tokens = pe_usage.get("input_tokens", 0)
        output_tokens = pe_usage.get("output_tokens", 0)
        if input_tokens or output_tokens:
            has_usage = True
            # Price by the actual plain-English model (may be local = $0), falling
            # back to Haiku for older reports that didn't record the model.
            pe_model = report.get("plain_english_model") or "claude-haiku-4-5"
            pricing = _price_for_model(pe_model)
            cost = (input_tokens * pricing["input"] / 1_000_000) + \
                   (output_tokens * pricing["output"] / 1_000_000)
            total_cost += cost

    return total_cost if has_usage else 0.50


def ingest_to_db(report: dict, existing_analysis_id: int | None = None):
    """Write structured analysis data to PostgreSQL.

    If existing_analysis_id is provided (from pipeline_status early creation),
    updates that row instead of inserting a new one.

    Inserts/updates samples, analyses, IOCs, techniques, capabilities,
    signatures, and network events. Returns analysis_id on success.
    """
    if not DB_PASSWORD:
        print("  [!] DB ingestion skipped — no database password configured")
        return False

    try:
        import psycopg2
        import psycopg2.extras
    except ImportError:
        print("  [!] DB ingestion skipped — psycopg2 not installed")
        return False

    try:
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASSWORD,
        )
        conn.autocommit = False
        cur = conn.cursor()
    except Exception as e:
        print(f"  [!] DB connection failed: {e}")
        return False

    try:
        # --- Upsert sample ---
        triage = report.get("triage", {})
        # SHA-256: prefer triage hashes, then extract from sample filename, then task_id
        sha256 = triage.get("hashes", {}).get("sha256", "")
        if not sha256:
            name = report.get("sample_name", "")
            # Sample filenames are often <sha256>.exe — extract if 64+ hex chars
            stem = name.rsplit(".", 1)[0] if "." in name else name
            if len(stem) == 64 and all(c in "0123456789abcdef" for c in stem.lower()):
                sha256 = stem.lower()
        if not sha256:
            sha256 = report.get("task_id", "unknown")

        # The conflict path has to write the triage columns, not just touch
        # last_seen. create_analysis_row() (pipeline_status.py) inserts this row
        # at the START of the run with only (sha256, filename) — triage has not
        # run yet — so by the time ingest_to_db arrives every sample is an
        # ON CONFLICT, and file_type/file_mime/entropy/ssdeep were dropped on
        # the floor for EVERY run rather than merely on a re-ingest. ssdeep
        # stayed empty forever, and select_ssdeep_edges filters on
        # `ssdeep IS NOT NULL AND ssdeep <> ''`, so no ssdeep_similar edge could
        # ever be built.
        #
        # NULLIF before COALESCE because these arrive as "" rather than NULL:
        # a plain COALESCE(EXCLUDED.x, samples.x) never falls back, so a later
        # run with an empty value would overwrite a good stored one. That was
        # already true of the filename line below.
        cur.execute("""
            INSERT INTO samples (sha256, filename, file_type, file_mime, entropy, ssdeep)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (sha256) DO UPDATE SET
                last_seen = NOW(),
                filename  = COALESCE(NULLIF(EXCLUDED.filename, ''), samples.filename),
                file_type = COALESCE(NULLIF(EXCLUDED.file_type, ''), samples.file_type),
                file_mime = COALESCE(NULLIF(EXCLUDED.file_mime, ''), samples.file_mime),
                entropy   = COALESCE(EXCLUDED.entropy, samples.entropy),
                ssdeep    = COALESCE(NULLIF(EXCLUDED.ssdeep, ''), samples.ssdeep)
            RETURNING id
        """, (
            sha256,
            report.get("sample_name", ""),
            triage.get("file_type", ""),
            triage.get("file_mime", ""),
            triage.get("entropy"),
            triage.get("ssdeep", ""),
        ))
        sample_id = cur.fetchone()[0]

        # --- Insert analysis ---
        interp = report.get("llm_interpretation", {})
        analysis = interp.get("analysis", {})
        summary = report.get("executive_summary", {})

        # Programmatic analysis is authoritative for severity. The LLM's
        # `risk_assessment` used to be the last fallback here, which meant that
        # whenever the programmatic verdict was absent the model wrote the verdict
        # column directly — the second path by which model output became a decision
        # (GHSA-f5q8-v78c-mr55; calculate_severity was the first).
        #
        # Absent stays absent. A missing verdict is a visible gap an analyst can
        # act on; a model-supplied one looks identical to a real verdict and is
        # trusted like one. The model's view is still stored on the analysis row
        # via the interpretation fields, so nothing is lost but the authority.
        severity = (report.get("severity")
                    or summary.get("severity"))
        family = (report.get("family")
                  or analysis.get("malware_family_guess"))

        # Analysis row values (shared between INSERT and UPDATE)
        analysis_values = {
            "sample_id": sample_id,
            "task_id": report.get("task_id", ""),
            "started_at": report.get("started_at"),
            "completed_at": report.get("completed_at"),
            "severity": severity,
            "malscore": report.get("cape", {}).get("malscore"),
            "malware_family_guess": family,
            "triage_completed": bool(triage),
            "cape_completed": report.get("cape", {}).get("status") == "reported",
            "cape_task_id": report.get("cape", {}).get("task_id"),
            "volatility_completed": bool(report.get("volatility", {}).get("plugins")),
            "volatility_triggered": report.get("volatility", {}).get("triggered", False),
            "ghidra_completed": bool(report.get("ghidra", {}).get("analyzed_files")),
            "ghidra_triggered": report.get("ghidra", {}).get("triggered", False),
            "interpret_completed": interp.get("enabled", False) and "error" not in interp,
            "summary_completed": bool(summary.get("executive_summary")),
            "interpret_model": interp.get("model_final", interp.get("model_initial")),
            "interpret_tool_calls": interp.get("tool_calls_used", 0),
            "interpret_duration_secs": interp.get("duration_seconds"),
            "interpret_escalated": interp.get("escalated", False),
            "possible_prompt_influence": interp.get("possible_prompt_influence", False),
            "narrative": analysis.get("narrative", ""),
            "working_notes": analysis.get("working_notes", ""),
            "executive_summary": summary.get("executive_summary", ""),
            "plain_english_summary": report.get("plain_english_summary", ""),
            "pipeline_status": "completed",
            "stage_timings": psycopg2.extras.Json(report.get("timing", {})),
            "report_json": psycopg2.extras.Json(report),
        }

        # Calculate LLM API cost from token usage
        llm_cost = _calculate_llm_cost(report)
        analysis_values["llm_cost_usd"] = llm_cost

        if existing_analysis_id:
            # Update the early-created row
            cur.execute(
                build_update("analyses", list(analysis_values), "id"),
                list(analysis_values.values()) + [existing_analysis_id],
            )
            analysis_id = existing_analysis_id
        else:
            # Insert new row (backward compatible)
            cur.execute(
                build_insert("analyses", list(analysis_values)),
                list(analysis_values.values()),
            )
            analysis_id = cur.fetchone()[0]

        # --- Insert IOCs ---
        for ioc in report.get("extracted_iocs", []):
            cur.execute("""
                INSERT INTO ioc_values (type, value)
                VALUES (%s, %s)
                ON CONFLICT (type, value) DO UPDATE SET
                    last_seen = NOW()
                RETURNING id
            """, (ioc["type"], ioc["value"]))
            ioc_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO analysis_iocs (analysis_id, ioc_id, source_stage, context)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (analysis_id, ioc_id, source_stage) DO NOTHING
            """, (analysis_id, ioc_id, ioc["source"], ioc.get("context", "")))

        # --- Insert MITRE techniques ---
        # From AI RE
        for t in analysis.get("attack_techniques", []):
            tid = t.get("id", "")
            tactics = MITRE_TACTICS.get(tid, [])
            cur.execute("""
                INSERT INTO technique_values (technique_id, technique_name, tactics)
                VALUES (%s, %s, %s)
                ON CONFLICT (technique_id) DO UPDATE SET
                    tactics = COALESCE(EXCLUDED.tactics, technique_values.tactics)
                RETURNING id
            """, (tid, t.get("name", ""), tactics or None))
            row = cur.fetchone()
            if row:
                tech_id = row[0]
            else:
                cur.execute("SELECT id FROM technique_values WHERE technique_id = %s",
                            (t.get("id", ""),))
                tech_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO analysis_techniques (analysis_id, technique_id, source_stage)
                VALUES (%s, %s, %s)
                ON CONFLICT (analysis_id, technique_id, source_stage) DO NOTHING
            """, (analysis_id, tech_id, "AI Reverse Engineering"))

        # From Cape TTPs
        for t in report.get("cape", {}).get("mitre_ttps", []):
            tid = t.get("id", "")
            tactics = MITRE_TACTICS.get(tid, [])
            cur.execute("""
                INSERT INTO technique_values (technique_id, technique_name, tactics)
                VALUES (%s, %s, %s)
                ON CONFLICT (technique_id) DO UPDATE SET
                    tactics = COALESCE(EXCLUDED.tactics, technique_values.tactics)
                RETURNING id
            """, (tid, t.get("source_signature", ""), tactics or None))
            row = cur.fetchone()
            if row:
                tech_id = row[0]
            else:
                cur.execute("SELECT id FROM technique_values WHERE technique_id = %s",
                            (t.get("id", ""),))
                tech_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO analysis_techniques (analysis_id, technique_id, source_stage, source_detail)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (analysis_id, technique_id, source_stage) DO NOTHING
            """, (analysis_id, tech_id, "Cape", t.get("source_signature", "")))

        # --- Insert capabilities ---
        for cap in analysis.get("capabilities", []):
            cur.execute("""
                INSERT INTO capabilities (analysis_id, description, source_stage)
                VALUES (%s, %s, %s)
            """, (analysis_id, cap, "AI Reverse Engineering"))

        # --- Insert signatures ---
        for sig in report.get("cape", {}).get("signatures", []):
            cur.execute("""
                INSERT INTO signatures (analysis_id, name, severity, description)
                VALUES (%s, %s, %s, %s)
            """, (analysis_id, sig.get("name", ""), sig.get("severity", 0),
                  sig.get("description", "")))

        # --- Insert network events ---
        cape_net = report.get("cape", {}).get("network", {})
        for d in cape_net.get("dns_queries", []):
            cur.execute("""
                INSERT INTO network_events (analysis_id, event_type, dns_query, dns_type, dns_answers)
                VALUES (%s, 'dns', %s, %s, %s)
            """, (analysis_id, d.get("domain", ""), d.get("type", ""),
                  psycopg2.extras.Json(d.get("answers", []))))

        for h in cape_net.get("http_requests", []):
            cur.execute("""
                INSERT INTO network_events (analysis_id, event_type, http_method, http_url, http_host)
                VALUES (%s, 'http', %s, %s, %s)
            """, (analysis_id, h.get("method", ""), h.get("url", ""), h.get("host", "")))

        # tcp_connections is deduplicated by destination upstream, so this now
        # writes one row per DESTINATION rather than one per connection — two
        # rows for a sample that made 194 attempts. `src` is gone with the
        # dedup: an ephemeral source port is not an IOC and was only ever
        # varying noise that made identical destinations look distinct.
        for c in cape_net.get("tcp_connections", []):
            dst = c.get("dst", "")
            src = ""
            dst_ip, dst_port = (dst.rsplit(":", 1) + ["0"])[:2] if ":" in dst else (dst, "0")
            src_ip, src_port = (src.rsplit(":", 1) + ["0"])[:2] if ":" in src else (src, "0")
            cur.execute("""
                INSERT INTO network_events (analysis_id, event_type, src_ip, src_port, dst_ip, dst_port)
                VALUES (%s, 'tcp', %s, %s, %s, %s)
            """, (analysis_id, src_ip, int(src_port) if src_port.isdigit() else 0,
                  dst_ip, int(dst_port) if dst_port.isdigit() else 0))

        # --- Insert IOC-technique mappings ---
        for mapping in report.get("ioc_technique_mappings", []):
            # Look up ioc_id
            cur.execute("SELECT id FROM ioc_values WHERE type = %s AND value = %s",
                        (mapping["ioc_type"], mapping["ioc_value"]))
            ioc_row = cur.fetchone()
            if not ioc_row:
                continue

            # Ensure technique exists
            cur.execute("""
                INSERT INTO technique_values (technique_id, technique_name)
                VALUES (%s, %s)
                ON CONFLICT (technique_id) DO NOTHING
                RETURNING id
            """, (mapping["technique_id"], mapping.get("technique_name", "")))
            tech_row = cur.fetchone()
            if not tech_row:
                cur.execute("SELECT id FROM technique_values WHERE technique_id = %s",
                            (mapping["technique_id"],))
                tech_row = cur.fetchone()

            if tech_row:
                cur.execute("""
                    INSERT INTO ioc_technique_mappings
                        (analysis_id, ioc_id, technique_id, evidence, method, confidence)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (analysis_id, ioc_id, technique_id) DO NOTHING
                """, (analysis_id, ioc_row[0], tech_row[0],
                      mapping.get("evidence", ""),
                      mapping.get("method", "programmatic"),
                      mapping.get("confidence", "high")))

        # --- Insert cross-tool correlations (#423) ---
        #
        # Delete-then-insert rather than append. Every other child table here
        # appends, which on the --replay path (#405 re-runs the whole ingest)
        # duplicates rows. For IOCs that is untidy; for correlations it would
        # corrupt the one number this table exists to produce, because a base
        # rate counted over duplicated findings is not a base rate. Correlation
        # output is wholly derived from the report, so replacing it wholesale is
        # the correct semantics — the same reasoning enrich_correlation_inputs
        # already applies to its own cache.
        cur.execute("DELETE FROM correlations WHERE analysis_id = %s", (analysis_id,))

        for row in correlation_rows(report.get("cross_correlations", []) or []):
            cur.execute("""
                INSERT INTO correlations
                    (analysis_id, type, severity, title, detail, sources, mitre, pid)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (analysis_id, *row))

        # Warnings are a column on the analysis, not rows beside the findings.
        # Setting it to a list — EMPTY LIST INCLUDED — is what records that
        # correlation ran: NULL means never recorded, '{}' means ran clean,
        # non-empty means ran blind (#411). Written after the inserts and inside
        # the same transaction, so a failure part-way cannot leave an analysis
        # claiming it was correlated when nothing landed.
        warnings = [str(w)[:500] for w in (report.get("correlation_warnings") or [])]
        cur.execute(
            "UPDATE analyses SET correlation_warnings = %s WHERE id = %s",
            (warnings, analysis_id))

        conn.commit()
        n_corr = len(report.get("cross_correlations", []) or [])
        print(f"  DB: ingested analysis {analysis_id} for sample {sample_id} "
              f"({n_corr} correlations, {len(warnings)} correlation warnings)")

        # Cross-sample campaign edges (non-fatal enrichment, separate from the
        # committed ingest above). A failure here never fails the analysis ingest.
        write_relationships_safe(conn, sample_id, _CFG)

        return analysis_id

    except Exception as e:
        conn.rollback()
        print(f"  [!] DB ingestion error: {e}")
        return None
    finally:
        cur.close()
        conn.close()


def mark_pdf_generated(analysis_id: int) -> bool:
    """Set pdf_generated=True for the given analysis row."""
    if not DB_PASSWORD or not analysis_id:
        return False

    try:
        import psycopg2
    except ImportError:
        return False

    try:
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
            user=DB_USER, password=DB_PASSWORD,
        )
        cur = conn.cursor()
        cur.execute("UPDATE analyses SET pdf_generated = TRUE WHERE id = %s", (analysis_id,))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"  [!] Failed to update pdf_generated: {e}")
        return False
