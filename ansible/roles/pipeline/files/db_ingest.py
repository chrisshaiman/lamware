"""
Database ingestion — write structured analysis data to PostgreSQL.

Author: Christopher Shaiman
License: Apache 2.0
"""

import math
import os
from contextlib import contextmanager
from datetime import datetime

from lamware_pipeline.config import PipelineConfig
from lamware_pipeline.correlation_rules import correlation_rows
from lamware_pipeline.db import build_insert, build_update
from lamware_pipeline.relationships import write_relationships_safe
from lamware_pipeline.report_depth import bound_report_depth
from lamware_pipeline.report_depth import describe as describe_depth_cut

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

# Anthropic's standard prompt-cache multipliers on the base input rate: a cache
# WRITE (5-minute ephemeral, what interpret's `cache_control: ephemeral` requests)
# costs 1.25x, a cache READ 0.1x. A _LLM_PRICING entry may override either with an
# explicit "cache_write" / "cache_read" rate when a model's published rates differ.
# Both counts arrive SEPARATELY from input_tokens (#718) — they are not a share of
# it — so a cost that reads only input/output never bills them at all.
_CACHE_WRITE_MULT = 1.25
_CACHE_READ_MULT = 0.1


# -------------------------------------------------------------------------
# Shape-checked reads from the report (#171)
# -------------------------------------------------------------------------
#
# Most of report.json is shaped by the sample (CAPE output, filenames, payload
# labels) or by a model that read the sample (the interpretation). dict.get(k, {})
# returns the default only when k is ABSENT, not when it is present as null, a
# string or a list — so `report.get("cape", {}).get("malscore")` raised on
# {"cape": null}, and every raise in ingest_to_db lands in its blanket
# `except: rollback` (#450). One wrong-typed field cost the analysis every row:
# sample, verdict, IOCs, techniques, signatures.
#
# Every read below goes through _Node instead. The rule it enforces:
#   - absent or null      -> the caller's default, silently (null carries no data;
#                            nullable columns still get NULL, as they always did)
#   - present, right type -> the value, unchanged
#   - present, wrong type -> the default, AND a warning naming the path
#     (or a value its column cannot hold: int4/float4 range, non-ISO timestamp)
# so a well-formed report ingests exactly as before, and nothing a malformed one
# loses is lost silently. The warnings travel in report_json["_ingest_warnings"]
# (no schema change) and on stdout.

_INT4_MAX = 2**31 - 1
_FLOAT4_MAX = 3.4028234e38      # `real` columns: a larger finite value is an
                                # out-of-range error in PostgreSQL, not a clamp
_LLM_COST_LIMIT = 10_000        # analyses.llm_cost_usd is numeric(8,4)
_MAX_INGEST_WARNINGS = 50       # a 100k-element list of junk is one problem, not 100k


def _type_name(value) -> str:
    return {dict: "object", list: "array", str: "string", bool: "boolean",
            int: "integer", float: "number", type(None): "null"}.get(
                type(value), type(value).__name__)


class _Node:
    """One object in the report, with typed accessors that never raise.

    `path` is built from our own key names and list indices only — never from
    report content — so a warning cannot carry sample-chosen text into the log.
    """

    __slots__ = ("data", "path", "warnings")

    def __init__(self, data: dict, path: str, warnings: list[str]):
        self.data = data
        self.path = path
        self.warnings = warnings

    def __bool__(self) -> bool:
        return bool(self.data)

    def __contains__(self, key: str) -> bool:
        return key in self.data

    def _at(self, key: str) -> str:
        return f"{self.path}.{key}" if self.path else key

    def _drop(self, key: str, expected: str, value) -> None:
        self.warnings.append(
            f"{self._at(key)}: expected {expected}, got {_type_name(value)} — not ingested")

    def raw(self, key: str, default=None):
        """The value as-is, for consumers that accept any JSON (jsonb, truthiness)."""
        return self.data.get(key, default)

    def obj(self, key: str) -> "_Node":
        value = self.data.get(key)
        if not isinstance(value, dict):
            if value is not None:
                self._drop(key, "object", value)
            value = {}
        return _Node(value, self._at(key), self.warnings)

    def array(self, key: str) -> list:
        value = self.data.get(key)
        if isinstance(value, list):
            return value
        if value is not None:
            self._drop(key, "array", value)
        return []

    def items(self, key: str) -> list["_Node"]:
        """The object elements of a list; any other element is dropped and named."""
        out = []
        for i, item in enumerate(self.array(key)):
            if isinstance(item, dict):
                out.append(_Node(item, f"{self._at(key)}[{i}]", self.warnings))
            else:
                self._drop(f"{key}[{i}]", "object", item)
        return out

    def texts(self, key: str) -> list[str]:
        out = []
        for i, item in enumerate(self.array(key)):
            if isinstance(item, str):
                out.append(item)
            else:
                self._drop(f"{key}[{i}]", "string", item)
        return out

    def text(self, key: str, default: str | None = "", nullable: bool = True) -> str | None:
        """A string. `nullable=False` for NOT NULL columns, where null takes the default."""
        if key not in self.data:
            return default
        value = self.data[key]
        if isinstance(value, str):
            return value
        if value is None:
            return None if nullable else default
        self._drop(key, "string", value)
        return default

    def integer(self, key: str, default: int | None = None) -> int | None:
        """An int that fits an `integer` column. bool is not an int here."""
        if key not in self.data:
            return default
        value = self.data[key]
        if value is None:
            return None
        if type(value) is not int:
            self._drop(key, "integer", value)
            return default
        if not -_INT4_MAX - 1 <= value <= _INT4_MAX:
            self.warnings.append(f"{self._at(key)}: integer out of range — not ingested")
            return default
        return value

    def number(self, key: str, default: float | None = None) -> float | int | None:
        """An int or float that fits a `real` column."""
        if key not in self.data:
            return default
        value = self.data[key]
        if value is None:
            return None
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            self._drop(key, "number", value)
            return default
        if math.isfinite(value) and abs(value) > _FLOAT4_MAX:
            self.warnings.append(f"{self._at(key)}: number out of range — not ingested")
            return default
        return value

    def flag(self, key: str, default: bool | None = False) -> bool | None:
        if key not in self.data:
            return default
        value = self.data[key]
        if value is None or isinstance(value, bool):
            return value
        self._drop(key, "boolean", value)
        return default

    def timestamp(self, key: str) -> str | None:
        """An ISO-8601 string, or None. A non-timestamp string would fail the
        INSERT as surely as a wrong type."""
        value = self.text(key, None)
        if value is None:
            return None
        try:
            datetime.fromisoformat(value)
        except ValueError:
            self.warnings.append(f"{self._at(key)}: not an ISO-8601 timestamp — not ingested")
            return None
        return value

    def required_texts(self, *keys: str) -> tuple[str, ...] | None:
        """All of `keys` as strings, or None (with one warning) if any is
        missing or wrong — for rows that cannot exist without them."""
        values = tuple(self.text(k, None) for k in keys)
        if any(v is None for v in values):
            missing = [k for k, v in zip(keys, values, strict=True) if v is None]
            self.warnings.append(
                f"{self.path}: missing {', '.join(missing)} — row not ingested")
            return None
        return values


def _read_report(report, warnings: list[str]) -> _Node:
    if not isinstance(report, dict):
        warnings.append(f"report: expected object, got {_type_name(report)} — not ingested")
        report = {}
    return _Node(report, "", warnings)


def _capped(warnings: list[str]) -> list[str]:
    """Deduplicated (a field read twice warns twice), then bounded."""
    unique = list(dict.fromkeys(warnings))
    if len(unique) <= _MAX_INGEST_WARNINGS:
        return unique
    return unique[:_MAX_INGEST_WARNINGS] + [
        f"... and {len(unique) - _MAX_INGEST_WARNINGS} more"]


# -------------------------------------------------------------------------
# Values PostgreSQL refuses whatever their type (#450)
# -------------------------------------------------------------------------
#
# _Node makes every value the right TYPE. Two things it cannot see still fail
# the statement they are bound to:
#   - a NUL character. psycopg2 refuses a str containing one before sending
#     ("A string literal cannot contain NUL (0x00) characters"), and jsonb
#     refuses the \u0000 escape json.dumps writes for it ("unsupported Unicode
#     escape sequence"). Malware strings, CAPE output and model text can all
#     carry one, and report_json carries all of them.
#   - NaN / Infinity inside a jsonb value. json.dumps writes them as bare
#     tokens; jsonb rejects them as invalid JSON.
# Both are removed at ONE choke point, _CleanCursor.execute, which every
# statement in ingest_to_db goes through — not per field, because the next
# field added would be the one nobody remembered.

_NUL = "\x00"


class _Cleaner:
    """Strips NUL from every string (and dict key) bound, and turns non-finite
    floats inside jsonb into null. Counts what it changed, never what it saw."""

    def __init__(self) -> None:
        self.nul = 0
        self.non_finite = 0

    # Both walks are iterative (#702). They see report_json whole, and the
    # guest sets how deep parts of it nest: the recursive versions raised
    # RecursionError from a pstree 247 processes deep (two frames a level,
    # any() plus the generator), and the blanket except in ingest_to_db turned
    # that into a rolled-back analysis with no row. ingest_to_db also bounds
    # the report's depth first (lamware_pipeline.report_depth); these do not
    # rely on it.

    @staticmethod
    def _dirty_leaf(value, in_json: bool) -> bool:
        if isinstance(value, str):
            return _NUL in value
        if isinstance(value, float):
            return in_json and not math.isfinite(value)
        return False

    def _dirty(self, value, in_json: bool) -> bool:
        stack = [value]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if self._dirty_leaf(k, in_json):
                        return True
                    stack.append(v)
            elif isinstance(node, (list, tuple)):
                stack.extend(node)
            elif self._dirty_leaf(node, in_json):
                return True
        return False

    def _clean_leaf(self, value, in_json: bool):
        if isinstance(value, str):
            if _NUL in value:
                self.nul += 1
                return value.replace(_NUL, "")
            return value
        if isinstance(value, float) and in_json and not math.isfinite(value):
            self.non_finite += 1
            return None
        return value

    def _clean(self, value, in_json: bool):
        """A cleaned copy of ``value``; the input is never modified.

        The recursive version's order is kept exactly — each key cleaned before
        its value, and a later key that cleans to the same string as an earlier
        one wins — by building each container only once all of its children
        are built, as the recursion did.
        """
        if not isinstance(value, (dict, list, tuple)):
            return self._clean_leaf(value, in_json)

        def frame(node):
            # [source, iterator over its children, the children built so far]
            items = iter(node.items()) if isinstance(node, dict) else iter(node)
            return [node, items, []]

        stack = [frame(value)]
        pending_key = []   # for each dict frame on the stack: the key its open child goes under
        while True:
            node, items, built = stack[-1]
            try:
                child = next(items)
            except StopIteration:
                stack.pop()
                if isinstance(node, dict):
                    result = dict(built)
                else:
                    result = type(node)(built)
                if not stack:
                    return result
                parent = stack[-1]
                if isinstance(parent[0], dict):
                    parent[2].append((pending_key.pop(), result))
                else:
                    parent[2].append(result)
                continue
            if isinstance(node, dict):
                k, v = child
                k = self._clean_leaf(k, in_json)
                if isinstance(v, (dict, list, tuple)):
                    pending_key.append(k)
                    stack.append(frame(v))
                else:
                    built.append((k, self._clean_leaf(v, in_json)))
            elif isinstance(child, (dict, list, tuple)):
                stack.append(frame(child))
            else:
                built.append(self._clean_leaf(child, in_json))

    def param(self, value):
        """One bound parameter, returned unchanged (the same object) when clean,
        so a well-formed report binds exactly what it bound before."""
        from psycopg2.extras import Json
        if isinstance(value, Json):
            if not self._dirty(value.adapted, True):
                return value
            return Json(self._clean(value.adapted, True))
        if not self._dirty(value, False):
            return value
        return self._clean(value, False)

    def warnings(self) -> list[str]:
        out = []
        if self.nul:
            out.append(f"NUL characters removed from {self.nul} value(s) — "
                       "PostgreSQL text and jsonb cannot store them")
        if self.non_finite:
            out.append(f"{self.non_finite} NaN/Infinity value(s) in jsonb stored as null")
        return out


class _CleanCursor:
    """The cursor ingest_to_db writes through: every parameter passes _Cleaner."""

    def __init__(self, cur, cleaner: _Cleaner):
        self._cur = cur
        self.cleaner = cleaner

    def execute(self, query, params=None):
        if params is None:
            return self._cur.execute(query)
        cleaned = [self.cleaner.param(p) for p in params]
        return self._cur.execute(query, tuple(cleaned) if isinstance(params, tuple) else cleaned)

    def fetchone(self):
        return self._cur.fetchone()

    def close(self):
        return self._cur.close()


# Core varchar columns whose value comes from the sample, the model or the
# submission. An over-long value here fails the samples/analyses write, which
# is the one failure no SAVEPOINT can contain: without those rows there is
# nothing to show. Clipped, with a warning. Must match api/alembic/versions;
# test_core_widths_match_the_migrations holds it there.
_CORE_WIDTHS = {
    "samples.sha256": 64,
    "samples.filename": 500,
    "samples.file_mime": 100,
    "samples.ssdeep": 200,
    "analyses.task_id": 100,
    "analyses.severity": 20,
    "analyses.malware_family_guess": 200,
    "analyses.interpret_model": 100,
}


def _clip(value: str | None, column: str, warnings: list[str]) -> str | None:
    width = _CORE_WIDTHS[column]
    if value is None or len(value) <= width:
        return value
    warnings.append(f"{column}: {len(value)} characters clipped to {width}")
    return value[:width]


# -------------------------------------------------------------------------
# Core and enrichment (#450)
# -------------------------------------------------------------------------
#
# CORE is what the analysis IS: the samples row and the analyses row, with
# report_json. Without them nothing reaches the UI. They are written and
# COMMITTED first, on their own.
#
# ENRICHMENT is everything derived from the report that hangs off the
# analysis: IOCs, techniques (AI and CAPE), capabilities, signatures, network
# events (dns, http, tcp), IOC-technique mappings, correlations with
# correlation_warnings, and the _ingest_warnings merge. Each GROUP runs inside
# its own SAVEPOINT, so a statement PostgreSQL refuses (a value too long for
# its varchar, a constraint) rolls back that group only, and is recorded in
# report_json["_ingest_warnings"]. Before this, one refused row anywhere rolled
# back the sample and the analysis with it.
#
# A new table that hangs off an analysis is enrichment: give it its own
# `with _enrichment(...)` block. Only something the analysis cannot be shown
# without belongs before the core commit.

_ENRICHMENT_GROUPS = (
    "iocs", "techniques_ai", "techniques_cape", "capabilities", "signatures",
    "network_dns", "network_http", "network_tcp", "ioc_technique_mappings",
    "correlations", "ingest_warnings",
)


@contextmanager
def _enrichment(cur, group: str, failed: list[str]):
    """Run one enrichment group inside SAVEPOINT; on any exception roll back to
    it, record the group in `failed`, and carry on.

    The savepoint name is one of our constants, never report text. Only the
    exception's class goes into `failed` (it is stored durably); PostgreSQL's
    DETAIL line can quote the offending value, i.e. sample-chosen text.
    If ROLLBACK TO SAVEPOINT itself fails the connection is gone, and that
    propagates: there is nothing left to write enrichment through.
    """
    if group not in _ENRICHMENT_GROUPS:
        raise ValueError(f"unknown enrichment group {group!r}")
    name = f"ingest_{group}"
    cur.execute(f"SAVEPOINT {name}")
    try:
        yield
    except Exception as exc:
        cur.execute(f"ROLLBACK TO SAVEPOINT {name}")
        failed.append(f"{group}: not ingested — {type(exc).__name__}")
        first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
        print(f"  [!] DB: enrichment group {group} rolled back: "
              f"{type(exc).__name__}: {first_line}")
    else:
        cur.execute(f"RELEASE SAVEPOINT {name}")


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


def _usage_cost(usage: _Node, model: str | None) -> tuple[bool, float]:
    """(had tokens, $) for one usage block, prompt-cache writes and reads included.

    The four token classes are disjoint on the Anthropic wire (#718): input_tokens
    excludes both cache counts, so they are summed, never subtracted. A usage block
    from before #718 has no cache keys and prices exactly as it did.
    """
    input_tokens = usage.number("input_tokens", 0) or 0
    output_tokens = usage.number("output_tokens", 0) or 0
    cache_write = usage.number("cache_creation_input_tokens", 0) or 0
    cache_read = usage.number("cache_read_input_tokens", 0) or 0
    if not (input_tokens or output_tokens or cache_write or cache_read):
        return False, 0.0
    # Resolved only once there is something to bill, so an empty block cannot
    # trigger the unknown-model warning.
    pricing = _price_for_model(model)
    write_rate = pricing.get("cache_write", pricing["input"] * _CACHE_WRITE_MULT)
    read_rate = pricing.get("cache_read", pricing["input"] * _CACHE_READ_MULT)
    return True, (input_tokens * pricing["input"]
                  + output_tokens * pricing["output"]
                  + cache_write * write_rate
                  + cache_read * read_rate) / 1_000_000


def _calculate_llm_cost(report: dict, root: _Node | None = None) -> float:
    """Calculate total LLM API cost from token usage across all stages.

    Reads usage data from llm_interpretation, executive_summary,
    evasion_analysis, and visual_analysis sections of the report.
    Falls back to $0.50 estimate if no usage data available.

    `root` is the ingest's shape-checked view of the same report, so wrong-typed
    usage fields are named in its warnings; called on its own, they are skipped.
    """
    if root is None:
        root = _read_report(report, [])
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
        section = root.obj(section_key)

        usage = section.obj("usage")
        if not usage:
            continue

        # First of these keys PRESENT wins, even when its value is null — the
        # nested-.get() order this replaces, kept so pricing does not move.
        model = "default"
        for model_key in ("model_used", "model_final", "model"):
            if model_key in section:
                model = section.text(model_key, None)
                break
        had_tokens, cost = _usage_cost(usage, model)
        if had_tokens:
            has_usage = True
            total_cost += cost

    # Plain English summary usage (stored separately at report root)
    pe_usage = root.obj("plain_english_usage")
    if pe_usage:
        # Price by the actual plain-English model (may be local = $0), falling
        # back to Haiku for older reports that didn't record the model.
        pe_model = root.text("plain_english_model", None) or "claude-haiku-4-5"
        had_tokens, cost = _usage_cost(pe_usage, pe_model)
        if had_tokens:
            has_usage = True
            total_cost += cost

    return total_cost if has_usage else 0.50


def network_events_has_attempts(cur) -> bool:
    """Whether the deployed schema has `network_events.attempts` yet (#488).

    The column arrives in an Alembic migration, which the `postgres` role runs;
    this file ships with the `pipeline` role. `make deploy TAGS=pipeline` is the
    most-used deploy command in this project, so the two can legitimately be out
    of step for a while.

    Without this probe that window ends in an UndefinedColumn inside the ingest's
    blanket `except`, which discards the WHOLE analysis — IOCs, techniques,
    signatures and correlations included, not merely the tcp rows (#450). One
    catalogue query per analysis is cheaper than that.
    """
    cur.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = 'network_events' AND column_name = 'attempts'"
    )
    return cur.fetchone() is not None


def tcp_event_rows(cape_net: dict) -> list:
    """(src_ip, src_port, dst_ip, dst_port, attempts) per `network_events` row.

    Two conventions live in the report corpus (#479, #488). Reports written
    before 2026-08-29 06:39 UTC carry one entry per CONNECTION, capped at fifty,
    each with a real ephemeral `src`. Later ones carry one entry per DESTINATION
    with an `attempts` count and no `src` at all.

    `attempts` is what tells them apart, and it is NULL for the old shape on
    purpose: a NULL says "this row is one connection", a number says "this row
    is a destination reached that many times". Without it `count(*)` over
    network_events silently changes meaning by a factor of ~25 across the
    deploy — and it changes DOWNWARD, which reads as network activity having
    stopped in the days right after the DNS fix made it start.

    The old shape's `src` is preserved rather than discarded. It is not an IOC
    and nothing queries it, but it exists in those reports, and dropping data
    during a re-ingest to match a newer convention would make the old rows
    describe something they are not.

    `cape_net` is a dict (tests, older callers) or the ingest's _Node, in which
    case malformed entries are named in its warnings.
    """
    net = cape_net if isinstance(cape_net, _Node) else _Node(
        cape_net if isinstance(cape_net, dict) else {}, "cape.network", [])
    rows = []
    for c in net.items("tcp_connections"):
        dst = c.text("dst", "") or ""
        src = c.text("src", "") or ""
        dst_ip, dst_port = (dst.rsplit(":", 1) + ["0"])[:2] if ":" in dst else (dst, "0")
        src_ip, src_port = (src.rsplit(":", 1) + ["0"])[:2] if ":" in src else (src, "0")
        rows.append((
            src_ip,
            _port(src_port, c, "src"),
            dst_ip,
            _port(dst_port, c, "dst"),
            c.integer("attempts"),
        ))
    return rows


def _port(text: str, node: _Node, key: str) -> int:
    """A TCP port from the text after the last ':', or 0.

    isdecimal, not isdigit: '²'.isdigit() is True and int('²') raises. A port
    outside 0-65535 is not a port, and one past int4 would fail the INSERT.
    """
    if not text.isdecimal():
        return 0
    port = int(text)
    if port > 65535:
        node.warnings.append(f"{node._at(key)}: port out of range — stored as 0")
        return 0
    return port


def insert_tcp_events(cur, analysis_id: int, cape_net) -> int:
    """Write this analysis's tcp rows; return how many. Extracted so the choice
    between the two INSERTs is testable — a branch that only exists inside
    ingest_to_db is one no test reaches without a live database, which is how a
    mis-wired helper passes its own unit tests while doing nothing.
    """
    rows = tcp_event_rows(cape_net)
    if not rows:
        return 0
    has_attempts = network_events_has_attempts(cur)
    if not has_attempts and any(r[4] is not None for r in rows):
        # Say so rather than silently write destination rows that become
        # indistinguishable from the pre-#479 connection rows they are not.
        print("    WARNING: network_events.attempts is missing — run the postgres "
              "role (alembic 0004). These tcp rows are destinations but will be "
              "stored looking like connections.")
    for src_ip, src_port, dst_ip, dst_port, attempts in rows:
        if has_attempts:
            cur.execute("""
                INSERT INTO network_events
                    (analysis_id, event_type, src_ip, src_port, dst_ip, dst_port, attempts)
                VALUES (%s, 'tcp', %s, %s, %s, %s, %s)
            """, (analysis_id, src_ip, src_port, dst_ip, dst_port, attempts))
        else:
            cur.execute("""
                INSERT INTO network_events
                    (analysis_id, event_type, src_ip, src_port, dst_ip, dst_port)
                VALUES (%s, 'tcp', %s, %s, %s, %s)
            """, (analysis_id, src_ip, src_port, dst_ip, dst_port))
    return len(rows)


def ingest_to_db(report: dict, existing_analysis_id: int | None = None):
    """Write structured analysis data to PostgreSQL.

    If existing_analysis_id is provided (from pipeline_status early creation),
    updates that row instead of inserting a new one.

    Inserts/updates samples, analyses, IOCs, techniques, capabilities,
    signatures, and network events. Returns analysis_id once the core rows are
    committed, None if they could not be.

    Every read from `report` is shape-checked (_Node): a wrong-typed field is
    skipped and named in report_json["_ingest_warnings"], and the rest of the
    analysis is still written (#171). The samples and analyses rows are
    committed before any enrichment, and each enrichment group runs in its own
    SAVEPOINT, so a row PostgreSQL refuses costs its group, not the analysis
    (#450; see "Core and enrichment" above).
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
        cleaner = _Cleaner()
        cur = _CleanCursor(conn.cursor(), cleaner)
    except Exception as e:
        print(f"  [!] DB connection failed: {e}")
        return False

    core_committed = False
    analysis_id = None
    try:
        warnings: list[str] = []
        # report_json is the whole report, adapted by psycopg2's Json
        # (json.dumps, RecursionError from 4,997 levels) and walked by
        # _Cleaner. run-pipeline bounds the report before writing it, so this is
        # a no-op there; it is here for every other caller (#702). In place, so
        # the depth_truncated record is in the row, beside what was removed.
        depth_line = describe_depth_cut(bound_report_depth(report))
        if depth_line:
            warnings.append(depth_line)
        root = _read_report(report, warnings)

        # --- Upsert sample ---
        triage = root.obj("triage")
        # SHA-256: prefer triage hashes, then extract from sample filename, then task_id
        sha256 = triage.obj("hashes").text("sha256", "")
        if not sha256:
            name = root.text("sample_name", "") or ""
            # Sample filenames are often <sha256>.exe — extract if 64+ hex chars
            stem = name.rsplit(".", 1)[0] if "." in name else name
            if len(stem) == 64 and all(c in "0123456789abcdef" for c in stem.lower()):
                sha256 = stem.lower()
        if not sha256:
            sha256 = root.text("task_id", "unknown") or "unknown"
        sha256 = _clip(sha256, "samples.sha256", warnings)

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
            _clip(root.text("sample_name", ""), "samples.filename", warnings),
            triage.text("file_type", ""),
            _clip(triage.text("file_mime", ""), "samples.file_mime", warnings),
            triage.number("entropy"),
            _clip(triage.text("ssdeep", ""), "samples.ssdeep", warnings),
        ))
        sample_id = cur.fetchone()[0]

        # --- Insert analysis ---
        interp = root.obj("llm_interpretation")
        analysis = interp.obj("analysis")
        summary = root.obj("executive_summary")
        cape = root.obj("cape")
        volatility = root.obj("volatility")
        ghidra = root.obj("ghidra")

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
        severity = (root.text("severity", None)
                    or summary.text("severity", None))
        family = (root.text("family", None)
                  or analysis.text("malware_family_guess", None))
        # model_final if the key is present (even as null), else model_initial —
        # the nested .get() this replaces.
        interpret_model = (interp.text("model_final", None) if "model_final" in interp
                           else interp.text("model_initial", None))

        # Analysis row values (shared between INSERT and UPDATE)
        analysis_values = {
            "sample_id": sample_id,
            "task_id": _clip(root.text("task_id", "", nullable=False),
                             "analyses.task_id", warnings),
            "started_at": root.timestamp("started_at"),
            "completed_at": root.timestamp("completed_at"),
            "severity": _clip(severity, "analyses.severity", warnings),
            "malscore": cape.number("malscore"),
            "malware_family_guess": _clip(family, "analyses.malware_family_guess", warnings),
            "triage_completed": bool(triage),
            "cape_completed": cape.raw("status") == "reported",
            "cape_task_id": cape.integer("task_id"),
            "volatility_completed": bool(volatility.raw("plugins")),
            "volatility_triggered": volatility.flag("triggered", False),
            "ghidra_completed": bool(ghidra.raw("analyzed_files")),
            "ghidra_triggered": ghidra.flag("triggered", False),
            "interpret_completed": interp.flag("enabled", False) and "error" not in interp,
            "summary_completed": bool(summary.raw("executive_summary")),
            "interpret_model": _clip(interpret_model, "analyses.interpret_model", warnings),
            "interpret_tool_calls": interp.integer("tool_calls_used", 0),
            "interpret_duration_secs": interp.number("duration_seconds"),
            "interpret_escalated": interp.flag("escalated", False),
            "possible_prompt_influence": interp.flag("possible_prompt_influence", False),
            "narrative": analysis.text("narrative", ""),
            "working_notes": analysis.text("working_notes", ""),
            "executive_summary": summary.text("executive_summary", ""),
            "plain_english_summary": root.text("plain_english_summary", ""),
            "pipeline_status": "completed",
            # jsonb takes any JSON value, so these two are stored as they came.
            "stage_timings": psycopg2.extras.Json(root.raw("timing", {})),
            "report_json": psycopg2.extras.Json(report),
        }

        # Calculate LLM API cost from token usage
        llm_cost = _calculate_llm_cost(report, root)
        if not (math.isfinite(llm_cost) and llm_cost < _LLM_COST_LIMIT):
            warnings.append("llm cost: token usage prices outside numeric(8,4) — not ingested")
            llm_cost = None
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

        # The analysis IS these two rows. Commit them before any enrichment
        # runs, so nothing below can take them back (#450).
        conn.commit()
        core_committed = True

        failed: list[str] = []

        # --- Insert IOCs ---
        with _enrichment(cur, "iocs", failed):
            for ioc in root.items("extracted_iocs"):
                required = ioc.required_texts("type", "value", "source")
                if required is None:
                    continue
                ioc_type, ioc_value, ioc_source = required
                cur.execute("""
                    INSERT INTO ioc_values (type, value)
                    VALUES (%s, %s)
                    ON CONFLICT (type, value) DO UPDATE SET
                        last_seen = NOW()
                    RETURNING id
                """, (ioc_type, ioc_value))
                ioc_id = cur.fetchone()[0]

                cur.execute("""
                    INSERT INTO analysis_iocs (analysis_id, ioc_id, source_stage, context)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (analysis_id, ioc_id, source_stage) DO NOTHING
                """, (analysis_id, ioc_id, ioc_source, ioc.text("context", "")))

        # --- Insert MITRE techniques ---
        # From AI RE
        with _enrichment(cur, "techniques_ai", failed):
            for t in analysis.items("attack_techniques"):
                tid = t.text("id", "", nullable=False)
                tactics = MITRE_TACTICS.get(tid, [])
                cur.execute("""
                    INSERT INTO technique_values (technique_id, technique_name, tactics)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (technique_id) DO UPDATE SET
                        tactics = COALESCE(EXCLUDED.tactics, technique_values.tactics)
                    RETURNING id
                """, (tid, t.text("name", ""), tactics or None))
                row = cur.fetchone()
                if row:
                    tech_id = row[0]
                else:
                    cur.execute("SELECT id FROM technique_values WHERE technique_id = %s",
                                (tid,))
                    tech_id = cur.fetchone()[0]

                cur.execute("""
                    INSERT INTO analysis_techniques (analysis_id, technique_id, source_stage)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (analysis_id, technique_id, source_stage) DO NOTHING
                """, (analysis_id, tech_id, "AI Reverse Engineering"))

        # From Cape TTPs
        with _enrichment(cur, "techniques_cape", failed):
            for t in cape.items("mitre_ttps"):
                tid = t.text("id", "", nullable=False)
                source_signature = t.text("source_signature", "")
                tactics = MITRE_TACTICS.get(tid, [])
                cur.execute("""
                    INSERT INTO technique_values (technique_id, technique_name, tactics)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (technique_id) DO UPDATE SET
                        tactics = COALESCE(EXCLUDED.tactics, technique_values.tactics)
                    RETURNING id
                """, (tid, source_signature, tactics or None))
                row = cur.fetchone()
                if row:
                    tech_id = row[0]
                else:
                    cur.execute("SELECT id FROM technique_values WHERE technique_id = %s",
                                (tid,))
                    tech_id = cur.fetchone()[0]

                cur.execute("""
                    INSERT INTO analysis_techniques (analysis_id, technique_id, source_stage, source_detail)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (analysis_id, technique_id, source_stage) DO NOTHING
                """, (analysis_id, tech_id, "Cape", source_signature))

        # --- Insert capabilities ---
        with _enrichment(cur, "capabilities", failed):
            for cap in analysis.texts("capabilities"):
                cur.execute("""
                    INSERT INTO capabilities (analysis_id, description, source_stage)
                    VALUES (%s, %s, %s)
                """, (analysis_id, cap, "AI Reverse Engineering"))

        # --- Insert signatures ---
        with _enrichment(cur, "signatures", failed):
            for sig in cape.items("signatures"):
                cur.execute("""
                    INSERT INTO signatures (analysis_id, name, severity, description)
                    VALUES (%s, %s, %s, %s)
                """, (analysis_id, sig.text("name", "", nullable=False),
                      sig.integer("severity", 0), sig.text("description", "")))

        # --- Insert network events ---
        # Three groups, not one: a sample-chosen domain past dns_query's
        # varchar(500) should not also cost the http and tcp rows.
        cape_net = cape.obj("network")
        with _enrichment(cur, "network_dns", failed):
            for d in cape_net.items("dns_queries"):
                cur.execute("""
                    INSERT INTO network_events (analysis_id, event_type, dns_query, dns_type, dns_answers)
                    VALUES (%s, 'dns', %s, %s, %s)
                """, (analysis_id, d.text("domain", ""), d.text("type", ""),
                      psycopg2.extras.Json(d.raw("answers", []))))

        with _enrichment(cur, "network_http", failed):
            for h in cape_net.items("http_requests"):
                cur.execute("""
                    INSERT INTO network_events (analysis_id, event_type, http_method, http_url, http_host)
                    VALUES (%s, 'http', %s, %s, %s)
                """, (analysis_id, h.text("method", ""), h.text("url", ""), h.text("host", "")))

        # One row per DESTINATION for post-#479 reports and one row per
        # CONNECTION for older ones, with `attempts` recording which — see
        # tcp_event_rows. A bare count of these rows is not comparable across
        # that boundary and must not be read as one (#488).
        with _enrichment(cur, "network_tcp", failed):
            insert_tcp_events(cur, analysis_id, cape_net)

        # --- Insert IOC-technique mappings ---
        # If the iocs group was rolled back, the lookups below find nothing
        # for this analysis's IOCs and those mappings are skipped, as they
        # always were for an IOC that is not in ioc_values.
        with _enrichment(cur, "ioc_technique_mappings", failed):
            for mapping in root.items("ioc_technique_mappings"):
                required = mapping.required_texts("ioc_type", "ioc_value", "technique_id")
                if required is None:
                    continue
                ioc_type, ioc_value, technique_id = required
                # Look up ioc_id
                cur.execute("SELECT id FROM ioc_values WHERE type = %s AND value = %s",
                            (ioc_type, ioc_value))
                ioc_row = cur.fetchone()
                if not ioc_row:
                    continue

                # Ensure technique exists
                cur.execute("""
                    INSERT INTO technique_values (technique_id, technique_name)
                    VALUES (%s, %s)
                    ON CONFLICT (technique_id) DO NOTHING
                    RETURNING id
                """, (technique_id, mapping.text("technique_name", "")))
                tech_row = cur.fetchone()
                if not tech_row:
                    cur.execute("SELECT id FROM technique_values WHERE technique_id = %s",
                                (technique_id,))
                    tech_row = cur.fetchone()

                if tech_row:
                    cur.execute("""
                        INSERT INTO ioc_technique_mappings
                            (analysis_id, ioc_id, technique_id, evidence, method, confidence)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (analysis_id, ioc_id, technique_id) DO NOTHING
                    """, (analysis_id, ioc_row[0], tech_row[0],
                          mapping.text("evidence", ""),
                          mapping.text("method", "programmatic", nullable=False),
                          mapping.text("confidence", "high")))

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
        #
        # Warnings are a column on the analysis, not rows beside the findings.
        # Setting it to a list — EMPTY LIST INCLUDED — is what records that
        # correlation ran: NULL means never recorded, '{}' means ran clean,
        # non-empty means ran blind (#411). Written after the inserts and inside
        # the SAME savepoint group, so a failure part-way cannot leave an
        # analysis claiming it was correlated when nothing landed: the group
        # rolls back whole, correlation_warnings keeps its previous value (NULL
        # for a new row), and the failure is named in _ingest_warnings.
        findings = root.items("cross_correlations")
        corr_warnings = [str(w)[:500] for w in root.array("correlation_warnings")]
        with _enrichment(cur, "correlations", failed):
            cur.execute("DELETE FROM correlations WHERE analysis_id = %s", (analysis_id,))
            for row in correlation_rows([f.data for f in findings]):
                cur.execute("""
                    INSERT INTO correlations
                        (analysis_id, type, severity, title, detail, sources, mitre, pid)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (analysis_id, *row))
            cur.execute(
                "UPDATE analyses SET correlation_warnings = %s WHERE id = %s",
                (corr_warnings, analysis_id))

        # What a malformed report cost, and which enrichment groups PostgreSQL
        # refused, recorded beside the report it describes. Merged into
        # report_json rather than a new column (no migration), and only when
        # there is something to say, so a well-formed report's stored JSON is
        # exactly what it was. Last, so every read and every group has run;
        # the cleaner's counts are read here, after every statement it saw.
        warnings.extend(failed)
        warnings.extend(cleaner.warnings())
        if warnings:
            capped = _capped(warnings)
            with _enrichment(cur, "ingest_warnings", failed):
                cur.execute(
                    "UPDATE analyses SET report_json = report_json || %s WHERE id = %s",
                    (psycopg2.extras.Json({"_ingest_warnings": capped}), analysis_id))
            print(f"  [!] DB: {len(set(warnings))} ingest warning(s), "
                  "recorded in report_json._ingest_warnings:")
            for w in capped:
                print(f"      {w}")

        conn.commit()
        rolled_back = f", {len(failed)} enrichment group(s) rolled back" if failed else ""
        print(f"  DB: ingested analysis {analysis_id} for sample {sample_id} "
              f"({len(findings)} correlations, {len(corr_warnings)} correlation warnings"
              f"{rolled_back})")

        # Cross-sample campaign edges (non-fatal enrichment, separate from the
        # committed ingest above). A failure here never fails the analysis ingest.
        write_relationships_safe(conn, sample_id, _CFG)

        return analysis_id

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass  # connection already gone; the server discards the transaction
        if core_committed:
            # Only reachable when the connection itself failed mid-enrichment:
            # a statement PostgreSQL refuses is contained by its savepoint. The
            # sample and analysis rows are committed, so the analysis exists.
            print(f"  [!] DB: enrichment aborted after analysis {analysis_id} was "
                  f"committed: {type(e).__name__}: {e}")
            return analysis_id
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
