# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A malformed report must not cost the analysis its database rows (#171).

`ingest_to_db` wraps every write in one transaction with a blanket
`except Exception: rollback` (#450). So any exception raised while READING the
report — `report.get("cape", {}).get("malscore")` on `{"cape": null}`,
`ioc["source"]` on an IOC without one, `t.get("id")` on a technique the model
emitted as a bare string — rolls back the samples row, the analysis row, every
IOC, technique and signature, and leaves one line on stdout. Much of report.json
is shaped by the sample (CAPE output) or by a model reading the sample (the
interpretation), so this was a cheap way to keep an analysis out of the DB/UI.

No PostgreSQL here, so these tests drive the REAL `ingest_to_db` against a fake
connection that records every `execute`. What makes that more than a mock:
each bound parameter is checked against the column it lands in, with column
types and NOT NULL read from the real Alembic migrations. A dict bound to a
text column, a string bound to an integer, NULL into NOT NULL, an int outside
int4 — the ways a wrong-typed value that got past the reader would still have
failed the INSERT on the real database — are reported as violations.

What the harness cannot see, so this file does not claim: varchar width
overflow (#450's territory); a NUL character in a text value or a NaN/Infinity
or \\u0000 inside jsonb (PostgreSQL rejects all three; none were found in the
14 reports on the host on 2026-10-01); whether PostgreSQL's timestamp parser
agrees with datetime.fromisoformat; constraints, foreign keys, and anything
PostgreSQL does at commit. Width overflow, NUL/NaN, and what a refused
statement does to the transaction are modelled in
test_db_ingest_enrichment_isolation.py (#450).

Base fixture: `fixtures/ingest_report_v655.json`, the real host report
`v655_5b4f596d3cf5` trimmed to the fields db_ingest reads, with hashes, IOC
values, network data and prose replaced by synthetic placeholders.
"""
from __future__ import annotations

import ast
import copy
import json
import math
import re
from datetime import datetime
from pathlib import Path
from unittest import mock

import db_ingest
import psycopg2
import psycopg2.extras
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from psycopg2 import sql as pgsql

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
BASE_REPORT = json.loads((FIXTURES / "ingest_report_v655.json").read_text(encoding="utf-8"))
GOLDEN = FIXTURES / "ingest_report_v655.calls.json"
MIGRATIONS = ROOT / "api" / "alembic" / "versions"

INT4 = 2**31 - 1
INT8 = 2**63 - 1
FLOAT4_MAX = 3.4028234e38


# ---------------------------------------------------------------------------
# The schema, read from the migrations rather than restated here
# ---------------------------------------------------------------------------

def _schema() -> dict[str, dict[str, tuple[str, bool]]]:
    """{table: {column: (pg_type, not_null)}} from 0001's SQL plus later ops."""
    tables: dict[str, dict[str, tuple[str, bool]]] = {}
    baseline = (MIGRATIONS / "0001_baseline.py").read_text(encoding="utf-8")
    for m in re.finditer(r"CREATE TABLE public\.(\w+) \((.*?)\n\);", baseline, re.S):
        cols = {}
        for line in m.group(2).strip().splitlines():
            line = line.strip().rstrip(",")
            name, rest = line.split(" ", 1)
            cols[name.strip('"')] = (rest.split(" DEFAULT")[0].replace(" NOT NULL", ""),
                                     "NOT NULL" in rest)
        tables[m.group(1)] = cols

    def sa_type(node: ast.expr) -> str:
        fn = node.func if isinstance(node, ast.Call) else node
        name = fn.attr if isinstance(fn, ast.Attribute) else fn.id
        if name == "ARRAY":
            return "character varying[]"
        return {"Integer": "integer", "String": "character varying",
                "DateTime": "timestamp with time zone"}[name]

    def column(call: ast.Call) -> tuple[str, tuple[str, bool]]:
        kw = {k.arg: k.value for k in call.keywords}
        nullable = kw.get("nullable")
        not_null = isinstance(nullable, ast.Constant) and nullable.value is False
        return call.args[0].value, (sa_type(call.args[1]), not_null)

    for path in sorted(MIGRATIONS.glob("000*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr == "create_table":
                table = tables.setdefault(node.args[0].value, {})
                for arg in node.args[1:]:
                    if (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                            and arg.func.attr == "Column"):
                        name, spec = column(arg)
                        table[name] = spec
            elif node.func.attr == "add_column":
                name, spec = column(node.args[1])
                tables[node.args[0].value][name] = spec
    return tables


SCHEMA = _schema()


def test_the_schema_reader_sees_the_columns_ingest_writes():
    """Guard on the guard: if the migration parser silently found nothing, every
    type check below would pass against an empty schema."""
    assert SCHEMA["analyses"]["cape_task_id"] == ("integer", False)
    assert SCHEMA["analyses"]["correlation_warnings"] == ("character varying[]", False)
    assert SCHEMA["network_events"]["attempts"] == ("integer", False)
    assert SCHEMA["ioc_values"]["value"] == ("text", True)
    assert SCHEMA["correlations"]["type"] == ("character varying", True)


# ---------------------------------------------------------------------------
# A recording connection
# ---------------------------------------------------------------------------

def _render(query) -> str:
    """SQL text of a str or a psycopg2.sql composition, without a connection."""
    if isinstance(query, str):
        return " ".join(query.split())
    if isinstance(query, pgsql.Composed):
        return "".join(_render(part) for part in query.seq)
    if isinstance(query, pgsql.Identifier):
        return ".".join(query.strings)
    if isinstance(query, pgsql.Placeholder):
        return "%s"
    if isinstance(query, pgsql.SQL):
        return query.string
    raise TypeError(f"unexpected SQL object {query!r}")


class _Cursor:
    def __init__(self):
        self.calls: list[tuple[str, tuple]] = []
        self._next_id = 100

    def execute(self, query, params=None):
        self.calls.append((_render(query), tuple(params or ())))

    def fetchone(self):
        # Distinct ids, so a test can tell WHICH returned id was bound where.
        self._next_id += 1
        return (self._next_id,)

    def fetchall(self):
        return []

    def close(self):
        pass


class _Conn:
    def __init__(self):
        self.cur = _Cursor()
        self.committed = False
        self.rolled_back = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


class IngestRun:
    def __init__(self, result, conn, out):
        self.result = result
        self.conn = conn
        self.out = out

    @property
    def calls(self):
        return self.conn.cur.calls

    def stored_report(self) -> dict:
        for text, params in self.calls:
            if text.startswith(("INSERT INTO analyses", "UPDATE analyses SET sample_id")):
                cols = _columns(text)
                return params[cols.index("report_json")].adapted
        raise AssertionError("no analyses write")


def run_ingest(report: dict, capsys=None, existing_analysis_id=None) -> IngestRun:
    conn = _Conn()
    with mock.patch.object(psycopg2, "connect", return_value=conn), \
            mock.patch.object(db_ingest, "write_relationships_safe", return_value=0):
        result = db_ingest.ingest_to_db(report, existing_analysis_id=existing_analysis_id)
    out = capsys.readouterr().out if capsys else ""
    return IngestRun(result, conn, out)


# ---------------------------------------------------------------------------
# Binding every parameter to its column
# ---------------------------------------------------------------------------

def _columns(text: str) -> list[str]:
    """Column names in bind order for an INSERT, or `col = %s` order otherwise."""
    if text.startswith("INSERT INTO"):
        cols = [c.strip() for c in text[text.index("(") + 1:text.index(")")].split(",")]
        values = text[text.index("VALUES") + len("VALUES"):]
        values = values[values.index("(") + 1:values.index(")")]
        return [c for c, v in zip(cols, values.split(","), strict=True) if v.strip() == "%s"]
    # `col = %s`, and `col = col || %s` for the jsonb merge of _ingest_warnings.
    return re.findall(r"(\w+)\s*=\s*(?:\w+\s*\|\|\s*)?%s", text)


def _table(text: str) -> str | None:
    m = re.match(r"(?:INSERT INTO|UPDATE|DELETE FROM|SELECT \w+ FROM) (\w+)", text)
    return m.group(1) if m else None


def _type_ok(pg_type: str, value) -> bool:
    if pg_type in ("integer", "bigint"):
        bound = INT4 if pg_type == "integer" else INT8
        return type(value) is int and -bound - 1 <= value <= bound
    if pg_type == "real" or pg_type.startswith("numeric"):
        if not (isinstance(value, (int, float)) and not isinstance(value, bool)):
            return False
        if pg_type == "real":
            return not math.isfinite(value) or abs(value) <= FLOAT4_MAX
        precision, scale = map(int, re.findall(r"\d+", pg_type))
        return math.isfinite(value) and abs(value) < 10 ** (precision - scale)
    if pg_type == "boolean":
        return isinstance(value, bool)
    if pg_type.startswith(("character varying", "text")) and not pg_type.endswith("[]"):
        return isinstance(value, str)
    if pg_type.endswith("[]"):
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    if pg_type.startswith("timestamp"):
        if not isinstance(value, str):
            return False
        try:
            datetime.fromisoformat(value)
        except ValueError:
            return False
        return True
    if pg_type == "jsonb":
        return isinstance(value, psycopg2.extras.Json)
    raise AssertionError(f"no rule for {pg_type}")


def binding_violations(calls) -> list[str]:
    out = []
    for text, params in calls:
        table = _table(text)
        if table is None or table == "information_schema":
            continue
        cols = _columns(text)
        assert len(cols) == len(params), f"cannot map params onto {text}"
        for col, value in zip(cols, params, strict=True):
            pg_type, not_null = SCHEMA[table][col]
            if value is None:
                if not_null:
                    out.append(f"{table}.{col}: NULL into NOT NULL ({text[:60]})")
                continue
            if not _type_ok(pg_type, value):
                out.append(f"{table}.{col} ({pg_type}): {type(value).__name__} {value!r:.60}")
    return out


def test_the_type_check_catches_what_postgres_would_reject():
    """Mutation check on the checker itself: each of these would have failed the
    INSERT on the real database, so each must be reported."""
    bad = [
        ("INSERT INTO capabilities (analysis_id, description, source_stage) VALUES (%s, %s, %s)",
         (1, {"name": "x"}, "AI")),
        ("INSERT INTO signatures (analysis_id, name, severity, description) VALUES (%s, %s, %s, %s)",
         (1, "n", "high", "d")),
        ("INSERT INTO ioc_values (type, value) VALUES (%s, %s)", ("t", None)),
        ("INSERT INTO network_events (analysis_id, event_type, src_ip, src_port, dst_ip, dst_port, attempts)"
         " VALUES (%s, 'tcp', %s, %s, %s, %s, %s)", (1, "a", 0, "b", 2**40, None)),
        ("UPDATE analyses SET correlation_warnings = %s WHERE id = %s", ([1], 1)),
    ]
    for text, params in bad:
        assert binding_violations([(text, params)]), text


# ---------------------------------------------------------------------------
# Golden: a well-formed report ingests exactly as it did before #171
# ---------------------------------------------------------------------------

def _canon(value):
    if isinstance(value, psycopg2.extras.Json):
        return {"$json": value.adapted}
    if isinstance(value, (list, tuple)):
        return [_canon(v) for v in value]
    return value


def canonical_calls(calls) -> list:
    return [[text, _canon(params)] for text, params in calls]


def _golden() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def ingest_warnings(run: IngestRun) -> list[str]:
    """What the ingest recorded in report_json["_ingest_warnings"], or []."""
    merged = [p for t, p in run.calls if "report_json = report_json ||" in t]
    assert len(merged) <= 1
    return merged[0][0].adapted["_ingest_warnings"] if merged else []


@pytest.mark.parametrize("path, existing_id", [("insert", None), ("update", 7)])
def test_a_well_formed_report_writes_exactly_what_it_did_before(path, existing_id):
    """Every statement, in order, with every bound value — compared with what
    origin/main (9e8df1e, before #171) executed for the same report.

    The golden file was produced by running THIS harness against the unmodified
    db_ingest.py. It is the "no data dropped" half of the change: the reader
    must be invisible to a report that was already well-formed. Do not
    regenerate it to make this pass; a diff here is a behaviour change.

    #450 added SAVEPOINT / RELEASE SAVEPOINT around each enrichment group.
    Those control statements are removed before comparing; every DATA
    statement is still compared, in order, with every value. Where the
    control statements sit is asserted exactly in
    test_db_ingest_enrichment_isolation.py.
    """
    run = run_ingest(copy.deepcopy(BASE_REPORT), existing_analysis_id=existing_id)
    assert run.conn.committed and not run.conn.rolled_back
    data = [c for c in run.calls if not SAVEPOINT_CONTROL.fullmatch(c[0])]
    assert json.loads(json.dumps(canonical_calls(data))) == _golden()[path]


# The only statements #450 added to a well-formed ingest. fullmatch, so a data
# statement can never be filtered out by it.
SAVEPOINT_CONTROL = re.compile(r"(?:SAVEPOINT|RELEASE SAVEPOINT) ingest_[a-z_]+")


def test_the_golden_reaches_every_write():
    """Guard on the fixture: a trimmed report that never reached, say, the http
    insert would make the golden comparison silent about it."""
    calls = _golden()["insert"]
    written = {" ".join(t.split()[:3]) for t, _ in calls}
    for prefix in ("INSERT INTO samples", "INSERT INTO analyses", "INSERT INTO ioc_values",
                   "INSERT INTO analysis_iocs", "INSERT INTO technique_values",
                   "INSERT INTO analysis_techniques", "INSERT INTO capabilities",
                   "INSERT INTO signatures", "INSERT INTO network_events",
                   "INSERT INTO ioc_technique_mappings", "INSERT INTO correlations",
                   "UPDATE analyses SET"):
        assert prefix in written, prefix
    kinds = {re.search(r"VALUES \(%s, '(\w+)'", t).group(1)
             for t, _ in calls if t.startswith("INSERT INTO network_events")}
    assert kinds == {"dns", "http", "tcp"}
    sources = {p[2] for t, p in calls if t.startswith("INSERT INTO analysis_techniques")}
    assert sources == {"AI Reverse Engineering", "Cape"}


def test_the_golden_binds_every_value_to_a_compatible_column():
    """The checker agrees with what PostgreSQL accepted for real reports."""
    def unjson(params):
        return tuple(psycopg2.extras.Json(p["$json"]) if isinstance(p, dict) and "$json" in p
                     else p for p in params)
    for path in ("insert", "update"):
        assert binding_violations([(t, unjson(p)) for t, p in _golden()[path]]) == []


def test_a_well_formed_report_records_no_ingest_warnings(capsys):
    run = run_ingest(copy.deepcopy(BASE_REPORT), capsys)
    assert ingest_warnings(run) == []
    assert "[!]" not in run.out


# ---------------------------------------------------------------------------
# The reproductions: each of these lost the whole analysis on origin/main
# ---------------------------------------------------------------------------

def _set(path, value):
    def mutate(report):
        node = report
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return mutate


def _delete(path):
    def mutate(report):
        node = report
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]
    return mutate


def _both(*mutations):
    def mutate(report):
        for m in mutations:
            m(report)
    return mutate


# (id, mutation, a warning that must be recorded or None, IOC rows still expected).
# The comment above each is what origin/main raised (or what PostgreSQL would
# have refused), all of which ended in the blanket rollback.
REPRODUCTIONS = [
    # AttributeError: 'NoneType' object has no attribute 'get'  (db_ingest.py:429)
    ("cape-null", _set(("cape",), None), None, 4),
    # AttributeError: 'str' object has no attribute 'get'  (:357)
    ("triage-hashes-string", _set(("triage", "hashes"), "x"),
     "triage.hashes: expected object, got string", 4),
    # TypeError: string indices must be integers, not 'str'  (:481)
    ("ioc-is-a-string", _set(("extracted_iocs", 0), "str"),
     "extracted_iocs[0]: expected object, got string", 3),
    # KeyError: 'source'  (:488)
    ("ioc-without-source", _delete(("extracted_iocs", 0, "source")),
     "extracted_iocs[0]: missing source", 3),
    # AttributeError: 'list' object has no attribute 'get'  (:445)
    ("analysis-is-a-list", _set(("llm_interpretation", "analysis"), []),
     "llm_interpretation.analysis: expected object, got array", 4),
    # AttributeError: 'int' object has no attribute 'get'  (:493)
    ("technique-is-an-int", _set(("llm_interpretation", "analysis", "attack_techniques", 0), 1),
     "llm_interpretation.analysis.attack_techniques[0]: expected object, got integer", 4),
    # AttributeError: 'NoneType' object has no attribute 'get'  (:553)
    ("signature-is-null", _set(("cape", "signatures", 0), None),
     "cape.signatures[0]: expected object, got null", 4),
    # AttributeError: 'str' object has no attribute 'get'  (:562)
    ("dns-queries-is-an-object", _set(("cape", "network", "dns_queries"), {"a": 1}),
     "cape.network.dns_queries: expected array, got object", 4),
    # TypeError: argument of type 'int' is not iterable  (:361)
    ("sample-name-is-an-int",
     _both(_delete(("triage", "hashes", "sha256")), _set(("sample_name",), 123)),
     "sample_name: expected string, got integer", 4),
    # AttributeError: 'list' object has no attribute 'get'  (:204, _calculate_llm_cost)
    ("usage-is-a-list", _set(("llm_interpretation", "usage"), [1]),
     "llm_interpretation.usage: expected object, got array", 4),
    # KeyError: 'ioc_type'  (:581)
    ("mapping-is-empty", _set(("ioc_technique_mappings", 0), {}),
     "ioc_technique_mappings[0]: missing ioc_type, ioc_value, technique_id", 4),
    # TypeError: 'int' object is not iterable  (:635)
    ("correlation-warnings-is-an-int", _set(("correlation_warnings",), 5),
     "correlation_warnings: expected array, got integer", 4),
    # TypeError: argument of type 'int' is not iterable  (:277, tcp_event_rows)
    ("tcp-dst-is-an-int", _set(("cape", "network", "tcp_connections", 0, "dst"), 5),
     "cape.network.tcp_connections[0].dst: expected string, got integer", 4),
    # PostgreSQL: can't adapt type 'dict' (capabilities.description).
    ("capability-is-an-object",
     _set(("llm_interpretation", "analysis", "capabilities", 0), {"name": "x"}),
     "llm_interpretation.analysis.capabilities[0]: expected string, got object", 4),
    # PostgreSQL: invalid input syntax for type integer (signatures.severity).
    ("signature-severity-is-text", _set(("cape", "signatures", 0, "severity"), "high"),
     "cape.signatures[0].severity: expected integer, got string", 4),
    # PostgreSQL: NULL into correlations.type NOT NULL.
    ("correlation-type-null", _set(("cross_correlations", 0, "type"), None), None, 4),
    # PostgreSQL: integer out of range (analyses.cape_task_id).
    ("cape-task-id-huge", _set(("cape", "task_id"), 2**40),
     "cape.task_id: integer out of range", 4),
    # ValueError: int('²') — '²'.isdigit() is True  (:282, tcp_event_rows)
    ("tcp-port-superscript",
     _set(("cape", "network", "tcp_connections", 0, "dst"), "192.0.2.1:²"), None, 4),
]


@pytest.mark.parametrize("mutate, warning, n_iocs",
                         [r[1:] for r in REPRODUCTIONS], ids=[r[0] for r in REPRODUCTIONS])
def test_a_malformed_field_costs_only_that_field(mutate, warning, n_iocs, capsys):
    report = copy.deepcopy(BASE_REPORT)
    mutate(report)
    run = run_ingest(report, capsys)

    assert isinstance(run.result, int), run.out
    assert run.conn.committed and not run.conn.rolled_back, run.out
    assert binding_violations(run.calls) == []
    # The rest of the analysis still landed.
    iocs = [p for t, p in run.calls if t.startswith("INSERT INTO ioc_values")]
    assert len(iocs) == n_iocs
    assert any(t.startswith("INSERT INTO correlations") for t, _ in run.calls)
    if warning is not None:
        assert any(w.startswith(warning) for w in ingest_warnings(run)), ingest_warnings(run)
        assert warning in run.out


def test_the_ingest_does_not_change_the_callers_report():
    """run-pipeline writes report.json before ingesting; the warnings go into the
    stored row, never back into the dict the caller holds."""
    report = copy.deepcopy(BASE_REPORT)
    report["triage"]["hashes"] = "x"
    before = copy.deepcopy(report)
    run = run_ingest(report)
    assert report == before
    assert "_ingest_warnings" not in run.stored_report()
    assert ingest_warnings(run)


def test_the_models_risk_assessment_never_becomes_the_severity():
    """Behavioural twin of test_severity_dual_scoring's source check
    (GHSA-f5q8-v78c-mr55), now that the reads go through the reader: with no
    programmatic verdict, the severity column stays NULL."""
    report = copy.deepcopy(BASE_REPORT)
    del report["severity"]
    del report["executive_summary"]["severity"]
    report["llm_interpretation"]["analysis"]["risk_assessment"] = "critical"
    run = run_ingest(report)
    text, params = next((t, p) for t, p in run.calls if t.startswith("INSERT INTO analyses"))
    assert params[_columns(text).index("severity")] is None


def test_a_report_that_is_not_an_object_still_ingests():
    run = run_ingest(["not", "a", "report"])
    assert isinstance(run.result, int) and run.conn.committed
    assert ingest_warnings(run) == ["report: expected object, got array — not ingested"]


def test_warnings_are_bounded_and_deduplicated():
    report = copy.deepcopy(BASE_REPORT)
    report["extracted_iocs"] = [1] * 500
    report["sample_name"] = 5
    report["triage"]["hashes"]["sha256"] = ""
    warnings = ingest_warnings(run_ingest(report))
    assert len(warnings) == db_ingest._MAX_INGEST_WARNINGS + 1
    assert warnings[-1].startswith("... and ")
    assert len(set(warnings)) == len(warnings)


# ---------------------------------------------------------------------------
# Fuzz: any field of a real report replaced by any wrong-typed value
# ---------------------------------------------------------------------------

def _paths(node, prefix=()):
    if isinstance(node, dict):
        for key, value in node.items():
            yield (*prefix, key)
            yield from _paths(value, (*prefix, key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield (*prefix, i)
            yield from _paths(value, (*prefix, i))


PATHS = list(_paths(BASE_REPORT))

_awkward = st.sampled_from([
    None, "", "x", 0, -1, 1.5, True, False, [], ["x"], [None], {}, {"x": 1},
    2**31, -(2**31) - 1, 2**63, 1e39, float("inf"), "not-a-date",
    "192.0.2.1:²", "192.0.2.1:99999999999", "T1055",
])
_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=True) | st.text(max_size=12),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=6), children, max_size=4),
    max_leaves=12,
)
_mutation = st.tuples(st.sampled_from(PATHS), st.booleans(), _awkward | _json)


def _apply(report, path, delete, value) -> None:
    node = report
    for key in path[:-1]:
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            return  # an earlier mutation replaced an ancestor
    if isinstance(node, dict) and delete:
        node.pop(path[-1], None)
    elif isinstance(node, dict) or (isinstance(node, list) and isinstance(path[-1], int)
                                    and path[-1] < len(node)):
        node[path[-1]] = value


@settings(max_examples=600, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(mutations=st.lists(_mutation, min_size=1, max_size=4))
def test_no_wrong_typed_field_loses_the_analysis(mutations):
    """Totality. Whatever is wrong with the report, the analysis is written,
    the transaction commits, and nothing bound would be refused by the schema."""
    report = copy.deepcopy(BASE_REPORT)
    for path, delete, value in mutations:
        _apply(report, path, delete, value)
    run = run_ingest(report)

    assert isinstance(run.result, int), run.out
    assert run.conn.committed and not run.conn.rolled_back
    assert binding_violations(run.calls) == []
    assert all(isinstance(w, str) for w in ingest_warnings(run))


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(report=st.dictionaries(st.sampled_from(sorted(BASE_REPORT)) | st.text(max_size=6),
                              _json, max_size=8))
def test_arbitrary_sections_do_not_lose_the_analysis(report):
    run = run_ingest(report)
    assert isinstance(run.result, int)
    assert run.conn.committed and not run.conn.rolled_back
    assert binding_violations(run.calls) == []


# ---------------------------------------------------------------------------
# The reader and the helpers it touches
# ---------------------------------------------------------------------------

def test_null_is_absent_and_a_wrong_type_is_named():
    warnings: list[str] = []
    node = db_ingest._Node({"a": None, "b": "s", "c": 3, "d": [1, {"k": 1}]}, "x", warnings)
    assert node.text("a", "dflt") is None          # nullable column: NULL, as before
    assert node.text("a", "dflt", nullable=False) == "dflt"
    assert node.text("missing", "dflt") == "dflt"
    assert node.text("b") == "s"
    assert node.text("c", "dflt") == "dflt"
    assert [n.data for n in node.items("d")] == [{"k": 1}]
    assert warnings == ["x.c: expected string, got integer — not ingested",
                        "x.d[0]: expected object, got integer — not ingested"]


def test_a_boolean_is_not_an_integer_or_a_number():
    warnings: list[str] = []
    node = db_ingest._Node({"t": True}, "", warnings)
    assert node.integer("t", 0) == 0
    assert node.number("t") is None
    assert len(warnings) == 2


def test_a_superscript_port_does_not_raise():
    rows = db_ingest.tcp_event_rows({"tcp_connections": [{"dst": "192.0.2.1:²"}]})
    assert rows == [("", 0, "192.0.2.1", 0, None)]


def test_llm_cost_survives_wrong_typed_usage():
    report = {"llm_interpretation": {"model_used": ["x"], "usage": {"input_tokens": "9"}},
              "plain_english_usage": "lots"}
    assert db_ingest._calculate_llm_cost(report) == 0.50


def test_a_null_correlation_type_takes_the_default():
    from lamware_pipeline.correlation_rules import correlation_rows
    (row,) = correlation_rows([{"type": None, "severity": None, "title": None}])
    assert row[:3] == ("unknown", "unknown", "")
