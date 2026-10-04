# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""One row PostgreSQL refuses must not cost the analysis (#450).

Before #450, `ingest_to_db` ran every write in ONE transaction under a blanket
`except: rollback`. A value one character too long for its varchar in a
signature name, a NUL byte in an IOC, a constraint on a correlation (#448) —
any refused statement rolled back the samples row and the analyses row with
it, so the analysis never reached the DB or the UI.

There is no PostgreSQL here. These tests drive the REAL `ingest_to_db` against
`PgConn`, a fake that models the parts of PostgreSQL's transaction behaviour
this change depends on — and says so, because a fake that only records cannot
show a rollback at all:

  - a refused statement ABORTS the transaction: every later statement raises
    InFailedSqlTransaction until ROLLBACK or ROLLBACK TO SAVEPOINT;
  - SAVEPOINT / RELEASE / ROLLBACK TO SAVEPOINT discard exactly what real
    savepoints discard; COMMIT of an aborted transaction is a ROLLBACK;
  - varchar widths are ENFORCED, read from api/alembic/versions (the host's
    information_schema was checked against them on 2026-10-03, read-only);
  - psycopg2 refuses a str containing NUL client-side (ValueError, statement
    never sent — verified against psycopg2 2.9.12); jsonb refuses \\u0000 and
    NaN/Infinity (UntranslatableCharacter / InvalidTextRepresentation — from
    the PostgreSQL docs, not observed here);
  - anything else (a constraint) is modelled by making the fake raise the
    psycopg2 error class PostgreSQL would raise, for a chosen statement.

What it does NOT model: real constraint evaluation, triggers, foreign keys,
deferred checks at COMMIT, and RETURNING returning no row on ON CONFLICT DO
NOTHING (the fake always returns an id).
"""
from __future__ import annotations

import ast
import copy
import json
import re
import zlib
from unittest import mock

import db_ingest
import psycopg2
import psycopg2.errors as pgerr
import psycopg2.extras
import pytest
from test_db_ingest_malformed_reports import (
    BASE_REPORT,
    MIGRATIONS,
    SCHEMA,
    _canon,
    _columns,
    _render,
    _table,
)

# ---------------------------------------------------------------------------
# varchar widths, from the migrations
# ---------------------------------------------------------------------------


def _widths() -> dict[tuple[str, str], int]:
    """{(table, column): N} for every character varying(N), scalar or array element."""
    out = {}
    for table, cols in SCHEMA.items():
        for col, (pg_type, _) in cols.items():
            m = re.fullmatch(r"character varying\((\d+)\)(\[\])?", pg_type)
            if m:
                out[table, col] = int(m.group(1))
    # SCHEMA drops sa.String(length=N) to "character varying"; read N here.
    for path in sorted(MIGRATIONS.glob("000*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr == "create_table":
                table, cols = node.args[0].value, node.args[1:]
            elif node.func.attr == "add_column":
                table, cols = node.args[0].value, [node.args[1]]
            else:
                continue
            for col in cols:
                if not (isinstance(col, ast.Call) and getattr(col.func, "attr", "") == "Column"):
                    continue
                for sub in ast.walk(col.args[1]):
                    if (isinstance(sub, ast.Call) and getattr(sub.func, "attr", "") == "String"):
                        length = {k.arg: k.value for k in sub.keywords}.get("length")
                        if isinstance(length, ast.Constant):
                            out[table, col.args[0].value] = length.value
    return out


WIDTHS = _widths()


def test_the_width_reader_sees_the_columns():
    """Guard on the guard: with an empty map nothing would ever be too long.
    Values agree with the host's information_schema (read 2026-10-03)."""
    assert WIDTHS["signatures", "name"] == 200
    assert WIDTHS["technique_values", "technique_id"] == 20
    assert WIDTHS["network_events", "dns_query"] == 500
    assert WIDTHS["correlations", "title"] == 500
    assert WIDTHS["analyses", "correlation_warnings"] == 500


def test_core_widths_match_the_migrations():
    """_CORE_WIDTHS clips the core rows; a drift from the schema would clip to
    the wrong width or not at all."""
    for column, width in db_ingest._CORE_WIDTHS.items():
        table, col = column.split(".")
        assert WIDTHS[table, col] == width, column


# ---------------------------------------------------------------------------
# A connection that behaves like a PostgreSQL transaction
# ---------------------------------------------------------------------------

CONTROL = re.compile(r"(SAVEPOINT|RELEASE SAVEPOINT|ROLLBACK TO SAVEPOINT) (\w+)")
COMMIT = ("<COMMIT>", ())


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


class PgCursor:
    def __init__(self, conn: PgConn):
        self.conn = conn
        self.last = None

    def execute(self, query, params=None):
        conn = self.conn
        text, params = _render(query), tuple(params or ())
        conn.executed.append((text, params))
        if conn.dead:
            raise psycopg2.InterfaceError("connection already closed")
        # psycopg2 refuses this before anything is sent: no server-side abort.
        if any("\x00" in s for s in _strings(params)):
            raise ValueError("A string literal cannot contain NUL (0x00) characters.")
        if conn.aborted and not text.startswith("ROLLBACK TO SAVEPOINT"):
            raise pgerr.InFailedSqlTransaction(
                "current transaction is aborted, commands ignored until end of transaction block")
        control = CONTROL.fullmatch(text)
        if control:
            conn.savepoint(control.group(1), control.group(2))
            conn.pending.append((text, params))
            return
        error = conn.refusal(text, params)
        if error is not None:
            conn.aborted = True
            if conn.die_on_failure:
                conn.dead = True
            raise error
        conn.pending.append((text, params))
        self.last = (text, params)

    def fetchone(self):
        # Derived from the statement, not a counter, so a run in which an
        # earlier group was rolled back binds the same ids in later groups.
        text, params = self.last
        return (zlib.crc32(repr((text, _canon(params))).encode()) % 1_000_000 + 1,)

    def close(self):
        pass


class PgConn:
    def __init__(self, fail=None, enforce=True, die_on_failure=False):
        self.fail = fail                    # (index, text, params) -> Exception | None
        self.enforce = enforce
        self.die_on_failure = die_on_failure
        self.executed: list = []            # every statement attempted
        self.pending: list = []
        self.committed: list = []           # what a later reader would see
        self.marks: list[tuple[str, int]] = []
        self.aborted = False
        self.dead = False
        self.data_index = -1

    def cursor(self):
        return PgCursor(self)

    def savepoint(self, verb: str, name: str) -> None:
        names = [n for n, _ in self.marks]
        if verb == "SAVEPOINT":
            self.marks.append((name, len(self.pending) + 1))
            return
        if name not in names:
            raise pgerr.InvalidSavepointSpecification(f"savepoint \"{name}\" does not exist")
        i = len(names) - 1 - names[::-1].index(name)
        if verb == "RELEASE SAVEPOINT":
            del self.marks[i:]
        else:  # ROLLBACK TO SAVEPOINT: undo, keep the savepoint, clear the abort
            del self.pending[self.marks[i][1]:]
            del self.marks[i + 1:]
            self.aborted = False

    def refusal(self, text, params):
        self.data_index += 1
        if self.fail is not None:
            error = self.fail(self.data_index, text, params)
            if error is not None:
                return error
        if not self.enforce:
            return None
        for value in params:
            if isinstance(value, psycopg2.extras.Json):
                try:
                    dumped = json.dumps(value.adapted, allow_nan=False)
                except ValueError:
                    return pgerr.InvalidTextRepresentation("invalid input syntax for type json")
                if "\\u0000" in dumped:
                    return pgerr.UntranslatableCharacter("unsupported Unicode escape sequence")
        table = _table(text)
        if table is None or table == "information_schema":
            return None
        for col, value in zip(_columns(text), params, strict=True):
            width = WIDTHS.get((table, col))
            if width is not None and any(len(s) > width for s in _strings(value)):
                return pgerr.StringDataRightTruncation(
                    f"value too long for type character varying({width})")
        return None

    def commit(self):
        if self.dead:
            raise psycopg2.InterfaceError("connection already closed")
        if not self.aborted:                # COMMIT of an aborted transaction = ROLLBACK
            self.committed.extend(self.pending)
            self.committed.append(COMMIT)
        self.pending, self.marks, self.aborted = [], [], False

    def rollback(self):
        if self.dead:
            raise psycopg2.InterfaceError("connection already closed")
        self.pending, self.marks, self.aborted = [], [], False

    def close(self):
        pass


class Run:
    def __init__(self, result, conn: PgConn, out: str):
        self.result, self.conn, self.out = result, conn, out

    @property
    def committed(self):
        return self.conn.committed

    def core(self) -> list:
        """What the first COMMIT made durable."""
        if COMMIT not in self.committed:
            return []
        return [(t, _canon(p)) for t, p in self.committed[:self.committed.index(COMMIT)]]

    def groups(self) -> dict[str, list | str]:
        """Committed statements after the core, by enrichment group. A group
        rolled back to its savepoint maps to "rolled back"; statements outside
        any group go under "<ungrouped>"."""
        out: dict = {}
        current = None
        rest = self.committed[self.committed.index(COMMIT) + 1:] if COMMIT in self.committed else []
        for text, params in rest:
            control = CONTROL.fullmatch(text)
            if control:
                verb, name = control.group(1), control.group(2).removeprefix("ingest_")
                if verb == "SAVEPOINT":
                    current = name
                    out[name] = []
                elif verb == "ROLLBACK TO SAVEPOINT":
                    assert out[name] == [], "rolled-back group kept statements"
                    out[name] = "rolled back"
                else:
                    current = None
                continue
            if (text, params) == COMMIT:
                continue
            key = current if current is not None else "<ungrouped>"
            out.setdefault(key, []).append((text, _canon(params)))
        return out

    def ingest_warnings(self) -> list[str]:
        merged = [p for t, p in self.committed if "report_json = report_json ||" in t]
        assert len(merged) <= 1
        return merged[0][0].adapted["_ingest_warnings"] if merged else []

    def stored(self, prefix: str, column: str):
        text, params = next((t, p) for t, p in self.committed if t.startswith(prefix))
        return params[_columns(text).index(column)]


def ingest(report, capsys=None, existing_analysis_id=None, **conn_kw) -> Run:
    conn = PgConn(**conn_kw)
    with mock.patch.object(psycopg2, "connect", return_value=conn), \
            mock.patch.object(db_ingest, "write_relationships_safe", return_value=0):
        result = db_ingest.ingest_to_db(report, existing_analysis_id=existing_analysis_id)
    return Run(result, conn, capsys.readouterr().out if capsys else "")


def fail_on(prefix: str, error: Exception):
    """Refuse the first statement starting with `prefix`."""
    seen = []

    def fail(_index, text, _params):
        if text.startswith(prefix) and not seen:
            seen.append(text)
            return error
        return None
    return fail


CORE = ("INSERT INTO samples", "INSERT INTO analyses", "UPDATE analyses SET sample_id")
GROUPS = ["iocs", "techniques_ai", "techniques_cape", "capabilities", "signatures",
          "network_dns", "network_http", "network_tcp", "ioc_technique_mappings",
          "correlations"]


def test_the_fake_aborts_like_postgres():
    """Guard on the guard. Without this, code that caught a refused statement
    and carried on WITHOUT a savepoint would look fine here and lose every later
    write on the real database (an aborted transaction refuses everything, and
    its COMMIT is a ROLLBACK)."""
    conn = PgConn(fail=fail_on("INSERT INTO signatures", pgerr.CheckViolation("x")))
    cur = conn.cursor()
    cur.execute("INSERT INTO capabilities (analysis_id, description, source_stage) "
                "VALUES (%s, %s, %s)", (1, "kept?", "AI"))
    with pytest.raises(pgerr.CheckViolation):
        cur.execute("INSERT INTO signatures (analysis_id, name, severity, description) "
                    "VALUES (%s, %s, %s, %s)", (1, "n", 0, "d"))
    with pytest.raises(pgerr.InFailedSqlTransaction):
        cur.execute("SELECT id FROM ioc_values WHERE type = %s AND value = %s", ("t", "v"))
    conn.commit()
    assert conn.committed == []

    conn = PgConn(fail=fail_on("INSERT INTO signatures", pgerr.CheckViolation("x")))
    cur = conn.cursor()
    cur.execute("INSERT INTO capabilities (analysis_id, description, source_stage) "
                "VALUES (%s, %s, %s)", (1, "kept", "AI"))
    cur.execute("SAVEPOINT ingest_signatures")
    with pytest.raises(pgerr.CheckViolation):
        cur.execute("INSERT INTO signatures (analysis_id, name, severity, description) "
                    "VALUES (%s, %s, %s, %s)", (1, "n", 0, "d"))
    cur.execute("ROLLBACK TO SAVEPOINT ingest_signatures")
    conn.commit()
    assert [p for t, p in conn.committed if t.startswith("INSERT")] == [(1, "kept", "AI")]


# ---------------------------------------------------------------------------
# The shape of a well-formed ingest
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("existing_id", [None, 7])
def test_core_commits_first_then_each_group_in_its_own_savepoint(existing_id):
    run = ingest(copy.deepcopy(BASE_REPORT), existing_analysis_id=existing_id)
    assert run.result == (existing_id or run.result) and isinstance(run.result, int)
    core = run.core()
    assert [t.split(" (")[0].split(" SET")[0] for t, _ in core] == (
        ["INSERT INTO samples", "INSERT INTO analyses"] if existing_id is None
        else ["INSERT INTO samples", "UPDATE analyses"])
    groups = run.groups()
    assert list(groups) == GROUPS          # in order, no ingest_warnings, nothing ungrouped
    assert all(isinstance(g, list) for g in groups.values())
    assert run.committed[-1] == COMMIT and run.committed.count(COMMIT) == 2
    assert run.ingest_warnings() == []


def test_an_unknown_group_name_is_refused():
    """The savepoint name is interpolated into SQL; only our constants may reach it."""
    with pytest.raises(ValueError), db_ingest._enrichment(mock.Mock(), "x; DROP", []):
        pass


# ---------------------------------------------------------------------------
# The reproductions: realistic refusals, one per group
# ---------------------------------------------------------------------------

def _set(path, value):
    def mutate(report):
        node = report
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
    return mutate


def _noop(report):
    pass


ANALYSIS = ("llm_interpretation", "analysis")

# (group, report mutation, injected failure or None, the exception PostgreSQL raises).
# Width overflows are ENFORCED by the fake from the migrations, not injected.
REFUSALS = [
    ("iocs", _set(("extracted_iocs", 0, "type"), "t" * 51), None, "StringDataRightTruncation"),
    ("techniques_ai", _set((*ANALYSIS, "attack_techniques", 0, "id"), "T" * 21), None,
     "StringDataRightTruncation"),
    ("techniques_cape", _set(("cape", "mitre_ttps", 0, "source_signature"), "s" * 201), None,
     "StringDataRightTruncation"),
    ("capabilities", _noop,
     fail_on("INSERT INTO capabilities", pgerr.CheckViolation("new row violates check constraint")),
     "CheckViolation"),
    ("signatures", _set(("cape", "signatures", 0, "name"), "n" * 201), None,
     "StringDataRightTruncation"),
    ("network_dns", _set(("cape", "network", "dns_queries", 0, "domain"), "d" * 501), None,
     "StringDataRightTruncation"),
    ("network_http", _set(("cape", "network", "http_requests", 0, "host"), "h" * 501), None,
     "StringDataRightTruncation"),
    ("network_tcp", _set(("cape", "network", "tcp_connections", 0, "dst"), "1" * 46 + ":80"),
     None, "StringDataRightTruncation"),
    ("ioc_technique_mappings", _set(("ioc_technique_mappings", 0, "method"), "m" * 21), None,
     "StringDataRightTruncation"),
    # #448: correlations.created_at NOT NULL with no default would have refused every row.
    ("correlations", _noop,
     fail_on("INSERT INTO correlations", pgerr.NotNullViolation(
         'null value in column "created_at" violates not-null constraint')),
     "NotNullViolation"),
]


@pytest.mark.parametrize("group, mutate, fail, error", [r for r in REFUSALS],
                         ids=[r[0] for r in REFUSALS])
def test_a_refused_row_costs_only_its_group(group, mutate, fail, error, capsys):
    report = copy.deepcopy(BASE_REPORT)
    mutate(report)
    # What every group writes for THIS report when nothing is refused.
    expected = ingest(copy.deepcopy(report), enforce=False)
    run = ingest(report, capsys, fail=fail)

    assert isinstance(run.result, int), run.out
    assert run.core() == expected.core() and len(run.core()) == 2
    groups, want = run.groups(), expected.groups()
    assert groups[group] == "rolled back"
    for other in GROUPS:
        if other != group:
            assert groups[other] == want[other], other
    assert "<ungrouped>" not in groups
    assert f"{group}: not ingested — {error}" in run.ingest_warnings()
    assert f"enrichment group {group} rolled back: {error}" in run.out
    if group == "correlations":
        # Rolled back WITH the findings: never "ran clean" when nothing landed (#411).
        assert not any(t.startswith("UPDATE analyses SET correlation_warnings")
                       for t, _ in run.committed)


def _data_statements(run: Run) -> list[str]:
    return [t for t, _ in run.conn.executed if not CONTROL.fullmatch(t)]


def test_every_statement_after_the_core_is_contained_by_a_group():
    """Exhaustive, not sampled: refuse each data statement of a well-formed
    ingest in turn. A refusal in the core loses the analysis (it must be atomic:
    nothing committed); a refusal anywhere else loses exactly the group it is
    in. A statement someone adds outside a group fails this test."""
    baseline = ingest(copy.deepcopy(BASE_REPORT))
    want = baseline.groups()
    n = len(_data_statements(baseline))
    assert n > 40
    for k in range(n):
        def fail(index, _text, _params, k=k):
            return pgerr.UniqueViolation("duplicate key") if index == k else None
        run = ingest(copy.deepcopy(BASE_REPORT), fail=fail)
        text = _data_statements(run)[k]
        if text.startswith(CORE):
            assert run.result is None, text
            assert run.committed == [], text
            continue
        assert isinstance(run.result, int), text
        assert run.core() == baseline.core(), text
        groups = run.groups()
        lost = [g for g in GROUPS if groups[g] == "rolled back"]
        assert len(lost) == 1, (text, lost)
        for other in GROUPS:
            if other != lost[0]:
                assert groups[other] == want[other], (text, other)
        assert run.ingest_warnings() == [f"{lost[0]}: not ingested — UniqueViolation"], text


def test_a_refused_core_row_still_loses_nothing_partially(capsys):
    """Core stays atomic: the analyses write refused means the sample upsert is
    rolled back too, and the caller gets None."""
    run = ingest(copy.deepcopy(BASE_REPORT), capsys,
                 fail=fail_on("INSERT INTO analyses", pgerr.CheckViolation("check")))
    assert run.result is None
    assert run.committed == []
    assert "[!] DB ingestion error" in run.out


def test_a_connection_lost_mid_enrichment_still_reports_the_analysis(capsys):
    """The core is committed before enrichment, so a dead connection in the
    middle of it leaves an analysis that exists — and the caller is told its id
    (run-pipeline passes it to mark_pdf_generated)."""
    run = ingest(copy.deepcopy(BASE_REPORT), capsys, die_on_failure=True,
                 fail=fail_on("INSERT INTO signatures",
                              psycopg2.OperationalError("server closed the connection")))
    assert isinstance(run.result, int)
    assert len(run.core()) == 2
    assert f"enrichment aborted after analysis {run.result} was committed" in run.out


# ---------------------------------------------------------------------------
# Core values PostgreSQL would refuse
# ---------------------------------------------------------------------------

def test_an_over_long_family_guess_is_clipped_not_fatal(capsys):
    """malware_family_guess is model output into varchar(200); before #450 an
    over-long one failed the analyses write and with it everything."""
    report = copy.deepcopy(BASE_REPORT)
    report.pop("family", None)
    report["llm_interpretation"]["analysis"]["malware_family_guess"] = "F" * 300
    run = ingest(report, capsys)
    assert isinstance(run.result, int), run.out
    assert run.stored("INSERT INTO analyses", "malware_family_guess") == "F" * 200
    assert ("analyses.malware_family_guess: 300 characters clipped to 200"
            in run.ingest_warnings())


def test_an_over_long_filename_is_clipped_not_fatal():
    report = copy.deepcopy(BASE_REPORT)
    report["sample_name"] = "n" * 600 + ".exe"
    run = ingest(report)
    assert isinstance(run.result, int)
    assert len(run.stored("INSERT INTO samples", "filename")) == 500


# ---------------------------------------------------------------------------
# NUL and non-finite numbers, at the one choke point
# ---------------------------------------------------------------------------

def test_a_nul_in_a_core_text_column_is_stripped(capsys):
    """psycopg2 refuses the whole statement for one NUL; in the analyses row
    that was the whole analysis."""
    report = copy.deepcopy(BASE_REPORT)
    report["llm_interpretation"]["analysis"]["narrative"] = "before\x00after"
    run = ingest(report, capsys)
    assert isinstance(run.result, int), run.out
    assert run.stored("INSERT INTO analyses", "narrative") == "beforeafter"
    # report_json carried the same NUL, so that is two values cleaned.
    assert any(w.startswith("NUL characters removed from 2 value(s)")
               for w in run.ingest_warnings()), run.ingest_warnings()


def test_a_nul_in_an_enrichment_value_is_stripped_and_the_row_kept():
    report = copy.deepcopy(BASE_REPORT)
    report["extracted_iocs"][1]["value"] = "c2.\x00example.invalid"
    report["llm_interpretation"]["analysis"]["capabilities"][0] = "cap\x00"
    run = ingest(report)
    groups = run.groups()
    assert all(isinstance(groups[g], list) for g in GROUPS)
    values = [p[1] for t, p in groups["iocs"] if t.startswith("INSERT INTO ioc_values")]
    assert "c2.example.invalid" in values
    assert not any("\x00" in s for _, p in run.committed for s in _strings(p))


def test_report_json_is_stored_without_nul_or_nan_anywhere():
    """jsonb refuses \\u0000 and NaN wherever they sit, keys included."""
    report = copy.deepcopy(BASE_REPORT)
    report["cape"]["deep"] = {"k\x00ey": ["v\x00", {"x": float("nan")}],
                              "inf": float("inf")}
    report["timing"]["cape"] = float("nan")
    run = ingest(report)
    assert isinstance(run.result, int)
    stored = run.stored("INSERT INTO analyses", "report_json").adapted
    assert stored["cape"]["deep"] == {"key": ["v", {"x": None}], "inf": None}
    assert stored["timing"]["cape"] is None
    assert run.stored("INSERT INTO analyses", "stage_timings").adapted["cape"] is None
    dumped = json.dumps(stored, allow_nan=False)
    assert "\\u0000" not in dumped
    warnings = run.ingest_warnings()
    assert any("NaN/Infinity" in w for w in warnings), warnings
    assert any(w.startswith("NUL characters removed") for w in warnings), warnings


def test_cleaning_does_not_change_the_callers_report():
    report = copy.deepcopy(BASE_REPORT)
    report["llm_interpretation"]["analysis"]["narrative"] = "a\x00b"
    report["timing"]["cape"] = float("inf")
    before = copy.deepcopy(report)
    ingest(report)
    assert json.dumps(report) == json.dumps(before)


def test_a_clean_value_is_bound_as_the_same_object():
    """The cleaner must be invisible to a well-formed report: no copy of a
    26 MB report_json, and the golden in test_db_ingest_malformed_reports holds."""
    cleaner = db_ingest._Cleaner()
    payload = psycopg2.extras.Json({"a": ["b", 1.5, {"c": None}]})
    assert cleaner.param(payload) is payload
    words = ["x", "y"]
    assert cleaner.param(words) is words
    assert cleaner.warnings() == []


def test_nan_outside_jsonb_is_left_alone():
    """A `real` column accepts NaN; only jsonb refuses it."""
    cleaner = db_ingest._Cleaner()
    assert cleaner.param(float("nan")) != cleaner.param(float("nan"))  # still NaN
    assert cleaner.non_finite == 0
