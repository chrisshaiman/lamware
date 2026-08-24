# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SQLModel definition for the `correlations` table.

Correlation is the project's stated thesis, and until now it was the only
analysis output that was computed, severity-scored, rendered into the PDF — and
then discarded. `cross_correlations` never reached the database, so across 998
analyses there was no way to answer "has correlation ever fired, and which
rules?". That blocks #420, whose first requirement is a corpus of samples where
correlation produces something.

Findings are rows. The rules that could NOT be evaluated are not — they live in
`analyses.correlation_warnings`, a nullable `text[]`, because that single column
carries the whole three-state distinction #411 is about:

    NULL   correlation was never recorded for this analysis
    '{}'   correlation ran, and every rule could be evaluated
    {...}  correlation ran, and these rules could not

A second table was the first shape here, on the reasoning that findings and
warnings must not be conflated. That reasoning was right and the shape was
wrong: a warning is one sentence, there are at most five per analysis (one per
entry in _PLUGIN_CONSUMERS, plus the Cape manifest), and they belong to the
ANALYSIS rather than to any finding. A table bought nothing a column does not,
and a separate `correlation_ran_at` timestamp then had to exist alongside it
purely to say "this ran" — two signals that could disagree, where the array
cannot disagree with itself.
"""

from datetime import UTC, datetime

from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlmodel import Field, SQLModel


class Correlation(SQLModel, table=True):
    __tablename__ = "correlations"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id", index=True)

    #: Rule that produced this — dropped_file_loaded, cmdline_spoofing,
    #: shellcode_self_modified, c2_live_in_memory, injection_corroborated.
    #: Stored rather than derived so the per-rule base rate is one GROUP BY.
    type: str = Field(max_length=100, index=True)

    #: The rules emit "high"/"critical". Kept as the rules' own string rather
    #: than mapped onto Cape's 0-3 integer scale (see signatures.severity),
    #: because the two scales mean different things and collapsing them would
    #: make the severity contribution ADR-017 tracks unreadable.
    severity: str = Field(max_length=20)

    title: str = Field(max_length=500)
    detail: str | None = Field(default=None)

    #: The tools that had to agree. This is what makes a finding a CORRELATION
    #: rather than an observation, so it is a column and not prose.
    sources: list[str] | None = Field(default=None, sa_column=Column(ARRAY(String(50))))

    mitre: str | None = Field(default=None, max_length=200)
    pid: str | None = Field(default=None, max_length=20)

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
