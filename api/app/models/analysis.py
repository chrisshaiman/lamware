# Copyright 2026 Christopher Shaiman
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
SQLModel definition for the `analyses` table.

One row per pipeline run. References samples by sample_id.
JSONB columns (report_json, stage_timings) use SQLAlchemy Column
wrappers since SQLModel's Field() doesn't natively handle JSONB.

pipeline_status and current_stage are denormalized from
pipeline_stage_events for fast dashboard queries.
stage_timings holds per-stage elapsed seconds as a dict.
"""

from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel


class Analysis(SQLModel, table=True):
    __tablename__ = "analyses"

    id: int | None = Field(default=None, primary_key=True)
    sample_id: int = Field(foreign_key="samples.id")
    task_id: str = Field(max_length=100)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)

    # Overall results
    severity: str | None = Field(default=None, max_length=20)
    malscore: float | None = Field(default=None)
    malware_family_guess: str | None = Field(default=None, max_length=200)

    # Stage completion flags
    triage_completed: bool | None = Field(default=False)
    cape_completed: bool | None = Field(default=False)
    cape_task_id: int | None = Field(default=None)
    volatility_completed: bool | None = Field(default=False)
    volatility_triggered: bool | None = Field(default=False)
    ghidra_completed: bool | None = Field(default=False)
    ghidra_triggered: bool | None = Field(default=False)
    interpret_completed: bool | None = Field(default=False)
    summary_completed: bool | None = Field(default=False)
    pdf_generated: bool | None = Field(default=False)

    # AI RE metadata
    interpret_model: str | None = Field(default=None, max_length=100)
    interpret_tool_calls: int | None = Field(default=0)
    interpret_duration_secs: float | None = Field(default=None)
    interpret_escalated: bool | None = Field(default=False)
    possible_prompt_influence: bool | None = Field(default=False)

    # LLM narrative fields (free text, searchable)
    narrative: str | None = Field(default=None)
    working_notes: str | None = Field(default=None)
    executive_summary: str | None = Field(default=None)
    plain_english_summary: str | None = Field(default=None)

    # Full pipeline report — stored as JSONB escape hatch
    report_json: dict | None = Field(default=None, sa_column=Column(JSONB))

    # Cost tracking (NUMERIC(8,4) in Postgres, Decimal in Python)
    llm_cost_usd: Decimal | None = Field(default=None)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Denormalized pipeline tracking columns (fast dashboard queries).
    # Written by the pipeline alongside pipeline_stage_events inserts.
    pipeline_status: str | None = Field(default=None, max_length=50)
    current_stage: str | None = Field(default=None, max_length=50)

    # Per-stage elapsed seconds — {"triage": 12.4, "cape": 180.1, ...}
    stage_timings: dict | None = Field(default=None, sa_column=Column(JSONB))

    # Submitter identity (added by migration_002_auth — ADR-017)
    submitted_by: str | None = Field(default=None, max_length=255)
