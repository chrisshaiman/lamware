# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SQLModel for the `pipeline_stage_events` table (per-stage status events)."""
from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class PipelineStageEvent(SQLModel, table=True):
    __tablename__ = "pipeline_stage_events"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id")
    stage: str = Field(max_length=50)
    status: str = Field(max_length=20)
    detail: str | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
