# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SQLModel for the `ioc_technique_mappings` table (IOC<->technique links)."""
from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class IocTechniqueMapping(SQLModel, table=True):
    __tablename__ = "ioc_technique_mappings"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id")
    ioc_id: int = Field(foreign_key="ioc_values.id")
    technique_id: int = Field(foreign_key="technique_values.id")
    evidence: str | None = Field(default=None)
    method: str = Field(default="programmatic", max_length=20)
    confidence: str | None = Field(default="high", max_length=20)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
