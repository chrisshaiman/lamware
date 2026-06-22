# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SQLModel for the `sample_relationships` table (parent/child sample lineage)."""
from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class SampleRelationship(SQLModel, table=True):
    __tablename__ = "sample_relationships"

    id: int | None = Field(default=None, primary_key=True)
    parent_id: int = Field(foreign_key="samples.id")
    child_id: int = Field(foreign_key="samples.id")
    relationship: str = Field(max_length=50)
    context: str | None = Field(default=None)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
