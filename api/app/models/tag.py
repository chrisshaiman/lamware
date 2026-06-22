# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SQLModel for the `tags` table."""
from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class Tag(SQLModel, table=True):
    __tablename__ = "tags"

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(max_length=200)
    taxonomy: str | None = Field(default=None, max_length=100)
    color: str | None = Field(default="#607d8b", max_length=7)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
