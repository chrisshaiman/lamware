# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SQLModel for the `audit_log` table."""
from datetime import datetime, timezone

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel


class AuditLog(SQLModel, table=True):
    __tablename__ = "audit_log"

    id: int | None = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: str = Field(max_length=255)
    email: str = Field(max_length=255)
    action: str = Field(max_length=50)
    resource_type: str = Field(max_length=50)
    resource_id: str | None = Field(default=None, max_length=255)
    details: dict | None = Field(default=None, sa_column=Column(JSONB))
