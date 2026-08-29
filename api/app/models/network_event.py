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
SQLModel definition for the `network_events` table.

Structured Cape network data — DNS, HTTP, TCP, UDP, SMTP events.
Stored structurally (not flattened to ioc_values strings) to support
queries like "which samples contacted port 443 on this IP."

dns_answers is JSONB (array of answer records) because DNS responses
are variable-length structured data that doesn't fit a flat column.
"""

from datetime import UTC, datetime

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import Field, SQLModel


class NetworkEvent(SQLModel, table=True):
    __tablename__ = "network_events"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id")
    event_type: str = Field(max_length=20)            # dns, http, tcp, udp, smtp

    # DNS fields
    dns_query: str | None = Field(default=None, max_length=500)
    dns_type: str | None = Field(default=None, max_length=10)   # A, AAAA, MX, TXT, etc.
    dns_answers: list | None = Field(                            # array of answer records
        default=None,
        sa_column=Column(JSONB),
    )

    # HTTP fields
    http_method: str | None = Field(default=None, max_length=10)
    http_url: str | None = Field(default=None)        # TEXT — no length limit
    http_host: str | None = Field(default=None, max_length=500)
    http_status: int | None = Field(default=None)
    http_user_agent: str | None = Field(default=None)  # TEXT

    # TCP/UDP fields
    src_ip: str | None = Field(default=None, max_length=45)     # supports IPv6
    src_port: int | None = Field(default=None)
    dst_ip: str | None = Field(default=None, max_length=45)
    dst_port: int | None = Field(default=None)
    # NULL = this row is one CONNECTION (reports written before #479).
    # A number = this row is a DESTINATION reached that many times.
    # Nullable and undefaulted: a default of 1 would make every historical row
    # claim to be a destination contacted once, which is the misreading the
    # column exists to prevent (#488).
    attempts: int | None = Field(default=None)

    # Common
    timestamp: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
