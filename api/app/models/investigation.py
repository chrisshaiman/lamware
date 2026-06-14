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
SQLModel definitions for investigation agent tables.

investigation_sessions: one row per analysis being investigated by an agent.
  Tracks model choice, token usage, and conversation state.

investigation_messages: conversation history for a session.
  Captures user input, assistant responses, tool calls, and tool results.

investigation_pins: analyst-promoted findings from a session.
  IOCs, techniques, notes, and other analyst-marked insights with context.
"""

from datetime import datetime, timezone
from decimal import Decimal

from sqlmodel import Field, SQLModel


class InvestigationSession(SQLModel, table=True):
    __tablename__ = "investigation_sessions"
    model_config = {"protected_namespaces": ()}  # allow field named "model"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id")
    user_sub: str
    model: str = Field(default="claude-sonnet-4-6")
    status: str = Field(default="active")  # active, completed, abandoned
    total_input_tokens: int = Field(default=0)
    total_output_tokens: int = Field(default=0)
    total_cost_usd: Decimal = Field(default_factory=lambda: Decimal("0"))
    max_turns: int = Field(default=100)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column_kwargs={"onupdate": lambda: datetime.now(timezone.utc)},
    )


class InvestigationMessage(SQLModel, table=True):
    __tablename__ = "investigation_messages"

    id: int | None = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="investigation_sessions.id")
    role: str  # user, assistant, tool_call, tool_result
    content: str
    tool_name: str | None = Field(default=None)
    input_tokens: int | None = Field(default=None)
    output_tokens: int | None = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InvestigationPin(SQLModel, table=True):
    __tablename__ = "investigation_pins"

    id: int | None = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="investigation_sessions.id")
    analysis_id: int = Field(foreign_key="analyses.id")
    pin_type: str  # ioc, technique, note
    value: str
    ioc_type: str | None = Field(default=None)  # STIX-style IOC type when pin_type is "ioc" (e.g., ipv4-addr, domain-name)
    context: str = Field(default="")
    promoted: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
