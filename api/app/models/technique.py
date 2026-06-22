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
SQLModel definitions for `technique_values` and `analysis_techniques` tables.

MITRE ATT&CK techniques are normalized — each technique_id (e.g. T1055.003)
exists once in technique_values. The tactics column is a Postgres VARCHAR[]
because many techniques span multiple tactics (e.g. defense-evasion AND
privilege-escalation).

ARRAY(String) requires the SQLAlchemy Column wrapper; SQLModel Field() alone
cannot express array column types.
"""

from datetime import UTC, datetime

from sqlalchemy import Column, String
from sqlalchemy.dialects.postgresql import ARRAY
from sqlmodel import Field, SQLModel


class TechniqueValue(SQLModel, table=True):
    __tablename__ = "technique_values"

    id: int | None = Field(default=None, primary_key=True)
    technique_id: str = Field(max_length=20)          # e.g. T1055.003
    technique_name: str | None = Field(default=None, max_length=300)
    # VARCHAR(100)[] in Postgres — list of tactic slugs
    tactics: list[str] | None = Field(
        default=None,
        sa_column=Column(ARRAY(String(100))),
    )
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AnalysisTechnique(SQLModel, table=True):
    __tablename__ = "analysis_techniques"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id")
    technique_id: int = Field(foreign_key="technique_values.id")
    source_stage: str = Field(max_length=50)          # Cape, AI Reverse Engineering, Summary
    source_detail: str | None = Field(default=None, max_length=200)  # triggering signature name
