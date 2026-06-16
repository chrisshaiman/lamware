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
SQLModel definition for the `signatures` table.

Behavioral signatures fired during Cape sandbox detonation.
Severity uses Cape's 0-3 integer scale (0=info, 1=low, 2=medium, 3=high).
"""

from datetime import datetime, timezone

from sqlmodel import Field, SQLModel


class Signature(SQLModel, table=True):
    __tablename__ = "signatures"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id")
    name: str = Field(max_length=200)
    severity: int | None = Field(default=0)           # 0–3 (Cape's scale)
    description: str | None = Field(default=None)
    source_stage: str = Field(default="Cape", max_length=50)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
