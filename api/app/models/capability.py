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
SQLModel definition for the `capabilities` table.

LLM-identified capabilities stored per-analysis (not deduplicated).
LLM output is non-deterministic, so exact-text deduplication creates
false distinctions. Aggregation happens at query time instead.
"""

from datetime import datetime

from sqlmodel import Field, SQLModel


class Capability(SQLModel, table=True):
    __tablename__ = "capabilities"

    id: int | None = Field(default=None, primary_key=True)
    analysis_id: int = Field(foreign_key="analyses.id")
    description: str                                  # TEXT — free-form LLM output
    source_stage: str = Field(max_length=50)
    created_at: datetime | None = Field(default=None)
