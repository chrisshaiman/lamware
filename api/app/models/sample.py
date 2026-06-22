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
SQLModel definition for the `samples` table.

One row per unique binary, keyed by SHA256. Tracks file identity,
metadata, and first/last-seen timestamps across all pipeline runs.
"""

from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


class Sample(SQLModel, table=True):
    __tablename__ = "samples"

    id: int | None = Field(default=None, primary_key=True)
    sha256: str = Field(max_length=64)
    sha1: str | None = Field(default=None, max_length=40)
    md5: str | None = Field(default=None, max_length=32)
    ssdeep: str | None = Field(default=None, max_length=200)
    filename: str | None = Field(default=None, max_length=500)
    file_type: str | None = Field(default=None, max_length=300)
    file_mime: str | None = Field(default=None, max_length=100)
    file_size: int | None = Field(default=None)
    entropy: float | None = Field(default=None)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
