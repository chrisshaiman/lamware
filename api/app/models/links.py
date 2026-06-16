# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SQLModel definitions for the tag join tables."""
from sqlmodel import Field, SQLModel


class AnalysisTag(SQLModel, table=True):
    __tablename__ = "analysis_tags"

    analysis_id: int = Field(foreign_key="analyses.id", primary_key=True)
    tag_id: int = Field(foreign_key="tags.id", primary_key=True)


class IocTag(SQLModel, table=True):
    __tablename__ = "ioc_tags"

    ioc_id: int = Field(foreign_key="ioc_values.id", primary_key=True)
    tag_id: int = Field(foreign_key="tags.id", primary_key=True)


class SampleTag(SQLModel, table=True):
    __tablename__ = "sample_tags"

    sample_id: int = Field(foreign_key="samples.id", primary_key=True)
    tag_id: int = Field(foreign_key="tags.id", primary_key=True)
