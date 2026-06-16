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
lamware API — database models package.

Import all SQLModel table classes here so SQLModel's metadata is fully
populated before create_all() or alembic migrations run. Routers and
other modules should import from here rather than from individual files.
"""

from app.models.analysis import Analysis
from app.models.audit import AuditLog
from app.models.capability import Capability
from app.models.investigation import (
    InvestigationMessage,
    InvestigationPin,
    InvestigationSession,
)
from app.models.ioc import AnalysisIoc, IocValue
from app.models.ioc_technique_mapping import IocTechniqueMapping
from app.models.links import AnalysisTag, IocTag, SampleTag
from app.models.network_event import NetworkEvent
from app.models.pipeline_event import PipelineStageEvent
from app.models.relationship import SampleRelationship
from app.models.sample import Sample
from app.models.signature import Signature
from app.models.tag import Tag
from app.models.technique import AnalysisTechnique, TechniqueValue

__all__ = [
    "Sample",
    "Analysis",
    "IocValue",
    "AnalysisIoc",
    "TechniqueValue",
    "AnalysisTechnique",
    "Signature",
    "Capability",
    "NetworkEvent",
    "InvestigationSession",
    "InvestigationMessage",
    "InvestigationPin",
    "Tag",
    "AnalysisTag",
    "IocTag",
    "SampleTag",
    "SampleRelationship",
    "PipelineStageEvent",
    "IocTechniqueMapping",
    "AuditLog",
]
