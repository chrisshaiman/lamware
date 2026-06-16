# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Shared Alembic autogenerate scoping for the malware_analysis schema.

Spec 2 strictness: autogenerate manages TABLES + COLUMNS + NULLABILITY only.
Indexes, unique/FK constraints, the 5 views, and the pg_trgm extension are
hand-authored in migrations, so they are excluded here to stop autogenerate from
proposing destructive drops of objects the ORM models do not declare.
"""

# Database views are not tables; guard against them ever being treated as such.
DB_VIEWS = {
    "correlated_iocs",
    "infrastructure_overlap",
    "recent_analyses",
    "sample_lineage",
    "technique_frequency",
}


def include_object(obj, name, type_, reflected, compare_to):
    """Limit autogenerate to tables + columns (+ nullability)."""
    if type_ in ("index", "unique_constraint", "foreign_key_constraint"):
        return False
    if type_ == "table" and name in DB_VIEWS:
        return False
    return True
