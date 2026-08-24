# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""persist cross-tool correlation findings

Correlation is the project's stated thesis and the only analysis output that was
computed, severity-scored, rendered into the PDF, and then thrown away. Nothing
wrote `cross_correlations` to the database, so across 998 analyses there was no
way to ask whether correlation has ever fired, or which rules do the work (#423).
That blocks #420, whose first requirement is a corpus of samples where
correlation produces something to reason about.

One table and one column:

  correlations                    one row per finding, carrying the rule `type`
                                  so the per-rule rate is a GROUP BY rather than
                                  a text search.
  analyses.correlation_warnings   nullable text[]. NULL means correlation was
                                  never recorded for this analysis; '{}' means
                                  it ran and every rule could be evaluated;
                                  non-empty means it ran and these could not.

The three states matter because without them a zero is unreadable — every
pre-existing row also has no findings. Being NOT NULL is what says "correlation
ran", so no separate timestamp column exists to disagree with it.

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-24
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "correlations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("analysis_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("detail", sa.String(), nullable=True),
        sa.Column("sources", postgresql.ARRAY(sa.String(length=50)), nullable=True),
        sa.Column("mitre", sa.String(length=200), nullable=True),
        sa.Column("pid", sa.String(length=20), nullable=True),
        # `timestamp with time zone DEFAULT now()`, matching every other
        # created_at in the baseline. Load-bearing, not cosmetic: db_ingest's
        # INSERT names eight columns and this is not one of them, exactly as the
        # signatures and capabilities inserts omit theirs. Without the default
        # every correlation insert raises NotNullViolation, which the ingest's
        # blanket `except Exception: rollback` turns into a lost analysis —
        # IOCs and techniques included, not just the correlations.
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["analysis_id"], ["analyses.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_correlations_analysis_id", "correlations", ["analysis_id"])
    # The per-rule base rate this exists to produce is
    #   SELECT type, count(DISTINCT analysis_id) FROM correlations GROUP BY type
    # so `type` is indexed rather than left to a sequential scan as the table grows.
    op.create_index("ix_correlations_type", "correlations", ["type"])

    # Nullable, and no server_default. A default of '{}' would mark all 998
    # pre-existing analyses as "correlation ran and found nothing to warn
    # about", which is the exact false claim this column exists to prevent.
    op.add_column(
        "analyses",
        sa.Column("correlation_warnings", postgresql.ARRAY(sa.String(length=500)),
                  nullable=True),
    )


def downgrade() -> None:
    op.drop_column("analyses", "correlation_warnings")
    op.drop_index("ix_correlations_type", table_name="correlations")
    op.drop_index("ix_correlations_analysis_id", table_name="correlations")
    op.drop_table("correlations")
