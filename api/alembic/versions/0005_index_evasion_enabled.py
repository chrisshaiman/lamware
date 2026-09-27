# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""index the evasion_analysis.enabled flag — /api/evasions was a 14s triple table scan

The post-deploy smoke gate failed on /evasions three times. The page was not
broken: the captured HTML showed it stuck in its own loading skeleton (four
`animate-pulse` divs, the `isLoading` branch), and the API log showed the request
completing `200 OK`. It was simply slower than the gate's 15s timeout.

`/api/evasions` runs three queries, each filtered on

    report_json->'evasion_analysis'->>'enabled' = 'true'

with no index to support it. `report_json` totals **3.3 GB** across 1096 rows, so
each query was a sequential scan that detoasted the lot:

    techniques extraction   4674 ms
    total count             4320 ms
    recommendations         5033 ms
                          --------
                           14.0 s   against a 15s timeout

Which is why it was intermittent rather than consistently red: one run squeezed
under the wire and looked like a pass.

Only 400 of 1096 rows have the flag set, so the filter is selective and an
expression index turns the scan into a bitmap index scan. Measured on the host:

    total count             4320 ms  ->     1.7 ms
    techniques extraction   4674 ms  ->  1192 ms
                                     -----------
    endpoint total            14.0 s  ->    ~2.4 s

The remaining ~1.2s per unnest is detoasting the matched rows' JSONB, which an
index cannot avoid — the query genuinely reads those documents. That is fine
against a 15s budget, and the structural fix (extracting evasion techniques into
their own table at ingest, as `cross_correlations` already does) is a larger
change that this does not foreclose.

The index was created by hand on the host while diagnosing, which is what
confirmed the numbers above. `IF NOT EXISTS` makes this migration idempotent
against that, and makes the hand-made index survive a rebuild rather than
quietly not existing on the next one.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-27
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

INDEX_NAME = "idx_analyses_evasion_enabled"

# Raw SQL rather than op.create_index: the target is an EXPRESSION on a jsonb
# path, which alembic's helper cannot express without a literal_column hack that
# reads worse than the SQL it generates.
CREATE = (
    f"CREATE INDEX IF NOT EXISTS {INDEX_NAME} "
    "ON analyses ((report_json->'evasion_analysis'->>'enabled'))"
)
DROP = f"DROP INDEX IF EXISTS {INDEX_NAME}"


def upgrade() -> None:
    op.execute(CREATE)


def downgrade() -> None:
    op.execute(DROP)
