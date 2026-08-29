# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""record which convention wrote a tcp network_event

#479 changed Cape's `tcp_connections` from a truncated list of CONNECTIONS
(one entry per connection, capped at fifty, ephemeral source port varying) to a
list of DESTINATIONS carrying an `attempts` count. db_ingest writes one row per
entry either way, so the same sample ingested either side of 2026-08-29 06:39
UTC differs by roughly 25x on `count(*)` — and differs DOWNWARD, which reads as
network activity having stopped in exactly the days after the DNS fix (#456)
made it start.

`recent_analyses.network_event_count` exposes that count, so the comparison was
available and looked sound.

  network_events.attempts    NULL means the row is one CONNECTION (pre-#479).
                             A number means the row is a DESTINATION that was
                             reached that many times.

Nullable and undefaulted on purpose. A `DEFAULT 1` would make every historical
row claim to be a destination contacted once, which is the misreading this
column exists to prevent — the old rows genuinely do not carry that fact, and a
column that cannot say "unknown" would invent it.

`recent_analyses` gains `tcp_convention` so the era is visible on the same row
as the count it governs, rather than inferable only by joining back to the
events. No attempt is made to reconcile the two eras into one comparable
number: the old data was censored by the cap, so the total it would need does
not exist and cannot be reconstructed. Making the difference visible is the
honest fix; making it disappear would not be.

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-29
"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


# Appended to the end of the existing select list, which is what lets this be a
# CREATE OR REPLACE rather than a DROP + CREATE: Postgres permits adding
# trailing columns to a view but not renaming or retyping existing ones.
_RECENT_ANALYSES = """
CREATE OR REPLACE VIEW public.recent_analyses AS
 SELECT a.id AS analysis_id,
    a.task_id,
    s.sha256,
    s.filename,
    s.file_type,
    a.malware_family_guess,
    a.severity,
    a.malscore,
    a.started_at,
    a.completed_at,
    a.interpret_tool_calls,
    a.possible_prompt_influence,
    ( SELECT count(*) AS count
           FROM public.analysis_iocs ai
          WHERE (ai.analysis_id = a.id)) AS ioc_count,
    ( SELECT count(*) AS count
           FROM public.analysis_techniques at2
          WHERE (at2.analysis_id = a.id)) AS technique_count,
    ( SELECT count(*) AS count
           FROM public.signatures sg
          WHERE (sg.analysis_id = a.id)) AS signature_count,
    ( SELECT count(*) AS count
           FROM public.network_events ne
          WHERE (ne.analysis_id = a.id)) AS network_event_count,
    ( SELECT
        CASE
            WHEN count(*) FILTER (WHERE ne2.event_type = 'tcp') = 0 THEN NULL
            WHEN count(*) FILTER (WHERE ne2.event_type = 'tcp'
                                    AND ne2.attempts IS NOT NULL) > 0
                THEN 'destinations'
            ELSE 'connections'
        END
           FROM public.network_events ne2
          WHERE (ne2.analysis_id = a.id)) AS tcp_convention
   FROM (public.analyses a
     JOIN public.samples s ON ((s.id = a.sample_id)))
  ORDER BY a.started_at DESC;
"""

_RECENT_ANALYSES_WITHOUT_CONVENTION = """
CREATE OR REPLACE VIEW public.recent_analyses AS
 SELECT a.id AS analysis_id,
    a.task_id,
    s.sha256,
    s.filename,
    s.file_type,
    a.malware_family_guess,
    a.severity,
    a.malscore,
    a.started_at,
    a.completed_at,
    a.interpret_tool_calls,
    a.possible_prompt_influence,
    ( SELECT count(*) AS count
           FROM public.analysis_iocs ai
          WHERE (ai.analysis_id = a.id)) AS ioc_count,
    ( SELECT count(*) AS count
           FROM public.analysis_techniques at2
          WHERE (at2.analysis_id = a.id)) AS technique_count,
    ( SELECT count(*) AS count
           FROM public.signatures sg
          WHERE (sg.analysis_id = a.id)) AS signature_count,
    ( SELECT count(*) AS count
           FROM public.network_events ne
          WHERE (ne.analysis_id = a.id)) AS network_event_count
   FROM (public.analyses a
     JOIN public.samples s ON ((s.id = a.sample_id)))
  ORDER BY a.started_at DESC;
"""


def upgrade() -> None:
    op.add_column("network_events", sa.Column("attempts", sa.Integer(), nullable=True))
    op.execute(_RECENT_ANALYSES)


def downgrade() -> None:
    # The view has to lose the column before the column can be dropped, and a
    # trailing column cannot be removed by CREATE OR REPLACE — hence the drop.
    op.execute("DROP VIEW IF EXISTS public.recent_analyses")
    op.execute(_RECENT_ANALYSES_WITHOUT_CONVENTION)
    op.drop_column("network_events", "attempts")
