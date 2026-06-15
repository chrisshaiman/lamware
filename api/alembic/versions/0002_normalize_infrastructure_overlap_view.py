# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""normalize infrastructure_overlap view to its canonical form

The `infrastructure_overlap` view's WHERE clause was stored from a hand-written
form whose array cast pg_dump does not re-serialize idempotently:

    prod stores ... = ANY ((ARRAY[...]::character varying[])::text[])
    a rebuild re-renders it as ... = ANY (ARRAY[(...)::text, ...])

The two are semantically identical, but the textual difference is the sole
remaining diff between a fresh `alembic upgrade head` build and production. This
migration issues a `CREATE OR REPLACE VIEW` with the canonical (round-tripped)
form so prod and a fresh build converge to byte-identical `pg_dump` output —
closing the equivalence-diff and satisfying Phase B's "a real change shipped via
a revision" gate. No semantic / behavioural change.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-14
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

# Canonical form (array cast applied per-element) — the form PostgreSQL produces
# after a parse->store->dump round-trip, so it is stable under future dumps.
UPGRADE_SQL = """
CREATE OR REPLACE VIEW public.infrastructure_overlap AS
 SELECT iv.value AS indicator,
    iv.type,
    iv.first_seen,
    iv.last_seen,
    count(DISTINCT a.malware_family_guess) AS family_count,
    array_agg(DISTINCT a.malware_family_guess) FILTER (WHERE (a.malware_family_guess IS NOT NULL)) AS families,
    count(DISTINCT a.sample_id) AS sample_count
   FROM ((public.ioc_values iv
     JOIN public.analysis_iocs ai ON ((ai.ioc_id = iv.id)))
     JOIN public.analyses a ON ((a.id = ai.analysis_id)))
  WHERE ((iv.type)::text = ANY (ARRAY[('ipv4-addr'::character varying)::text, ('ipv6-addr'::character varying)::text, ('domain-name'::character varying)::text, ('url'::character varying)::text]))
  GROUP BY iv.id, iv.value, iv.type, iv.first_seen, iv.last_seen
 HAVING (count(DISTINCT a.malware_family_guess) > 1)
  ORDER BY (count(DISTINCT a.malware_family_guess)) DESC, (count(DISTINCT a.sample_id)) DESC;
"""

# Original baseline form (whole-array cast) — restores the 0001 definition.
DOWNGRADE_SQL = """
CREATE OR REPLACE VIEW public.infrastructure_overlap AS
 SELECT iv.value AS indicator,
    iv.type,
    iv.first_seen,
    iv.last_seen,
    count(DISTINCT a.malware_family_guess) AS family_count,
    array_agg(DISTINCT a.malware_family_guess) FILTER (WHERE (a.malware_family_guess IS NOT NULL)) AS families,
    count(DISTINCT a.sample_id) AS sample_count
   FROM ((public.ioc_values iv
     JOIN public.analysis_iocs ai ON ((ai.ioc_id = iv.id)))
     JOIN public.analyses a ON ((a.id = ai.analysis_id)))
  WHERE ((iv.type)::text = ANY ((ARRAY['ipv4-addr'::character varying, 'ipv6-addr'::character varying, 'domain-name'::character varying, 'url'::character varying])::text[]))
  GROUP BY iv.id, iv.value, iv.type, iv.first_seen, iv.last_seen
 HAVING (count(DISTINCT a.malware_family_guess) > 1)
  ORDER BY (count(DISTINCT a.malware_family_guess)) DESC, (count(DISTINCT a.sample_id)) DESC;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
