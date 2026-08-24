# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The queries #423 exists to make answerable.

Correlation is the project's stated thesis, and until these tables landed nobody
could say how often it fires. These are the questions #420 has to be able to
answer before an A/B on correlation-guided investigation means anything — you
cannot measure whether putting correlated evidence in front of the investigator
helps if the treatment arm is usually empty and nobody has checked.

Kept as named SQL rather than a REST endpoint because the consumer is an
experiment write-up, not the dashboard, and because a query in source is a query
a reader can run by hand against a psql prompt.

THE DENOMINATOR IS `correlation_warnings IS NOT NULL`, always. That column is
NULL until correlation has been recorded for an analysis, so it doubles as the
"this ran" marker; analyses predating persistence have no findings and would
otherwise inflate every "produced nothing" figure — 998 of them at the time of
writing, which would have made the base rate look like ~0% regardless of truth.
"""

#: How many analyses correlation has actually been recorded for. Every other
#: number here is a fraction of this one, so it is the first thing to read.
COVERAGE = """
SELECT count(*) FILTER (WHERE correlation_warnings IS NOT NULL) AS recorded,
       count(*) FILTER (WHERE correlation_warnings IS NULL)     AS not_recorded,
       count(*)                                                  AS total
FROM analyses
"""

#: The headline: of the analyses correlation ran for, how many produced anything.
FIRE_RATE = """
SELECT count(DISTINCT a.id)                        AS analyses_with_correlation,
       (SELECT count(*) FROM analyses
         WHERE correlation_warnings IS NOT NULL)   AS analyses_measured
FROM analyses a
JOIN correlations c ON c.analysis_id = a.id
WHERE a.correlation_warnings IS NOT NULL
"""

#: Which rules do the work. The acceptance criterion of #423.
#:
#: Read this next to BLIND_RATE below. A rule with a count of zero has either
#: never matched or never been able to run, and those are different problems:
#: as of 2026-08-24, four of the five rules had produced nothing on any of the
#: seven surviving reports, and rule_dropped_file_loaded had been structurally
#: incapable of producing anything at all until #436.
BY_RULE = """
SELECT c.type,
       count(*)                      AS findings,
       count(DISTINCT c.analysis_id) AS analyses,
       count(*) FILTER (WHERE c.severity = 'critical') AS critical,
       count(*) FILTER (WHERE c.severity = 'high')     AS high
FROM correlations c
JOIN analyses a ON a.id = c.analysis_id
WHERE a.correlation_warnings IS NOT NULL
GROUP BY c.type
ORDER BY analyses DESC, findings DESC
"""

#: The number that makes a zero readable. An analysis with no findings AND no
#: warnings was checked and was clean; one with no findings and warnings was
#: never able to look. Conflating them is #411.
BLIND_RATE = """
SELECT
  count(*) FILTER (WHERE f.n = 0 AND cardinality(a.correlation_warnings) = 0) AS clean,
  count(*) FILTER (WHERE f.n = 0 AND cardinality(a.correlation_warnings) > 0) AS blind,
  count(*) FILTER (WHERE f.n > 0)                                             AS produced_findings
FROM analyses a
CROSS JOIN LATERAL (
  SELECT count(*) AS n FROM correlations WHERE analysis_id = a.id) f
WHERE a.correlation_warnings IS NOT NULL
"""

#: Candidate corpus for #420: analyses where correlation produced the most, and
#: from the most distinct rules. This is the query that was impossible before —
#: the reason #420 is blocked is that nobody could ask it.
CORPUS_CANDIDATES = """
SELECT a.id            AS analysis_id,
       a.task_id,
       s.sha256,
       a.malware_family_guess,
       count(*)                 AS findings,
       count(DISTINCT c.type)   AS distinct_rules,
       array_agg(DISTINCT c.type ORDER BY c.type) AS rules
FROM analyses a
JOIN samples s      ON s.id = a.sample_id
JOIN correlations c ON c.analysis_id = a.id
WHERE a.correlation_warnings IS NOT NULL
GROUP BY a.id, a.task_id, s.sha256, a.malware_family_guess
ORDER BY distinct_rules DESC, findings DESC
LIMIT 50
"""

#: Which rules are going unevaluated, and how often. Previously this needed a
#: join and a GROUP BY over a whole table; it is now an unnest of one column.
#:
#: This is the number that says whether a rule's zero means "never matches" or
#: "never gets to run" — the distinction #411 exists for, asked across the whole
#: corpus rather than one report at a time.
WARNING_FREQUENCY = """
SELECT w AS warning, count(*) AS analyses
FROM analyses a, unnest(a.correlation_warnings) AS w
WHERE a.correlation_warnings IS NOT NULL
GROUP BY w
ORDER BY analyses DESC
"""

QUERIES = {
    "coverage": COVERAGE,
    "fire_rate": FIRE_RATE,
    "by_rule": BY_RULE,
    "blind_rate": BLIND_RATE,
    "warning_frequency": WARNING_FREQUENCY,
    "corpus_candidates": CORPUS_CANDIDATES,
}
