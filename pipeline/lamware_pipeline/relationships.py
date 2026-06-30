# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cross-sample relationship writer ("campaign graph").

Materializes typed edges into the sample_relationships table from shared network
IOCs, shared JA3, and ssdeep similarity. Pure functions turn candidate rows into
edge dicts (unit-tested, no DB); a thin psycopg2 layer fetches candidates and
upserts edges idempotently (ON CONFLICT DO NOTHING). Edges are symmetric, stored
once with parent_id = min(sample_id), child_id = max(sample_id).

SAFETY: this never touches malware bytes. Hashing (ppdeep.hash) happens in the
isolated triage container; here we only compare the stored fuzzy-hash strings and
join already-extracted IOC strings — string/set/integer ops only.
"""

# IOC types that can form a cross-sample edge. JA3 is a TLS fingerprint; the rest
# are network indicators. Excludes noisy types like file:name and mutex.
_ALLOWED_IOC_TYPES = ("ipv4-addr", "ipv6-addr", "domain-name", "url", "ja3")

_REL_NETWORK = "shares_network_ioc"
_REL_JA3 = "shares_ja3"
_REL_SSDEEP = "ssdeep_similar"

_CONTEXT_MAX_VALUES = 3  # how many shared indicator values to name in context


def normalize_edge(sample_a: int, sample_b: int, relationship: str, context: str) -> dict | None:
    """Order a symmetric edge as parent_id = min, child_id = max (stored once).
    Returns None for a self-edge."""
    if sample_a == sample_b:
        return None
    parent_id, child_id = (sample_a, sample_b) if sample_a < sample_b else (sample_b, sample_a)
    return {"parent_id": parent_id, "child_id": child_id,
            "relationship": relationship, "context": context}


def _summarize_context(values: list) -> str:
    """e.g. '2 shared: a.evil.com, b.evil.com' (caps the listed values)."""
    ordered = sorted(set(values))
    shown = ordered[:_CONTEXT_MAX_VALUES]
    extra = len(ordered) - len(shown)
    suffix = f" (+{extra} more)" if extra > 0 else ""
    return f"{len(ordered)} shared: {', '.join(shown)}{suffix}"


def select_shared_ioc_edges(sample_id: int, candidates: list, freq_by_ioc: dict, max_freq: int) -> list:
    """Build one edge per (peer, relationship) from rows sharing an allowed IOC.

    candidates: [{other_sample_id, ioc_id, ioc_type, ioc_value}, ...]
    freq_by_ioc: {ioc_id: distinct-sample count}; indicators over max_freq are dropped.
    JA3 -> shares_ja3; other allowed types -> shares_network_ioc.
    """
    grouped: dict = {}  # (other_sample_id, relationship) -> [ioc_value, ...]
    for c in candidates:
        if c["ioc_type"] not in _ALLOWED_IOC_TYPES:
            continue
        if freq_by_ioc.get(c["ioc_id"], 0) > max_freq:
            continue
        rel = _REL_JA3 if c["ioc_type"] == "ja3" else _REL_NETWORK
        grouped.setdefault((c["other_sample_id"], rel), []).append(c["ioc_value"])

    edges = []
    for (other, rel), values in grouped.items():
        edge = normalize_edge(sample_id, other, rel, _summarize_context(values))
        if edge:
            edges.append(edge)
    edges.sort(key=lambda e: (e["parent_id"], e["child_id"], e["relationship"]))
    return edges


def select_ssdeep_edges(sample_id: int, ssdeep: str, others: list,
                        threshold: int, compare_fn) -> list:
    """Build ssdeep_similar edges where compare_fn(ssdeep, other) >= threshold.

    others: [(other_sample_id, other_ssdeep), ...]. compare_fn is injected
    (ppdeep.compare in prod). A compare error skips that pair (never crashes).
    """
    if not ssdeep:
        return []
    edges = []
    for other_id, other_hash in others:
        if other_id == sample_id or not other_hash:
            continue
        try:
            score = compare_fn(ssdeep, other_hash)
        except Exception:
            continue
        if score is not None and score >= threshold:
            edge = normalize_edge(sample_id, other_id, _REL_SSDEEP, f"ssdeep score={score}")
            # normalize_edge only returns None for self-edges (already guarded above);
            # the check is belt-and-suspenders.
            if edge:
                edges.append(edge)
    edges.sort(key=lambda e: (e["parent_id"], e["child_id"]))
    return edges


# ---------------------------------------------------------------------------
# Thin SQL layer (psycopg2). Validated end-to-end at deploy via the backfill;
# only the static upsert SQL is unit-asserted here.
# ---------------------------------------------------------------------------

# The private/localhost/broadcast EXCLUSION predicate mirrors api/app/routers/iocs.py
# (/api/iocs/clusters) character-for-character. The TYPE SET intentionally diverges:
# we include 'ja3' (split into a separate shares_ja3 relationship), which /clusters
# does not — do not "sync" the two by removing ja3. Static text, no interpolation.
_SHARED_IOC_SQL = """
WITH meaningful AS (
    SELECT id, type, value FROM ioc_values
    WHERE type = ANY(%(types)s)
      AND NOT (
        (type = 'ipv4-addr' AND (
            value LIKE '127.%%' OR value LIKE '10.%%' OR value LIKE '192.168.%%'
            OR value LIKE '172.16.%%' OR value LIKE '172.17.%%' OR value LIKE '172.18.%%'
            OR value LIKE '172.19.%%' OR value LIKE '172.2_.%%' OR value LIKE '172.30.%%'
            OR value LIKE '172.31.%%' OR value = '0.0.0.0' OR value = '255.255.255.255'
        ))
        OR (type = 'domain-name' AND value IN ('localhost', 'localhost.localdomain'))
      )
),
my_iocs AS (
    SELECT DISTINCT ai.ioc_id
    FROM analysis_iocs ai JOIN analyses a ON a.id = ai.analysis_id
    WHERE a.sample_id = %(sid)s AND ai.ioc_id IN (SELECT id FROM meaningful)
),
freq AS (
    SELECT ai.ioc_id, COUNT(DISTINCT a.sample_id) AS sample_count
    FROM analysis_iocs ai JOIN analyses a ON a.id = ai.analysis_id
    WHERE ai.ioc_id IN (SELECT ioc_id FROM my_iocs)
    GROUP BY ai.ioc_id
)
SELECT DISTINCT a2.sample_id AS other_sample_id, m.id AS ioc_id,
       m.type AS ioc_type, m.value AS ioc_value, f.sample_count
FROM my_iocs mi
JOIN meaningful m ON m.id = mi.ioc_id
JOIN freq f ON f.ioc_id = mi.ioc_id
JOIN analysis_iocs a2i ON a2i.ioc_id = mi.ioc_id
JOIN analyses a2 ON a2.id = a2i.analysis_id AND a2.sample_id <> %(sid)s
"""

_SSDEEP_SQL = """
SELECT id, ssdeep FROM samples
WHERE id <> %(sid)s AND ssdeep IS NOT NULL AND ssdeep <> ''
"""

_UPSERT_SQL = """
INSERT INTO sample_relationships (parent_id, child_id, relationship, context)
VALUES %s
ON CONFLICT (parent_id, child_id, relationship) DO NOTHING
"""


def fetch_shared_ioc_candidates(conn, sample_id: int):
    """Return (candidates, freq_by_ioc) of samples sharing a meaningful IOC."""
    with conn.cursor() as cur:
        cur.execute(_SHARED_IOC_SQL, {"types": list(_ALLOWED_IOC_TYPES), "sid": sample_id})
        rows = cur.fetchall()
    candidates = [
        {"other_sample_id": r[0], "ioc_id": r[1], "ioc_type": r[2], "ioc_value": r[3]}
        for r in rows
    ]
    freq_by_ioc = {r[1]: r[4] for r in rows}
    return candidates, freq_by_ioc


def fetch_ssdeep_candidates(conn, sample_id: int):
    """Return (this_sample_ssdeep, [(other_id, other_ssdeep), ...]).

    Loads all other samples' non-empty ssdeep hashes for a Python-side O(corpus)
    compare. Fine at current scale; a very large corpus would want a chunk-prefix
    prefilter or batching.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT ssdeep FROM samples WHERE id = %(sid)s", {"sid": sample_id})
        row = cur.fetchone()
        this_ssdeep = (row[0] if row else "") or ""
        if not this_ssdeep:
            return "", []
        cur.execute(_SSDEEP_SQL, {"sid": sample_id})
        others = [(r[0], r[1]) for r in cur.fetchall()]
    return this_ssdeep, others


def upsert_edges(conn, edges: list) -> int:
    """Batch-insert edges, skipping duplicates (idempotent). Returns rows inserted."""
    if not edges:
        return 0
    import psycopg2.extras  # lazy (like ppdeep): module imports without psycopg2
    rows = [(e["parent_id"], e["child_id"], e["relationship"], e["context"]) for e in edges]
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, _UPSERT_SQL, rows)
        return cur.rowcount


def compute_and_write_edges(conn, sample_id: int, config) -> int:
    """Compute all edges for sample_id vs the corpus and upsert them. Returns the
    number of new edges written.

    Commits on `conn` — so any other pending work on `conn` must already be
    committed before calling this. The db_ingest hook calls it only AFTER the
    analysis ingest has committed, so the edge upsert is its own transaction.
    """
    import ppdeep  # lazy: pure-core unit tests don't need ppdeep installed

    candidates, freq_by_ioc = fetch_shared_ioc_candidates(conn, sample_id)
    edges = select_shared_ioc_edges(
        sample_id, candidates, freq_by_ioc, config.relationship_max_ioc_frequency
    )
    this_ssdeep, others = fetch_ssdeep_candidates(conn, sample_id)
    edges += select_ssdeep_edges(
        sample_id, this_ssdeep, others, config.relationship_ssdeep_threshold, ppdeep.compare
    )
    written = upsert_edges(conn, edges)
    conn.commit()
    return written


def write_relationships_safe(conn, sample_id: int, config) -> int:
    """Non-fatal ingest hook: compute + write edges, never raising. On error,
    roll back the (uncommitted) edge work so the connection stays usable and
    return 0 — the analysis ingest (already committed) is unaffected."""
    try:
        n = compute_and_write_edges(conn, sample_id, config)
        if n:
            print(f"  Relationships: wrote {n} cross-sample edge(s) for sample {sample_id}")
        return n
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        print(f"  [!] Relationship computation skipped (non-fatal): {e}")
        return 0


def backfill_all(conn, config) -> int:
    """Compute + write edges for every sample in the corpus. Returns total edges
    written. Errors propagate (unlike the ingest hook) so a backfill failure is
    visible to the operator."""
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM samples ORDER BY id")
        sample_ids = [r[0] for r in cur.fetchall()]
    total = 0
    for sid in sample_ids:
        total += compute_and_write_edges(conn, sid, config)
    return total
