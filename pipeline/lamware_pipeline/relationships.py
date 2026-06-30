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


def normalize_edge(sample_a: int, sample_b: int, relationship: str, context: str):
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
            if edge:
                edges.append(edge)
    edges.sort(key=lambda e: (e["parent_id"], e["child_id"]))
    return edges
