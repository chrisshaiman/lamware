# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every report.json key a consumer reads is one a real report carries (#409).

#406: the investigate tool read ``cape.behavior``, which nothing wrote, and
answered "0 processes" for every analysis for months. #408: a stage read
``_sample_path``, likewise never written, so a branch never ran. Both read a key
with no producer and degraded to a confident empty answer, and the tests passed
because each supplied the key by hand.

What this compares, and why it is not a source-text check on both sides:

* The PRODUCER side is real reports, not producer source. Their key shapes
  (paths and JSON types, no values) were read off the host from pipeline runs,
  the eval corpus and a sample of stored analyses, and are committed as
  ``tests/fixtures/report_key_shapes.json``. A key is "written" when a real
  report has it. Scanning producer code would have to model every ``update``,
  stage result and container JSON that lands in the report; the report already
  is the result of all of them.
* The CONSUMER side has to be read from source: no test can run the API, the
  ingest and the eval against every report and record every lookup. So that
  half is structural, done with ``ast`` and an abstract interpreter that
  follows the report through aliases, helpers, loops and db_ingest's ``_Node``
  accessors (``tests/report_keys.py``). It reports what it cannot resolve
  rather than skipping it, and ``test_no_unreviewed_blind_spots`` fails when a
  new one appears.

Keys absent from the pipeline-run reports are allowed only by an entry in
``ALLOWED`` with a reason, and the entry's kind is checked against the data:
``older`` keys must be in an older report; ``unobserved`` keys must name a
producer that writes them; ``never-written`` keys say why reading them is
harmless. Entries that stop being needed fail ``test_allowlist_is_not_stale``.

Not covered, and why: the interpret container's own reads of the init payload
(``interpret-ghidra.py``, behind JSON on stdin); ``api/app/routers/evasions.py``,
which reads the report in SQL (``report_json->'evasion_analysis'...``), not
Python; the frontend (it reads the flow graph and tool results, not the
report); the stages, ioc_extract, generate-report and lamware_pipeline, which
#409 also lists (the stages call CAPE's raw report ``report`` too, so the root
name alone cannot tell the two apart, and a stage may read a key a LATER stage
writes). A report shape that changes after the fixture was built is invisible
until the fixture is rebuilt (see ``tests/report_keys.py``).
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass

import pytest

from tests.report_keys import (
    ANY,
    CONSUMERS,
    ELEM,
    ROOT,
    SHAPES,
    Shape,
    consumer_reads,
    load_shapes,
    parse_path,
    path_str,
    reduce_report,
)

_FILES = "ansible/roles/pipeline/files"
_ROLES = "ansible/roles"


@dataclass(frozen=True)
class Allowed:
    """Why a read key may be absent from every pipeline-run report."""

    kind: str          # "older" | "unobserved" | "never-written"
    reason: str
    producers: tuple[str, ...] = ()   # required for "unobserved"


def _older(reason: str) -> Allowed:
    return Allowed("older", reason)


def _unobserved(reason: str, *producers: str) -> Allowed:
    return Allowed("unobserved", reason, producers)


def _never(reason: str) -> Allowed:
    return Allowed("never-written", reason)


_PIPE = f"{_FILES}/run-pipeline.py"
_ROUTED = {  # routed analyser -> the stage module that runs it
    "office": f"{_FILES}/stages/office.py",
    "powershell": f"{_FILES}/stages/powershell.py",
    "script": f"{_FILES}/stages/script_analysis.py",
    "dotnet": f"{_FILES}/stages/dotnet.py",
    "go": f"{_FILES}/stages/go.py",
    "pyinstaller": f"{_FILES}/stages/pyinstaller.py",
    "java": f"{_FILES}/stages/java.py",
}
_RARE_TYPE = "no sample of this type in the reports the fixture was built from"

ALLOWED: dict[str, Allowed] = {
    # --- the report's own history ------------------------------------------
    "cape.error": _older("written only when CAPE submission raised; no recent run did"),
    "cape.network.tcp_connections[].src": _older(
        "pre-#479 connection shape; db_ingest keeps it for re-ingesting those rows"),
    "ghidra.analyzed_files[].error": _older("written per file only when Ghidra failed on it"),
    "dotnet_analysis.error": _older("written only when the .NET analyser failed"),
    "dotnet_analysis.extraction_source": _older(
        "written only when the .NET input came from a CAPE extraction"),
    "dotnet_analysis.extraction_source.sha256": _older("as dotnet_analysis.extraction_source"),
    "dotnet_analysis.extraction_source.source_dir": _older(
        "as dotnet_analysis.extraction_source"),
    "cape.process_activity.processes[].truncated_fields": _unobserved(
        "written only when a process name, path or command line hit its cap",
        f"{_FILES}/stages/process_activity.py"),
    "ghidra.payload_access_error": _unobserved(
        "written only when CAPE storage was unreadable (#377)", f"{_FILES}/stages/ghidra.py"),
    "volatility.error": _unobserved("written only when Volatility timed out", _PIPE),
    "office_analysis.has_macros": _unobserved(
        _RARE_TYPE, f"{_ROLES}/office-macro-analysis/templates/analyze-office.py.j2"),
    "java_analysis.analysis_success": _unobserved(_RARE_TYPE, f"{_FILES}/stages/java.py"),
    "office_analysis.analysis_success": _unobserved(_RARE_TYPE, f"{_FILES}/stages/office.py"),

    # --- one loop, several sections: each section writes one of the keys ----
    # db_ingest prices each LLM section by the first of model_used / model_final /
    # model PRESENT in it. Each section writes exactly one, so the other two are
    # read and absent by design; the first-present rule is what makes that safe.
    **{f"{section}.{key}": _never(
        f"db_ingest's model precedence loop; {section} writes "
        f"{'model' if section == 'executive_summary' else 'model_final'} instead")
       for section in ("llm_interpretation", "evasion_analysis", "visual_analysis",
                       "executive_summary")
       for key in ("model_used", "model_final", "model")
       if key != ("model" if section == "executive_summary" else "model_final")},

    # --- the eval hands run_interpret the Ghidra section ---------------------
    "ghidra.bazaar_family": _never(
        "run_interpret reads it from any init; only single-shot inits carry it, and "
        "production's Ghidra targets do not either"),
    "ghidra.analysis_type": _never(
        "absent on the main agentic pass in production too; it names the audit file "
        "tool_calls.json, which lamware_eval.rebuild expects"),

    # --- the .NET init payload rides in the Ghidra target's argument (#646) --
    # run_interpret and the eval's init_payload_for take EITHER a Ghidra target
    # or a .NET init payload; the walker maps that argument to the ghidra
    # section. These are keys of the .NET init, written by its builders.
    **{f"ghidra.{k}": _unobserved(
        ".NET init-payload key, read where run_interpret/init_payload_for receive "
        "a .NET init instead of a Ghidra target", f"{_FILES}/stages/{src}")
       for k, src in (("dotnet_mode", "dotnet_agentic.py"),
                      ("dotnet_agentic_failed", "dotnet_agentic.py"),
                      ("decompiled_source", "dotnet_agentic.py"),
                      ("source_truncated_by_analyser", "single_shot_init.py"),
                      ("source_bytes_total", "single_shot_init.py"))},
    **{f"ghidra.analyzed_files[].{k}": _never(
        "a per-program Ghidra target never carries .NET init keys; the read "
        "returns the default and the target is treated as native")
       for k in ("dotnet_mode", "dotnet_agentic_failed", "decompiled_source",
                 "source_truncated_by_analyser", "source_bytes_total")},

    # --- written since the fixture was built --------------------------------
    "ghidra.original_sample_included": _unobserved(
        "added by #666 (2026-10-03), after the shapes fixture was built; written "
        "on every native run_ghidra result", f"{_FILES}/stages/ghidra.py"),
    # What behavioural evidence the RE agent was given (#674). run-pipeline puts
    # the record into llm_interpretation.input on the three agentic branches;
    # stages/correlated_evidence.evidence_record writes its fields. given/keys/
    # bytes on a run that was given it, given/reason on one that was not.
    "llm_interpretation.input.correlated_evidence": _unobserved(
        "added by #674, after the shapes fixture was built; written on the routed-"
        "payload, .NET and native Stage 4.5 branches", _PIPE),
    **{f"llm_interpretation.input.correlated_evidence.{k}": _unobserved(
        "added by #674, after the shapes fixture was built; a field of "
        "evidence_record", f"{_FILES}/stages/correlated_evidence.py")
       for k in ("given", "keys", "bytes", "reason")},

    # Prompt-cache token counts (#718). The interpret container emits both on
    # every usage dict it returns; run_interpret, run_summarize and
    # run_plain_english pass that dict through whole into these sections.
    # db_ingest prices them. Written since the fixture was built.
    **{f"{section}.{key}": _unobserved(
        "added by #718, after the shapes fixture was built; the interpret "
        "container writes it on every usage dict it emits",
        f"{_ROLES}/interpret/files/interpret-ghidra.py")
       for section in ("llm_interpretation.usage", "executive_summary.usage",
                       "evasion_analysis.usage", "visual_analysis.usage",
                       "plain_english_usage")
       for key in ("cache_creation_input_tokens", "cache_read_input_tokens")},

    # --- run_interpret is handed ONE program's entry, not the whole section ---
    # Since #651 (routed payload) and #666 (native canonical) the agent's target is
    # an analyzed_files entry. These optional reads exist only on the whole ghidra
    # section; absent on an entry means "native, no family hint", as intended.
    "ghidra.analyzed_files[].analysis_type": _never(
        "per-program entries carry no analysis_type; run_interpret treats absence "
        "as the native agentic pass (same reason as ghidra.analysis_type)"),
    "ghidra.analyzed_files[].bazaar_family": _never(
        "per-program entries carry no bazaar_family; run_interpret sends none, "
        "as for production's whole-section Ghidra targets (ghidra.bazaar_family)"),
    "ghidra.analyzed_files[].analyzed_files": _never(
        "without_host_paths strips per-file paths from a whole section; an entry "
        "has no nested analyzed_files, so the read finds nothing to strip"),
    # The eval's order-variants (#715) reorder the init's shown lists. Variants
    # run only on native_pe / unpacked_payload inits, which are one entry; the
    # whole-section init (a pre-#697 replay) carries none and gets no variant.
    **{f"ghidra.{k}": _never(
        "lamware_eval.variants.apply_variant reads it from the init; only a "
        "per-program entry carries it, and only entries are ever reordered")
       for k in ("imports", "strings_of_interest")},

    # --- routed analysers (flow.py loops over all seven) ---------------------
    **{f"{a}_analysis": _unobserved(_RARE_TYPE, _PIPE)
       for a in ("office", "java")},
    **{f"{a}_analysis": _older(_RARE_TYPE + " recently")
       for a in ("go", "pyinstaller", "script")},
    **{f"{a}_analysis.analysis_success": _older(_RARE_TYPE + " recently")
       for a in ("go", "pyinstaller", "script")},
    **{f"ghidra.{a}_routed": _unobserved(_RARE_TYPE, _PIPE)
       for a in ("office", "powershell", "java")},
    **{f"ghidra.{a}_routed": _older(_RARE_TYPE + " recently")
       for a in ("go", "pyinstaller", "script")},
    **{f"{a}_analysis.error": _unobserved("written only when the analyser failed", stage)
       for a, stage in _ROUTED.items() if a != "dotnet"},
    # flow.py asks every routed analyser whether its input came from CAPE.
    # Only .NET records extraction_source and only PowerShell records
    # cape_extracted; for the rest, absent correctly means "from the sample".
    **{f"{a}_analysis.extraction_source": _never(
        "flow.py's CAPE-origin check; only dotnet_analysis records extraction_source")
       for a in _ROUTED if a != "dotnet"},
    **{f"{a}_analysis.cape_extracted": _never(
        "flow.py's CAPE-origin check; only powershell_analysis records cape_extracted")
       for a in _ROUTED if a != "powershell"},
}

#: Consumers that read the report. If one of these stops showing reads, the
#: walker lost track of the report there (a renamed parameter, a new wrapper),
#: and every other assertion here would pass vacuously for that file.
READS_THE_REPORT = frozenset({
    "api/app/investigate/tools.py",
    "api/app/investigate/system_prompt.py",
    "api/app/flow.py",
    f"{_FILES}/db_ingest.py",
    f"{_FILES}/lamware_eval/runner.py",
    f"{_FILES}/lamware_eval/rebuild.py",
    f"{_FILES}/lamware_eval/metrics.py",
})


@pytest.fixture(scope="module")
def shapes() -> dict[str, Shape]:
    return load_shapes()


@pytest.fixture(scope="module")
def reads():
    return consumer_reads()


def _unexplained(reads, shapes: dict[str, Shape]) -> dict[str, list[str]]:
    """Read paths no pipeline-run report has and no ALLOWED entry covers."""
    out = {}
    for path, sites in reads.reads.items():
        if shapes["current"].has(path) or path_str(path) in ALLOWED:
            continue
        out[path_str(path)] = sorted(str(s) for s in sites)
    return out


def _missing_from_every_report(reads, shapes: dict[str, Shape]) -> set[str]:
    return {path_str(p) for p in reads.reads
            if not any(s.has(p) for s in shapes.values())}


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


def test_every_read_key_is_in_a_real_report(reads, shapes):
    bad = _unexplained(reads, shapes)
    assert not bad, (
        "A consumer reads report keys that no pipeline-run report carries. Either the "
        "consumer reads a key nothing writes (#406), or the key is legitimately "
        "conditional/older and needs an ALLOWED entry with its reason:\n"
        + "\n".join(f"  {p}  <- {', '.join(s[:3])}" for p, s in sorted(bad.items())))


def test_allowed_kinds_match_the_reports(shapes):
    """An entry's kind is a claim about the data; check it against the data."""
    wrong = []
    for p, a in ALLOWED.items():
        path = parse_path(p)
        in_older = shapes["older"].has(path)
        if a.kind == "older" and not in_older:
            wrong.append(f"{p}: kind 'older' but no older report has it")
        elif a.kind in ("unobserved", "never-written") and in_older:
            wrong.append(f"{p}: kind {a.kind!r} but an older report has it; use 'older'")
        elif a.kind == "unobserved" and not a.producers:
            wrong.append(f"{p}: 'unobserved' must name the producer that writes it")
        elif a.kind not in ("older", "unobserved", "never-written"):
            wrong.append(f"{p}: unknown kind {a.kind!r}")
        if not a.reason.strip():
            wrong.append(f"{p}: no reason")
    assert not wrong, "\n".join(wrong)


def _written_keys(rel: str) -> set[str]:
    """Keys a producer file writes: dict-literal keys, subscript stores,
    ``dict(key=...)`` and ``setdefault("key", ...)``.

    Structural, and the weakest check in this module: it only confirms the
    named producer has code that writes the key, for keys no real report has
    shown yet. Container templates (.j2) are Jinja around Python; when ``ast``
    cannot parse one, the same forms are matched on comment-stripped lines.
    """
    src = (ROOT / rel).read_text()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        code = "\n".join(line.split("#", 1)[0] for line in src.splitlines())
        return set(re.findall(r"""["']([A-Za-z_]\w*)["']\s*:""", code)) | set(
            re.findall(r"""\[\s*["']([A-Za-z_]\w*)["']\s*\]\s*=(?!=)""", code))
    out: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            out |= {k.value for k in n.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        elif isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant):
                    out.add(t.slice.value)
        elif isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute)):
            fname = n.func.id if isinstance(n.func, ast.Name) else n.func.attr
            if fname == "dict":
                out |= {k.arg for k in n.keywords if k.arg}
            if fname == "setdefault" and n.args and isinstance(n.args[0], ast.Constant):
                out.add(n.args[0].value)
    return {k for k in out if isinstance(k, str)}


def test_unobserved_keys_have_a_producer_that_writes_them():
    missing = []
    for p, a in ALLOWED.items():
        if a.kind != "unobserved":
            continue
        leaf = [part for part in parse_path(p) if part != ELEM][-1]
        for rel in a.producers:
            if not (ROOT / rel).is_file():
                missing.append(f"{p}: producer {rel} does not exist")
            elif leaf not in _written_keys(rel):
                missing.append(f"{p}: {rel} has no code writing {leaf!r}")
    assert not missing, "\n".join(missing)


def test_allowlist_is_not_stale(reads, shapes):
    """An entry for a key no consumer reads any more, or that pipeline runs now
    carry, hides nothing and would hide the next real orphan of that name."""
    read = {path_str(p) for p in reads.reads}
    stale = [f"{p}: no consumer reads it" for p in ALLOWED if p not in read]
    stale += [f"{p}: pipeline-run reports carry it now" for p in ALLOWED
              if shapes["current"].has(parse_path(p))]
    assert not stale, "remove from ALLOWED:\n" + "\n".join(stale)


def test_no_unreviewed_blind_spots(reads, shapes):
    """What the walker could not follow. Both lists are empty today; a new
    entry is a read this guard cannot check, so it has to be looked at.

    A handoff of a string or number to a library call is not a blind spot
    (nothing reads a key from a string), so only object/array values count.
    """
    types = _types()
    structural_handoffs = sorted(
        f"{site} -> {callee}({path_str(path)})"
        for site, callee, path in reads.handoffs
        if types.get(path_str(path), set()) & {"object", "array"})
    dynamic = sorted(f"{site} reads {path_str(path) or '<report>'}[<non-constant>]"
                     for site, path in reads.dynamic)
    assert not structural_handoffs, (
        "report sections handed to code the guard does not follow:\n  "
        + "\n  ".join(structural_handoffs))
    assert not dynamic, "report keys read with a non-constant key:\n  " + "\n  ".join(dynamic)


def _types() -> dict[str, set[str]]:
    """Path -> JSON types seen there, across every report in the fixture."""
    data = json.loads(SHAPES.read_text())
    out: dict[str, set[str]] = {}
    for body in data["eras"].values():
        for p, t in body["paths"].items():
            out.setdefault(p, set()).update(t)
    return out


def test_the_evidence_builders_reads_are_followed(reads):
    """#674 moved ``correlated_evidence`` out of lamware_eval.runner (a consumer)
    into stages/correlated_evidence.py. Before that module was added to
    FOLLOWED, runner's two calls became handoffs of the WHOLE report, which
    ``test_no_unreviewed_blind_spots`` does not count (the report root has no
    JSON type in the fixture), and ``volatility.insights`` dropped out of the
    reads with every test here still green. Observed while making the move."""
    builder = f"{_FILES}/stages/correlated_evidence.py"
    sites = reads.reads.get(parse_path("volatility.insights"), set())
    assert any(s.file == builder for s in sites), (
        "the evidence builder's reads are not followed: add it to FOLLOWED")
    lost = sorted(str(site) for site, callee, _ in reads.handoffs
                  if callee == "correlated_evidence")
    assert not lost, f"the report is handed to correlated_evidence unfollowed: {lost}"


def test_every_consumer_that_reads_the_report_is_seen(reads):
    seen = {s.file for sites in reads.reads.values() for s in sites}
    assert set(CONSUMERS) >= READS_THE_REPORT, "READS_THE_REPORT names a non-consumer"
    lost = READS_THE_REPORT - seen
    assert not lost, f"the walker found no report reads in {sorted(lost)}: it lost the report"


# ---------------------------------------------------------------------------
# The guard catches the bugs it exists for (run against real shapes)
# ---------------------------------------------------------------------------

#: _get_api_traces as it was before #406 (b7492ab^), trimmed to its reads.
_PRE_406 = '''
def _get_api_traces(args: dict, report: dict) -> dict:
    cape = report.get("cape") or {}
    behavior = cape.get("behavior") or {}
    processes = behavior.get("processes") or []
    result = []
    for proc in processes[:10]:
        proc_name = proc.get("process_name", "") or ""
        calls = proc.get("calls") or []
        result.append({"process_name": proc_name, "pid": proc.get("pid")})
    return {"processes": result, "process_count": len(result)}
'''

#: stages/powershell.py's shape before #408: a key nothing ever set.
_PRE_408 = '''
def detect_powershell(report):
    sample_path = report["_sample_path"]
    return sample_path.endswith(".ps1")
'''


def _orphans(src: str, shapes: dict[str, Shape], roots=frozenset({"report"})) -> set[str]:
    r = consumer_reads({"consumer.py": src}, {"consumer.py": roots})
    return _missing_from_every_report(r, shapes)


def test_guard_fails_on_406(shapes):
    assert {"cape.behavior", "cape.behavior.processes",
            "cape.behavior.processes[].calls"} <= _orphans(_PRE_406, shapes)


def test_guard_fails_on_408(shapes):
    assert _orphans(_PRE_408, shapes) == {"_sample_path"}


def test_the_fixed_406_code_passes(shapes):
    fixed = _PRE_406.replace('"behavior"', '"process_activity"').replace(
        '"process_name"', '"name"').replace('proc.get("calls") or []', "[]")
    assert _orphans(fixed, shapes) == set()


# ---------------------------------------------------------------------------
# The walker: what it must follow, and what it must not invent
# ---------------------------------------------------------------------------


def _read_paths(src: str, roots=frozenset({"report"})) -> set[str]:
    r = consumer_reads({"m.py": src}, {"m.py": roots})
    return {path_str(p) for p in r.reads}


def test_walker_follows_aliases_helpers_and_loops():
    src = '''
KEYS = (("a_flag", "a_analysis"), ("b_flag", "b_analysis"))

def _dict(v):
    return v if isinstance(v, dict) else None

def _detail(key, data):
    if key == "a_analysis":
        return data.get("only_a")
    return None

def derive(report):
    r = report if isinstance(report, dict) else {}
    g = _dict(r.get("ghidra")) or {}
    for flag, key in KEYS:
        data = _dict(r.get(key))
        if g.get(flag) and data.get("ok"):
            _detail(key, data)
    files = [f for f in g.get("files") or [] if isinstance(f, dict)]
    first = next((f for f in files if f.get("x")), None)
    by = {}
    for f in files:
        by.setdefault(f.get("sha"), []).append(f)
    for rest in by.values():
        for f in rest:
            f.get("y")
    return first.get("z") if first else None
'''
    got = _read_paths(src)
    assert {"ghidra", "ghidra.a_flag", "ghidra.b_flag", "a_analysis", "b_analysis",
            "a_analysis.ok", "b_analysis.ok", "a_analysis.only_a", "ghidra.files",
            "ghidra.files[].x", "ghidra.files[].sha", "ghidra.files[].y",
            "ghidra.files[].z"} <= got
    assert "b_analysis.only_a" not in got, "the key == 'a_analysis' branch leaked into b"


def test_walker_follows_db_ingest_node_accessors():
    src = '''
class _Node:
    def __init__(self, data, path, warnings):
        self.data = data

def ingest(report):
    root = _Node(report, "", [])
    cape = root.obj("cape")
    for t in cape.items("mitre_ttps"):
        t.text("id", "")
    for t in root.obj("llm").obj("analysis").items("techniques"):
        t.text("name", "")
    if "model_final" in root.obj("llm"):
        pass
    root.items("iocs")[0].required_texts("type", "value")
    [f.data for f in root.items("cc")]
'''
    got = _read_paths(src)
    assert {"cape", "cape.mitre_ttps", "cape.mitre_ttps[].id", "llm.analysis.techniques[].name",
            "llm.model_final", "iocs[].type", "iocs[].value", "cc"} <= got
    # One loop variable reused by two loops must not cross them.
    assert "cape.mitre_ttps[].name" not in got
    assert "llm.analysis.techniques[].id" not in got


def test_walker_does_not_invent_reads():
    src = '''
import json
TABLE = {"T1055": 1}

def f(args, report):
    args.get("process")
    name = report.get("sample_name") or ""
    if ":" in name or "." in name:
        pass
    TABLE.get(report.get("tid"))
    json.dumps(report)
    other = {"k": report.get("a")}
    other.get("k")
'''
    assert _read_paths(src) == {"sample_name", "tid", "a"}


def test_walker_reports_what_it_cannot_resolve():
    src = '''
from somewhere import mystery

def f(report, key):
    report.get(key)
    mystery(report.get("cape"))
'''
    r = consumer_reads({"m.py": src}, {"m.py": frozenset({"report"})})
    assert {path_str(p) for _s, p in r.dynamic} == {""}
    assert {(c, path_str(p)) for _s, c, p in r.handoffs} == {("mystery", "cape")}


# ---------------------------------------------------------------------------
# The committed shapes hold no values
# ---------------------------------------------------------------------------


def test_reducer_keeps_keys_and_types_only():
    secret = "203.0.113.9-evil.example-5b4f596d3cf5aaaa-C:\\Users\\x\\a.exe"
    report = {
        "sample_name": secret,
        "cape": {"process_cmdlines": {"4228": secret},
                 "network": {"dns_queries": [{"domain": secret, "answers": [secret]}]},
                 "detonation": {"child_image_bases": {"1364": 4194304}}},
        "volatility": {"plugins": {"pstree": [{"Offset(V)": 1, "ImageFileName": secret}]}},
        "by_hash": {"5b4f596d3cf5aaaa": 1, "deadbeefcafe1234": 2},
    }
    shape = reduce_report(report)
    dumped = json.dumps({path_str(p): sorted(t) for p, t in shape.items()})
    for fragment in ("203.0.113", "evil", "5b4f596d", "deadbeef", "Users", "4228", "1364",
                     "Offset", "ImageFileName"):
        assert fragment not in dumped, f"{fragment!r} survived reduction"
    assert shape[("cape", "process_cmdlines", ANY)] == {"string"}
    assert shape[("cape", "network", "dns_queries", ELEM, "domain")] == {"string"}
    assert shape[("by_hash", ANY)] == {"integer"}


def test_committed_shapes_hold_no_values():
    data = json.loads(SHAPES.read_text())
    label = re.compile(r"pipeline-run-[a-z0-9]+|eval-corpus-\d\d|analyses-row-\d{4}-\d\d-\d\d")
    key = re.compile(r"[a-z_][a-z0-9_]{0,63}")
    json_types = {"object", "array", "string", "integer", "number", "boolean", "null"}
    assert set(data["eras"]) == {"current", "older"}
    for era, body in data["eras"].items():
        assert body["sources"], f"{era}: no sources"
        bad_labels = [s for s in body["sources"] if not label.fullmatch(s)]
        assert not bad_labels, f"{era}: source labels carry more than a run name: {bad_labels}"
        for p, types in body["paths"].items():
            parts = parse_path(p)
            assert all(x in (ANY, ELEM) or (key.fullmatch(x) and not re.search(r"[0-9a-f]{12}", x))
                       for x in parts), f"{era}: {p!r} has a key that is not a schema key"
            assert set(types) <= json_types, f"{era}: {p!r} carries {types}"
    # The fixture is what the guard stands on: sanity-check it is the real thing.
    current = load_shapes()["current"]
    for must in ("cape.task_id", "cape.process_activity.processes[].pid", "ghidra.analyzed_files"):
        assert current.has(parse_path(must)), f"fixture lacks {must}: rebuilt from the wrong input?"


def test_reads_resolve_against_paths_the_fixture_spells_the_same_way():
    """path_str/parse_path round-trip; a mismatch would make every read 'missing'."""
    for p in ("cape.mitre_ttps[].id", "a[][].b", "x.*.y", "top"):
        assert path_str(parse_path(p)) == p
    assert parse_path("a[][].b") == ("a", ELEM, ELEM, "b")
