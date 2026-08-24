# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The README must not claim capabilities the code does not have (#416).

Documentation drift here is the same defect class the rest of the suite hunts — a
consumer reading a contract its producer no longer honours:

  #406  `get_api_traces` read `cape.behavior`, which nothing writes.
  #409  the general guard for consumers reading keys with no producer.
  #411  a correlation rule read a failure value as an empty result.
  README  advertised "malware family identification" while ADR-019 had measured it
          at 0/14 local and 0/7 on the frontier reference and formally retired it.

The last one sat in `main` for weeks. Nothing could have caught it, because nothing
asserted that prose matches code.

This is not a new kind of test for this repo. `test_smoke_gate_honesty.py` already
asserts that the smoke gate "must not claim readiness it has not proven";
`test_dead_controls.py` reads templates as text and asserts constructs are absent;
`test_version_consistency.py` enforces one claim across every manifest. This
generalises them to the README.

WHY IT HAS TO BE MECHANICAL. Verifying these by hand is unreliable even with the
repo checked out. While fact-checking a README rewrite on 2026-08-19, two claims
were wrongly judged false: Zeek "was not deployed" (a bad `grep --include=*` missed
`roles/pcap-analysis/templates/Containerfile.j2`, which installs it) and entropy
analysis "was not part of triage" (it is in the triage Containerfile, not
`stages/triage.py`). Both were correct claims about to be deleted as drift. A third
check found real drift the same way: the README said Volatility ran "7 plugins" when
6 are standard — 7 is the parallel WORKER count.

Matching is deliberately loose — presence of a name, not exact prose — so ordinary
editing does not fail the build. The target is claims that have become FALSE.
"""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
ARCHITECTURE = (ROOT / "ARCHITECTURE.md").read_text(encoding="utf-8")
VALIDATORS = (ROOT / "shared" / "lamware_shared" / "tool_validators.py").read_text(encoding="utf-8")
RUN_PIPELINE = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "run-pipeline.py").read_text(
    encoding="utf-8")

# Prose-only view: an "absence" assertion must not be satisfiable by the comment or
# table cell that explains the absence. Same guard test_dead_controls.py applies.
README_PROSE = "\n".join(
    ln for ln in README.splitlines() if not ln.lstrip().startswith(("<!--", "|", ">")))


def _tool_table() -> set[str]:
    r"""Backticked names in the README's `| Tool | Description |` table only.

    Scoped deliberately: a bare `^\| `name` \|` match also swept the Evaluation
    section's metrics table and reported `grounded_ratio` as an undefined Ghidra tool.
    """
    m = re.search(r"^\| Tool \| Description \|\n\|[-|]+\|\n((?:\|.*\n)+)", README, re.M)
    assert m, "the Ghidra tool table moved — update this test with it"
    return set(re.findall(r"^\| `([a-z_]+)` \|", m.group(1), re.M))


def _block(source: str, name: str) -> list[str]:
    """String literals inside a `NAME = [ ... ]` assignment."""
    m = re.search(rf"^{name}\s*=\s*\[(.*?)^\]", source, re.S | re.M)
    assert m, f"{name} block not found — the parser needs updating, not deleting"
    return re.findall(r'"([^"]+)"', m.group(1))


# --- Ghidra tool table matches the validators ------------------------------

def test_readme_ghidra_tools_all_exist():
    """A tool renamed or removed in code but left in the README table."""
    documented = _tool_table()
    real = set(re.findall(r'^\s{4}"([a-z_]+)": \{', VALIDATORS, re.M))
    assert real, "GHIDRA_ARG_VALIDATORS parse failed — fix the parser"
    undocumented_claims = documented - real
    assert not undocumented_claims, (
        f"README documents Ghidra tool(s) {sorted(undocumented_claims)} that "
        f"GHIDRA_ARG_VALIDATORS does not define")


def test_every_real_ghidra_tool_is_documented():
    documented = _tool_table()
    real = set(re.findall(r'^\s{4}"([a-z_]+)": \{', VALIDATORS, re.M))
    assert not (real - documented), (
        f"Ghidra tool(s) {sorted(real - documented)} exist but are undocumented")


def test_readme_tool_count_matches():
    """The prose says "6 Ghidra query tools"; the count must not drift from it."""
    m = re.search(r"(\d+) Ghidra query tools", README)
    assert m, "the tool-count claim moved — update this test with it"
    real = re.findall(r'^\s{4}"([a-z_]+)": \{', VALIDATORS, re.M)
    assert int(m.group(1)) == len(real), (
        f"README claims {m.group(1)} Ghidra tools; {len(real)} are defined")


# --- Volatility plugin claims ----------------------------------------------

def test_readme_volatility_plugin_count_matches():
    """Found drift when written: the README said 7, six are standard, and 7 is the
    parallel worker count. Two different numbers that look like one."""
    m = re.search(r"(\d+) standard plugins", README)
    assert m, "the Volatility plugin-count claim moved — update this test with it"
    plugins = _block(RUN_PIPELINE, "VOLATILITY_STANDARD_PLUGINS")
    assert int(m.group(1)) == len(plugins), (
        f"README claims {m.group(1)} standard Volatility plugins; "
        f"VOLATILITY_STANDARD_PLUGINS has {len(plugins)}: {plugins}")


# --- Retired capabilities stay retired -------------------------------------

#: (regex, the ADR that retired it). The regression test for the defect that
#: motivated this file.
_RETIRED = [
    (r"malware family identification", "ADR-019"),
    (r"identifies?\s+(?:the\s+)?malware family", "ADR-019"),
]


def test_retired_capabilities_are_not_advertised():
    for pattern, adr in _RETIRED:
        hit = re.search(pattern, README_PROSE, re.I)
        assert not hit, (
            f"README advertises {hit.group(0)!r}, retired by {adr}. Family labels "
            f"come from CAPE signatures or MalwareBazaar metadata and are presented "
            f"as provenance, not as an RE-stage result.")


def test_readme_still_states_who_decides_maliciousness():
    """The positive half. Deleting the disclaimer must fail as loudly as
    re-adding the claim, or the guard only works in one direction."""
    assert re.search(r"does not decide whether a sample is malicious|"
                     r"it does not decide maliciousness", README, re.I), (
        "README no longer states that the AI does not decide maliciousness")


# --- Terminology that overstates what an observation establishes ------------

#: Subjects whose description must not claim "ground truth". Deliberately NOT a blanket
#: ban on the phrase: "expert ground truth" (the MOTIF corpus) and "ground truth for
#: recall comes from CAPE detonation ... treated as a lower bound" are correct, qualified
#: uses about evaluation. What must never be called ground truth is the INJECTION
#: EXTRACTION, which is an observation of what was written.
_EXTRACTION_SUBJECT = re.compile(
    r"WriteProcessMemory|injection buffer|injected bytes|shellcode extraction", re.I)


def test_extraction_is_not_described_as_ground_truth():
    r"""`WriteProcessMemory` traces are a strong observation, not ground truth.

    The bytes are what CAPE recorded being written. That does not establish they are the
    final executable payload — which is precisely what the malfind correlation exists to
    test. Calling it "ground truth" is the same overclaim ADR-019 retired family
    attribution for.

    THIS TEST'S FIRST VERSION WAS A DEAD CONTROL, and the failure is instructive enough
    to keep on the record. It matched `ground[- ]truth\s+\w*\s*(extraction|shellcode)`
    and read README.md only. The live instance was a mermaid node reading
    "WriteProcessMemory API traces — ground truth" — the phrase TRAILS its subject, so
    the regex missed it — and the same commit that "fixed" the wording moved that
    diagram into ARCHITECTURE.md, outside the file the guard read. The guard passed, the
    claim survived, and a reviewer found it. A control that watches a proxy rather than
    the thing it protects is exactly what test_dead_controls.py exists for.

    Now: scan BOTH documents, match on the SUBJECT rather than a phrase ordering.
    """
    for name, doc in (("README.md", README), ("ARCHITECTURE.md", ARCHITECTURE)):
        for line in doc.splitlines():
            if _EXTRACTION_SUBJECT.search(line) and re.search(r"ground[- ]truth", line, re.I):
                raise AssertionError(
                    f"{name} calls injection extraction ground truth: {line.strip()!r}. "
                    f"CAPE's WriteProcessMemory observation is trace-derived — it records "
                    f"what was written, not that those bytes are the final payload.")


def test_air_gap_claim_is_scoped_to_the_detonation_network():
    """"Air-gapped" unqualified reads as "this machine has no egress", which is false —
    the LiteLLM gateway holds an outbound HTTPS path to the Anthropic API. People
    deploy malware infrastructure off README wording, so the two must not blur.
    """
    if not re.search(r"air[- ]gapped", README, re.I):
        return  # the claim is gone entirely; nothing to scope
    assert re.search(r"detonation network is air-gapped", README, re.I), (
        "README says 'air-gapped' without scoping it to the detonation network")
    assert re.search(r"analysis host is not", README, re.I), (
        "README claims an air gap without stating that the analysis host has a "
        "controlled outbound path for the LLM gateway")


# --- Documented layout exists ----------------------------------------------

def test_documented_project_structure_exists():
    """A proposed rewrite placed `lamware_eval/` at top level; it lives under
    ansible/roles/pipeline/files/. Cheap to assert, and it would have caught it."""
    block = re.search(r"```\nlamware/\n(.*?)```", README, re.S)
    assert block, "project-structure block not found — update this test with it"
    dirs = re.findall(r"^[├└]──\s+(\S+?)/", block.group(1), re.M)
    assert dirs, "project-structure parse failed — fix the parser"
    missing = [d for d in dirs if not (ROOT / d).is_dir()]
    assert not missing, f"README documents non-existent director(ies): {missing}"


# --- Language routing table matches the dispatch ---------------------------

def test_documented_analysis_stages_exist():
    """Each language path named in the README has a stage module behind it."""
    stages = ROOT / "ansible" / "roles" / "pipeline" / "files" / "stages"
    for module in ("ghidra", "dotnet", "go", "pyinstaller", "java", "office",
                   "powershell"):
        assert (stages / f"{module}.py").is_file(), (
            f"README documents a {module} analysis path with no stages/{module}.py")


# --- the central-question paragraph is about ORDER, so assert the order ------

def test_the_readme_does_not_cite_source_line_numbers():
    """A one-line edit to run-pipeline.py silently falsifies whatever paragraph
    cites a line number, and no test could notice — the number is still a number.

    This one mattered because the paragraph it appeared in describes the
    project's central open research question (#420). Both citations were still
    accurate when this test was written; the problem was that nothing kept them
    that way.
    """
    citations = re.findall(r"\bat line \d+|\bline \d{2,}\b", README_PROSE)
    assert not citations, (
        f"README cites source line numbers {citations} — cite the symbol and "
        f"assert the relationship instead, as test_correlation_runs_after_the_"
        f"investigator does")


def _call_line(source: str, func: str, callee: str) -> int:
    """Line of the first `callee(` call inside `def func`, via the parsed tree."""
    tree = ast.parse(source)
    target = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func),
        None)
    assert target is not None, f"{func} not found in run-pipeline.py"
    calls = [
        n for n in ast.walk(target)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == callee
    ]
    assert calls, f"{func} does not call {callee}"
    return min(c.lineno for c in calls)


def test_correlation_runs_after_the_investigator():
    """The claim the README makes, checked against the call order in the code
    rather than against two line numbers that happen to be written down.

    If this ever fails, #420 has been closed and the README paragraph — and the
    "central open research question" framing around it — needs rewriting, not
    the test.
    """
    interpret = _call_line(RUN_PIPELINE, "run_pipeline", "run_interpret")
    correlate = _call_line(RUN_PIPELINE, "run_pipeline", "cross_correlate")
    assert interpret < correlate, (
        f"run_interpret is called at line {interpret} and cross_correlate at "
        f"{correlate} — correlation now precedes the investigator, so the "
        f"README's 'Correlation runs after the investigator' limitation is stale")


def test_the_readme_states_that_ordering_limitation():
    assert "Correlation runs after the investigator" in README, (
        "the limitation is still true in the code; it must stay documented")


# --- the payload boundary is stated at the width it actually has -------------

def test_the_does_not_table_does_not_claim_all_cross_analysis_access_is_blocked():
    """The five database tools take an analysis_id and honour it, deliberately —
    cross-sample correlation is the point of the platform. The security-claims
    table said "Access another analysis by changing an analysis_id", which is
    the worst place to be imprecise about a boundary that does exist but is
    narrower than stated.
    """
    does_not = [
        ln.split("|")[2].strip()
        for ln in README.splitlines()
        if ln.startswith("|") and ln.count("|") >= 3
    ]
    offending = [c for c in does_not
                 if "another analysis" in c.lower() and "payload" not in c.lower()]
    assert not offending, (
        f"the does-not table claims {offending}, but the database tools accept "
        f"and honour an analysis_id — name the payload tools instead")


def test_the_payload_tools_named_in_the_readme_take_no_analysis_id():
    """The boundary the README now claims, checked against the tool schemas."""
    tools_src = (ROOT / "api" / "app" / "investigate" / "tools.py").read_text(encoding="utf-8")
    for tool in ("get_cape_payloads", "read_payload", "get_pcap_summary", "get_api_traces"):
        assert tool in README, f"{tool} is named as a boundary; keep it documented"
        m = re.search(rf'"name":\s*"{tool}".*?"input_schema":\s*\{{(.*?)\n        \}}',
                      tools_src, re.S)
        assert m, f"could not locate {tool}'s input_schema — update this test with it"
        assert "analysis_id" not in m.group(1), (
            f"{tool} now advertises an analysis_id, so the README's payload "
            f"boundary no longer holds")
