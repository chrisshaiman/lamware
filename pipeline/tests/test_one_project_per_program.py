# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every program Ghidra analyses gets its own project, and every one is checked (#655).

Each headless run begins with "Creating project", which wipes whatever is in the
output directory's project. Loaders that shared a directory therefore kept only
their last program, while the report listed every one with a function count:

    shellcode loader, shellcode_0_unknown   269 programs in 101 analyses  (#648)
    PE loader,        output_dir/project     36 programs in 14 analyses   (#655)

#648 fixed one loader. The rule these tests hold for both, and for any loader
added later: a program's project directory is named by its content hash, and
after Stage 4 every program claiming success is checked against its project's
own index, with the result recorded as ``in_project``.
"""
import ast
import hashlib
from pathlib import Path

import pytest
from stages import ghidra

FLOW = Path(__file__).resolve().parents[2] / "api/app/flow.py"


def _sha12(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


@pytest.fixture
def loaders(monkeypatch):
    """Record the output directory each loader is handed; analyse nothing."""
    seen = []

    def fake_pe(pe_path, output_dir, ghidra_cmd):
        seen.append(("pe", Path(pe_path).read_bytes(), Path(output_dir)))
        return {"analysis_success": True, "functions_count": 10,
                "program_name": Path(pe_path).name, "project_dir": "/output/project",
                "host_output_dir": str(output_dir)}

    def fake_sc(candidate, output_dir, ghidra_cmd):
        data = Path(candidate["path"]).read_bytes()
        out = output_dir / f"shellcode_0_unknown_{ghidra._content_token(candidate)}"
        seen.append(("shellcode", data, out))
        return {"source": "cape_payload", "analysis_success": True, "functions_count": 5,
                "program_name": candidate["sha256"], "project_dir": "/output/project",
                "host_output_dir": str(out)}

    monkeypatch.setattr(ghidra, "run_ghidra_on_file", fake_pe)
    monkeypatch.setattr(ghidra, "run_ghidra_shellcode", fake_sc)
    monkeypatch.setattr(ghidra, "make_ghidra_verifier", lambda _c: (lambda *_a: None))
    return seen


def _pes(tmp_path, monkeypatch, *contents):
    paths = []
    for i, data in enumerate(contents):
        p = tmp_path / f"dropped{i}.exe"
        p.write_bytes(data)
        paths.append(p)
    monkeypatch.setattr(ghidra, "discover_pe_files", lambda *_a, **_k: (paths, None))
    return paths


def _run(tmp_path, candidates=None):
    return ghidra.run_ghidra({"id": 1}, tmp_path / "out", tmp_path / "s.bin", "ghidra",
                             get_cape_signatures_fn=lambda d: [],
                             shellcode_candidates=candidates, include_original=False)


def test_two_dropped_pes_get_two_projects(tmp_path, monkeypatch, loaders):
    """formbook v651b: 8c38731c and a314d770 shared output_dir/project; one survived."""
    _pes(tmp_path, monkeypatch, b"MZ" + b"\x01" * 600, b"MZ" + b"\x02" * 600)
    _run(tmp_path)
    dirs = [d for kind, _, d in loaders if kind == "pe"]
    assert len(dirs) == 2 and dirs[0] != dirs[1], dirs
    assert dirs[0] != tmp_path / "out", "a PE still writes to the shared output_dir"


def test_every_loader_names_its_directory_by_content(tmp_path, monkeypatch, loaders):
    """The class, not the instance: whatever loader ran, the directory carries
    the hash of the bytes it analysed, so different programs never collide."""
    a, b = b"MZ" + b"\x03" * 600, b"MZ" + b"\x04" * 600
    _pes(tmp_path, monkeypatch, a, b)
    payload = tmp_path / "p.bin"
    payload.write_bytes(b"\x90" * 2048)
    cand = {"source": "cape_payload", "path": payload, "analyze_with_ghidra": True,
            "sha256": hashlib.sha256(payload.read_bytes()).hexdigest()}
    _run(tmp_path, [cand])
    assert {k for k, _, _ in loaders} == {"pe", "shellcode"}
    for kind, data, out in loaders:
        assert out.name.endswith(_sha12(data)), (kind, out)
    assert len({out for _, _, out in loaders}) == len(loaders)


def _project(root: Path, *names: str) -> Path:
    idata = root / "project" / "analysis.rep" / "idata"
    idata.mkdir(parents=True)
    lines = ["VERSION=1", "/"] + [f"  0000000{i}:{n}:7f00{i}" for i, n in enumerate(names)]
    (idata / "~index.dat").write_text("\n".join(lines + ["NEXT-ID:9", "MD5:x"]) + "\n")
    return root


def test_presence_is_recorded_for_every_program(tmp_path):
    shared = _project(tmp_path / "shared", "kept")
    files = [
        {"analysis_success": True, "program_name": "kept", "functions_count": 163,
         "host_output_dir": str(shared)},
        {"analysis_success": True, "program_name": "erased", "functions_count": 7,
         "host_output_dir": str(shared)},
        {"analysis_success": True, "program_name": "nowhere", "functions_count": 3,
         "host_output_dir": str(tmp_path / "no-project-here")},
        {"analysis_success": False, "program_name": "failed"},
    ]
    warnings = ghidra.record_project_presence(files, tmp_path)
    assert [f.get("in_project") for f in files] == [True, False, None, None]
    assert len(warnings) == 1 and warnings[0].startswith("Ghidra: erased claims 7 functions")


def test_the_warning_is_one_the_flow_view_reads(tmp_path):
    """api/app/flow.py marks a program lost by matching the verifier's wording.
    The presence check must emit the same, or the view keeps showing it loaded.
    Matched against what record_project_presence actually returns."""
    import re
    tree = ast.parse(FLOW.read_text())
    pattern = next(ast.literal_eval(n.value.args[0]) for n in ast.walk(tree)
                   if isinstance(n, ast.Assign)
                   and any(getattr(t, "id", "") == "_LOST_RE" for t in n.targets))
    root = _project(tmp_path / "p", "a314d7708b70a681")
    files = [{"analysis_success": True, "program_name": "8c38731c203b0743abcdef",
              "functions_count": 7, "host_output_dir": str(root)}]
    (warning,) = ghidra.record_project_presence(files, tmp_path)
    m = re.match(pattern, warning)
    assert m, warning
    assert m.group(1) == "8c38731c203b0743"


def test_a_missing_program_is_never_handed_to_the_agent(tmp_path):
    """Even when the Ghidra verifier cannot answer (None), a program the index
    says is absent must not be chosen: every tool call against it fails."""
    root = _project(tmp_path / "p", "small")
    files = [
        {"analysis_success": True, "program_name": "big", "functions_count": 4064,
         "project_dir": "/output/project", "host_output_dir": str(root), "in_project": False},
        {"analysis_success": True, "program_name": "small", "functions_count": 163,
         "project_dir": "/output/project", "host_output_dir": str(root), "in_project": True},
    ]
    _, name = ghidra.propagate_project_dir(files, tmp_path, verify=lambda *_: None)
    assert name == "small"


def test_payload_selection_skips_a_missing_program():
    files = [{"source": "cape_payload", "analysis_success": True, "functions_count": 377,
              "program_name": "fb", "project_dir": "/r/fb/project",
              "cape_type": "Formbook Payload", "in_project": False}]
    data = {"dotnet_routed": True, "program_name": "fb", "project_dir": "/r/fb/project",
            "analyzed_files": files}
    assert ghidra.select_payload_target(data, verify=lambda *_: True) == (None, None)


def test_run_ghidra_records_presence_and_warns(tmp_path, monkeypatch):
    """End to end: a PE whose project lacks it is marked and reported by
    run_ghidra itself, not only when the helper is called directly."""
    def fake_pe(pe_path, output_dir, ghidra_cmd):
        name = Path(pe_path).name
        # The second PE's project is written without it: the #655 state.
        stored = name if name.endswith("0.exe") else "something-else"
        _project(Path(output_dir), stored)
        return {"analysis_success": True, "functions_count": 10, "program_name": name,
                "project_dir": "/output/project", "host_output_dir": str(output_dir)}

    monkeypatch.setattr(ghidra, "run_ghidra_on_file", fake_pe)
    monkeypatch.setattr(ghidra, "make_ghidra_verifier", lambda _c: (lambda *_a: None))
    _pes(tmp_path, monkeypatch, b"MZ" + b"\x05" * 600, b"MZ" + b"\x06" * 600)
    out = _run(tmp_path)
    marks = {f["program_name"]: f.get("in_project") for f in out["analyzed_files"]}
    assert marks == {"dropped0.exe": True, "dropped1.exe": False}, marks
    assert any(w.startswith("Ghidra: dropped1.exe claims") for w in out["analysis_warnings"])
    assert out.get("program_name") == "dropped0.exe", "a missing program was chosen"
