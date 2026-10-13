# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""PowerShell layers are unwrapped statically, and a failure says so (#766).

PSDecode was never installed in the image, so every PowerShell analysis took
the fallback path while reporting success, and the RE agent was told
"PSDecode: failed (fallback decode)" for months. It also has no licence. The
replacement is minusone (static, MIT) plus a small driver that follows
`iex "<script>"`, `"<script>" | iex`, `[ScriptBlock]::Create(...)` and
`-EncodedCommand`. minusone itself runs in the image; here it is replaced by a
stub so the driver's own logic is what is tested.
"""
import base64
import importlib.machinery
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "ansible" / "roles" / "powershell-analysis"
SCRIPT = ROLE / "templates" / "analyze-powershell.py.j2"


@pytest.fixture(scope="module")
def aps():
    # A .j2 suffix has no default loader; the file is plain Python (no Jinja).
    loader = importlib.machinery.SourceFileLoader("_aps", str(SCRIPT))
    spec = importlib.util.spec_from_loader("_aps", loader)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def u16(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


@pytest.mark.parametrize("src,start,value", [
    ('"a `"b`" c"', 0, 'a "b" c'),
    ('"a ""b"" c"', 0, 'a "b" c'),
    ("'it''s'", 0, "it's"),
    ('"tab`tend"', 0, "tab\tend"),
])
def test_powershell_string_literals_are_read_with_their_escapes(aps, src, start, value):
    assert aps._read_ps_string(src, start)[0] == value


def test_an_unterminated_literal_is_not_a_layer(aps):
    assert aps._read_ps_string('"never closed', 0) is None


@pytest.mark.parametrize("text,nxt", [
    ('iex "Write-Host 1"', "Write-Host 1"),
    ("Invoke-Expression ('Write-Host 2')", "Write-Host 2"),
    ('"Write-Host 3" | iex', "Write-Host 3"),
    ("'Write-Host 4' | Invoke-Expression", "Write-Host 4"),
    ('[ScriptBlock]::Create("Write-Host 5").Invoke()', "Write-Host 5"),
    (f"powershell -nop -enc {u16('Write-Host 6')}", "Write-Host 6"),
    (f"pwsh -EncodedCommand {u16('Write-Host 7')}", "Write-Host 7"),
    (f"powershell -e {u16('Write-Host 8')}", "Write-Host 8"),
])
def test_each_layer_form_yields_the_next_script(aps, text, nxt):
    assert aps._next_layer(text) == nxt


def test_a_plain_script_has_no_next_layer(aps):
    assert aps._next_layer('Write-Host "done"; Start-Sleep 1') is None


def _identity(monkeypatch, aps, calls=None):
    def fake(text):
        if calls is not None:
            calls.append(text)
        return text, None
    monkeypatch.setattr(aps, "_minusone", fake)


def test_nested_layers_are_followed_to_the_innermost(aps, monkeypatch):
    _identity(monkeypatch, aps)
    inner = "Write-Host 'innermost'"
    mid = f'iex "{inner}"'
    outer = f"powershell -enc {u16(mid)}"
    layers, err = aps._deobfuscate(outer)
    assert err is None
    assert layers == [outer, mid, inner]


def test_a_cycle_between_layers_stops_when_a_layer_repeats(aps, monkeypatch):
    """A -> B -> A must stop at the repeat, not run to MAX_LAYERS."""
    _identity(monkeypatch, aps)
    nxt = {"A": "B", "B": "A"}
    monkeypatch.setattr(aps, "_next_layer", lambda text: nxt.get(text.strip()))
    layers, err = aps._deobfuscate("A")
    assert err is None
    assert layers == ["A", "B", "A"], layers
    assert len(layers) < aps.MAX_LAYERS


def test_an_unbounded_chain_stops_at_max_layers(aps, monkeypatch):
    calls = []
    _identity(monkeypatch, aps, calls)
    script = "Write-Host end"
    for i in range(aps.MAX_LAYERS + 5):
        script = f"powershell -enc {u16(script + ' #' + str(i))}"
    layers, _ = aps._deobfuscate(script)
    assert len(layers) == aps.MAX_LAYERS == len(calls)


def test_a_first_layer_failure_is_reported_not_hidden(aps, monkeypatch):
    monkeypatch.setattr(aps, "_minusone", lambda t: (None, "minusone timed out after 30s"))
    layers, err = aps._deobfuscate("iex 'x'")
    assert layers is None and "timed out" in err


def test_a_deeper_failure_keeps_the_layers_reached(aps, monkeypatch):
    seen = []

    def fake(text):
        seen.append(text)
        return (text, None) if len(seen) == 1 else (None, "boom")
    monkeypatch.setattr(aps, "_minusone", fake)
    layers, err = aps._deobfuscate('iex "Write-Host deep"')
    assert err is None and layers == ['iex "Write-Host deep"']


def test_the_report_names_the_deobfuscator_and_its_outcome(aps, monkeypatch, tmp_path):
    monkeypatch.setattr(aps, "_minusone", lambda t: (None, "minusone could not run: no module"))
    f = tmp_path / "s.ps1"
    f.write_text("Write-Host hi")
    r = aps.analyze_powershell(str(f))
    assert r["deobfuscator"].startswith("minusone")
    assert r["deobfuscation_success"] is False and "could not run" in r["deobfuscation_error"]
    assert not any(k.startswith("psdecode") for k in r), "the PSDecode fields described a tool never installed"


def test_nothing_reads_the_old_psdecode_fields():
    roots = [ROOT / "ansible" / "roles", ROOT / "api" / "app"]
    hits = []
    for root in roots:
        for p in list(root.rglob("*.py")) + list(root.rglob("*.py.j2")):
            if re.search(r"""["']psdecode_(success|error)["']""", p.read_text(errors="replace")):
                hits.append(str(p.relative_to(ROOT)))
    assert not hits, hits


def test_the_image_verifies_the_wheel_and_ships_the_licence():
    cf = (ROLE / "templates" / "Containerfile.j2").read_text()
    code = "\n".join(ln for ln in cf.splitlines() if not ln.lstrip().startswith("#"))
    assert "Install-Module" not in code and "PSGallery" not in code
    assert "hashlib.sha256" in code and "/tmp/requirements.lock" in code
    assert "COPY minusone-LICENSE /usr/share/doc/pyminusone/LICENSE" in code
    assert (ROLE / "files" / "minusone-LICENSE").read_text().startswith("MIT License")
