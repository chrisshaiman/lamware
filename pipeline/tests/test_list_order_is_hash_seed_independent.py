# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The same input must give the same lists in every process (#689).

Lists built as `list(set(...))` iterate in an order that follows str hash
randomisation, and PYTHONHASHSEED is random per process. On the host the
stored `volatility.insights.mutexes[].unique_processes` differed from a
recomputation on 13 of 13 reports, and re-scanning real CAPE payloads gave
`shellcode_artifacts.file_paths` / `.dll_names` in a different order on two
runs out of two. Since #680 these lists reach the RE agent's
correlated_evidence, and the agent is byte-deterministic for fixed input, so
the order was a per-run perturbation of what it was shown.

The property is about separate interpreters, so it is tested in separate
interpreters: each check runs the real function in child processes under
different PYTHONHASHSEED values and compares the serialised output. A
same-process test cannot see this bug — every call in one process shares a
seed.
"""
import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

from stages.volatility import artifacts_from_bytes, extract_volatility_insights

PIPELINE_FILES = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline" / "files"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
RM630 = FIXTURES / "volatility_plugins_rm630.json"

# Six seeds: under the old code six of six gave six different orders for each
# list below, so agreement here is not luck of a seed pair.
SEEDS = ("0", "1", "2", "3", "4", "5")

ARTIFACT_KEYS = ("file_paths", "dll_names", "urls", "ip_addresses", "registry_keys")
CAPS = {"file_paths": 20, "dll_names": 20, "urls": 20, "ip_addresses": 20, "registry_keys": 10}


def _region(n: int) -> bytes:
    """`n` distinct values of each artifact kind, each occurring twice, in a
    fixed interleaved order that is neither sorted nor reverse-sorted — so
    first-seen order, sorted order and set order are three different lists."""
    order = [(i * 7) % n for i in range(n)]  # a permutation: n is coprime with 7
    parts = []
    for _ in range(2):
        for i in order:
            parts += [f"C:\\Users\\u\\AppData\\f{i:02d}.exe",
                      f"mod{i:02d}x.dll",
                      f"http://h{i:02d}.example/p",
                      f"10.1.0.{i + 1}",
                      f"HKEY_CURRENT_USER\\Software\\k{i:02d}"]
    return "\x00".join(parts).encode()


# Child program: run the function on fixed input, print the result as JSON.
CHILD = r"""
import contextlib, io, json, sys
sys.path.insert(0, sys.argv[1])
from stages.volatility import artifacts_from_bytes, extract_volatility_insights
which = sys.argv[2]
if which == "artifacts":
    data = open(sys.argv[3], "rb").read()
    out = artifacts_from_bytes(data)
else:
    plugins = json.load(open(sys.argv[3], encoding="utf-8"))
    with contextlib.redirect_stdout(io.StringIO()):
        out = extract_volatility_insights(plugins)
print(json.dumps(out))
"""


def _run_under_seeds(which: str, input_path: Path) -> dict[str, str]:
    outs = {}
    for seed in SEEDS:
        env = {**os.environ, "PYTHONHASHSEED": seed}
        r = subprocess.run([sys.executable, "-c", CHILD, str(PIPELINE_FILES), which,
                            str(input_path)],
                           capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr
        outs[seed] = r.stdout
    return outs


def _assert_one_output(outs: dict[str, str]) -> None:
    distinct = set(outs.values())
    assert len(distinct) == 1, (
        f"{len(distinct)} different outputs from {len(outs)} hash seeds: "
        + "; ".join(f"seed {s}: {o[:200]}" for s, o in outs.items()))


# ---------------------------------------------------------------------------
# shellcode_artifacts: file_paths, dll_names, urls, ip_addresses, registry_keys
# ---------------------------------------------------------------------------

def test_shellcode_artifacts_are_identical_under_every_hash_seed(tmp_path):
    for n in (8, 30):  # under every cap, and over every cap
        region = tmp_path / f"region{n}.bin"
        region.write_bytes(_region(n))
        outs = _run_under_seeds("artifacts", region)
        _assert_one_output(outs)
        found = json.loads(next(iter(outs.values())))
        # Guard on the guard: every list the fix touches is present and has
        # more than one entry, so a single fixed order was possible to miss.
        for key in ARTIFACT_KEYS:
            assert len(found[key]) > 1, key


def test_under_the_cap_the_contents_are_what_the_old_code_returned():
    """Only the order changed: the same distinct values, no more, no fewer.
    The old expression is reproduced here as the specification."""
    found = artifacts_from_bytes(_region(8))
    text = _region(8).decode("ascii")
    from stages.volatility import _IP_RE, _PATH_RE, _URL_RE, _dll_names, _registry_keys
    old = {
        "file_paths": list(set(_PATH_RE.findall(text)))[:20],
        "dll_names": list(set(d for d in _dll_names(text) if len(d) > 5))[:20],
        "urls": list(set(_URL_RE.findall(text)))[:20],
        "ip_addresses": list(set(_IP_RE.findall(text)))[:20],
        "registry_keys": list(set(_registry_keys(text)))[:10],
    }
    for key, old_list in old.items():
        assert len(found[key]) == len(old_list) == 8, key
        assert set(found[key]) == set(old_list), key


def test_the_order_is_first_occurrence_in_the_region():
    found = artifacts_from_bytes(_region(8))
    expected_order = [(i * 7) % 8 for i in range(8)]
    assert found["file_paths"] == [f"C:\\Users\\u\\AppData\\f{i:02d}.exe" for i in expected_order]
    assert found["dll_names"] == [f"mod{i:02d}x.dll" for i in expected_order]
    assert found["registry_keys"] == [f"HKEY_CURRENT_USER\\Software\\k{i:02d}"
                                      for i in expected_order]
    # Deliberately not sorted: sorting would be the other deterministic choice,
    # and the region order is the one pe_offsets/interesting_strings use.
    assert found["file_paths"] != sorted(found["file_paths"])


def test_over_the_cap_the_first_occurrences_are_kept():
    """Past the cap the old code kept a seed-dependent subset. The new one keeps
    the first `cap` distinct values in region order — still a subset of what was
    found, still exactly `cap` long."""
    found = artifacts_from_bytes(_region(30))
    order = [(i * 7) % 30 for i in range(30)]
    for key, cap in CAPS.items():
        assert len(found[key]) == cap, key
        assert len(set(found[key])) == cap, key
    assert found["file_paths"] == [f"C:\\Users\\u\\AppData\\f{i:02d}.exe" for i in order[:20]]
    assert found["registry_keys"] == [f"HKEY_CURRENT_USER\\Software\\k{i:02d}"
                                      for i in order[:10]]


# ---------------------------------------------------------------------------
# volatility.insights.mutexes[].unique_processes
# ---------------------------------------------------------------------------

def _mutex_plugins() -> dict:
    """Eight distinct processes and a null one holding one mutex."""
    rows = [{"Name": "\\BaseNamedObjects\\m1", "Type": "Mutant", "PID": i,
             "Process": f"p{(i * 5) % 8}.exe"} for i in range(8)]
    rows.append({"Name": "\\BaseNamedObjects\\m1", "Type": "Mutant", "PID": 99,
                 "Process": None})
    return {"handles": rows}


def test_unique_processes_are_identical_under_every_hash_seed(tmp_path):
    synthetic = tmp_path / "handles.json"
    synthetic.write_text(json.dumps(_mutex_plugins()), encoding="utf-8")
    for plugins in (synthetic, RM630):  # constructed, and real handles output
        outs = _run_under_seeds("insights", plugins)
        _assert_one_output(outs)
        mutexes = json.loads(next(iter(outs.values())))["mutexes"]
        assert any(len(m["unique_processes"]) > 1 for m in mutexes), plugins


def test_unique_processes_hold_the_same_processes_sorted_with_null_last():
    plugins = _mutex_plugins()
    with contextlib.redirect_stdout(io.StringIO()):
        m = extract_volatility_insights(plugins)["mutexes"][0]
    assert m["unique_processes"] == [f"p{i}.exe" for i in range(8)] + [None]
    # Same contents the old list({...}) produced.
    assert set(m["unique_processes"]) == {r["Process"] for r in plugins["handles"]}
