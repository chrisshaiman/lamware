# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Order-variants of the init payload (#715): what moves, what must not, and replay.

Measured on the host 2026-10-05/07: reordering the imports/strings in the
agent's first message, meaning unchanged, swung amadey's technique recall
0.00-0.67 across five orderings. The ad-hoc scripts that measured it shuffled
whole lists (changing WHICH 200 of cobaltstrike's 301 imports were shown) and
copied corpus directories. These tests pin the supported replacement.

Behavioural where possible: the first message is rendered by the container's
own `build_initial_message` (imported from interpret-ghidra.py, as
test_eval_native_init_is_not_blind does), the sweep is the real `run_arm` with
only the container faked, and the replay is the real `rebuild`.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from lamware_eval import __main__ as cli
from lamware_eval import runner
from lamware_eval.arms import resolve_arm
from lamware_eval.corpus import load_corpus
from lamware_eval.rebuild import rebuild
from lamware_eval.runner import VariantNotApplicable, cell_dir_name, init_payload_for
from lamware_eval.stats import render_variant_stats
from lamware_eval.variants import (
    DEFAULT_CAPS,
    RECORD_KEYS,
    apply_variant,
    caps_from_config,
    permute_shown,
    split_variant_dir,
    variant_seed,
)
from stages.interpret import without_host_paths
from test_eval_variants_off_is_unchanged import (
    IMPORTS,
    STRINGS,
    build_corpus,
    native_report,
    patch_runner,
)

SCRIPT = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "interpret"
          / "files" / "interpret-ghidra.py")
SHA = "a" * 64
CAPS = {"imports": 6, "strings_of_interest": 4}
CFG = {"max_imports": 6, "max_strings": 4}


@pytest.fixture(scope="module")
def container():
    name = "_interpret_ghidra_715"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop(name, None)


def _section(msg: str, heading: str) -> list[str]:
    body = msg.split(f"## {heading}\n---UNTRUSTED_DATA---\n", 1)[1]
    return body.split("---END_UNTRUSTED_DATA---", 1)[0].strip().splitlines()


def _render(container, init: dict) -> str:
    return container.build_initial_message(without_host_paths(init),
                                           {**container.DEFAULT_CONFIG, **CFG})


# --- the seed ---


def test_the_seed_is_pinned_for_a_sample_and_k():
    """A literal, so an edit that changes the derivation (and silently makes
    every recorded variant unreplayable by number) fails here. Mutation-tested:
    dropping k from the key, or `.lower()`, changes these values."""
    assert variant_seed(SHA, 1) == variant_seed(SHA.upper(), 1)
    assert variant_seed(SHA, 1) == "c11c8aaf3c6a48b6"
    assert variant_seed(SHA, 2) == "ee71625f945e98f4"
    seeds = {variant_seed(SHA, k) for k in range(1, 9)}
    assert len(seeds) == 8, "k must enter the seed"
    assert variant_seed(SHA, 1) != variant_seed("b" * 64, 1), "the sample must enter the seed"


def test_the_permutation_is_the_same_in_another_process_with_another_hash_seed():
    """`hash()` is salted per process; a seed or sort key built on it would
    give a different ordering on every run. Run the derivation in two fresh
    interpreters with different PYTHONHASHSEED and compare."""
    files = Path(runner.__file__).resolve().parents[1]
    code = (f"import sys; sys.path.insert(0, {str(files)!r})\n"
            "from lamware_eval.variants import variant_seed, permute_shown\n"
            f"s = variant_seed({SHA!r}, 3)\n"
            "print(s, permute_shown(list(range(40)), 30, s, 'imports'))")
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           check=True, env={"PYTHONHASHSEED": h}).stdout
            for h in ("1", "2", "777")}
    assert len(outs) == 1, outs


# --- what moves ---


def test_only_the_first_cap_items_move_and_the_tail_stays_put():
    items = list(range(10))
    seed = variant_seed(SHA, 1)
    out = permute_shown(items, 4, seed, "imports")
    assert out[4:] == items[4:], "items past the cap must keep their place"
    assert sorted(out[:4]) == items[:4], "the shown set must not change"
    assert out[:4] != items[:4]


def test_the_cap_boundary_is_exact_across_many_seeds():
    """Mutation-tested: `items[:cap+1]` or `items[:cap-1]` as the head fails
    this for some seed; a whole-list shuffle fails it for nearly every seed."""
    items = list(range(12))
    moved: set[int] = set()
    for k in range(1, 30):
        out = permute_shown(items, 5, variant_seed(SHA, k), "strings_of_interest")
        assert set(out[:5]) == set(items[:5]), k
        assert out[5:] == items[5:], k
        moved |= {i for i in range(5) if out[i] != items[i]}
    # The LAST shown item moves too: a head of cap-1 keeps content but never
    # reorders the final shown position.
    assert moved == set(range(5))


def test_v0_is_the_init_itself():
    init = {"imports": [1, 2, 3], "strings_of_interest": ["a", "b"]}
    out, moved = apply_variant(init, None, CAPS)
    assert out is init and moved is False


def test_a_variant_never_mutates_the_init_it_was_given():
    init = {"imports": list(IMPORTS), "strings_of_interest": list(STRINGS)}
    apply_variant(init, variant_seed(SHA, 1), CAPS)
    assert init == {"imports": IMPORTS, "strings_of_interest": STRINGS}


def test_lists_too_short_to_reorder_are_recorded_as_ineffective(tmp_path):
    report = native_report()
    f = report["ghidra"]["analyzed_files"][0]
    f["imports"], f["strings_of_interest"] = ["only::one"], []
    init, modality, source, read = init_payload_for(report)
    _i0, _s0, v0 = runner._variant_of(init, modality, source, 0, None, CAPS)
    _i1, _s1, v1 = runner._variant_of(init, modality, source, 1, variant_seed(SHA, 1), CAPS)
    assert v1["variant_effective"] is False
    assert v1["input_sha"] == v0["input_sha"], "an ineffective variant is v0's input"
    assert v0["variant_effective"] is None, "v0 is the reference, not a reordering"


def test_the_default_caps_are_the_containers(container):
    """The container merges its runtime config over DEFAULT_CONFIG, so a config
    without caps gets these; the variant must permute exactly that many."""
    assert DEFAULT_CAPS == {"imports": container.DEFAULT_CONFIG["max_imports"],
                            "strings_of_interest": container.DEFAULT_CONFIG["max_strings"]}
    assert caps_from_config({}) == DEFAULT_CAPS
    assert caps_from_config(CFG) == CAPS


# --- what the agent is shown ---


def test_a_variant_shows_the_same_items_in_a_different_order(container):
    """THE property. The rendered import and string sections of every variant
    hold exactly v0's lines (same set, same truncation note) in another order.
    Mutation-tested: permuting the whole list (the host scripts' behaviour)
    changes the shown set and fails the set assertion."""
    init, modality, source, _read = init_payload_for(native_report())
    v0 = _render(container, init)
    differs = 0
    for k in range(1, 6):
        vk_init, _src, rec = runner._variant_of(init, modality, source, k,
                                                variant_seed(SHA, k), CAPS)
        vk = _render(container, vk_init)
        for heading in ("Imports", "Strings of Interest"):
            # The truncation note is inside the fence, so it is in the set too.
            assert sorted(_section(vk, heading)) == sorted(_section(v0, heading)), (k, heading)
        assert rec["variant_effective"] is True
        differs += vk != v0
    assert "[...2 more imports truncated]" in v0
    assert "[...2 more strings truncated]" in v0
    assert differs == 5, "every variant of a reorderable input must change the message"


def test_the_grounding_source_is_the_reordered_input(container):
    init, modality, source, _read = init_payload_for(native_report())
    vk_init, vk_source, _rec = runner._variant_of(init, modality, source, 1,
                                                  variant_seed(SHA, 1), CAPS)
    assert vk_source == runner.agent_visible_text(vk_init)
    assert sorted(vk_source) == sorted(source), "same content, reordered"
    assert vk_source != source


def test_dotnet_inputs_get_no_variants():
    with pytest.raises(VariantNotApplicable):
        runner._variant_of({}, "dotnet", "", 1, variant_seed(SHA, 1), CAPS)
    with pytest.raises(VariantNotApplicable):
        runner._variant_of({}, "dotnet_agentic", "", 1, variant_seed(SHA, 1), CAPS)
    # v0 of a .NET input is fine: it is the unperturbed input.
    runner._variant_of({}, "dotnet", "", 0, None, CAPS)


# --- directories ---


def test_variant_directories_round_trip():
    for name in ("qwen_10", "qwen_10+corr", "qwen_10_s42+ss+corr"):
        assert split_variant_dir(name) == (name, 0)
        for k in (1, 7, 12):
            assert split_variant_dir(f"{name}__v{k}") == (name, k)


# --- the sweep, recording, replay ---


def _sweep(tmp_path, variants=2, arms=("qwen@10", "qwen@10+corr")):
    manifest = build_corpus(tmp_path)
    samples = load_corpus(str(manifest))
    with pytest.MonkeyPatch.context() as mp:
        patch_runner(mp, runner)
        cells = cli.sweep_variants(samples, [resolve_arm(a) for a in arms],
                                   CFG, "/bin/true", "/bin/true", variants)
    return manifest, samples, cells


def test_the_sweep_writes_v0_where_it_always_was_and_variants_beside_it(tmp_path, capsys):
    _manifest, samples, cells = _sweep(tmp_path)
    assert len(cells) == 2 * 2 * 3
    for s in samples:
        dirs = sorted(p.name for p in (Path(s.corpus_dir) / "eval").iterdir())
        assert dirs == ["qwen_10", "qwen_10+corr", "qwen_10+corr__v1", "qwen_10+corr__v2",
                        "qwen_10__v1", "qwen_10__v2"]
    rec = json.loads((Path(samples[0].corpus_dir) / "eval" / "qwen_10__v2"
                      / "result.json").read_text())["input"]
    assert set(RECORD_KEYS) <= set(rec)
    assert rec["variant"] == 2 and rec["variant_seed"] == variant_seed(samples[0].sha256, 2)
    assert rec["variant_effective"] is True and rec["variant_caps"] == CAPS
    # Corpus untouched: the report on disk is still the unperturbed one.
    report = json.loads((Path(samples[0].corpus_dir) / "report.json").read_text())
    assert report == native_report()


def test_pairs_complete_before_the_next_variant_starts(tmp_path, capsys):
    """Arms are interleaved inside each variant, so an interrupted sweep leaves
    whole pairs. Mutation-tested: arm-major order fails this."""
    _m, _s, cells = _sweep(tmp_path)
    order = [(c["sample"], c["input_detail"]["variant"], c["arm"]) for c in cells]
    assert order[:6] == [(order[0][0], k, a) for k in range(3)
                         for a in ("qwen@10", "qwen@10+corr")]


def test_the_two_arms_see_the_same_input_on_the_same_variant(tmp_path, capsys):
    _m, _s, cells = _sweep(tmp_path)
    by = {(c["sample"], c["input_detail"]["variant"], c["arm"]): c["input_detail"]["input_sha"]
          for c in cells}
    for (sample, k, arm), sha in by.items():
        assert by[(sample, k, "qwen@10")] == sha
    assert len({v for (s, k, a), v in by.items() if a == "qwen@10"}) == 6


def test_rebuild_replays_the_permutation_and_scores_what_the_sweep_scored(tmp_path, capsys):
    manifest, _s, live = _sweep(tmp_path)
    md, rebuilt = rebuild(str(manifest), "r")
    key = lambda c: (c["sample"], c["input_detail"].get("variant"),  # noqa: E731
                     c["arm"] if "@" not in c["arm"] else cell_dir_name(c["arm"]))
    live_by, re_by = {key(c): c for c in live}, {key(c): c for c in rebuilt}
    assert set(live_by) == set(re_by)
    # Fields that legitimately differ between the two paths and always have:
    # the live arm name vs its directory, and the harness's clock vs the
    # container's recorded duration.
    skip = {"arm", "wall_seconds", "seed", "sampling"}
    for k, c in live_by.items():
        r = re_by[k]
        assert {f: v for f, v in c.items() if f not in skip} == \
               {f: v for f, v in r.items() if f not in skip}, k
    # And the statistics sections agree once the arm names are mapped.
    renamed = [{**c, "arm": cell_dir_name(c["arm"])} for c in live]
    assert render_variant_stats(renamed) == render_variant_stats(rebuilt)
    assert "## Paired comparison" in md


def test_rebuild_refuses_a_variant_whose_input_changed(tmp_path, capsys):
    manifest, samples, _ = _sweep(tmp_path, variants=1, arms=("qwen@10",))
    rp = Path(samples[0].corpus_dir) / "report.json"
    report = json.loads(rp.read_text())
    report["ghidra"]["analyzed_files"][0]["imports"].append("NEW::Import")
    rp.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="corpus report changed"):
        rebuild(str(manifest), "r")


DOTNET_REPORT = {
    "ghidra": {"triggered": True, "dotnet_routed": True, "analyzed_files": []},
    "dotnet_analysis": {"analysis_success": True, "analysis_type": "dotnet_ilspy",
                        "decompilation": {"source": "class L { void R() {} }"},
                        "classes": ["L"], "strings_of_interest": ["http://c2.example"]},
}


def test_a_dotnet_sample_runs_v0_only_and_the_run_goes_on(tmp_path, capsys):
    manifest = build_corpus(tmp_path)
    dot = tmp_path / "dotnet_cccccccc"
    dot.mkdir()
    (dot / "report.json").write_text(json.dumps(DOTNET_REPORT))
    data = json.loads(manifest.read_text())
    data["samples"].insert(0, {"sha256": "c" * 64, "mb_family": "agenttesla",
                               "corpus_dir": str(dot)})
    manifest.write_text(json.dumps(data))
    samples = load_corpus(str(manifest))
    with pytest.MonkeyPatch.context() as mp:
        patch_runner(mp, runner)
        cells = cli.sweep_variants(samples, [resolve_arm("qwen@10+ss")], CFG,
                                   "/bin/true", "/bin/true", 2)
    by_sample = {}
    for c in cells:
        by_sample.setdefault(c["sample"], []).append(c["input_detail"]["variant"])
    assert by_sample == {"c" * 12: [0], "a" * 12: [0, 1, 2], "b" * 12: [0, 1, 2]}
    assert "no order-variants for .NET inputs" in capsys.readouterr().out
    assert "v0 only: no .NET variants" in render_variant_stats(cells)


def test_a_v0_that_failed_before_reading_runs_no_variants(tmp_path, capsys):
    seen = []

    def run(s, a, *args, variant):
        seen.append(variant)
        raise runner.NoAnalysisData("nothing succeeded")
    samples = load_corpus(str(build_corpus(tmp_path)))[:1]
    cells = cli.sweep_variants(samples, [resolve_arm("qwen@10")], CFG, "", "", 3, run=run)
    assert seen == [0] and len(cells) == 1
    assert cells[0]["input_detail"] == {"variant": 0}


def test_the_cost_line_counts_eligible_samples_and_prior_wall_time(tmp_path, capsys):
    manifest, samples, _ = _sweep(tmp_path, variants=1, arms=("qwen@10",))
    dot = tmp_path / "dotnet_cccccccc"
    dot.mkdir()
    (dot / "report.json").write_text(json.dumps(DOTNET_REPORT))
    from lamware_eval.corpus import CorpusSample
    allsamples = [*samples, CorpusSample("c" * 64, "agenttesla", str(dot))]
    line = cli.cost_line(allsamples, [resolve_arm("qwen@10"), resolve_arm("qwen@10+corr")], 4)
    # 2 eligible samples x 2 arms x 5 + 1 .NET sample x 2 arms x 1
    assert "= 22 cells" in line
    # 4 prior cells of qwen@10 on disk at 30s each.
    assert "30s mean of 4 prior cell(s)" in line and "~0.2 h" in line


def test_a_negative_variant_count_is_refused(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["lamware_eval", "run", "--corpus", "x", "--arms",
                                      "qwen@10", "--variants", "-1"])
    with pytest.raises(SystemExit):
        cli.main()
