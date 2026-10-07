# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Order-variants of a sample's init payload (#715).

Measured on the host 2026-10-05/07: the agent's output is deterministic for an
identical first message, but reordering the `imports` / `strings_of_interest`
lists in it, meaning unchanged, swung per-sample technique recall from 0.00 to
0.67 (amadey) across five orderings. One cell per sample is therefore one draw,
and a comparison between arms has to be over a distribution of orderings,
paired by ordering. This module makes the orderings: deterministic, recorded,
and replayable by the offline re-scorer.

Three rules, each a defect the ad-hoc host scripts had:

* ONLY THE SHOWN SET MOVES. `build_initial_message` (interpret-ghidra.py) shows
  the first `max_imports` imports and `max_strings` strings and truncates the
  rest. Shuffling the whole list changes WHICH items are shown (cobaltstrike's
  301 imports: a different 200 every time), so a "reordering" changed content.
  Here the first `cap` items are permuted among themselves and the tail stays
  where it is.
* STABLE ACROSS MACHINES AND PYTHON VERSIONS. The seed is a sha256 of
  (sample sha256, k), never `hash()` (salted per process), and the permutation
  is a keyed sort on sha256, never `random.shuffle` (whose algorithm Python
  does not promise to keep).
* A VARIANT THAT CHANGED NOTHING SAYS SO. A list shorter than two cannot be
  reordered; the record carries `variant_effective: false` so the statistics do
  not count an identical input as a second draw.

`decompiled_functions` are NOT reordered in this change: they are code the
agent reads in full, not a capped list, and whether their order matters is a
separate question.
"""
import hashlib

#: Modalities whose init is rendered by `build_initial_message`, the renderer
#: the reordering is defined against. The .NET modalities (`dotnet`,
#: `dotnet_agentic`) get no variants in this change.
VARIANT_MODALITIES: tuple[str, ...] = ("native_pe", "unpacked_payload")

#: interpret-ghidra.py `DEFAULT_CONFIG`, used when the deployed interpret config
#: carries no cap. The container merges its runtime config over the same
#: defaults, so this is the cap it applies. test_eval_order_variants checks the
#: two agree.
DEFAULT_CAPS: dict[str, int] = {"imports": 200, "strings_of_interest": 100}

#: The init keys that are reordered, and the interpret config key that caps
#: each. A constant tuple rather than a loop over the caps dict so the report-key
#: guard (tests/test_report_reads_have_producers.py) can see which keys are read.
REORDERED_FIELDS: tuple[str, ...] = ("imports", "strings_of_interest")
_CAP_KEYS: dict[str, str] = {"imports": "max_imports", "strings_of_interest": "max_strings"}

#: The record fields a variant adds to a cell's input record. Listed once so
#: the live path and the replay carry exactly the same keys.
RECORD_KEYS: tuple[str, ...] = ("variant", "variant_seed", "variant_effective",
                                "variant_caps", "input_sha")


def caps_from_config(cfg: dict | None) -> dict[str, int]:
    """The shown-set caps the interpret container will apply for this config."""
    cfg = cfg or {}
    return {field: int(cfg.get(key, DEFAULT_CAPS[field])) for field, key in _CAP_KEYS.items()}


def variant_seed(sample_sha256: str, k: int) -> str:
    """The seed for variant k of a sample: 16 hex chars, the same everywhere."""
    return hashlib.sha256(f"lamware-eval-variant:{sample_sha256.lower()}:{k}"
                          .encode()).hexdigest()[:16]


def permute_shown(items: list, cap: int, seed: str, field: str) -> list:
    """`items` with its first `cap` entries reordered by `seed`, the rest in place.

    A keyed sort: each shown position gets a sha256 of (seed, field, position)
    and the positions are sorted by it. `field` is in the key so imports and
    strings are not permuted in lock-step.
    """
    head, tail = list(items[:cap]), list(items[cap:])
    order = sorted(range(len(head)),
                   key=lambda i: hashlib.sha256(f"{seed}:{field}:{i}".encode()).digest())
    return [head[i] for i in order] + tail


def apply_variant(init: dict, seed: str | None, caps: dict[str, int]) -> tuple[dict, bool]:
    """(the init with its shown lists reordered, whether anything moved).

    `seed=None` is variant 0: the init itself, unchanged. The returned dict is
    a shallow copy; the caller's init and the report it came from are never
    mutated, which is what keeps the corpus untouched.
    """
    if seed is None:
        return init, False
    out = dict(init)
    moved = False
    for field in REORDERED_FIELDS:
        items = init.get(field)
        if not isinstance(items, list):
            continue
        permuted = permute_shown(items, caps[field], seed, field)
        moved = moved or permuted != items
        out[field] = permuted
    return out, moved


def input_sha(agent_visible_text: str) -> str:
    """Short hash of what the agent was sent. Two cells with the same hash were
    the same input, and since output is deterministic, the same draw."""
    return hashlib.sha256(agent_visible_text.encode()).hexdigest()[:16]


def variant_record(k: int, seed: str | None, effective: bool | None,
                   caps: dict[str, int], visible_text: str) -> dict:
    """The fields a variant run adds to the cell's input record."""
    return {"variant": k, "variant_seed": seed, "variant_effective": effective,
            "variant_caps": dict(caps), "input_sha": input_sha(visible_text)}


def variant_dir_suffix(k: int) -> str:
    """`""` for v0 (the cell directory every existing reader knows), `__v<k>` else."""
    return f"__v{k}" if k else ""


def split_variant_dir(dirname: str) -> tuple[str, int]:
    """`qwen_10__v3` -> (`qwen_10`, 3); a v0 directory -> (name, 0)."""
    base, sep, k = dirname.rpartition("__v")
    if sep and base and k.isdigit():
        return base, int(k)
    return dirname, 0


def recorded_variant(read: dict | None) -> dict:
    """The variant fields of a recorded input, or {} for a cell run without variants."""
    return {k: read[k] for k in RECORD_KEYS if read and k in read}

