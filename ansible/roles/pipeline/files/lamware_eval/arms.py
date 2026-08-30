# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Named model/config arms for the eval harness. Each maps to an interpret cfg override."""
from dataclasses import dataclass

_LOCAL_MODEL = "local-qwen-llamacpp-re"

# Seeds exposed as pinned LiteLLM model aliases (`local-qwen-llamacpp-re-s<seed>`).
#
# MUST match litellm_llamacpp_seeds in ansible/roles/litellm/defaults/main.yml —
# an arm naming a seed with no alias behind it fails at request time with a model
# -not-found, hours into a run. test_eval_seed_arms.py enforces the two stay in sync.
#
# These values are arbitrary and exist to be REPORTED, not tuned. Running N seeds
# and keeping the best-scoring one is selection on noise: it inflates the metric and
# is the single sentence that would discredit a published result. See issue #222.
SEEDS: tuple[int, ...] = (42, 1337, 8675309)


#: Evidence the agent is given, ORTHOGONAL to the model axis (#420).
#:
#: "ghidra"     — report["ghidra"] only. What every arm has always received.
#: "correlated" — the same, plus cross_correlations, Cape behavioural signatures
#:                and Volatility insights: the evidence the platform already
#:                computes and, until now, showed only to the summary writer.
#:
#: The thesis this exists to test is "correlation before generation". Correlation
#: runs AFTER the agent in run_pipeline, so the agent has never seen a correlation
#: finding. The eval harness inherited that: run_arm passes report["ghidra"] and
#: nothing else. So the value question was never measured on the architecture the
#: project describes — a different hypothesis was.
EVIDENCE_MODES: tuple[str, ...] = ("ghidra", "correlated")


@dataclass
class Arm:
    name: str
    model: str
    re_backend: str | None  # "local" routes via the LiteLLM router; None = cloud passthrough
    max_tool_calls: int
    seed: int | None = None  # None = server default; unpinned, so runs are not reproducible
    evidence: str = "ghidra"


_REGISTRY: dict[str, Arm] = {
    "qwen@10": Arm("qwen@10", _LOCAL_MODEL, "local", 10),
    # A MEASUREMENT arm. The depth question is OPEN — do not promote this over qwen@10
    # without more n, and do not read the single completed run as settling anything.
    #
    # What one run showed (qwen@15:s1337, raccoonstealer, 3017s / 16 calls): grounded
    # 5/5 = 1.000 after the #286 scorer fix. Tempting, but qwen@10 already reaches
    # 1.000 on this same sample at THREE separate seeds, and spans 0.500-1.000 across
    # its five runs here. A single 1.000 at depth 15 sits inside that spread and is
    # not evidence of improvement.
    #
    # The signal that does look real is recall, not precision. Absolute grounded
    # findings on this sample scale with depth while the RATIO stays flat and noisy:
    #
    #     depth 10   ~3 grounded (mean of 5 runs)   ratio 0.860 (0.500-1.000)
    #     depth 15    5 grounded (n=1)              ratio 1.000
    #     depth 30    9 grounded (n=1)              ratio 0.750
    #
    # So depth may buy MORE true findings rather than better-grounded ones — which
    # matters for analyst-facing reports and not at all for triage, where qwen@10 at
    # ~14min is the operating point. n=1 at depths 15 and 30 is far too thin to act
    # on; that is what this arm exists to fix.
    #
    # It also exists because 25 does NOT fit. On 2026-08-03 qwen@25:s1337 finished its
    # tool loop in 97.6min, then was SIGKILLed at exactly 10801s with phase-2a still
    # generating, 82.5min into a single request. The killer was not depth but KV
    # prefix reuse collapsing as context grows -- measured across these two runs:
    #
    #     depth 15  ~38.6k tok ctx   5,354 tok re-evaluated   86% reuse   13.2min
    #     depth 25  ~67.6k tok ctx  35,828 tok re-evaluated   47% reuse  >82.5min
    #
    # 1.75x the context, 6.7x the re-evaluated tokens, and the eval rate degrades
    # 12.3 -> 8.2 tok/s on top. At depth 15's reuse rate, depth 25's synthesis would
    # have taken ~29min and the run would have landed at ~127min, inside the budget.
    "qwen@15": Arm("qwen@15", _LOCAL_MODEL, "local", 15),
    "qwen@25": Arm("qwen@25", _LOCAL_MODEL, "local", 25),
    # Depth probe: let the local model run to its natural stopping point rather than
    # to a budget. Local inference is $0, so the question "how deep does it go before
    # findings flatten?" is answerable here in a way it never was on a metered model.
    # NB: the cap is approximate — parallel tool calls are counted per-block after
    # increment, so a run can overshoot it.
    # 30 is the depth-probe target after the two ceilings found on 2026-07-27:
    # context (fixed by --ctx-size 65536) and then request latency (fixed by
    # streaming). Both probes died around 20-22 calls WITHOUT producing an analysis,
    # so no run has yet shown whether cycles beyond ~15 add anything. 30 is chosen to
    # clear that unknown while still being likely to COMPLETE — an incomplete run
    # answers nothing, which is the lesson of qwen@75.
    "qwen@30": Arm("qwen@30", _LOCAL_MODEL, "local", 30),
    "qwen@75": Arm("qwen@75", _LOCAL_MODEL, "local", 75),
    "claude-sonnet-5": Arm("claude-sonnet-5", "claude-sonnet-5", None, 10),
    "claude-opus-5": Arm("claude-opus-5", "claude-opus-5", None, 10),
}

# Seed-pinned variants of every local arm: `qwen@30:s42` routes to the
# `local-qwen-llamacpp-re-s42` LiteLLM alias. Registered for all local arms rather
# than a chosen few so a seeded run is always available at whatever depth is under
# test — the depth question and the variance question are independent.
#
# Two uses:
#   PAIRED COMPARISON — same seeds across arms, so shared sampling variance cancels
#     and a smaller effect is detectable at the same n. Worth roughly 3 paired runs
#     to 6-8 unpaired ones. It does NOT reduce the number of runs needed: a fixed
#     seed is one sample from a distribution, repeatable but not representative.
#   CONSENSUS — run N seeds, keep claims appearing in >= k of them.
#
# NEITHER USE WORKS. The seeds do not reach the sampler (#292): llama-server ignores
# `seed` on /v1/messages, which is the transport #285 chose because the OpenAI leg
# discarded thinking. So seeded variants of one arm are byte-identical, paired
# comparison has no shared variance to cancel, and `--consensus-k` now refuses them
# outright rather than reporting 100% agreement.
#
# The variants stay registered so existing arm names and stored result paths keep
# resolving. Prefer the unseeded name for new work; `:s42` conveys a precision that
# does not exist. Determinism is not purely a loss — it is why the noise floor is
# 0.22% and why a single-run depth difference can be trusted — but it means `n` comes
# from MORE SAMPLES, never from more seeds. #310 tracks the real independence axis.
def _register_seed_variants(registry: dict[str, Arm]) -> None:
    for base in [a for a in list(registry.values()) if a.re_backend == "local"]:
        for seed in SEEDS:
            name = f"{base.name}:s{seed}"
            registry[name] = Arm(
                name, f"{_LOCAL_MODEL}-s{seed}", "local", base.max_tool_calls, seed=seed,
                # Carried explicitly. Defaulting here would make a seeded +corr arm
                # silently ghidra-only, so the pair would stop differing and the
                # experiment would compare an arm against itself.
                evidence=base.evidence,
            )


def _register_evidence_variants(registry: dict[str, Arm]) -> None:
    """`<arm>+corr` for every arm: same model, same depth, richer evidence.

    Registered as a suffix rather than a separate arm so the pair differs in
    exactly one variable. Comparing `qwen@10` against `qwen@10+corr` is the
    experiment; comparing it against a differently-named arm would not be.

    PAIRING MATTERS MORE THAN n HERE. The local model is deterministic within a
    llama.cpp server session, so a same-sample pair has no sampling noise to
    overcome and a difference is the evidence effect. But determinism does NOT
    survive a server restart, so the two arms of a pair must run BACK TO BACK on
    each sample. Running every `ghidra` cell and then every `correlated` cell
    would put a restart between the halves and confound the only variable being
    tested — the same defect that made an earlier sweep's cells incomparable
    across restarts.
    """
    for base in [a for a in list(registry.values()) if a.evidence == "ghidra"]:
        name = f"{base.name}+corr"
        registry[name] = Arm(name, base.model, base.re_backend, base.max_tool_calls,
                             seed=base.seed, evidence="correlated")


_register_evidence_variants(_REGISTRY)
_register_seed_variants(_REGISTRY)


def registered_arms() -> list[str]:
    """Every arm name the registry knows. Public so callers that need to map a
    persisted cell directory back to its arm do not reach into `_REGISTRY`."""
    return sorted(_REGISTRY)


def resolve_arm(name: str) -> Arm:
    if name not in _REGISTRY:
        raise KeyError(f"unknown arm: {name}. Known: {sorted(_REGISTRY)}")
    return _REGISTRY[name]


def parse_arms(csv: str) -> list[Arm]:
    return [resolve_arm(n.strip()) for n in csv.split(",") if n.strip()]
