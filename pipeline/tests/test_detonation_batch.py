# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The detonation batch invariants, each of which was learned by losing data.

The host-side shell driver (runbatch.sh) already had all four corrections. None
of them were testable, so the only thing standing between the next experiment
and tasks 1132/1133 happening again was whoever remembered to copy the right
script. These tests are what makes the knowledge survive a rewrite.
"""
from pathlib import Path

import pytest
from lamware_detonate.aggregate import METRICS, stratify, summarize
from lamware_detonate.batch import (
    DONE,
    BatchResult,
    RunRecord,
    classify_poll,
    plan_submission,
    run_batch,
    verify_ran_on,
)

SAMPLE = Path("/opt/pipeline/post-rebuild-samples/quasarrat_1f2b2263/quasarrat.exe")


# --- I1: the guest is pinned -------------------------------------------------

def test_machine_is_pinned_on_every_submit():
    fields = plan_submission(SAMPLE, machine="clean")
    assert fields["machine"] == "clean"


def test_an_unpinned_batch_cannot_be_expressed():
    # kvm.conf tags BOTH clean and office as x64, so an empty machine is not a
    # harmless default -- it is the tasks 1132/1133 confound.
    with pytest.raises(ValueError, match="machine must be pinned"):
        plan_submission(SAMPLE, machine="")


# --- P1: no full-VM memory dump ---------------------------------------------

def test_no_memory_dump_is_requested():
    fields = plan_submission(SAMPLE, machine="clean")
    assert "memory" not in fields, (
        "8.6 GB per run with delete_memdump=no filled the disk and CAPE silently "
        "stopped scheduling below freespace=50000 while every service read active")


# --- I3: a stalled or failed run aborts the batch ----------------------------

def test_poll_waits_while_running_inside_the_deadline():
    assert classify_poll("running", waited_s=30, deadline_s=3600).action == "wait"


def test_reported_is_done():
    assert classify_poll(DONE, waited_s=30, deadline_s=3600).action == "done"


def test_poll_timeout_aborts_the_batch():
    d = classify_poll("running", waited_s=3600, deadline_s=3600)
    assert d.action == "abort"
    assert "office" in d.reason, "the abort must say WHY continuing is unsafe"


def test_failed_analysis_aborts_without_waiting_out_the_deadline():
    # Waiting an hour on a status that can never become "reported" burns the
    # batch window and still ends in an abort.
    d = classify_poll("failed_analysis", waited_s=5, deadline_s=3600)
    assert d.action == "abort"


# --- I4: pinning is verified, not trusted ------------------------------------

def test_machine_mismatch_is_detected():
    assert verify_ran_on({"machine": {"name": "office"}}, "clean") is not None


def test_matching_machine_passes():
    assert verify_ran_on({"machine": {"name": "clean"}}, "clean") is None


def test_bare_string_machine_shape_is_supported():
    assert verify_ran_on({"machine": "clean"}, "clean") is None


def test_unknown_machine_shape_is_a_failure_not_a_pass():
    # "we could not check" and "it checked out" must never look alike.
    #
    # Asserting merely that SOMETHING is returned is not enough: with the
    # unknown-shape branch removed, the mismatch branch still fires and returns
    # "ran on None, not 'clean' -- pinning is not holding", which sends the
    # operator to debug guest pinning when the actual fault is that CAPE's
    # report shape changed and verification is no longer possible. The reason
    # text is the part that has to be right, so the reason text is asserted.
    for info in ({}, {"machine": None}, {"machine": {}}):
        reason = verify_ran_on(info, "clean")
        assert reason is not None, f"unknown shape {info!r} must not verify"
        assert "could not determine" in reason and "refusing to assume" in reason, (
            f"unknown shape {info!r} misdiagnosed as a pinning failure: {reason!r}")


# --- I2: strictly one task in flight -----------------------------------------

def _fake_env(statuses_per_run, machines=None, tiers=None):
    """Record the exact order of external calls so sequencing can be asserted."""
    events = []
    state = {"run": 0}

    def submit(sample, fields):
        state["run"] += 1
        events.append(("submit", state["run"]))
        return 1000 + state["run"]

    # A poll budget, not just a status script. Without it, a regression that
    # stops honouring the deadline turns the suite into an infinite loop instead
    # of a failure -- and a hang and a pass are indistinguishable in CI.
    #
    # It derives from BaseException on purpose. run_batch deliberately swallows
    # `Exception` from poll_status, because a transient API error must not kill
    # an hours-long batch -- so a budget raised as AssertionError is caught by
    # the code under test and the suite hangs anyway. That is exactly what
    # happened the first time this was written.
    POLL_BUDGET = 500

    class PollBudgetExceeded(BaseException):
        pass

    def poll_status(task_id):
        seq = statuses_per_run[task_id - 1001]
        seen = len([e for e in events if e == ("poll", task_id)])
        if seen > POLL_BUDGET:
            raise PollBudgetExceeded(
                f"task {task_id} polled {seen} times without reaching a terminal "
                "decision: run_batch is no longer honouring its deadline")
        idx = min(seen, len(seq) - 1)
        events.append(("poll", task_id))
        return seq[idx]

    def fetch_report(task_id):
        events.append(("report", task_id))
        m = (machines or {}).get(task_id, "clean")
        return {"info": {"id": task_id, "machine": {"name": m}}}

    def measure(report):
        tid = report["info"]["id"]
        tier = (tiers or {}).get(tid, "CLEAN")
        return tier, {"observed_behaviour": 50, "signatures": 34,
                      "payloads_extracted": 10}, {"tier": tier}

    return events, submit, poll_status, fetch_report, measure


def _run(statuses, runs, **kw):
    events, submit, poll_status, fetch_report, measure = _fake_env(
        statuses, kw.pop("machines", None), kw.pop("tiers", None))
    clock = {"t": 0.0}

    def now():
        return clock["t"]

    def sleep(s):
        clock["t"] += s

    res = run_batch(sample=SAMPLE, machine="clean", runs=runs, submit=submit,
                    poll_status=poll_status, fetch_report=fetch_report,
                    measure=measure, sleep=sleep, now=now, log=lambda m: None, **kw)
    return res, events


def test_never_two_tasks_in_flight():
    res, events = _run([["running", DONE], ["running", DONE], ["running", DONE]], runs=3)
    assert not res.aborted
    submits = [i for i, e in enumerate(events) if e[0] == "submit"]
    # Between consecutive submits there must be a completed poll+report for the
    # PREVIOUS task. Two submits back to back is the concurrency bug.
    for a, b in zip(submits, submits[1:]):
        between = events[a + 1:b]
        assert ("report", 1000 + events[a][1]) in between, (
            f"run {events[a][1]} was not verified before the next submit: {between}")


def test_abort_stops_every_further_submission():
    # Run 2 never reaches a terminal state; the batch must not start run 3.
    res, events = _run([["running", DONE], ["running"], ["running", DONE]],
                       runs=3, deadline_s=100.0)
    assert res.aborted
    assert len([e for e in events if e[0] == "submit"]) == 2, (
        "a stalled run must abort the batch, not be skipped past -- skipping is "
        "how two tasks ended up in flight on two different machines")


def test_a_run_on_the_wrong_machine_aborts_the_batch():
    res, events = _run([["running", DONE], ["running", DONE]], runs=2,
                       machines={1002: "office"})
    assert res.aborted
    assert "office" in res.abort_reason
    assert len([e for e in events if e[0] == "submit"]) == 2


def test_aborted_batch_keeps_the_runs_it_did_complete():
    res, _ = _run([["running", DONE], ["running"]], runs=2, deadline_s=100.0)
    assert len(res.completed) == 1


# --- the #518 lesson: pooling across tiers is the artefact -------------------

def _rec(i, tier, observed):
    return RunRecord(index=i, task_id=1000 + i, status=DONE, machine="clean",
                     tier=tier, metrics={"observed_behaviour": observed,
                                         "signatures": observed - 10,
                                         "payloads_extracted": 5})


def test_stratify_separates_tiers_in_a_stable_order():
    runs = [_rec(1, "PARTIAL", 45), _rec(2, "CLEAN", 54), _rec(3, "CLEAN", 53)]
    assert list(stratify(runs)) == ["CLEAN", "PARTIAL"]


def test_pooled_is_not_a_measurement_when_tiers_are_mixed():
    res = BatchResult(runs=[_rec(1, "CLEAN", 54), _rec(2, "ALL-LOST", 26)])
    s = summarize(res)
    assert s["pooled_is_a_measurement"] is False
    assert "NOT a measurement" in s["pooled_caveat"]
    # And the strata must actually be separated, not just flagged.
    assert s["tiers"]["CLEAN"]["observed_behaviour"]["mean"] == 54
    assert s["tiers"]["ALL-LOST"]["observed_behaviour"]["mean"] == 26


def test_pooled_is_a_measurement_within_one_tier():
    res = BatchResult(runs=[_rec(1, "CLEAN", 54), _rec(2, "CLEAN", 53)])
    assert summarize(res)["pooled_is_a_measurement"] is True


def test_sd_is_none_at_n_of_one_not_zero():
    res = BatchResult(runs=[_rec(1, "CLEAN", 54)])
    st = summarize(res)["tiers"]["CLEAN"]["observed_behaviour"]
    assert st["n"] == 1 and st["sd"] is None, (
        "sd=0.0 at n=1 reads as perfect reproducibility from a sample size that "
        "cannot support any claim about spread")


def test_every_stratified_metric_is_reported_per_tier():
    res = BatchResult(runs=[_rec(1, "CLEAN", 54), _rec(2, "PARTIAL", 45)])
    for tier in ("CLEAN", "PARTIAL"):
        for m in METRICS:
            assert m in summarize(res)["tiers"][tier]


# --- the deploy boundary -----------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]


def test_every_lamware_detonate_module_is_in_the_deploy_loop():
    """Cross-copy drift guard, same shape as lamware_eval's.

    The Ansible copy loop is enumerated rather than a glob, so a new module is
    silently left behind on the host: the code merges, CI stays green, and the
    gap surfaces as an ImportError partway through a multi-hour batch. rebuild.py
    shipped in #189 and was missed exactly this way.
    """
    pkg = ROOT / "ansible" / "roles" / "pipeline" / "files" / "lamware_detonate"
    tasks = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text()
    missing = [p.name for p in sorted(pkg.glob("*.py")) if f"- {p.name}" not in tasks]
    assert not missing, (
        f"lamware_detonate modules exist but are never deployed: {missing}. "
        f"Add them to the copy loop in roles/pipeline/tasks/main.yml.")


def test_the_install_directory_is_created_before_files_are_copied():
    """copy: does not create a missing parent dir with the right mode/owner.

    Without the file: task the package lands (or fails to) under whatever
    permissions happen to exist, and the pipeline user cannot import it.
    """
    tasks = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text()
    assert '- "{{ pipeline_install_dir }}/lamware_detonate"' in tasks
