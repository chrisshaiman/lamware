# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Drive N sequential detonations of ONE sample and record the tier of each.

FOUR INVARIANTS. Each is here because breaking it destroyed real measurements,
and each is a pure function so a test can prove it still holds (the host-side
shell driver had all four and none of them were testable).

  I1  machine is PINNED on every submit.
      kvm.conf has `machines = clean,office` and BOTH are tagged x64. office is
      a different guest -- host-passthrough CPU instead of the pinned custom
      model, plus Office installed. Unpinned, CAPE falls through to it whenever
      the queue backs up. Tasks 1132/1133 landed there and were discarded.

  I2  never submit while a task is outstanding.
      An earlier driver skipped ahead on a poll timeout, so two tasks were in
      flight and CAPE ran them on both machines CONCURRENTLY -- destroying the
      "sequential, idle host" condition the whole measurement rests on.

  I3  a poll timeout or a failed status ABORTS the batch.
      Continuing past one produces a batch whose runs were taken under two
      different conditions, which is unpoolable and looks fine.

  I4  every completed run is VERIFIED to have run on the pinned machine.
      A pinned parameter that silently stops being honoured is the exact failure
      this project keeps finding. Checked, not trusted.

And one prohibition:

  P1  `memory` is NEVER submitted.
      It is a host-side full-VM RAM dump taken AFTER analysis ends, so it cannot
      affect the in-guest instrumentation race this measures -- but at 8.6 GB a
      run, with delete_memdump=no and Volatility processing off, 8 runs filled
      the disk and CAPE silently stopped scheduling below freespace=50000 while
      every service still reported active.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# Shared with the production submit path on purpose. When each carried its own
# copy, only this one pinned the guest and verified the pin.
from lamware_pipeline.cape_guest import MACHINE_REQUIRED, verify_ran_on  # noqa: F401

# CAPE task states that will never become "reported" no matter how long we wait.
TERMINAL_FAILURES = ("failed_analysis", "failed_processing")
DONE = "reported"


def plan_submission(sample: Path, machine: str, package: str = "exe",
                    timeout_s: int = 200, options: str = "procmemdump=1,procdump=1") -> dict:
    """The exact form fields for one submission.

    Pure so I1 and P1 can be asserted directly instead of inferred from a curl
    line. `machine` is not defaulted -- an unpinned batch must be impossible to
    express, not merely discouraged.
    """
    if not machine:
        raise ValueError(MACHINE_REQUIRED)
    fields = {
        "package": package,
        "timeout": str(timeout_s),
        "machine": machine,
    }
    if options:
        fields["options"] = options
    # P1: no `memory` key, ever. A raise rather than an assert -- `python -O`
    # strips asserts, and a disk-exhaustion guard that silently vanishes under an
    # optimisation flag is the same silent-degradation shape this module exists
    # to prevent. Covered by test_no_memory_dump_is_requested.
    if "memory" in fields:
        raise ValueError(
            "`memory` must never be submitted: an 8.6 GB full-VM dump per run, with "
            "delete_memdump=no and Volatility processing disabled, filled the disk "
            "and CAPE silently stopped scheduling below freespace=50000 (P1)")
    return fields


@dataclass(frozen=True)
class PollDecision:
    action: str          # "wait" | "done" | "abort"
    reason: str = ""


def classify_poll(status: str, waited_s: float, deadline_s: float) -> PollDecision:
    """What to do with one poll response. Pure; I3 lives here.

    A batch that runs past its deadline is not salvageable by waiting longer --
    task 1131 legitimately took over 30 minutes, which is why the deadline is
    generous rather than absent.
    """
    if status == DONE:
        return PollDecision("done")
    if status in TERMINAL_FAILURES:
        return PollDecision("abort", f"CAPE reported {status}")
    if waited_s >= deadline_s:
        return PollDecision(
            "abort",
            f"status={status or '<none>'} after {int(waited_s)}s (deadline {int(deadline_s)}s). "
            "Not submitting further runs: a second task in flight would let CAPE use "
            "the office machine concurrently and invalidate the batch (I2).")
    return PollDecision("wait")


@dataclass
class RunRecord:
    index: int
    task_id: int | None = None
    status: str = ""
    machine: str = ""
    tier: str = ""
    metrics: dict = field(default_factory=dict)
    health: dict = field(default_factory=dict)
    error: str = ""


@dataclass
class BatchResult:
    runs: list[RunRecord] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""

    @property
    def completed(self) -> list[RunRecord]:
        return [r for r in self.runs if r.status == DONE and not r.error]


def run_batch(*, sample: Path, machine: str, runs: int,
              submit: Callable[[Path, dict], int],
              poll_status: Callable[[int], str],
              fetch_report: Callable[[int], dict],
              measure: Callable[[dict], tuple[str, dict, dict]],
              package: str = "exe",
              analysis_timeout_s: int = 200,
              options: str = "procmemdump=1,procdump=1",
              deadline_s: float = 3600.0,
              poll_interval_s: float = 10.0,
              sleep: Callable[[float], None] = time.sleep,
              now: Callable[[], float] = time.monotonic,
              log: Callable[[str], None] = print) -> BatchResult:
    """Run `sample` `runs` times, strictly one at a time, recording each tier.

    Every external effect is injected so the sequencing invariants can be tested
    against fakes. I2 is structural: the submit call for run n+1 is not reachable
    until run n has been polled to a terminal state and verified.
    """
    fields = plan_submission(sample, machine, package, analysis_timeout_s, options)
    result = BatchResult()

    for i in range(1, runs + 1):
        rec = RunRecord(index=i)
        result.runs.append(rec)
        log(f"=== run {i}/{runs} ===")

        try:
            rec.task_id = submit(sample, dict(fields))
        except Exception as e:  # noqa: BLE001
            rec.error = f"submit failed: {type(e).__name__}: {e}"
            result.aborted, result.abort_reason = True, rec.error
            log(f"  ABORT: {rec.error}")
            return result
        log(f"  task={rec.task_id}")

        started = now()
        while True:
            try:
                rec.status = poll_status(rec.task_id) or ""
            except Exception as e:  # noqa: BLE001
                rec.status = ""
                log(f"  poll error (transient, still counting toward deadline): {e}")
            decision = classify_poll(rec.status, now() - started, deadline_s)
            if decision.action != "wait":
                break
            sleep(poll_interval_s)

        if decision.action == "abort":
            rec.error = decision.reason
            result.aborted, result.abort_reason = True, decision.reason
            log(f"  ABORT: {decision.reason}")
            return result

        try:
            report = fetch_report(rec.task_id)
        except Exception as e:  # noqa: BLE001
            rec.error = f"could not read report: {type(e).__name__}: {e}"
            result.aborted, result.abort_reason = True, rec.error
            log(f"  ABORT: {rec.error}")
            return result

        problem = verify_ran_on(report.get("info") or {}, machine)
        if problem:
            rec.error = problem
            result.aborted, result.abort_reason = True, problem
            log(f"  ABORT: task {rec.task_id} {problem}")
            return result
        rec.machine = machine

        rec.tier, rec.metrics, rec.health = measure(report)
        log(f"  status=reported machine={machine} tier={rec.tier} "
            f"observed_behaviour={rec.metrics.get('observed_behaviour')}")

    return result
