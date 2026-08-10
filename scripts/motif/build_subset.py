#!/usr/bin/env python3
"""Build the MOTIF benchmark subset: select, extract, normalise, manifest.

Run as root on the sandbox. Reads /opt/motif/MOTIF.7z and the dataset index,
writes /opt/motif/corpus/.

TWO TIERS, because the two things we need pull in opposite directions:

  breadth  maximises DISTINCT REPORTS -> independent family labels.
           Answers "can it identify families at all", which today is
           unmeasurable (0/7 for qwen AND for the Claude reference).

  ioc      clusters within reports that publish IOCs -> claim-level ground
           truth for #314. report_ioc_url is all-or-nothing per report
           (icedid: 102/102 from one Palo Alto article, 0 from the other five),
           so maximising report spread minimises this. Clustering is also
           cheaper to label: one report read yields truth for several samples.

Sized to stay runnable. At the 10-40 min/sample measured for qwen@15, 30
samples is already 5-20 hours per arm, so this is an on-demand regression
benchmark and not a per-deploy gate.
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/opt/motif/lib")
from lamware_eval.motif import (  # noqa: E402
    load_motif_index,
    normalise_file,
    read_header,
    select_ioc_subset,
    select_subset,
    subset_report,
)

ROOT = Path("/opt/motif")
CORPUS = ROOT / "corpus"
SAMPLES = CORPUS / "samples"
ARCHIVE = ROOT / "MOTIF.7z"
PASSWORD = "i_assume_all_risk_opening_malware"

# icedid + emotet are shared with the live MalwareBazaar corpus. trickbot (17
# reports) and azorult (14) carry the most independent ground truth in MOTIF.
# ursnif is the only selected family with AMD64 samples, which is what exercises
# the 0x8664 normalisation path on real data rather than only in a unit test.
BREADTH = {"icedid": 4, "emotet": 4, "trickbot": 4, "azorult": 4, "ursnif": 2}

# Only these three have any IOC-bearing report at all. emotet has 6 reports and
# ZERO report_ioc_urls, so it contributes family-label truth and nothing else.
IOC = {"icedid": 6, "azorult": 3, "trickbot": 3}


def main() -> int:
    rows = load_motif_index(ROOT / "motif_dataset.jsonl")

    breadth = select_subset(rows, BREADTH)
    ioc = select_ioc_subset(rows, IOC, per_report=3)

    tiers: dict[str, set[str]] = {}
    for r in breadth:
        tiers.setdefault(r["md5"], set()).add("breadth")
    for r in ioc:
        tiers.setdefault(r["md5"], set()).add("ioc")

    picked = {r["md5"]: r for r in breadth}
    picked.update({r["md5"]: r for r in ioc})
    selected = [picked[m] for m in sorted(picked)]

    print(f"breadth tier : {len(breadth)}")
    for fam, d in sorted(subset_report(breadth)["families"].items()):
        print(f"    {fam:10} n={d['n']:3} distinct_reports={d['distinct_reports']:3}")
    print(f"ioc tier     : {len(ioc)}")
    for fam, d in sorted(subset_report(ioc)["families"].items()):
        print(f"    {fam:10} n={d['n']:3} distinct_reports={d['distinct_reports']:3} "
              f"with_ioc_url={d['with_ioc_url']:3}")
    print(f"union        : {len(selected)} samples "
          f"({len(breadth) + len(ioc) - len(selected)} in both tiers)")

    SAMPLES.mkdir(parents=True, exist_ok=True)
    # Explicit, not umask-derived: root's umask here creates 0700, and the
    # pipeline user must be able to traverse to reach the samples. run-ghidra
    # fails at `realpath` with a bare "Permission denied" that says nothing
    # about which directory in the path was the problem.
    for d in (ROOT, CORPUS, SAMPLES):
        d.chmod(0o755)

    members = [f"MOTIF_defanged/MOTIF_{r['md5']}" for r in selected]
    staging = ROOT / "staging"
    staging.mkdir(exist_ok=True)
    proc = subprocess.run(
        ["7z", "e", "-y", f"-p{PASSWORD}", str(ARCHIVE), *members, f"-o{staging}"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        print("EXTRACT FAILED:", proc.stderr[-500:])
        return 1

    manifest, failures = [], []
    arch_seen: dict[str, int] = {}
    for r in selected:
        src = staging / f"MOTIF_{r['md5']}"
        if not src.exists():
            failures.append(f"{r['md5']}: not extracted")
            continue
        dst = SAMPLES / f"{r['family']}_{r['md5'][:12]}.bin"
        try:
            res = normalise_file(src, dst, r["machine"])
        except Exception as e:  # noqa: BLE001
            failures.append(f"{r['md5']}: {type(e).__name__}: {e}")
            continue
        # Verify the ARTIFACT, not the return value.
        machine, subsystem = read_header(dst.read_bytes())
        if machine != res.machine_after:
            failures.append(f"{dst.name}: machine not written")
            continue
        if subsystem != 0:
            failures.append(f"{dst.name}: SUBSYSTEM RESTORED — sample re-armed")
            continue
        arch_seen[r["machine"]] = arch_seen.get(r["machine"], 0) + 1
        manifest.append({
            "sha256": r["sha256"],
            "md5": r["md5"],
            "mb_family": r["family"],          # ground truth, from threat reports
            "corpus_dir": str(CORPUS / f"{r['family']}_{r['md5'][:12]}"),
            "analyst_label": None,
            "sample_path": str(dst),
            "tiers": sorted(tiers[r["md5"]]),
            "machine_restored": f"{machine:#06x}",
            "subsystem": subsystem,
            "report_url": r["report_url"],
            "report_ioc_url": r["report_ioc_url"],
            "report_date": r["report_date"],
            "report_source": r["report_source"],
        })

    out = {
        "source": "MOTIF (Booz Allen Public License v1.0) — INTERNAL USE ONLY. "
                  "Do not commit samples or the archive to the public repo.",
        "normalisation": "COFF Machine restored from MOTIF's recorded header. "
                         "Subsystem deliberately left 0 so samples remain "
                         "unloadable by Windows.",
        "limitations": {
            "report_date_range": "2016-01-07 to 2020-12-23",
            "ground_truth_granularity": "per report_url, not per sample",
            "families_in_live_corpus_but_absent_here": [
                "latrodectus", "rhadamanthys", "warmcookie"],
            "emotet_has_no_ioc_urls": True,
            "architectures": arch_seen,
        },
        "tiers": {
            "breadth": "distinct reports; independent family labels",
            "ioc": "clustered in IOC-publishing reports; claim-level truth (#314)",
        },
        "samples": manifest,
    }
    (CORPUS / "corpus.json").write_text(
        json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")

    print(f"\nwrote {CORPUS / 'corpus.json'}: {len(manifest)} samples, arch={arch_seen}")
    if failures:
        print("FAILURES:")
        for f in failures:
            print("  ", f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
