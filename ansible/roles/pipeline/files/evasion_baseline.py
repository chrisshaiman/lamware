# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Capture what the CURRENT guest images let us observe, so a rebuild can be judged.

A guest rebuild is a one-way door. Once the images change there is no way back to
measure what the old ones did, so the before-baseline has to be taken first or the
comparison is unavailable forever (#517).

This reads STORED reports. It does not detonate anything — every corpus report was
produced on the images now on disk (built 2026-05-06), so the baseline already
exists and only needs to be pinned down in a form that survives.

THE PRIMARY METRIC IS CHOSEN HERE, BEFORE THE COMPARISON EXISTS. Picking one after
seeing the after-numbers is how a result becomes unfalsifiable, which is the same
discipline the held-out MITRE key exists to enforce (#491).

    primary    observed_behaviour = signatures + payloads + injected pids
               Evasion, when it works, makes a sample do LESS in front of us.
               More observed behaviour after a rebuild is the effect we predict;
               less would be a real negative result and must be reported as one.

    secondary  malscore, dns_queries, tcp_attempts, correlations

    NOT a metric: the anti-* signature names. A sample CHECKING for a VM says
    nothing about whether it found one, and reading those as a score would be
    measuring the question rather than the answer (#478).
"""
import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

GUEST_IMAGE_DIR = Path("/var/lib/libvirt/images")


def _cape(report: dict) -> dict:
    c = report.get("cape")
    return c if isinstance(c, dict) else {}


def sample_metrics(report: dict) -> dict:
    """What this analysis was able to observe."""
    cape = _cape(report)
    net = cape.get("network") if isinstance(cape.get("network"), dict) else {}
    sigs = cape.get("signatures") or []
    tcp = net.get("tcp_connections") or []
    # Post-#479 rows carry `attempts`; older ones are one row per connection and
    # capped at 50, so the two are not comparable and the shape is recorded
    # rather than silently summed (#488).
    attempts = net.get("tcp_attempts_total")
    if attempts is None:
        attempts = len(tcp) if tcp else 0
        tcp_shape = "connections(capped)" if len(tcp) >= 50 else "connections"
    else:
        tcp_shape = "destinations"

    observed = (len(sigs)
                + int(cape.get("payloads_extracted") or 0)
                + len(cape.get("injection_pids") or []))
    return {
        "observed_behaviour": observed,
        "signatures": len(sigs),
        "payloads_extracted": cape.get("payloads_extracted"),
        "injected_pids": len(cape.get("injection_pids") or []),
        "processes_seen": len(cape.get("process_cmdlines") or {}),
        "malscore": cape.get("malscore"),
        "dns_queries": len(net.get("dns_queries") or []),
        "tcp_attempts": attempts,
        "tcp_shape": tcp_shape,
        "correlations": len(report.get("cross_correlations") or []),
        "mitre_ttps": len({t.get("id") for t in (cape.get("mitre_ttps") or [])
                           if isinstance(t, dict)}),
        # Recorded, deliberately NOT scored — see the module docstring.
        "anti_checks": sorted(
            s.get("name", "") for s in sigs
            if isinstance(s, dict)
            and any(k in str(s.get("name", ""))
                    for k in ("antivm", "antisandbox", "antidebug", "stealth"))),
    }


def guest_images(image_dir: Path = GUEST_IMAGE_DIR) -> list:
    """The images this baseline describes. Without them it is a set of numbers
    with no era attached, which is the whole failure #486 exists to prevent."""
    out = []
    try:
        images = sorted(image_dir.glob("*.qcow2"))
    except OSError:
        return out
    for img in images:
        try:
            st = img.stat()
        except OSError:
            continue
        out.append({"image": img.name,
                    "mtime": datetime.fromtimestamp(st.st_mtime, UTC).date().isoformat(),
                    "bytes": st.st_size})
    return out


def capture(corpus_path: str) -> dict:
    manifest = json.loads(Path(corpus_path).read_text())
    samples = {}
    for s in manifest.get("samples", []):
        d = Path(s["corpus_dir"])
        try:
            report = json.loads((d / "report.json").read_text())
        except (OSError, ValueError) as e:
            samples[d.name] = {"error": f"{type(e).__name__}: {e}"}
            continue
        samples[d.name] = sample_metrics(report)
    return {
        "captured_at": datetime.now(UTC).isoformat(),
        "corpus_path": str(corpus_path),
        "corpus_sha256": hashlib.sha256(
            Path(corpus_path).read_bytes()).hexdigest()[:16],
        "guest_images": guest_images(),
        "primary_metric": "observed_behaviour",
        "direction": "higher is less evasion",
        "samples": samples,
    }


def render(base: dict) -> str:
    lines = [f"captured {base['captured_at']}",
             f"corpus   {base['corpus_path']} sha256:{base['corpus_sha256']}"]
    if base["guest_images"]:
        for img in base["guest_images"]:
            lines.append(f"image    {img['image']} built {img['mtime']}")
    else:
        # Printing nothing here would be the failure this whole file exists to
        # avoid: a baseline with no era attached looks like a baseline. The
        # image directory is not readable by the pipeline user, so capture this
        # as root or the record cannot say what it describes.
        lines.append("image    *** NONE READABLE — this baseline names no era. "
                     "Re-run as a user that can stat "
                     f"{GUEST_IMAGE_DIR} ***")
    lines.append("")
    lines.append(f"{'sample':30} {'observed':>8} {'sigs':>5} {'payl':>5} "
                 f"{'inj':>4} {'proc':>5} {'mal':>5} {'ttps':>5} {'corr':>5}")
    for name, m in sorted(base["samples"].items()):
        if "error" in m:
            lines.append(f"{name:30} {m['error']}")
            continue
        lines.append(f"{name:30} {m['observed_behaviour']:>8} {m['signatures']:>5} "
                     f"{str(m['payloads_extracted']):>5} {m['injected_pids']:>4} "
                     f"{m['processes_seen']:>5} {str(m['malscore']):>5} "
                     f"{m['mitre_ttps']:>5} {m['correlations']:>5}")
    ok = [m for m in base["samples"].values() if "error" not in m]
    if ok:
        total = sum(m["observed_behaviour"] for m in ok)
        lines.append("")
        lines.append(f"TOTAL observed_behaviour across {len(ok)} sample(s): {total}")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out", help="write the JSON baseline here as well")
    args = ap.parse_args()
    base = capture(args.corpus)
    print(render(base))
    if not base["guest_images"] and args.out:
        raise SystemExit(
            "refusing to write a baseline that cannot say which images it "
            "describes — run as a user that can read the image directory")
    if args.out:
        out = Path(args.out)
        if out.exists():
            raise SystemExit(
                f"refusing to overwrite {out}\n"
                f"  a baseline is a record of a moment that cannot be retaken.")
        out.write_text(json.dumps(base, indent=2))
        print(f"[baseline] wrote {out}")


if __name__ == "__main__":
    main()
