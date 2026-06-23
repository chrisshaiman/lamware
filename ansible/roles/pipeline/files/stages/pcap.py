"""
Stage 3.6: PCAP analysis — Zeek + Suricata on Cape's network capture.

Runs when Cape produced a PCAP file (dump.pcap in the Cape analysis
directory). Extracts protocol metadata, JA3 fingerprints, HTTP
transactions, and IDS alerts from the raw packet capture.

Complements Cape's behavioral network logging (DNS/HTTP/TCP) with
full-packet inspection — catches things like JA3 fingerprints,
non-standard protocol use, and Suricata signature matches.

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import os
import subprocess
from pathlib import Path


CAPE_STORAGE = "/opt/CAPEv2/storage/analyses"


def get_cape_pcap(cape_task_id: int | str) -> str | None:
    """Return the path to Cape's PCAP if it exists and has data."""
    if not cape_task_id:
        return None
    pcap_path = os.path.join(CAPE_STORAGE, str(cape_task_id), "dump.pcap")
    if os.path.isfile(pcap_path) and os.path.getsize(pcap_path) > 0:
        return pcap_path
    return None


def run_pcap_analysis(pcap_path: str, output_dir: str, pcap_cmd: str,
                      timeout: int = 120) -> dict:
    """Run Zeek + Suricata on a PCAP file via the containerized wrapper.

    Returns structured JSON with Zeek logs, Suricata alerts, and
    extracted IOCs (JA3, URLs, user-agents).
    """
    os.makedirs(output_dir, exist_ok=True)

    try:
        result = subprocess.run(
            [pcap_cmd, pcap_path, output_dir],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return {"error": f"PCAP analysis command not found: {pcap_cmd}"}
    except subprocess.TimeoutExpired:
        return {"error": f"PCAP analysis timed out ({timeout}s)"}

    if result.returncode != 0:
        return {"error": f"PCAP analysis failed: {result.stderr[:300]}"}

    # The container writes JSON to stdout
    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": f"Failed to parse PCAP output: {result.stdout[:200]}"}

    return output
