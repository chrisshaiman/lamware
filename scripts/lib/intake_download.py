#!/usr/bin/env python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Download ONE MalwareBazaar sample by SHA-256 into a staging dir (corpus intake).

Runs on the sandbox as the auto-feeder user -- the only account with egress to
MalwareBazaar -- and IMPORTS the feeder's own download_sample / extract_sample
rather than restating them, so the zip handling, size cap and password are one
implementation. Prints `<path>\t<filename>` on success.

    intake_download.py <sha256> <out_dir>
"""
import hashlib
import importlib.util
import os
import sys
from pathlib import Path

FEEDER = Path("/opt/auto-feeder/auto-feeder.py")


def _feeder():
    spec = importlib.util.spec_from_file_location("auto_feeder", FEEDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    sha, out = sys.argv[1].lower(), Path(sys.argv[2])
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        print(f"not a sha256: {sha!r}", file=sys.stderr)
        return 2
    af = _feeder()
    cfg = af.load_shared_config()
    api = cfg.get("bazaar_api_url", "https://mb-api.abuse.ch/api/v1/")
    headers = {"Auth-Key": cfg["bazaar_auth_key"]} if cfg.get("bazaar_auth_key") else {}
    name, content = af.extract_sample(af.download_sample(api, sha, headers))
    got = hashlib.sha256(content).hexdigest()
    if got != sha:
        print(f"sha256 mismatch: expected {sha}, got {got}", file=sys.stderr)
        return 3
    out.mkdir(mode=0o2750, exist_ok=True)
    path = out / name
    # O_EXCL|O_NOFOLLOW: never write through something already there (#537).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "wb") as f:
        f.write(content)
    print(f"{path}\t{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
