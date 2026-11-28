# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Reading files that another service account can write (ADR-031's rule).

The feeder's state.json lives in a directory the feeder and the API share
(group lamware-feeder). A reader that follows a planted symlink discloses or
corrupts the link's target, and one that opens a planted FIFO blocks the API's
event loop. So shared state is opened with O_NOFOLLOW and O_NONBLOCK, and only a
regular file is read.
"""
from __future__ import annotations

import json
import os
import stat
from typing import Any


def read_json_nofollow(path: str) -> Any:
    """The JSON in `path`, if it is a regular file reached without a symlink.

    Raises OSError (a symlink: ELOOP; missing: ENOENT; not a regular file: EINVAL)
    or ValueError (not JSON). Callers treat either as "no state".
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(22, "not a regular file", path)
        with os.fdopen(fd, "r", closefd=False) as f:
            return json.load(f)
    finally:
        os.close(fd)
