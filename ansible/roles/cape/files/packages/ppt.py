# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
#
# Modified: LibreOffice fallback when MS PowerPoint is not installed.

from lib.common.abstracts import Package
from lib.common.constants import MSOFFICE_TRUSTED_PATH, TRUSTED_PATH_TEXT
from lib.common.exceptions import CuckooPackageError


class PPT(Package):
    """PowerPoint analysis package with LibreOffice fallback."""

    default_curdir = MSOFFICE_TRUSTED_PATH

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "POWERPNT.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "POWERPNT.EXE"),
        ("ProgramFiles", "LibreOffice", "program", "soffice.exe"),
    ]
    summary = "Opens sample file with Powerpoint or LibreOffice."
    description = f"""Uses 'POWERPNT.EXE /s <sample>' or LibreOffice soffice.exe.
    {TRUSTED_PATH_TEXT}
    """

    def start(self, path):
        # Try MS PowerPoint first
        try:
            powerpoint = self.get_path_glob("POWERPNT.EXE")
            return self.execute(powerpoint, f'/s "{path}"', path)
        except CuckooPackageError:
            pass

        # Fall back to LibreOffice
        soffice = self.get_path_glob("soffice.exe")
        return self.execute(
            soffice,
            f'--norestore --impress "{path}"',
            path,
        )
