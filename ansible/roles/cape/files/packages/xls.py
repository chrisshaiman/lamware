# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
#
# Modified: LibreOffice fallback when MS Excel is not installed.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import MSOFFICE_TRUSTED_PATH, TRUSTED_PATH_TEXT
from lib.common.exceptions import CuckooPackageError


class XLS(Package):
    """Excel analysis package with LibreOffice fallback."""

    default_curdir = MSOFFICE_TRUSTED_PATH

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "EXCEL.EXE"),
        ("ProgramFiles", "LibreOffice", "program", "soffice.exe"),
    ]
    summary = "Opens the supplied document with EXCEL.EXE or LibreOffice."
    description = f"""Uses 'EXCEL.EXE <path> /dde' or LibreOffice soffice.exe.
    {TRUSTED_PATH_TEXT}
    The .xls filename extension will be added automatically."""

    def start(self, path):
        if not path.endswith((".xls", ".xlsx", ".xlsb", ".xlsm", ".slk", ".ods")):
            path = check_file_extension(path, ".xls")

        # Try MS Excel first
        try:
            excel = self.get_path_glob("EXCEL.EXE")
            return self.execute(excel, f'"{path}" /dde', path)
        except CuckooPackageError:
            pass

        # Fall back to LibreOffice
        soffice = self.get_path_glob("soffice.exe")
        return self.execute(
            soffice,
            f'--norestore --calc "{path}"',
            path,
        )
