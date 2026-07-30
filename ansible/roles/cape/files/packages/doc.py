# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
#
# Modified: LibreOffice fallback when MS Word is not installed.


from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import MSOFFICE_TRUSTED_PATH, TRUSTED_PATH_TEXT
from lib.common.exceptions import CuckooPackageError


class DOC(Package):
    """Word analysis package with LibreOffice fallback."""

    default_curdir = MSOFFICE_TRUSTED_PATH

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
        ("ProgramFiles", "LibreOffice", "program", "soffice.exe"),
    ]
    summary = "Opens a document file with WINWORD.EXE or LibreOffice."
    description = f"""Uses 'WINWORD.EXE /q', or if unavailable, LibreOffice soffice.exe.
    {TRUSTED_PATH_TEXT}
    The .doc filename extension will be added automatically."""

    def start(self, path):
        if not path.endswith((".doc", ".docx", ".docm", ".dotm", ".odt")):
            path = check_file_extension(path, ".doc")

        # Try MS Word first
        try:
            word = self.get_path_glob("WINWORD.EXE")
            return self.execute(word, f'"{path}" /q', path)
        except CuckooPackageError:
            pass

        # Try WordView
        try:
            word = self.get_path_glob("WORDVIEW.EXE")
            return self.execute(word, f'"{path}" /q', path)
        except CuckooPackageError:
            pass

        # Fall back to LibreOffice
        soffice = self.get_path_glob("soffice.exe")
        return self.execute(
            soffice,
            f'--norestore --writer "{path}"',
            path,
        )
