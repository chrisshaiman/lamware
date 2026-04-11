"""
Unit tests for qemu_monitor key mapping helpers.

These tests cover the pure character-to-QEMU-key logic only — no socket
or subprocess calls are made, so no QEMU process is required.
"""

import sys
from pathlib import Path

# Allow importing src/ without installing the package
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from qemu_monitor import _char_to_qkey  # noqa: E402


class TestCharToQkey:
    def test_lowercase_passthrough(self):
        assert _char_to_qkey("a") == "a"
        assert _char_to_qkey("z") == "z"

    def test_digit_passthrough(self):
        assert _char_to_qkey("0") == "0"
        assert _char_to_qkey("9") == "9"

    def test_uppercase_gets_shift(self):
        assert _char_to_qkey("A") == "shift-a"
        assert _char_to_qkey("Z") == "shift-z"

    def test_dot_maps_to_dot_not_period(self):
        # "period" is silently broken in QEMU — must be "dot"
        assert _char_to_qkey(".") == "dot"

    def test_space_maps_to_spc(self):
        assert _char_to_qkey(" ") == "spc"

    def test_backslash(self):
        assert _char_to_qkey("\\") == "backslash"

    def test_tab(self):
        assert _char_to_qkey("\t") == "tab"

    def test_shift_symbols(self):
        assert _char_to_qkey("!") == "shift-1"
        assert _char_to_qkey("@") == "shift-2"
        assert _char_to_qkey("_") == "shift-minus"

    def test_plain_map_entries(self):
        assert _char_to_qkey("-") == "minus"
        assert _char_to_qkey("=") == "equal"
        assert _char_to_qkey("/") == "slash"
