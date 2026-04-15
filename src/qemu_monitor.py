"""
qemu_monitor.py — QEMU human monitor socket helpers.

Shared by vm_agent.py (Packer build monitoring) and vm_agent_cape.py
(Cape detonation session monitoring). All VM interaction goes through
the QEMU human monitor Unix socket — VNC is never used for keystrokes
or screenshots so there is no conflict with attached VNC viewers or
Packer's boot_command VNC client.

Public API:
    monitor_cmd(sock_path, cmd)            — send one raw monitor command
    screenshot(sock_path, outfile)         — screendump → PNG via Pillow
    send_keys(sock_path, sequence)         — Packer-style sequence (boot_command format)
    type_string(text, sock_path)           — type text character-by-character
    send_key(key, sock_path)               — send a single named key (enter, tab, esc …)

Author: Christopher Shaiman
License: Apache 2.0
"""

import re
import socket
import time
from pathlib import Path

try:
    from PIL import Image
except ImportError as exc:
    raise ImportError("Pillow is required: pip3 install Pillow") from exc


# ---------------------------------------------------------------------------
# Key maps
# ---------------------------------------------------------------------------

# Named keys → QEMU key names
_KEY_MAP: dict[str, str] = {
    "enter": "ret", "return": "ret", "tab": "tab", "esc": "esc",
    "space": "spc", "bs": "backspace", "backspace": "backspace",
    "delete": "delete",
    "up": "up", "down": "down", "left": "left", "right": "right",
    "f1": "f1", "f2": "f2", "f3": "f3", "f4": "f4",
    "f5": "f5", "f6": "f6", "f7": "f7", "f8": "f8",
    "f9": "f9", "f10": "f10", "f11": "f11", "f12": "f12",
}

# Plain characters whose QEMU key name differs from the literal character.
# IMPORTANT: "." must map to "dot" — QEMU silently accepts "period" but
# produces no character in the guest. Verified by live testing.
_PLAIN_MAP: dict[str, str] = {
    ".": "dot", ",": "comma", "/": "slash", ";": "semicolon",
    "'": "apostrophe", "`": "grave", "-": "minus", "=": "equal",
    "[": "bracket_left", "]": "bracket_right",
}

# Characters that require Shift on a US keyboard → base QEMU key name
_SHIFT_MAP: dict[str, str] = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5",
    "^": "6", "&": "7", "*": "8", "(": "9", ")": "0",
    "_": "minus", "+": "equal", "{": "bracket_left",
    "}": "bracket_right", "|": "backslash", ":": "semicolon",
    '"': "apostrophe", "<": "comma", ">": "dot", "?": "slash",
    "~": "grave",
}


# ---------------------------------------------------------------------------
# Low-level monitor socket
# ---------------------------------------------------------------------------

def monitor_cmd(sock_path: str, cmd: str) -> None:
    """Send a single command to the QEMU human monitor Unix socket."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect(sock_path)
        s.recv(4096)  # consume QEMU greeting banner
        s.sendall((cmd + "\n").encode())
        time.sleep(0.05)


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------

def screenshot(sock_path: str, outfile: str = "/tmp/vm_screenshot.png") -> str:
    """Take a screenshot via QEMU monitor screendump and save as PNG.

    Writes a PPM framebuffer to /tmp/vm_screendump.ppm via the QEMU monitor,
    then converts it to PNG with Pillow. Never touches VNC — safe to call
    while Packer is sending boot_command or a VNC viewer is attached.

    Returns the path to the written PNG file.
    """
    ppm_path = "/tmp/vm_screendump.ppm"
    monitor_cmd(sock_path, f"screendump {ppm_path}")
    time.sleep(0.5)  # give QEMU time to flush the file

    p = Path(ppm_path)
    if not p.exists() or p.stat().st_size == 0:
        raise RuntimeError(
            f"QEMU screendump did not write {ppm_path} — "
            "is the monitor socket path correct?"
        )

    Image.open(ppm_path).save(outfile)
    return outfile


# ---------------------------------------------------------------------------
# Keystroke helpers
# ---------------------------------------------------------------------------

def _char_to_qkey(char: str) -> str:
    """Map a single character to its QEMU sendkey name."""
    if char in _SHIFT_MAP:
        return f"shift-{_SHIFT_MAP[char]}"
    if char.isupper():
        return f"shift-{char.lower()}"
    if char == "\\":
        return "backslash"
    if char == " ":
        return "spc"
    if char == "\t":
        return "tab"
    if char in _PLAIN_MAP:
        return _PLAIN_MAP[char]
    return char


def click_at(sock_path: str, x: int, y: int) -> None:
    """Click at absolute screen coordinates via the QEMU monitor.

    Uses mouse_move + mouse_button commands — no VNC client needed.
    """
    monitor_cmd(sock_path, f"mouse_move {x} {y}")
    time.sleep(0.05)
    monitor_cmd(sock_path, "mouse_button 1")   # left button press
    time.sleep(0.05)
    monitor_cmd(sock_path, "mouse_button 0")   # release
    time.sleep(0.2)


def type_string(text: str, sock_path: str) -> None:
    """Type a string character-by-character via the QEMU monitor."""
    for char in text:
        monitor_cmd(sock_path, f"sendkey {_char_to_qkey(char)}")
        time.sleep(0.04)


def send_key(key: str, sock_path: str) -> None:
    """Send a single named key (enter, tab, esc, f10 …) via the QEMU monitor."""
    qkey = _KEY_MAP.get(key.lower(), key.lower())
    monitor_cmd(sock_path, f"sendkey {qkey}")
    time.sleep(0.05)


def send_keys(sock_path: str, sequence: str) -> None:
    """Send a Packer boot_command-style keystroke sequence via the QEMU monitor.

    Sequence format:
      - Plain text is typed character by character
      - <enter>, <tab>, <esc>, <bs>, <space>, <f1>–<f12> send those keys
      - <shift-f10> (or any <shift-X>) sends the Shift combo
      - <waitN> pauses N seconds (e.g. <wait2>)

    Example:
        send_keys(sock, "FS1:<enter>EFI\\\\BOOT\\\\bootx64.efi<enter><wait1><enter>")
    """
    tokens = re.split(r"(<[^>]+>)", sequence)
    for token in tokens:
        if not token:
            continue
        if token.startswith("<") and token.endswith(">"):
            inner = token[1:-1].lower()
            if inner.startswith("wait"):
                wait_str = inner[4:]
                secs = min(int(wait_str) if wait_str.isdigit() else 1, 300)
                time.sleep(secs)
                continue
            if inner.startswith("shift-"):
                base = inner[6:]
                qkey = f"shift-{_KEY_MAP.get(base, base)}"
            else:
                qkey = _KEY_MAP.get(inner, inner)
            monitor_cmd(sock_path, f"sendkey {qkey}")
        else:
            for char in token:
                monitor_cmd(sock_path, f"sendkey {_char_to_qkey(char)}")
                time.sleep(0.05)
