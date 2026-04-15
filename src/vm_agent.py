"""
vm_agent.py — QEMU monitor-based VM vision agent for Packer build monitoring.

Uses the QEMU human monitor socket for screenshots (screendump) and keystroke
injection (sendkey). Sends screenshots to the Claude API for interpretation
and acts based on the response.

VNC is NOT used. The monitor socket never conflicts with Packer's VNC boot_command
or any attached VNC viewer. Packer's VNC server only allows one client — connecting
a VNC viewer while Packer is sending boot_command causes the build to fail.

Usage:
    # Snapshot only — describe what's on screen
    python3 vm_agent.py --monitor /path/to/qemu-monitor.sock --snapshot

    # Open screenshot in Windows Explorer after taking it
    python3 vm_agent.py --monitor /path/to/qemu-monitor.sock --snapshot --open

    # Full agent loop — interpret and act until WinRM ready or timeout
    python3 vm_agent.py --monitor /path/to/qemu-monitor.sock --act

    # One-shot keystroke sequence
    python3 vm_agent.py --monitor /path/to/qemu-monitor.sock --type "FS1:<enter>"

Author: Christopher Shaiman
License: Apache 2.0
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import time

try:
    import anthropic
except ImportError:
    print("ERROR: anthropic package not installed. Run: pip3 install anthropic")
    sys.exit(1)

from qemu_monitor import screenshot, send_keys

# ---------------------------------------------------------------------------
# Vision prompt
# ---------------------------------------------------------------------------

VISION_PROMPT = """You are monitoring a QEMU virtual machine screen during a Windows 11
Packer build. Analyze the screenshot and respond with a JSON object containing:

{
  "state": "<one of the states below>",
  "description": "<one sentence describing what you see>",
  "action": "<recommended next action, or null if none needed>"
}

States:
- "uefi_shell"          — UEFI interactive shell with Shell> prompt visible
- "uefi_shell_booting"  — UEFI shell ran bootloader, now loading
- "windows_setup"       — Windows Setup installer screens (language, license, disk)
- "windows_setup_error" — "This PC doesn't meet requirements" or similar error dialog
- "windows_installing"  — Windows is copying/expanding files, progress bar visible
- "windows_rebooting"   — Black screen or "restarting" message during install
- "oobe"                — Out-of-box experience (country, account, privacy screens)
- "windows_desktop"     — Windows desktop loaded, install complete
- "winrm_ready"         — Windows desktop visible with no install activity (WinRM likely up)
- "blank"               — Black or blank screen
- "unknown"             — Cannot determine state

For "uefi_shell" state, set action to the exact keystrokes needed to boot Windows,
e.g. "FS1:<enter>EFI\\BOOT\\bootx64.efi<enter>" — use the FS mapping that has
VenMedia (the EFI FAT partition on the USB ISO).

For "windows_setup_error" (TPM/Secure Boot check failure), set action to:
"shift+f10:reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f<enter>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f<enter>"

Respond with ONLY the JSON object, no other text."""


# ---------------------------------------------------------------------------
# Claude vision interpretation
# ---------------------------------------------------------------------------

def interpret(image_path: str) -> dict:
    """Send screenshot to Claude vision API and return parsed state dict."""
    client = anthropic.Anthropic()

    with open(image_path, "rb") as f:
        image_data = base64.standard_b64encode(f.read()).decode("utf-8")

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": image_data,
                    },
                },
                {"type": "text", "text": VISION_PROMPT},
            ],
        }],
    )

    text = response.content[0].text.strip()
    if text.startswith("```"):
        # Strip opening fence (```json or ```) and closing fence
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text.strip())


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def agent_loop(
    monitor_sock: str,
    max_iterations: int = 60,
    interval: int = 30,
    out: str = "/tmp/vm_screenshot.png",
) -> str:
    """Main agent loop: screenshot → interpret → act → repeat.

    Stops when state is "winrm_ready" or "windows_desktop", or max_iterations reached.
    All screenshots and keystrokes go via the QEMU monitor socket — never VNC.
    """
    print(f"[vm_agent] Starting loop — monitor: {monitor_sock}, interval: {interval}s")

    terminal_states = {"winrm_ready", "windows_desktop"}
    acted_states: set[str] = set()

    for i in range(max_iterations):
        print(f"\n[vm_agent] Iteration {i+1}/{max_iterations}")

        try:
            img = screenshot(monitor_sock, out)
            print(f"  Screenshot: {img}")
        except Exception as e:
            print(f"  [warn] Screenshot failed: {e} — retrying next cycle")
            time.sleep(interval)
            continue

        try:
            result = interpret(img)
        except Exception as e:
            print(f"  [warn] Vision API failed: {e}")
            time.sleep(interval)
            continue

        state: str = result.get("state", "unknown")
        description: str = result.get("description", "")
        action: str | None = result.get("action")

        print(f"  State:       {state}")
        print(f"  Description: {description}")
        print(f"  Action:      {action or 'none'}")

        if state in terminal_states:
            print(f"\n[vm_agent] Terminal state reached: {state}. Done.")
            return state

        if action and state not in acted_states:
            print("  [vm_agent] Sending action...")
            try:
                send_keys(monitor_sock, action)
                acted_states.add(state)
                print("  [vm_agent] Action sent.")
            except Exception as e:
                print(f"  [warn] Action failed: {e}")

        time.sleep(interval)

    print("\n[vm_agent] Max iterations reached without terminal state.")
    return "timeout"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="QEMU monitor-based VM vision agent — no VNC required"
    )
    parser.add_argument(
        "--monitor", required=True,
        help="Path to QEMU human monitor Unix socket (e.g. /path/to/packer-output/qemu-monitor.sock)"
    )
    parser.add_argument("--snapshot", action="store_true",
                        help="Take a screenshot, describe it, then exit")
    parser.add_argument("--open", action="store_true",
                        help="Open the screenshot in Windows Explorer after --snapshot")
    parser.add_argument("--act", action="store_true",
                        help="Run the full agent loop (screenshot → interpret → act)")
    parser.add_argument("--type", dest="typestr", default=None,
                        help="Send a keystroke sequence and exit")
    parser.add_argument("--out", default="/tmp/vm_screenshot.png",
                        help="Screenshot output path (default: /tmp/vm_screenshot.png)")
    parser.add_argument("--interval", type=int, default=30,
                        help="Seconds between checks in agent loop (default: 30)")
    args = parser.parse_args()

    if args.typestr:
        print(f"[vm_agent] Sending keystrokes via monitor: {args.monitor}")
        send_keys(args.monitor, args.typestr)
        print("[vm_agent] Done.")

    elif args.snapshot:
        img = screenshot(args.monitor, args.out)
        print(f"[vm_agent] Screenshot: {img}")
        result = interpret(img)
        print(f"  State:       {result.get('state')}")
        print(f"  Description: {result.get('description')}")
        print(f"  Action:      {result.get('action')}")
        if args.open:
            win_path = subprocess.check_output(["wslpath", "-w", img]).decode().strip()
            subprocess.Popen(["explorer.exe", win_path])

    elif args.act:
        agent_loop(args.monitor, interval=args.interval, out=args.out)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
