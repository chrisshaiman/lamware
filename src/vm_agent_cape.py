"""
vm_agent_cape.py — VM vision agent for Cape malware detonation sessions.

Monitors a QEMU VNC session during active Cape analysis. Uses Claude vision
to identify UI states that would block or limit sample execution, interacts
with the VM to unblock them, and logs every action with screenshots to S3.

Interactions performed:
  - UAC prompts → click Yes (triggers elevation-dependent payload stages)
  - Error / crash dialogs → click OK/Close (lets execution continue)
  - Installer wizards → click Next/Install/Accept (unpacks staged droppers)
  - Credential prompts → enter fake credentials from fake_credentials.py
    (triggers C2 callbacks in credential harvesters and banking trojans)
  - Ransom notes / full-screen overlays → screenshot and log only, no interaction

Every action is logged with:
  - Timestamp
  - Screenshot before and after action
  - Action taken and credentials entered (if any)
  - Uploaded to S3 alongside the Cape report

Forensic integrity:
  - Agent actions are tagged in the session log so analysts can correlate
    network captures with agent-triggered events
  - Fake credentials are logged so analysts know exactly what was submitted
  - Agent never executes shell commands, navigates browsers, or performs
    any action beyond what a naive human user would do

Usage:
    python3 vm_agent_cape.py \\
        --monitor /var/lib/libvirt/images/qemu-monitor.sock \\
        --analysis-id <cape_task_id> \\
        --s3-bucket <reports_bucket> \\
        --duration 120

Author: Christopher Shaiman
License: Apache 2.0
"""

import argparse
import base64
import json
import logging
import re
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import anthropic
except ImportError:
    print("ERROR: pip3 install anthropic")
    sys.exit(1)

try:
    import boto3
except ImportError:
    print("ERROR: pip3 install boto3")
    sys.exit(1)

from fake_credentials import FINANCIAL, GUEST_IDENTITY, PROMPT_CREDENTIALS
from qemu_monitor import click_at, screenshot, send_key, type_string

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [cape-agent] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("vm_agent_cape")

# ---------------------------------------------------------------------------
# Claude vision prompt
# ---------------------------------------------------------------------------
VISION_PROMPT = """You are monitoring a Windows VM screen during live malware analysis.
The VM is running a potentially malicious sample. Your job is to identify UI states
that require interaction and specify the exact action to take.

Respond with ONLY a JSON object:
{
  "state": "<state>",
  "description": "<one sentence>",
  "action": "<action or null>",
  "credential_type": "<type or null>",
  "interact": true/false
}

States:
- "uac_prompt"              — Windows UAC elevation dialog
- "error_dialog"            — application error, crash, or Windows error dialog
- "installer_wizard"        — setup wizard (Next/Install/Accept/Finish buttons)
- "credential_prompt"       — login form, password field, or Windows credential dialog
- "payment_form"            — credit card or banking input form
- "personal_info_form"      — name/address/SSN/identity form
- "ransom_note"             — ransom demand or full-screen overlay (DO NOT INTERACT)
- "file_open_dialog"        — open/save file dialog
- "browser_prompt"          — browser security warning or download prompt
- "clean_desktop"           — normal desktop, no dialogs
- "sample_running"          — visible sample activity (file drops, network, registry)
- "vm_unresponsive"         — screen frozen or black for extended period
- "unknown"                 — cannot determine

Actions (use exact strings):
- "click_yes"               — click Yes or Allow button
- "click_ok"                — click OK or Close button
- "click_next"              — click Next button
- "click_install"           — click Install or Accept button
- "click_run"               — click Run or Execute button
- "enter_credentials"       — tab through fields and enter fake credentials
- "screenshot_only"         — log screenshot but take no action
- null                      — no action needed

credential_type: one of the keys from PROMPT_CREDENTIALS in fake_credentials.py,
or null if no credentials needed:
  "login_email_password", "windows_credential_dialog", "payment_form",
  "banking_login", "personal_info_form", "ssn_prompt"

interact: false for ransom_note, vm_unresponsive, clean_desktop, sample_running, unknown.
          true for everything else that needs an action.

Respond with ONLY the JSON. No other text."""


# Screenshots and mouse clicks use the QEMU monitor socket (qemu_monitor.py).
# VNC/vncdo is not used — it conflicts with attached VNC viewers and is
# unavailable when libvirt manages the domain socket directly.


# ---------------------------------------------------------------------------
# Claude vision interpretation
# ---------------------------------------------------------------------------

def interpret_screen(image_path: str) -> dict:
    """Send screenshot to Claude vision API and return parsed state dict."""
    client = anthropic.Anthropic()
    with open(image_path, "rb") as f:
        data = base64.standard_b64encode(f.read()).decode()
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=512,
        messages=[{
            "role": "user",
            "content": [
                {"type": "image", "source": {
                    "type": "base64", "media_type": "image/png", "data": data}},
                {"type": "text", "text": VISION_PROMPT},
            ],
        }],
    )
    text = response.content[0].text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return json.loads(text.strip())


# ---------------------------------------------------------------------------
# Action execution
# ---------------------------------------------------------------------------

# Common button positions on 1920x1080 screen (approximate center of typical dialogs)
# Claude identifies the state; we use screen-center heuristics for common dialogs.
# A more robust implementation would use Claude to return exact coordinates.
_BUTTON_COORDS: dict[str, tuple[int, int]] = {
    "click_yes":     (960, 620),   # UAC Yes / generic Yes
    "click_ok":      (960, 620),   # Error dialog OK
    "click_next":    (1100, 650),  # Wizard Next (bottom-right)
    "click_install": (1100, 650),  # Wizard Install
    "click_run":     (960, 620),   # Run/Execute
}


def execute_action(
    action: str,
    credential_type: str | None,
    monitor_sock: str,
) -> dict:
    """Execute the agent action.

    Returns a dict describing what was done, including any credentials
    entered (for the forensic log).
    """
    result: dict = {"action": action, "credentials_entered": None}

    if action in _BUTTON_COORDS:
        x, y = _BUTTON_COORDS[action]
        log.info("  Clicking %s at (%s, %s)", action, x, y)
        click_at(monitor_sock, x, y)

    elif action == "enter_credentials" and credential_type:
        cred_set = PROMPT_CREDENTIALS.get(credential_type)
        if not cred_set:
            log.warning("  Unknown credential_type: %s — skipping", credential_type)
            return result

        log.info("  Entering fake credentials: %s", credential_type)
        entered: dict[str, str] = {}
        for field in cred_set["fields"]:
            log.info("    Field: %s = %s", field["label"], field["value"])
            type_string(field["value"], monitor_sock)
            send_key("tab", monitor_sock)
            time.sleep(0.1)
            entered[field["label"]] = field["value"]

        send_key("enter", monitor_sock)
        result["credentials_entered"] = entered

    elif action == "screenshot_only":
        log.info("  Screenshot-only state — no interaction")

    return result


# ---------------------------------------------------------------------------
# S3 upload
# ---------------------------------------------------------------------------

def upload_to_s3(local_path: str, bucket: str, s3_key: str) -> None:
    """Upload a local file to S3. Logs a warning on failure (non-fatal)."""
    try:
        s3 = boto3.client("s3")
        s3.upload_file(local_path, bucket, s3_key)
        log.info("  Uploaded to s3://%s/%s", bucket, s3_key)
    except Exception as e:
        log.warning("  S3 upload failed (non-fatal): %s", e)


# ---------------------------------------------------------------------------
# Main agent loop
# ---------------------------------------------------------------------------

def run_cape_agent(
    monitor_sock: str,
    analysis_id: str,
    s3_bucket: str | None,
    duration: int,
    interval: int,
    screenshot_dir: str,
) -> list[dict]:
    """Run the Cape detonation agent loop.

    Takes screenshots on each interval, interprets via Claude vision,
    acts on interactive states, and logs everything to S3.
    """
    Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
    session_log: list[dict] = []
    start = time.monotonic()
    iteration = 0

    log.info("Cape VM agent starting — analysis %s", analysis_id)
    log.info("Monitor: %s", monitor_sock)
    log.info("Duration: %ss | Interval: %ss", duration, interval)

    while time.monotonic() - start < duration:
        iteration += 1
        ts = datetime.now(datetime.UTC).isoformat()
        elapsed = int(time.monotonic() - start)
        log.info("[%ss/%ss] Iteration %s", elapsed, duration, iteration)

        # Screenshot
        img_path = f"{screenshot_dir}/{analysis_id}_{iteration:04d}_before.png"
        try:
            screenshot(monitor_sock, img_path)
        except Exception as e:
            log.warning("  Screenshot failed: %s", e)
            time.sleep(interval)
            continue

        # Interpret
        try:
            result = interpret_screen(img_path)
        except Exception as e:
            log.warning("  Vision API failed: %s", e)
            time.sleep(interval)
            continue

        state: str = result.get("state", "unknown")
        description: str = result.get("description", "")
        action: str | None = result.get("action")
        credential_type: str | None = result.get("credential_type")
        interact: bool = result.get("interact", False)

        log.info("  State: %s", state)
        log.info("  Description: %s", description)
        log.info("  Action: %s | Interact: %s", action, interact)

        event: dict = {
            "timestamp": ts,
            "elapsed_seconds": elapsed,
            "iteration": iteration,
            "state": state,
            "description": description,
            "action": action,
            "interact": interact,
            "screenshot_before": img_path,
            "screenshot_after": None,
            "action_result": None,
        }

        # Act
        if interact and action and action != "screenshot_only":
            try:
                action_result = execute_action(action, credential_type, monitor_sock)
                event["action_result"] = action_result

                # Screenshot after action
                time.sleep(1)
                img_after = f"{screenshot_dir}/{analysis_id}_{iteration:04d}_after.png"
                screenshot(monitor_sock, img_after)
                event["screenshot_after"] = img_after

                if s3_bucket:
                    prefix = f"agent-logs/{analysis_id}"
                    upload_to_s3(img_path, s3_bucket,
                                 f"{prefix}/{Path(img_path).name}")
                    upload_to_s3(img_after, s3_bucket,
                                 f"{prefix}/{Path(img_after).name}")
            except Exception as e:
                log.warning("  Action failed: %s", e)
        else:
            # Upload before screenshot for passive states worth preserving
            if s3_bucket and state in ("ransom_note", "sample_running"):
                prefix = f"agent-logs/{analysis_id}"
                upload_to_s3(img_path, s3_bucket,
                             f"{prefix}/{Path(img_path).name}")

        session_log.append(event)
        time.sleep(interval)

    # Write session log
    log_path = f"{screenshot_dir}/{analysis_id}_agent_log.json"
    with open(log_path, "w") as f:
        json.dump({
            "analysis_id": analysis_id,
            "duration_seconds": duration,
            "iterations": iteration,
            "events": session_log,
            "fake_credentials_config": {
                "guest_email": GUEST_IDENTITY["email"],
                "cc_number": FINANCIAL["cc_number"],
                "note": "All credentials are provably fake — see fake_credentials.py",
            },
        }, f, indent=2)

    log.info("Session log written: %s", log_path)

    if s3_bucket:
        upload_to_s3(log_path, s3_bucket,
                     f"agent-logs/{analysis_id}/{analysis_id}_agent_log.json")

    log.info("Cape VM agent complete — %s iterations over %ss", iteration, duration)
    return session_log


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cape VM vision agent — monitors and interacts during malware detonation")
    parser.add_argument("--monitor", required=True,
                        help="Path to QEMU monitor Unix socket")
    parser.add_argument("--analysis-id", required=True,
                        help="Cape task/analysis ID (used for log naming)")
    parser.add_argument("--s3-bucket", default=None,
                        help="S3 bucket for uploading screenshots and logs")
    parser.add_argument("--duration", type=int, default=120,
                        help="Analysis window in seconds (default: 120)")
    parser.add_argument("--interval", type=int, default=10,
                        help="Seconds between screen checks (default: 10)")
    parser.add_argument("--screenshot-dir", default="/tmp/cape-agent-screenshots",
                        help="Local directory for screenshots")
    args = parser.parse_args()

    run_cape_agent(
        monitor_sock=args.monitor,
        analysis_id=args.analysis_id,
        s3_bucket=args.s3_bucket,
        duration=args.duration,
        interval=args.interval,
        screenshot_dir=args.screenshot_dir,
    )


if __name__ == "__main__":
    main()
