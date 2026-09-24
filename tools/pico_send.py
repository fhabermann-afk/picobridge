#!/usr/bin/env python3
"""Comfortable front-end for typing into the PicoBridge USB-HID target.

Designed for daily use: run it, type the secret (hidden), switch to the
target window, and the script starts typing after a configurable countdown.

Examples:
  pico-send                      hidden password prompt, 5s delay, Enter after
  pico-send -t "url=http://x"    visible text mode, no trailing Enter
  pico-send -d 10                10 second countdown before typing
  pico-send --no-enter           do not press Enter after the password
  echo pw | pico-send --stdin    pipe a secret in (never use argv for secrets)

Secrets are never accepted as command-line arguments (shell history and
/proc/<pid>/cmdline leak them). Owner defaults to the current uid; command
ids are fresh random values so the device's replay ledger never rejects a
legitimate transaction.
"""
import argparse
import asyncio
import getpass
import importlib.util
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CTL_PATH = HERE / "pico_bridge_ctl.py"


def load_ctl():
    spec = importlib.util.spec_from_file_location("pico_bridge_ctl", CTL_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {CTL_PATH} (keep it next to pico-send.py)")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def connect_with_retry(ctl, retries, timeout):
    last = None
    for attempt in range(1, retries + 1):
        try:
            return await ctl.scan_and_connect(timeout)
        except Exception as exc:  # BLE scans drop intermittently after rapid connects
            last = exc
            print(f"  scan attempt {attempt}/{retries} failed: {exc}", file=sys.stderr)
            await asyncio.sleep(2)
    raise SystemExit(f"giving up after {retries} scan attempts: {last}")


def clipboard_backend():
    """Pick the clipboard reader/writer pair for this session, or None."""
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste") and shutil.which("wl-copy"):
        return "wayland"
    if os.environ.get("DISPLAY") or os.environ.get("XAUTHORITY"):
        if shutil.which("xclip"):
            return "xclip"
        if shutil.which("xsel"):
            return "xsel"
    return None


def clipboard_read(backend):
    cmd = {"wayland": ["wl-paste", "-n"],
           "xclip": ["xclip", "-selection", "clipboard", "-o"],
           "xsel": ["xsel", "--clipboard", "--output"]}[backend]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"clipboard read failed ({result.stderr.decode(errors='replace').strip()})")
    # Clipboard copies of secrets never carry meaningful trailing newlines;
    # and in password mode the firmware would reject them anyway.
    return result.stdout.rstrip(b"\r\n")


def clipboard_clear(backend):
    cmd = {"wayland": ["wl-copy"],
           "xclip": ["xclip", "-selection", "clipboard"],
           "xsel": ["xsel", "--clipboard", "--clear"]}[backend]
    subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True)


def resolve_default_identity():
    """Pick the first existing Noise identity; fall back to the canonical path."""
    candidates = [
        Path.home() / ".config/pico-bridge/noise-ik.json",
        HERE.parent / "private/noise-ik-current/noise-ik.json",
        HERE.parent / "private/noise-ik.json",
    ]
    for p in candidates:
        if p.is_file():
            return p
    return candidates[0]


async def run(args):
    ctl = load_ctl()

    if args.clipboard:
        backend = clipboard_backend()
        if backend is None:
            raise SystemExit("No usable clipboard backend: install wl-clipboard (Wayland) or xclip/xsel (X11), and run inside that graphical session.")
        raw = clipboard_read(backend)
    elif args.stdin:
        raw = sys.stdin.buffer.read().rstrip(b"\n")
    elif args.text is not None:
        raw = args.text.encode("utf-8")
    elif args.visible:
        raw = input("Text for PicoBridge target: ").encode("utf-8")
    else:
        raw = getpass.getpass("Secret for PicoBridge target (input hidden): ").encode("utf-8")

    if not raw:
        raise SystemExit("Empty input, aborting.")
    if len(raw) > 1024:
        raise SystemExit(f"Input too long ({len(raw)} bytes, maximum 1024).")

    mode = ctl.BRIDGE_MODE_TEXT if (args.text is not None or args.visible or args.mode == "text") \
        else ctl.BRIDGE_MODE_PASSWORD
    layout = ctl.BRIDGE_LAYOUT_DE if args.layout == "de" else ctl.BRIDGE_LAYOUT_US
    owner = args.owner if args.owner is not None else os.geteuid()
    identity = args.identity or resolve_default_identity()
    if not identity.is_file():
        raise SystemExit(f"Noise identity not found: {identity}\n"
                         "Create one with tools/noise_ik_provision.py or pass --identity PATH.")

    # Countdown FIRST: the device holds a staged entry for a short TTL only,
    # so stage+confirm must happen back-to-back after the user focused the
    # target window. BLE connection setup never steals window focus.
    if args.delay > 0:
        print(f"\n{args.delay} seconds — focus the target window now!", file=sys.stderr)
        for remaining in range(args.delay, 0, -1):
            print(f"  sending in {remaining}...", end="\r", file=sys.stderr, flush=True)
            await asyncio.sleep(1)
        print("  go!             ", file=sys.stderr)

    device, client = await connect_with_retry(ctl, args.retries, args.timeout)
    try:
        noise = await ctl.perform_noise_handshake(client, str(identity))
        cmd_id = secrets.randbelow(0xFFFFFFFE) + 1
        packet = ctl.build_stage_packet(owner, cmd_id, layout, mode, 0, raw)
        await ctl.send_command(client, packet, noise=noise)
        await ctl.send_command(client, ctl.build_confirm_packet(owner, cmd_id), noise=noise)
        print(f"OK: typed {len(raw)} characters ({'password' if mode == ctl.BRIDGE_MODE_PASSWORD else 'text'} mode).")

        if args.enter:
            await asyncio.sleep(0.15)
            enter_id = secrets.randbelow(0xFFFFFFFE) + 1
            enter_packet = ctl.build_stage_packet(
                owner, enter_id, layout, ctl.BRIDGE_MODE_TEXT, ctl.BRIDGE_FLAG_ALLOW_LF, b"\n")
            await ctl.send_command(client, enter_packet, noise=noise)
            await ctl.send_command(client, ctl.build_confirm_packet(owner, enter_id), noise=noise)
            print("OK: sent Enter.")
    finally:
        await client.disconnect()


def main():
    parser = argparse.ArgumentParser(
        prog="pico-send", description="Convenience front-end for sending text/passwords to the PicoBridge USB target")
    parser.add_argument("-t", "--text", help="Pass text directly (visible mode, NOT for passwords!)")
    parser.add_argument("--visible", action="store_true", help="Enter text interactively with echo")
    parser.add_argument("--stdin", action="store_true", help="Read the secret from stdin")
    parser.add_argument("--clipboard", action="store_true",
                        help="Read secret from the system clipboard (KeePassXC etc.); does not clear it")
    parser.add_argument("--mode", choices=["password", "text"], default="password",
                        help="Mode for prompt/stdin (default: password, hidden)")
    parser.add_argument("-d", "--delay", type=int, default=5,
                        help="Countdown seconds before typing (default: 5, 0=immediately)")
    parser.add_argument("--no-enter", dest="enter", action="store_false",
                        help="Do not send Enter after the secret (default: Enter on)")
    parser.add_argument("--layout", choices=["de", "us"], default="de")
    parser.add_argument("--owner", type=int, help="Owner id (default: current uid)")
    parser.add_argument("--identity", type=Path, default=None,
                        help="Noise identity (default: first found under "
                             "~/.config/pico-bridge/ or private/noise-ik-current/)")
    parser.add_argument("--retries", type=int, default=5, help="BLE scan retries")
    parser.add_argument("--timeout", type=int, default=10, help="BLE scan timeout (s)")
    args = parser.parse_args()
    sources = sum((args.stdin, args.clipboard, args.text is not None, args.visible))
    if sources > 1:
        raise SystemExit("Choose exactly one input source: --stdin, --clipboard, --text, or --visible.")
    if args.delay < 0 or args.delay > 300:
        raise SystemExit("--delay must be between 0 and 300 seconds.")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        raise SystemExit("aborted")


if __name__ == "__main__":
    main()
