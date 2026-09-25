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
CACHE_PATH = Path.home() / ".config" / "pico-bridge" / "last-device"


def load_ctl():
    spec = importlib.util.spec_from_file_location("pico_bridge_ctl", CTL_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {CTL_PATH} (keep it next to pico-send.py)")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_cached_device():
    try:
        addr = CACHE_PATH.read_text().strip()
    except OSError:
        return None
    # BLE address (public or random): 12 hex digits with : or - separators
    parts = addr.replace("-", ":").split(":")
    if len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789abcdefABCDEF" for c in p) for p in parts):
        return addr
    return None


def write_cached_device(addr):
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(addr + "\n")
    except OSError:
        pass  # cache is a speed-up only, never fatal


async def connect_fast(ctl, timeout, retries, rescan):
    """Connect with the lowest possible latency.

    1. If we talked to a PicoBridge before, connect straight to its cached
       address (BlueZ page: ~1-3 s instead of scan + connect ~13 s).
    2. Otherwise scan with an early-exit callback: as soon as the first
       PicoBridge advert, the scan stops — BleakScanner.discover() always
       burns its full timeout, which is the 10 s most users notice.
    Retries the whole sequence on intermittent BLE failures.
    """
    from bleak import BleakClient, BleakScanner

    last = None
    for attempt in range(1, retries + 1):
        if attempt > 1:
            await asyncio.sleep(2)
        cached = None if rescan else read_cached_device()
        if cached:
            try:
                client = BleakClient(cached)
                await asyncio.wait_for(client.connect(), timeout=timeout)
                print(f"  cached device {cached} connected", file=sys.stderr)
                return cached, client
            except Exception as exc:
                last = exc
                print(f"  cached device unreachable ({exc}); falling back to scan", file=sys.stderr)
        # Early-exit scan
        try:
            match = None
            found = asyncio.Event()

            async def on_adv(device, advertisement):
                nonlocal match
                if match is None and "PicoBridge" in (device.name or ""):
                    match = device
                    found.set()

            # NOTE: BleakScanner takes `detection_callback`; a wrong keyword
            # is swallowed by **kwargs and silently yields zero events.
            scanner = BleakScanner(detection_callback=on_adv)
            await scanner.start()
            try:
                await asyncio.wait_for(found.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass
            finally:
                await scanner.stop()
            if match is None:
                raise RuntimeError("No PicoBridge device found in range.")
            client = BleakClient(match)
            await asyncio.wait_for(client.connect(), timeout=timeout)
            write_cached_device(client.address if hasattr(client, "address") else match.address)
            return match.address, client
        except Exception as exc:
            last = exc
            print(f"  scan attempt {attempt}/{retries} failed: {exc}", file=sys.stderr)
    raise SystemExit(f"giving up after {retries} attempts: {last}")


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
        raise SystemExit("Leere Eingabe abgebrochen.")
    if len(raw) > 1024:
        raise SystemExit(f"Eingabe zu lang ({len(raw)} Byte, Maximum 1024).")

    mode = ctl.BRIDGE_MODE_TEXT if (args.text is not None or args.visible or args.mode == "text") \
        else ctl.BRIDGE_MODE_PASSWORD
    layout = ctl.BRIDGE_LAYOUT_DE if args.layout == "de" else ctl.BRIDGE_LAYOUT_US
    owner = args.owner if args.owner is not None else os.geteuid()
    identity = args.identity or resolve_default_identity()
    if not identity.is_file():
        raise SystemExit(f"Noise-Identität nicht gefunden: {identity}\n"
                         "Erzeugen mit tools/noise_ik_provision.py oder --identity PFAD angeben.")

    # Connect and authenticate BEFORE the countdown: the BLE handshake never
    # steals window focus, and after the countdown stage+confirm fire
    # back-to-back so the device's short stage TTL can never expire.
    # With a cached device address this costs ~1-3 s and happens while the
    # user is still switching to the target window.
    device, client = await connect_fast(ctl, args.timeout, args.retries, args.rescan)
    try:
        noise = await ctl.perform_noise_handshake(client, str(identity))

        if args.delay > 0:
            print(f"\n{args.delay} Sekunden — jetzt Ziel-Fenster fokussieren!", file=sys.stderr)
            for remaining in range(args.delay, 0, -1):
                print(f"  sende in {remaining}...", end="\r", file=sys.stderr, flush=True)
                await asyncio.sleep(1)
            print("  los!            ", file=sys.stderr)

        cmd_id = secrets.randbelow(0xFFFFFFFE) + 1
        packet = ctl.build_stage_packet(owner, cmd_id, layout, mode, 0, raw)
        await ctl.send_command(client, packet, noise=noise)
        await ctl.send_command(client, ctl.build_confirm_packet(owner, cmd_id), noise=noise)
        print(f"OK: {len(raw)} Zeichen gesendet ({'Passwort' if mode == ctl.BRIDGE_MODE_PASSWORD else 'Text'}-Modus).")

        if args.enter:
            await asyncio.sleep(0.15)
            enter_id = secrets.randbelow(0xFFFFFFFE) + 1
            enter_packet = ctl.build_stage_packet(
                owner, enter_id, layout, ctl.BRIDGE_MODE_TEXT, ctl.BRIDGE_FLAG_ALLOW_LF, b"\n")
            await ctl.send_command(client, enter_packet, noise=noise)
            await ctl.send_command(client, ctl.build_confirm_packet(owner, enter_id), noise=noise)
            print("OK: Enter gesendet.")
    finally:
        await client.disconnect()


def main():
    parser = argparse.ArgumentParser(
        prog="pico-send", description="Bequemes Senden von Text/Passwort zum PicoBridge-USB-Ziel")
    parser.add_argument("-t", "--text", help="Text direkt übergeben (sichtbarer Modus, KEIN Passwort!)")
    parser.add_argument("--visible", action="store_true", help="Text interaktiv sichtbar eingeben")
    parser.add_argument("--stdin", action="store_true", help="Read the secret from stdin")
    parser.add_argument("--clipboard", action="store_true",
                        help="Read secret from the system clipboard (KeePassXC etc.); does not clear it")
    parser.add_argument("--mode", choices=["password", "text"], default="password",
                        help="Modus für Prompt/stdin (Default: password, unsichtbar)")
    parser.add_argument("-d", "--delay", type=int, default=5,
                        help="Countdown-Sekunden vor dem Tippen (Default: 5, 0=sofort)")
    parser.add_argument("--no-enter", dest="enter", action="store_false",
                        help="Kein Enter nach dem Passwort senden (Default: Enter an)")
    parser.add_argument("--layout", choices=["de", "us"], default="de")
    parser.add_argument("--owner", type=int, help="Owner-ID (Default: aktuelle UID)")
    parser.add_argument("--identity", type=Path, default=None,
                        help="Noise-Identitaet (Default: gefundene unter "
                             "~/.config/pico-bridge/ oder private/noise-ik-current/)")
    parser.add_argument("--retries", type=int, default=5, help="BLE-Scan-Wiederholungen")
    parser.add_argument("--timeout", type=int, default=10, help="BLE-Scan-Timeout (s)")
    parser.add_argument("--rescan", action="store_true",
                        help="Ignoriere die letzte bekannte Adresse und neu scannen")
    args = parser.parse_args()
    sources = sum((args.stdin, args.clipboard, args.text is not None, args.visible))
    if sources > 1:
        raise SystemExit("Choose exactly one input source: --stdin, --clipboard, --text, or --visible.")
    if args.delay < 0 or args.delay > 300:
        raise SystemExit("--delay muss zwischen 0 und 300 Sekunden liegen.")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        raise SystemExit("abgebrochen")


if __name__ == "__main__":
    main()
