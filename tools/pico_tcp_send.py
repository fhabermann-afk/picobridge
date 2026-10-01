#!/usr/bin/env python3
"""Noise IK over TCP for PicoBridge network endpoints.

Wire format (must match firmware/net_endpoint.c):
  message := 4-byte big-endian length || payload
  handshake request  := [0x05] || 80-byte IK initiator message
  handshake response := [0x35 bytes]  (type byte stripped by firmware)
  command frame      := [0x06] || nonce64 || ciphertext || tag
  receipt            := [0x06] || nonce64 || ciphertext || tag

All cryptography is delegated to NoiseIKInitiator from pico_bridge_ctl.py —
this module is framing only, so both transports cannot drift apart.
"""
import argparse
import time
import asyncio
import getpass
import importlib.util
import os
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BRIDGE_ERR_BUSY = 4  # bridge_core: previous command still typing
CTL_PATH = HERE / "pico_bridge_ctl.py"
DEFAULT_PORT = 44901


def load_ctl():
    spec = importlib.util.spec_from_file_location("pico_bridge_ctl", CTL_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {CTL_PATH} (keep it next to pico_tcp_send.py)")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoiseTcpSession:
    def __init__(self, ctl, host, port, identity_path, timeout=10.0):
        self.ctl = ctl
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.noise = None
        self._identity = identity_path

    def _send_frame(self, payload: bytes):
        self.sock.sendall(len(payload).to_bytes(4, "big") + payload)

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("device closed the connection")
            buf += chunk
        return bytes(buf)

    def _recv_frame(self) -> bytes:
        head = self._recv_exact(4)
        length = int.from_bytes(head, "big")
        if not 1 <= length <= 65535:
            raise ConnectionError(f"invalid frame length {length}")
        return self._recv_exact(length)

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self.noise = self.ctl.NoiseIKInitiator(self._identity)
        init = self.noise.begin_handshake()
        self._send_frame(bytes([self.ctl.CMD_NOISE]) + init)
        response = self._recv_frame()
        if len(response) != 1 + 53 or response[0] != self.ctl.CMD_NOISE:
            raise ConnectionError(f"unexpected handshake response {len(response)}B")
        self.noise.complete_handshake(response[1:])

    def command(self, plaintext: bytes) -> int:
        """Send an authenticated command; return the device receipt status."""
        self._send_frame(self.noise.encrypt_packet(plaintext))
        receipt = self._recv_frame()
        return self.noise.verify_transport_ack(receipt)

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()


def clipboard_backend():
    """Return the session's safe clipboard reader, or None.

    Do not use a shell command: it would risk the secret being interpolated
    into argv or shell diagnostics.  The password manager remains owner of
    clearing the clipboard timeout.
    """
    if os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste"):
        return ["wl-paste", "--no-newline"]
    if os.environ.get("DISPLAY") or os.environ.get("XAUTHORITY"):
        if shutil.which("xclip"):
            return ["xclip", "-selection", "clipboard", "-o"]
        if shutil.which("xsel"):
            return ["xsel", "--clipboard", "--output"]
    return None


def clipboard_read():
    cmd = clipboard_backend()
    if cmd is None:
        raise SystemExit(
            "Kein Clipboard-Backend: wl-clipboard (Wayland) oder xclip/xsel "
            "(X11) installieren und in der grafischen Sitzung ausführen.")
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise SystemExit("Clipboard-Lesen fehlgeschlagen: " +
                         result.stderr.decode(errors="replace").strip())
    # xclip/xsel commonly append LF; it is not part of a copied password.
    return result.stdout.rstrip(b"\r\n")


def stage_and_confirm(session, ctl, packet, confirm, label,
                      busy_deadline_s=20.0):
    """Stage, then confirm. A long password is still being typed when the
    next stage arrives: the device answers BUSY (status=4) until the
    previous execution drains, so retry until idle instead of failing."""
    deadline = time.monotonic() + busy_deadline_s
    while True:
        try:
            session.command(packet)
            break
        except ctl.NoiseHandshakeError as exc:
            # verify_transport_ack raises on every non-zero status; only
            # BRIDGE_ERR_BUSY (device still typing) is retryable.
            if "status=4" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
    status = session.command(confirm)
    if status != 0:
        raise SystemExit(f"{label}-confirm abgelehnt (status={status})")


def resolve_identity(explicit: str | None, fleet_entry=None) -> str:
    if explicit:
        return explicit
    if fleet_entry and fleet_entry.get("identity"):
        return str(Path(fleet_entry["identity"]).expanduser())
    candidates = [
        Path.home() / ".config/pico-bridge/noise-ik.json",
        HERE.parent / "private/noise-ik-current/noise-ik.json",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    raise SystemExit("keine Noise-Identität gefunden (--identity verwenden)")


async def amain():
    parser = argparse.ArgumentParser(
        prog="pico-tcp-send",
        description="PicoBridge network endpoint: Noise IK over TCP, wie BLE aber ohne Funk")
    parser.add_argument("target", help="host[:port] des Picos (Default-Port 44901)")
    parser.add_argument("-t", "--text", help="sichtbarer Text (KEIN Passwort)")
    parser.add_argument("--stdin", action="store_true", help="Secret von stdin lesen")
    parser.add_argument("--clipboard", action="store_true",
                        help="Secret aus der grafischen Zwischenablage lesen (wl-paste/xclip/xsel)")
    parser.add_argument("--mode", choices=["password", "text"], default="password")
    parser.add_argument("-d", "--delay", type=int, default=0,
                        help="Sekunden zwischen Connect und Stage (Default 0; "
                             "der TCP-Pfad ist schnell, Countdown wie bei BLE meist unnötig)")
    parser.add_argument("--no-enter", dest="enter", action="store_false")
    parser.add_argument("--layout", choices=["de", "us"], default="us",
                        help="Default us: Netzwerk-Picos hängen an Boot-Prompts")
    parser.add_argument("--identity", default=None)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    ctl = load_ctl()
    try:
        import pico_fleet
    except ImportError:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location("pico_fleet", HERE / "pico_fleet.py")
        pico_fleet = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(pico_fleet)
    fleet_entry = pico_fleet.resolve(args.target)
    if fleet_entry:
        if not fleet_entry.get("host"):
            raise SystemExit(f"fleet-Alias {args.target!r} hat keinen host-Eintrag")
        print(f"Flotte: {args.target} -> {fleet_entry['host']}", file=sys.stderr)
        target = fleet_entry["host"]
    else:
        target = args.target
    host, _, port_s = target.partition(":")
    port = int(port_s) if port_s else DEFAULT_PORT

    sources = sum((args.stdin, args.clipboard, args.text is not None))
    if sources > 1:
        raise SystemExit("Genau eine Quelle: --stdin, --clipboard oder --text.")
    if args.clipboard:
        raw = clipboard_read()
    elif args.stdin:
        raw = sys.stdin.buffer.read().rstrip(b"\r\n")
    elif args.text is not None:
        raw = args.text.encode("utf-8")
    else:
        raw = getpass.getpass("Secret for PicoBridge target (input hidden): ").encode("utf-8")
    if not raw:
        raise SystemExit("Leere Eingabe abgebrochen.")
    if len(raw) > 1024:
        raise SystemExit(f"Eingabe zu lang ({len(raw)} Byte, Maximum 1024).")

    mode = ctl.BRIDGE_MODE_TEXT if (args.text is not None or args.mode == "text") \
        else ctl.BRIDGE_MODE_PASSWORD
    layout = ctl.BRIDGE_LAYOUT_DE if args.layout == "de" else ctl.BRIDGE_LAYOUT_US
    owner = os.geteuid()
    identity = resolve_identity(args.identity, fleet_entry)

    def exchange():
        with NoiseTcpSession(ctl, host, port, identity) as s:
            print(f"Noise IK handshake OK — {host}:{port} authentifiziert")
            if args.delay > 0:
                print(f"{args.delay}s Countdown...", file=sys.stderr)
                time.sleep(args.delay)
            cmd_id = secrets.randbelow(0xFFFFFFFE) + 1
            stage_and_confirm(
                s, ctl, ctl.build_stage_packet(owner, cmd_id, layout, mode, 0, raw),
                ctl.build_confirm_packet(owner, cmd_id), "stage")
            print(f"OK: {len(raw)} Zeichen gesendet.")
            if args.enter:
                enter_id = secrets.randbelow(0xFFFFFFFE) + 1
                enter = ctl.build_stage_packet(
                    owner, enter_id, layout, ctl.BRIDGE_MODE_TEXT,
                    ctl.BRIDGE_FLAG_ALLOW_LF, b"\n")
                stage_and_confirm(
                    s, ctl, enter, ctl.build_confirm_packet(owner, enter_id), "Enter")
                print("OK: Enter gesendet.")

    await asyncio.get_running_loop().run_in_executor(None, exchange)


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        raise SystemExit("abgebrochen")
    except (ConnectionError, socket.timeout, TimeoutError) as exc:
        raise SystemExit(f"Verbindung fehlgeschlagen: {exc}")
