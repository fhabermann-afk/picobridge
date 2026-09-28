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
import asyncio
import getpass
import importlib.util
import secrets
import socket
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
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
        if len(response) != 53:
            raise ConnectionError(f"unexpected handshake response length {len(response)}")
        self.noise.complete_handshake(response)

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


def resolve_identity(explicit: str | None) -> str:
    if explicit:
        return explicit
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
    host, _, port_s = args.target.partition(":")
    port = int(port_s) if port_s else DEFAULT_PORT

    if args.stdin:
        raw = sys.stdin.buffer.read().rstrip(b"\n")
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
    owner = __import__("os").geteuid()
    identity = resolve_identity(args.identity)

    def exchange():
        with NoiseTcpSession(ctl, host, port, identity) as s:
            print(f"Noise IK handshake OK — {host}:{port} authentifiziert")
            if args.delay > 0:
                print(f"{args.delay}s Countdown...", file=sys.stderr)
                time = __import__("time")
                time.sleep(args.delay)
            cmd_id = secrets.randbelow(0xFFFFFFFE) + 1
            status = s.command(ctl.build_stage_packet(owner, cmd_id, layout, mode, 0, raw))
            if status != 0:
                raise SystemExit(f"stage abgelehnt (status={status})")
            status = s.command(ctl.build_confirm_packet(owner, cmd_id))
            if status != 0:
                raise SystemExit(f"confirm abgelehnt (status={status})")
            print(f"OK: {len(raw)} Zeichen gesendet.")
            if args.enter:
                time = __import__("time")
                time.sleep(0.15)
                enter_id = secrets.randbelow(0xFFFFFFFE) + 1
                enter = ctl.build_stage_packet(
                    owner, enter_id, layout, ctl.BRIDGE_MODE_TEXT,
                    ctl.BRIDGE_FLAG_ALLOW_LF, b"\n")
                status = s.command(enter)
                if status != 0:
                    raise SystemExit(f"enter-stage abgelehnt (status={status})")
                status = s.command(ctl.build_confirm_packet(owner, enter_id))
                if status != 0:
                    raise SystemExit(f"enter-confirm abgelehnt (status={status})")
                print("OK: Enter gesendet.")

    await asyncio.get_running_loop().run_in_executor(None, exchange)


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        raise SystemExit("abgebrochen")
    except (ConnectionError, socket.timeout, TimeoutError) as exc:
        raise SystemExit(f"Verbindung fehlgeschlagen: {exc}")
