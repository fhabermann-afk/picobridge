#!/usr/bin/env python3
"""Host-side CLI for staging keystrokes to the PicoBridge device over BLE.

Sends UTF-8 text or a password to the device's BLE command
characteristic. The device feeds it to bridge_core_stage and emits USB HID
keyboard reports.

Usage:
  pico_bridge_ctl.py stage --text "Hello World" --owner 1 --id 100
  pico_bridge_ctl.py stage --prompt --mode password --owner 1 --id 101
  pico_bridge_ctl.py stage --file /path/to/script.sh --owner 1 --id 102

Passwords must never appear on the command line (shell history, process
table). Use --prompt (getpass, no echo) or --file with 0600 permissions.

Uses dbus + bluetoothctl for BLE communication (Linux BlueZ).
The device must already be paired/bonded.
"""
import argparse
import asyncio
import base64
import json
import struct
import sys
import time
import logging
import hashlib
import os
import stat
from pathlib import Path

try:
    from bleak import BleakClient
    from bleak.backends.device import BLEDevice
except ImportError:
    print("Install with: pip install bleak", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# BLE UUIDs — must match firmware/bridge_main.c
# Custom 128-bit command service: 6e400001-b9a9-8132-8f32-0a9e1b8c7d4e
BRIDGE_SERVICE_UUID = "6e400001-b9a9-8132-8f32-0a9e1b8c7d4e"
# Command characteristic: 6e400002-b9a9-8132-8f32-0a9e1b8c7d4e
COMMAND_CHAR_UUID = "6e400002-b9a9-8132-8f32-0a9e1b8c7d4e"

# Command types (must match firmware)
CMD_STAGE = 1
CMD_CONFIRM = 2
CMD_CANCEL = 3
CMD_TICK = 4
CMD_NOISE = 5
CMD_CONTROLLER_ADD = 7
CMD_CONTROLLER_REVOKE = 8

# Bridge modes (must match bridge_core.h)
BRIDGE_LAYOUT_US = 1
BRIDGE_LAYOUT_DE = 2
BRIDGE_MODE_PASSWORD = 1
BRIDGE_MODE_TEXT = 2
CONTROLLER_ROLE_OPERATOR = 1
CONTROLLER_ROLE_ADMIN = 2

# Bridge flags
BRIDGE_FLAG_ALLOW_LF = 0x01
BRIDGE_FLAG_ALLOW_TAB = 0x02

LOG = logging.getLogger("pico_bridge_ctl")


# ---- Mutually authenticated Noise IK initiator ----

CMD_ENCRYPTED = 6
NOISE_INIT_MESSAGE_LEN = 80  # e(32) || EncryptAndHash(s)(32 + tag16)
NOISE_RESPONSE_MESSAGE_LEN = 53  # e(32) || EncryptAndHash("PBIK1")(5 + tag16)
NOISE_ACK = b"PBIK1"
TRANSPORT_ACK = b"PBOK1"


class NoiseHandshakeError(RuntimeError):
    """The peer did not prove possession of the provisioned Noise IK key."""


def _decode_noise_key(value, field):
    if not isinstance(value, str):
        raise NoiseHandshakeError(f"invalid {field} in Noise identity")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise NoiseHandshakeError(f"invalid {field} in Noise identity") from exc
    if len(raw) != 32:
        raise NoiseHandshakeError(f"invalid {field} length in Noise identity")
    return raw


def load_noise_identity(identity_path):
    """Load one locally provisioned host identity without accepting loose perms."""
    path = Path(identity_path).expanduser()
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise NoiseHandshakeError("Noise identity must be a private regular file owned by this user")
        raw = path.read_bytes()
        if len(raw) > 4096:
            raise NoiseHandshakeError("Noise identity is unexpectedly large")
        data = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NoiseHandshakeError("could not read private Noise identity") from exc
    if not isinstance(data, dict) or data.get("schema") != 1 or data.get("protocol") != NoiseIKInitiator.PROTO.decode():
        raise NoiseHandshakeError("unsupported Noise identity format")
    return (_decode_noise_key(data.get("initiator_private_b64"), "initiator private key"),
            _decode_noise_key(data.get("device_public_b64"), "device public key"))


class NoiseIKInitiator:
    """Noise_IK_25519_ChaChaPoly_SHA256 initiator with pinned device identity."""

    PROTO = b"Noise_IK_25519_ChaChaPoly_SHA256"

    def __init__(self, identity_path):
        initiator_private, device_public = load_noise_identity(identity_path)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self.static_priv = X25519PrivateKey.from_private_bytes(initiator_private)
        self.static_pub = self.static_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.device_pub = X25519PublicKey.from_public_bytes(device_public)
        self._h = hashlib.sha256(self.PROTO).digest()
        self._ck = self._h
        self._mix_hash(device_public)  # IK pre-message: <- s
        self._nonce = 0
        self._key = None  # handshake CipherState only
        self._send_key = None
        self._receive_key = None
        self._send_nonce = 0
        self._receive_nonce = 0
        self.eph_priv = None
        self.eph_pub = None

    @staticmethod
    def _noise_nonce(counter):
        if not 0 <= counter < (1 << 64):
            raise NoiseHandshakeError("Noise nonce exhausted")
        return b"\0" * 4 + counter.to_bytes(8, "little")

    def _mix_hash(self, data):
        self._h = hashlib.sha256(self._h + data).digest()

    def _mix_key(self, data):
        import hmac
        prk = hmac.new(self._ck, data, hashlib.sha256).digest()
        t1 = hmac.new(prk, b"\x01", hashlib.sha256).digest()
        t2 = hmac.new(prk, t1 + b"\x02", hashlib.sha256).digest()
        self._ck, self._key, self._nonce = t1, t2, 0

    def _encrypt_and_hash(self, plaintext):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        if self._key is None:
            raise NoiseHandshakeError("Noise cipher key missing")
        ciphertext = ChaCha20Poly1305(self._key).encrypt(self._noise_nonce(self._nonce), plaintext, self._h)
        self._nonce += 1
        self._mix_hash(ciphertext)
        return ciphertext

    def _decrypt_and_hash(self, ciphertext):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        if self._key is None:
            raise NoiseHandshakeError("Noise cipher key missing")
        try:
            plaintext = ChaCha20Poly1305(self._key).decrypt(self._noise_nonce(self._nonce), ciphertext, self._h)
        except InvalidTag as exc:
            raise NoiseHandshakeError("device authentication failed") from exc
        self._nonce += 1
        self._mix_hash(ciphertext)
        return plaintext

    def _split(self):
        """Noise Split(): derive distinct initiator-send and initiator-receive keys."""
        import hmac
        prk = hmac.new(self._ck, b"", hashlib.sha256).digest()
        first = hmac.new(prk, b"\x01", hashlib.sha256).digest()
        second = hmac.new(prk, first + b"\x02", hashlib.sha256).digest()
        self._send_key, self._receive_key = first, second
        self._send_nonce = 0
        self._receive_nonce = 0
        self._key = None

    def begin_handshake(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self.eph_priv = X25519PrivateKey.generate()
        self.eph_pub = self.eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._mix_hash(self.eph_pub)                       # -> e
        self._mix_key(self.eph_priv.exchange(self.device_pub))  # es
        encrypted_static = self._encrypt_and_hash(self.static_pub)  # s
        self._mix_key(self.static_priv.exchange(self.device_pub))   # ss
        return self.eph_pub + encrypted_static

    def complete_handshake(self, response):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        if self.eph_priv is None or len(response) != NOISE_RESPONSE_MESSAGE_LEN:
            raise NoiseHandshakeError("unexpected Noise response length")
        responder_eph = bytes(response[:32])
        encrypted_ack = bytes(response[32:])
        responder_key = X25519PublicKey.from_public_bytes(responder_eph)
        self._mix_hash(responder_eph)                          # <- e
        self._mix_key(self.eph_priv.exchange(responder_key))   # ee
        self._mix_key(self.static_priv.exchange(responder_key))  # se
        if self._decrypt_and_hash(encrypted_ack) != NOISE_ACK:
            raise NoiseHandshakeError("device authentication acknowledgement mismatch")
        self._split()

    def is_ready(self):
        return self._send_key is not None and self._receive_key is not None

    def encrypt_packet(self, plaintext):
        """Frame a transport command as CMD_ENCRYPTED || nonce64 || ciphertext/tag."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        if not self.is_ready():
            raise NoiseHandshakeError("Noise handshake is not authenticated")
        nonce = self._send_nonce
        ciphertext = ChaCha20Poly1305(self._send_key).encrypt(self._noise_nonce(nonce), plaintext, None)
        self._send_nonce += 1
        return bytes([CMD_ENCRYPTED]) + nonce.to_bytes(8, "little") + ciphertext

    def verify_transport_ack(self, packet):
        """Verify the device's encrypted receipt after every transport command."""
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        packet = bytes(packet)
        if not self.is_ready() or len(packet) != 1 + 8 + len(TRANSPORT_ACK) + 1 + 16 or packet[0] != CMD_ENCRYPTED:
            raise NoiseHandshakeError("missing encrypted device receipt")
        nonce = int.from_bytes(packet[1:9], "little")
        if nonce != self._receive_nonce:
            raise NoiseHandshakeError("unexpected device receipt nonce")
        try:
            plaintext = ChaCha20Poly1305(self._receive_key).decrypt(
                self._noise_nonce(nonce), packet[9:], None
            )
        except InvalidTag as exc:
            raise NoiseHandshakeError("invalid encrypted device receipt") from exc
        self._receive_nonce += 1
        if len(plaintext) != len(TRANSPORT_ACK) + 1 or plaintext[:len(TRANSPORT_ACK)] != TRANSPORT_ACK:
            raise NoiseHandshakeError("unexpected encrypted device receipt")
        status = plaintext[-1]
        if status != 0:
            raise NoiseHandshakeError(f"device rejected bridge command (status={status})")
        return status


def build_stage_packet(owner, cmd_id, layout, mode, flags, payload_bytes):
    """Build a BLE stage command packet.

    Packet format:
      byte 0: command type (1=stage)
      bytes 1-4: owner (uint32 LE)
      bytes 5-8: id (uint32 LE)
      byte 9: layout (1=US, 2=DE)
      byte 10: mode (1=password, 2=text)
      byte 11: flags
      bytes 12-13: utf8_len (uint16 LE)
      bytes 14+: utf8 payload
    """
    packet = bytearray()
    packet.append(CMD_STAGE)
    packet += struct.pack("<I", owner)
    packet += struct.pack("<I", cmd_id)
    packet.append(layout)
    packet.append(mode)
    packet.append(flags)
    packet += struct.pack("<H", len(payload_bytes))
    packet += payload_bytes
    return bytes(packet)


def build_confirm_packet(owner, cmd_id):
    packet = bytearray()
    packet.append(CMD_CONFIRM)
    packet += struct.pack("<I", owner)
    packet += struct.pack("<I", cmd_id)
    return bytes(packet)


def build_cancel_packet(owner, cmd_id):
    packet = bytearray()
    packet.append(CMD_CANCEL)
    packet += struct.pack("<I", owner)
    packet += struct.pack("<I", cmd_id)
    return bytes(packet)


async def scan_and_connect(timeout=10):
    """Scan for nearby PicoBridge devices and connect to the first one."""
    from bleak import BleakScanner
    LOG.info("Scanning for PicoBridge devices (timeout=%ds)...", timeout)
    devices = await BleakScanner.discover(timeout=timeout)
    pico_devices = [d for d in devices if "PicoBridge" in (d.name or "")]
    if not pico_devices:
        LOG.error("No PicoBridge device found in range.")
        sys.exit(1)
    if len(pico_devices) > 1:
        LOG.info("Multiple devices found:")
        for i, d in enumerate(pico_devices):
            LOG.info("  [%d] %s (%s) RSSI=%d", i, d.name, d.address, d.rssI if hasattr(d, 'rssi') else 0)
        choice = int(input("Select device: "))
        device = pico_devices[choice]
    else:
        device = pico_devices[0]
    LOG.info("Connecting to %s (%s)", device.name, device.address)
    client = BleakClient(device)
    await client.connect()
    return device, client


# BLE MTU for write-without-response: 20 bytes (3-byte ATT overhead)
BLE_MTU_PAYLOAD = 19  # 1 byte fragment header + 19 bytes data
FRAG_MORE = 0x01


def fragment_packet(packet):
    """Fragment a command packet into BLE write-without-response chunks.

    Protocol:
      Fragment byte (1) | payload (19 max)
      Bit 0 = MORE (set if more fragments follow)
      Bits 1-7 = sequence number (0 for first fragment)
    """
    fragments = []
    offset = 0
    seq = 0
    while offset < len(packet):
        frag_len = min(BLE_MTU_PAYLOAD, len(packet) - offset)
        more = offset + frag_len < len(packet)
        hdr = (seq << 1) | (1 if more else 0)
        frag = bytearray()
        frag.append(hdr)
        frag += packet[offset:offset + frag_len]
        fragments.append(bytes(frag))
        offset += frag_len
        seq += 1
    return fragments


async def send_command(client, packet, expect_response=False, noise=None):
    """Send a command packet to the device's command characteristic.

    If noise (NoiseIKInitiator) is provided and handshake is complete,
    the packet is encrypted with ChaChaPoly before fragmentation.
    Fragments if the packet exceeds the BLE MTU.
    """
    if noise and noise.is_ready():
        packet = noise.encrypt_packet(packet)
        LOG.debug("Encrypted packet: %d bytes", len(packet))
    LOG.debug("Sending %d bytes: %s", len(packet), packet.hex())
    fragments = fragment_packet(packet)
    for i, frag in enumerate(fragments):
        LOG.debug("Fragment %d/%d (%d bytes)", i + 1, len(fragments), len(frag))
        try:
            await client.write_gatt_char(COMMAND_CHAR_UUID, frag, response=False)
        except Exception:
            await client.write_gatt_char(COMMAND_CHAR_UUID, frag, response=True)
        # Small delay between fragments to avoid flooding
        if expect_response or len(fragments) > 1:
            await asyncio.sleep(0.01)
    if noise and noise.is_ready():
        noise.verify_transport_ack(await client.read_gatt_char(COMMAND_CHAR_UUID))
    elif expect_response:
        await asyncio.sleep(0.05)


async def perform_noise_handshake(client, identity_path) -> NoiseIKInitiator:
    """Authenticate the provisioned Pico and establish a Noise IK transport session."""
    noise = NoiseIKInitiator(identity_path)
    init_message = noise.begin_handshake()
    if len(init_message) != NOISE_INIT_MESSAGE_LEN:
        raise NoiseHandshakeError("invalid local Noise handshake message")
    await send_command(client, bytes([CMD_NOISE]) + init_message)
    LOG.debug("Sent authenticated Noise IK initiator message (%d bytes)", len(init_message))

    response = bytes(await client.read_gatt_char(COMMAND_CHAR_UUID))
    if len(response) != NOISE_RESPONSE_MESSAGE_LEN:
        raise NoiseHandshakeError(f"unexpected Noise response length {len(response)}")
    noise.complete_handshake(response)
    LOG.info("Mutual Noise IK handshake complete — device identity verified")
    return noise


async def cmd_stage(args):
    """Stage keystrokes on the device."""
    # Gather payload
    if args.prompt:
        import getpass
        if args.mode == "password":
            # getpass disables echo; the value never touches shell history,
            # the process table, or stdout/stderr.
            secret = getpass.getpass("Password for PicoBridge (hidden input): ")
        else:
            secret = input("Text for PicoBridge: ")
        raw = secret.encode("utf-8")
    elif args.stdin:
        raw = sys.stdin.buffer.read()
    elif args.text:
        if args.mode == "password":
            LOG.error("Refusing --text with --mode password: the value would leak into shell history and the process table.")
            LOG.error("Use --prompt (hidden input) or --file (0600 regular file) for passwords.")
            sys.exit(1)
        raw = args.text.encode("utf-8")
    elif args.file:
        path = Path(args.file).expanduser()
        if args.mode == "password":
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                    LOG.error("Password file must be a regular file with 0600 permissions (got %s).", oct(info.st_mode & 0o777))
                    sys.exit(1)
            except OSError as exc:
                LOG.error("Cannot check password file: %s", exc)
                sys.exit(1)
        raw = path.read_bytes()
    else:
        LOG.error("Must specify --prompt, --text, --stdin, or --file")
        sys.exit(1)

    if not raw:
        LOG.error("Empty input")
        sys.exit(1)

    if len(raw) > 1024:
        LOG.error("Input too long (%d bytes), max 1024", len(raw))
        sys.exit(1)

    if args.mode == "password" and (args.allow_lf or args.allow_tab):
        # Firmware rejects these too (fail-closed); surface it early.
        LOG.error("Password mode forbids --allow-lf/--allow-tab (firmware policy).")
        sys.exit(1)

    flags = 0
    if args.allow_lf:
        flags |= BRIDGE_FLAG_ALLOW_LF
    if args.allow_tab:
        flags |= BRIDGE_FLAG_ALLOW_TAB

    mode = BRIDGE_MODE_TEXT if args.mode == "text" else BRIDGE_MODE_PASSWORD
    layout = BRIDGE_LAYOUT_DE if args.layout == "de" else BRIDGE_LAYOUT_US

    packet = build_stage_packet(
        owner=args.owner,
        cmd_id=args.id,
        layout=layout,
        mode=mode,
        flags=flags,
        payload_bytes=raw,
    )

    device, client = await scan_and_connect(args.timeout)
    try:
        noise = await perform_noise_handshake(client, args.noise_identity)
        await send_command(client, packet, noise=noise)
        LOG.info("Staged %d bytes (owner=%d, id=%d, mode=%s, layout=%s) [authenticated]",
                 len(raw), args.owner, args.id, args.mode, args.layout)

        if args.auto_confirm:
            confirm_pkt = build_confirm_packet(args.owner, args.id)
            await send_command(client, confirm_pkt, noise=noise)
            LOG.info("Auto-confirmed staging")
        elif not args.no_confirm:
            LOG.info("Run 'pico_bridge_ctl.py confirm --owner %d --id %d' to send keystrokes",
                     args.owner, args.id)
    finally:
        await client.disconnect()


async def cmd_confirm(args):
    """Confirm a previously staged entry."""
    packet = build_confirm_packet(args.owner, args.id)
    device, client = await scan_and_connect(args.timeout)
    try:
        noise = await perform_noise_handshake(client, args.noise_identity)
        await send_command(client, packet, noise=noise)
        LOG.info("Confirmed staging (owner=%d, id=%d) [authenticated]", args.owner, args.id)
    finally:
        await client.disconnect()


async def cmd_cancel(args):
    """Cancel a previously staged entry."""
    packet = build_cancel_packet(args.owner, args.id)
    device, client = await scan_and_connect(args.timeout)
    try:
        noise = await perform_noise_handshake(client, args.noise_identity)
        await send_command(client, packet, noise=noise)
        LOG.info("Cancelled staging (owner=%d, id=%d) [authenticated]", args.owner, args.id)
    finally:
        await client.disconnect()


def load_enrollment_public(path: Path) -> bytes:
    """Load a public controller enrollment file; reject links and malformed data."""
    path = Path(path).expanduser()
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > 4096:
            raise NoiseHandshakeError("invalid enrollment file")
        data = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NoiseHandshakeError("could not read enrollment file") from exc
    if not isinstance(data, dict) or data.get("schema") != 1 or \
       data.get("protocol") != NoiseIKInitiator.PROTO.decode() or \
       data.get("kind") != "picobridge-controller-enrollment":
        raise NoiseHandshakeError("unsupported enrollment file")
    return _decode_noise_key(data.get("initiator_public_b64"), "enrollment public key")


async def cmd_controller_add(args):
    """Add a public controller key through an authenticated admin session."""
    public_key = load_enrollment_public(args.public)
    role = CONTROLLER_ROLE_OPERATOR if args.role == "operator" else CONTROLLER_ROLE_ADMIN
    device, client = await scan_and_connect(args.timeout)
    try:
        noise = await perform_noise_handshake(client, args.noise_identity)
        await send_command(client, bytes([CMD_CONTROLLER_ADD, role]) + public_key, noise=noise)
        LOG.info("Controller added as %s [authenticated]", args.role)
    finally:
        await client.disconnect()


async def cmd_controller_revoke(args):
    """Revoke one non-recovery controller slot through another admin session."""
    if not 1 <= args.slot <= 4:
        raise NoiseHandshakeError("controller slot must be in 1..4")
    device, client = await scan_and_connect(args.timeout)
    try:
        noise = await perform_noise_handshake(client, args.noise_identity)
        await send_command(client, bytes([CMD_CONTROLLER_REVOKE, args.slot]), noise=noise)
        LOG.info("Controller slot %d revoked [authenticated]", args.slot)
    finally:
        await client.disconnect()


def add_noise_identity_argument(command):
    command.add_argument(
        "--noise-identity", type=Path,
        default=Path.home() / ".config" / "pico-bridge" / "noise-ik.json",
        help="Private local Noise IK identity (default: ~/.config/pico-bridge/noise-ik.json)",
    )


def main():
    parser = argparse.ArgumentParser(
        prog="pico_bridge_ctl",
        description="Stage keystrokes to PicoBridge device over BLE",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Stage command
    stage = sub.add_parser("stage", help="Stage keystrokes on the device")
    stage.add_argument("--text", type=str, help="Text to type (UTF-8; not allowed for passwords)")
    stage.add_argument("--prompt", action="store_true", help="Prompt for hidden input (recommended for passwords)")
    stage.add_argument("--stdin", action="store_true", help="Read payload from stdin")
    stage.add_argument("--file", type=Path, help="Read payload from file (0600 required for passwords)")
    stage.add_argument("--owner", type=int, required=True, help="Owner ID (uint32)")
    stage.add_argument("--id", type=int, required=True, help="Entry ID (uint32)")
    stage.add_argument("--mode", choices=["password", "text"], default="text",
                       help="Input mode (default: text)")
    stage.add_argument("--layout", choices=["us", "de"], default="us",
                       help="Keyboard layout (default: us)")
    stage.add_argument("--allow-lf", action="store_true", help="Allow LF (enter/return)")
    stage.add_argument("--allow-tab", action="store_true", help="Allow TAB character")
    add_noise_identity_argument(stage)
    stage.add_argument("--auto-confirm", action="store_true",
                       help="Send keystrokes immediately after staging")
    stage.add_argument("--no-confirm", action="store_true",
                       help="Stage only, do not prompt to confirm")
    stage.add_argument("--timeout", type=int, default=10, help="BLE scan timeout (seconds)")
    stage.set_defaults(func=cmd_stage)

    # Confirm command
    confirm = sub.add_parser("confirm", help="Confirm a staged entry")
    confirm.add_argument("--owner", type=int, required=True)
    confirm.add_argument("--id", type=int, required=True)
    confirm.add_argument("--timeout", type=int, default=10)
    add_noise_identity_argument(confirm)
    confirm.set_defaults(func=cmd_confirm)

    # Cancel command
    cancel = sub.add_parser("cancel", help="Cancel a staged entry")
    cancel.add_argument("--owner", type=int, required=True)
    cancel.add_argument("--id", type=int, required=True)
    cancel.add_argument("--timeout", type=int, default=10)
    add_noise_identity_argument(cancel)
    cancel.set_defaults(func=cmd_cancel)

    # Controller administration — requires a currently enrolled admin identity.
    controller = sub.add_parser("controller", help="Manage enrolled BLE controllers")
    controller_sub = controller.add_subparsers(dest="controller_cmd", required=True)
    controller_add = controller_sub.add_parser("add", help="Enroll public controller key")
    controller_add.add_argument("--public", type=Path, required=True,
                                help="public enrollment.json from the new controller")
    controller_add.add_argument("--role", choices=["operator", "admin"], default="operator")
    controller_add.add_argument("--timeout", type=int, default=10)
    add_noise_identity_argument(controller_add)
    controller_add.set_defaults(func=cmd_controller_add)
    controller_revoke = controller_sub.add_parser("revoke", help="Revoke controller slot 1..4")
    controller_revoke.add_argument("--slot", type=int, required=True)
    controller_revoke.add_argument("--timeout", type=int, default=10)
    add_noise_identity_argument(controller_revoke)
    controller_revoke.set_defaults(func=cmd_controller_revoke)

    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        asyncio.run(args.func(args))
    except NoiseHandshakeError as exc:
        LOG.error("Mutual device authentication failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
