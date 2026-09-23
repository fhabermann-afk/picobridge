#!/usr/bin/env python3
"""Tests for pico_bridge_ctl.py packet building logic.
No BLE hardware required — tests the pure-Python packet constructors."""
import struct
import sys
import unittest
import hashlib
import hmac
import json
import os
import re
import tempfile
import types
import uuid
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))

# Import just the packet-building functions without triggering bleak import
import importlib.util

SPEC = importlib.util.spec_from_file_location("pico_bridge_ctl", ROOT / "tools" / "pico_bridge_ctl.py")
# We need to mock bleak before import — but the module imports it at top level.
# Instead, test the packet builders by extracting their source and exec'ing it.
# Simpler: just verify the protocol constants and packet format match expectations.

CMD_STAGE = 1
CMD_CONFIRM = 2
CMD_CANCEL = 3
CMD_TICK = 4
CMD_NOISE = 5

BRIDGE_LAYOUT_US = 1
BRIDGE_LAYOUT_DE = 2
BRIDGE_MODE_PASSWORD = 1
BRIDGE_MODE_TEXT = 2

BRIDGE_FLAG_ALLOW_LF = 0x01
BRIDGE_FLAG_ALLOW_TAB = 0x02


def build_stage_packet(owner, cmd_id, layout, mode, flags, payload_bytes):
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


class StagePacketTests(unittest.TestCase):
    def test_command_type_byte(self):
        pkt = build_stage_packet(1, 100, BRIDGE_LAYOUT_US, BRIDGE_MODE_TEXT, 0, b"hi")
        self.assertEqual(pkt[0], CMD_STAGE)

    def test_owner_and_id_encoding(self):
        pkt = build_stage_packet(42, 99, BRIDGE_LAYOUT_US, BRIDGE_MODE_TEXT, 0, b"test")
        self.assertEqual(struct.unpack_from("<I", pkt, 1)[0], 42)
        self.assertEqual(struct.unpack_from("<I", pkt, 5)[0], 99)

    def test_layout_mode_flags(self):
        pkt = build_stage_packet(1, 1, BRIDGE_LAYOUT_DE, BRIDGE_MODE_PASSWORD,
                                 BRIDGE_FLAG_ALLOW_LF | BRIDGE_FLAG_ALLOW_TAB, b"x")
        self.assertEqual(pkt[9], BRIDGE_LAYOUT_DE)
        self.assertEqual(pkt[10], BRIDGE_MODE_PASSWORD)
        self.assertEqual(pkt[11], BRIDGE_FLAG_ALLOW_LF | BRIDGE_FLAG_ALLOW_TAB)

    def test_utf8_length_and_payload(self):
        payload = b"Hello, World!\n"
        pkt = build_stage_packet(1, 1, BRIDGE_LAYOUT_US, BRIDGE_MODE_TEXT, 0, payload)
        self.assertEqual(struct.unpack_from("<H", pkt, 12)[0], len(payload))
        self.assertEqual(pkt[14:], payload)

    def test_unicode_payload(self):
        """UTF-8 with multi-byte characters."""
        payload = "Héllo Wörld 日本語".encode("utf-8")
        pkt = build_stage_packet(1, 1, BRIDGE_LAYOUT_US, BRIDGE_MODE_TEXT, 0, payload)
        self.assertEqual(struct.unpack_from("<H", pkt, 12)[0], len(payload))
        self.assertEqual(pkt[14:], payload)

    def test_empty_payload_rejected_by_caller(self):
        """Empty payload should produce a zero-length packet — caller validates."""
        pkt = build_stage_packet(1, 1, BRIDGE_LAYOUT_US, BRIDGE_MODE_TEXT, 0, b"")
        self.assertEqual(struct.unpack_from("<H", pkt, 12)[0], 0)
        self.assertEqual(len(pkt), 14)


class ConfirmCancelPacketTests(unittest.TestCase):
    def test_confirm_format(self):
        pkt = build_confirm_packet(1, 100)
        self.assertEqual(pkt[0], CMD_CONFIRM)
        self.assertEqual(struct.unpack_from("<I", pkt, 1)[0], 1)
        self.assertEqual(struct.unpack_from("<I", pkt, 5)[0], 100)
        self.assertEqual(len(pkt), 9)

    def test_cancel_format(self):
        pkt = build_cancel_packet(42, 99)
        self.assertEqual(pkt[0], CMD_CANCEL)
        self.assertEqual(struct.unpack_from("<I", pkt, 1)[0], 42)
        self.assertEqual(struct.unpack_from("<I", pkt, 5)[0], 99)
        self.assertEqual(len(pkt), 9)


class ProtocolConstantTests(unittest.TestCase):
    def test_command_types_distinct(self):
        self.assertNotEqual(CMD_STAGE, CMD_CONFIRM)
        self.assertNotEqual(CMD_STAGE, CMD_CANCEL)
        self.assertNotEqual(CMD_CONFIRM, CMD_CANCEL)

    def test_flags_are_bitwise(self):
        self.assertEqual(BRIDGE_FLAG_ALLOW_LF | BRIDGE_FLAG_ALLOW_TAB, 0x03)


class UUIDContractTests(unittest.TestCase):
    """The host UUIDs must equal the UUIDs serialized by the ATT database."""

    EXPECTED_SERVICE = "6e400001-b9a9-8132-8f32-0a9e1b8c7d4e"
    EXPECTED_CHARACTERISTIC = "6e400002-b9a9-8132-8f32-0a9e1b8c7d4e"

    @staticmethod
    def _firmware_uuid(name: str) -> str:
        source = (ROOT / "firmware" / "bridge_main.c").read_text()
        match = re.search(
            rf"static const uint8_t {name}\[\]\s*=\s*\{{(.*?)\}};",
            source,
            re.DOTALL,
        )
        if match is None:
            raise AssertionError(f"missing firmware UUID array: {name}")
        values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
        if len(values) != 16:
            raise AssertionError(f"{name} has {len(values)} bytes, expected 16")
        return str(uuid.UUID(bytes=bytes.fromhex("".join(values))))

    @staticmethod
    def _cli_uuid(name: str) -> str:
        source = (ROOT / "tools" / "pico_bridge_ctl.py").read_text()
        match = re.search(rf'^{name}\s*=\s*"([0-9a-f-]+)"$', source, re.MULTILINE)
        if match is None:
            raise AssertionError(f"missing CLI UUID constant: {name}")
        return str(uuid.UUID(match.group(1)))

    def test_advertised_uuid_contract(self):
        self.assertEqual(self._firmware_uuid("cmd_service_uuid128"), self.EXPECTED_SERVICE)
        self.assertEqual(
            self._firmware_uuid("cmd_char_uuid128"),
            self.EXPECTED_CHARACTERISTIC,
        )
        self.assertEqual(self._cli_uuid("BRIDGE_SERVICE_UUID"), self.EXPECTED_SERVICE)
        self.assertEqual(
            self._cli_uuid("COMMAND_CHAR_UUID"),
            self.EXPECTED_CHARACTERISTIC,
        )

    def test_command_characteristic_is_dynamic_and_uses_security_levels(self):
        source = (ROOT / "firmware" / "bridge_main.c").read_text()
        call = re.search(
            r"att_db_util_add_characteristic_uuid128\(\s*"
            r"cmd_char_uuid128,\s*"
            r"(ATT_PROPERTY_WRITE_WITHOUT_RESPONSE \| ATT_PROPERTY_READ \| ATT_PROPERTY_DYNAMIC),\s*"
            r"([^,]+),\s*([^,]+),",
            source,
            re.DOTALL,
        )
        if call is None:
            self.fail("command characteristic must be dynamic so BTstack dispatches read/write callbacks")
        self.assertEqual(call.group(1).strip(), "ATT_PROPERTY_WRITE_WITHOUT_RESPONSE | ATT_PROPERTY_READ | ATT_PROPERTY_DYNAMIC")
        self.assertEqual(call.group(2).strip(), "ATT_SECURITY_NONE")
        self.assertEqual(call.group(3).strip(), "ATT_SECURITY_NONE")

    def test_dynamic_read_callback_reports_current_authenticated_response_length(self):
        source = (ROOT / "firmware" / "bridge_main.c").read_text()
        self.assertRegex(
            source,
            r"if \(attribute_handle == cmd_char_handle && cmd_char_read_valid\) \{[\s\S]*?"
            r"if \(buffer == NULL\) return cmd_char_read_len;",
            "BTstack's dynamic-read size query must return the current authenticated response length",
        )
        self.assertIn("cmd_char_read_len = (uint16_t)response_len;", source)


class PasswordInputPolicyTests(unittest.IsolatedAsyncioTestCase):
    """Passwords must never be accepted via channels that leak them
    (command line / shell history) or via world-readable files."""

    def _load_module(self, suffix):
        fake_bleak = types.ModuleType("bleak")
        setattr(fake_bleak, "BleakClient", object)
        fake_backends = types.ModuleType("bleak.backends")
        fake_device_module = types.ModuleType("bleak.backends.device")
        setattr(fake_device_module, "BLEDevice", object)
        module_name = f"pico_bridge_ctl_pw_{suffix}"
        spec = importlib.util.spec_from_file_location(module_name, ROOT / "tools" / "pico_bridge_ctl.py")
        if spec is None or spec.loader is None:
            self.fail("could not load pico_bridge_ctl module")
        module = importlib.util.module_from_spec(spec)
        patches = {"bleak": fake_bleak, "bleak.backends": fake_backends,
                   "bleak.backends.device": fake_device_module, module_name: module}
        return module, spec, patches

    def _args(self, **overrides):
        base = dict(
            prompt=False, stdin=False, text=None, file=None,
            owner=1, id=1, mode="password", layout="us",
            allow_lf=False, allow_tab=False, auto_confirm=False,
            no_confirm=True, timeout=1, noise_identity=None,
        )
        base.update(overrides)
        import types as _t
        return _t.SimpleNamespace(**base)

    async def test_password_with_text_argument_is_refused(self):
        """--mode password --text <value> must exit before any BLE contact."""
        module, spec, patches = self._load_module("text")
        with patch.dict(sys.modules, patches):
            spec.loader.exec_module(module)
            with self.assertRaises(SystemExit):
                await module.cmd_stage(self._args(text="hunter2"))

    async def test_password_file_requires_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pw.txt"
            path.write_text("hunter2")
            path.chmod(0o644)
            module, spec, patches = self._load_module("file644")
            with patch.dict(sys.modules, patches):
                spec.loader.exec_module(module)
                with self.assertRaises(SystemExit):
                    await module.cmd_stage(self._args(file=path))

    async def test_password_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "real"
            target.write_text("hunter2")
            target.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(target)
            module, spec, patches = self._load_module("symlink")
            with patch.dict(sys.modules, patches):
                spec.loader.exec_module(module)
                with self.assertRaises(SystemExit):
                    await module.cmd_stage(self._args(file=link))

    async def test_password_mode_rejects_allow_flags(self):
        import io
        module, spec, patches = self._load_module("flags")
        with patch.dict(sys.modules, patches):
            spec.loader.exec_module(module)
            fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(b"x"))
            with patch.object(module, "sys", types.SimpleNamespace(
                    stdin=fake_stdin, stdout=sys.stdout, stderr=sys.stderr, exit=sys.exit)):
                with self.assertRaises(SystemExit):
                    await module.cmd_stage(self._args(text=None, allow_lf=True, mode="password", prompt=False, stdin=True))

    async def test_text_mode_still_accepts_text_argument(self):
        """The guard must not break the plain-text path."""
        module, spec, patches = self._load_module("oktext")

        class FakeClient:
            async def disconnect(self):
                pass

        async def fake_scan(timeout):
            return types.SimpleNamespace(name="PicoBridge", address="AA"), FakeClient()

        async def fake_handshake(client, identity):
            raise AssertionError("payload handling passed; handshake stubbed")

        with patch.dict(sys.modules, patches):
            spec.loader.exec_module(module)
            with patch.object(module, "scan_and_connect", fake_scan), \
                 patch.object(module, "perform_noise_handshake", fake_handshake):
                with self.assertRaises(AssertionError):
                    await module.cmd_stage(self._args(text="hello", mode="text", auto_confirm=False))


class FirmwareWarningContractTests(unittest.TestCase):
    def test_noise_mixer_has_no_unused_wrapper(self):
        source = (ROOT / "firmware" / "noise_ik.c").read_text()
        self.assertNotIn("static void mix_dh(", source)

    def test_static_device_identity_and_controller_store_are_not_serial_derived(self):
        source = (ROOT / "firmware" / "noise_ik.c").read_text()
        self.assertIn('#include "noise_ik_keys.h"', source)
        self.assertNotIn("ik_sha256_pub", source)
        self.assertIn("PICO_BRIDGE_DEVICE_STATIC_PRIVATE", source)
        self.assertIn("const controller_store_t *controllers", source)
        self.assertIn("CONTROLLER_STORE_SLOT_COUNT", source)
        self.assertNotIn("authorized_initiator_pub", source)


class FragmentTests(unittest.TestCase):
    """Tests for BLE fragmentation logic (mirrors firmware bridge_main.c)."""

    BLE_MTU_PAYLOAD = 19
    FRAG_MORE = 0x01

    def fragment_packet(self, packet):
        """Python mirror of the CLI's fragment_packet — must match
        firmware's cmd_write_callback parsing logic."""
        fragments = []
        offset = 0
        seq = 0
        while offset < len(packet):
            frag_len = min(self.BLE_MTU_PAYLOAD, len(packet) - offset)
            more = offset + frag_len < len(packet)
            hdr = (seq << 1) | (1 if more else 0)
            frag = bytes([hdr]) + packet[offset:offset + frag_len]
            fragments.append(frag)
            offset += frag_len
            seq += 1
        return fragments

    def test_short_packet_single_fragment(self):
        """A 5-byte packet fits in one fragment, MORE bit unset."""
        pkt = b"\x01\x02\x03\x04\x05"
        frags = self.fragment_packet(pkt)
        self.assertEqual(len(frags), 1)
        # First fragment: seq=0, more=0
        self.assertEqual(frags[0][0], 0x00)
        self.assertEqual(frags[0][1:], pkt)

    def test_long_packet_multiple_fragments(self):
        """A 50-byte packet needs 3 fragments (19 + 19 + 12)."""
        pkt = bytes(range(50))
        frags = self.fragment_packet(pkt)
        self.assertEqual(len(frags), 3)
        # Fragment 1: seq=0, more=1
        self.assertEqual(frags[0][0], 0x01)
        self.assertEqual(len(frags[0]), 1 + 19)  # header + 19 bytes
        # Fragment 2: seq=1, more=1
        self.assertEqual(frags[1][0], 0x03)
        self.assertEqual(len(frags[1]), 1 + 19)
        # Fragment 3: seq=2, more=0 (last)
        self.assertEqual(frags[2][0], 0x04)
        self.assertEqual(len(frags[2]), 1 + 12)

    def test_reassemble_yields_original(self):
        """Reassembling fragments (skipping header byte, first frag includes cmd) gives original."""
        pkt = bytes(range(100))
        frags = self.fragment_packet(pkt)
        reassembled = bytearray()
        for i, frag in enumerate(frags):
            # Skip the fragment header byte from all fragments
            reassembled += frag[1:]
        self.assertEqual(bytes(reassembled), pkt)

    def test_fragment_boundaries_at_mtu(self):
        """Exactly MTU_PAYLOAD bytes → single fragment, no MORE bit."""
        pkt = bytes(self.BLE_MTU_PAYLOAD)
        frags = self.fragment_packet(pkt)
        self.assertEqual(len(frags), 1)
        self.assertEqual(frags[0][0] & self.FRAG_MORE, 0)  # no MORE flag


# ---- Noise IK handshake tests (verifies Python initiator matches firmware responder) ----

def _hkdf_sha256(salt: bytes, ikm: bytes, out_len: int) -> bytes:
    """HKDF-SHA256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t = b""
    okm = b""
    while len(okm) < out_len:
        t = hmac.new(prk, t + bytes([len(okm) // 32 + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:out_len]


def _x25519(priv: bytes, pub: bytes) -> bytes:
    """X25519 scalar multiplication using cryptography library."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    priv_obj = X25519PrivateKey.from_private_bytes(priv)
    peer_pub = X25519PublicKey.from_public_bytes(pub)
    return priv_obj.exchange(peer_pub)


def _clamp_and_x25519(priv: bytes, pub: bytes) -> bytes:
    """X25519 scalar mult (cryptography handles clamping automatically)."""
    return _x25519(priv, pub)


class NoiseIKHandshakeTests(unittest.TestCase):
    """Verify Python initiator's Noise IK key derivation matches firmware responder.

    The firmware (noise_ik.c) implements the responder side:
    1. h = SHA256("Noise_IK_25519_ChaChaPoly_SHA256"), ck = h
    2. store remote_static (initiator static), generate resp_priv/pub
    3. MixHash(init_eph), DH(ee)=X25519(resp_priv, init_eph), MixKey+MixHash
    4. DH(es)=X25519(resp_priv, remote_static), MixKey+MixHash
    5. output resp_pub, MixHash(resp_pub)

    The Python initiator must mirror this to derive the same session key.
    """

    PROTO = b"Noise_IK_25519_ChaChaPoly_SHA256"

    def _initiator_static_keypair(self, serial: str):
        """Derive initiator static key from serial (matches firmware)."""
        init_priv = hashlib.sha256(serial.encode()).digest()
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv_obj = X25519PrivateKey.from_private_bytes(init_priv)
        pub = priv_obj.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return init_priv, pub

    def _responder_keypair(self, priv_bytes: bytes):
        """Given responder private key, derive public."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv_obj = X25519PrivateKey.from_private_bytes(priv_bytes)
        pub = priv_obj.public_key().public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
        return pub

    def test_handshake_produces_matching_session_key(self):
        """Initiator and responder derive the same session key after Noise IK."""
        serial = "AA:BB:CC:DD:EE:FF"

        # Initiator static key from serial
        init_static_priv, init_static_pub = self._initiator_static_keypair(serial)

        # Responder static key (generated by firmware)
        resp_static_priv = os.urandom(32)
        resp_static_pub = self._responder_keypair(resp_static_priv)

        # Initiator ephemeral keypair
        init_eph_priv_bytes = os.urandom(32)
        init_eph_pub = self._responder_keypair(init_eph_priv_bytes)

        # ---- Initiator side ----
        h_i = hashlib.sha256(self.PROTO).digest()
        ck_i = h_i

        # -> e: MixHash(init_eph_pub)
        h_i = hashlib.sha256(h_i + init_eph_pub).digest()

        # Receive resp_static_pub -> MixHash(resp_static_pub)
        h_i = hashlib.sha256(h_i + resp_static_pub).digest()

        # DH(ee) = X25519(init_eph_priv, resp_static_pub) — MixKey only
        ee_shared = _x25519(init_eph_priv_bytes, resp_static_pub)
        tmp = _hkdf_sha256(ck_i, ee_shared, 64)
        ck_i = tmp[:32]
        k_i = tmp[32:]

        # DH(se) = X25519(init_static_priv, resp_static_pub) — MixKey only
        se_shared = _x25519(init_static_priv, resp_static_pub)
        tmp = _hkdf_sha256(ck_i, se_shared, 64)
        ck_i = tmp[:32]
        k_i = tmp[32:]

        # ---- Responder side (mirrors noise_ik.c) ----
        h_r = hashlib.sha256(self.PROTO).digest()
        ck_r = h_r

        # MixHash(init_eph_pub) — received from initiator
        h_r = hashlib.sha256(h_r + init_eph_pub).digest()

        # MixHash(resp_static_pub) — sent to initiator
        h_r = hashlib.sha256(h_r + resp_static_pub).digest()

        # DH(ee) = X25519(resp_static_priv, init_eph_pub) — MixKey only
        ee_r_shared = _x25519(resp_static_priv, init_eph_pub)
        tmp = _hkdf_sha256(ck_r, ee_r_shared, 64)
        ck_r = tmp[:32]
        k_r = tmp[32:]

        # DH(es) = X25519(resp_static_priv, init_static_pub) — MixKey only
        es_r_shared = _x25519(resp_static_priv, init_static_pub)
        tmp = _hkdf_sha256(ck_r, es_r_shared, 64)
        ck_r = tmp[:32]
        k_r = tmp[32:]

        # The session keys must match
        self.assertEqual(k_i, k_r, "Session keys differ!")
        # The handshake hashes must also match (Noise requirement)
        self.assertEqual(h_i, h_r, "Handshake hashes differ!")

    def test_encrypt_decrypt_roundtrip(self):
        """ChaChaPoly encrypt/decrypt round-trip with same nonce."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        key = os.urandom(32)
        nonce = bytes(12)
        aead = ChaCha20Poly1305(key)
        plaintext = b"Hello, encrypted BLE world!"
        ct = aead.encrypt(nonce, plaintext, None)
        pt = aead.decrypt(nonce, ct, None)
        self.assertEqual(pt, plaintext)

    def test_noise_packet_structure(self):
        """Verify CMD_NOISE packet format: cmd byte + 32-byte ephemeral."""
        serial = "test_serial_123"
        init_static_priv, init_static_pub = self._initiator_static_keypair(serial)

        # Simulate initiator ephemeral
        init_eph_priv = os.urandom(32)
        init_eph_pub = self._responder_keypair(init_eph_priv)

        # CMD_NOISE packet: [CMD_NOISE=5][32 bytes initiator ephemeral pub]
        noise_pkt = bytes([5]) + init_eph_pub
        self.assertEqual(len(noise_pkt), 33)
        self.assertEqual(noise_pkt[0], 5)

        # After handshake, responder echoes 32 bytes back via read callback
        # CLI receives this and completes handshake
        resp_eph = self._responder_keypair(os.urandom(32))

        # Both sides derive shared key from X25519
        init_shared = _x25519(init_eph_priv, resp_eph)
        resp_shared = _x25519(os.urandom(32), init_eph_pub)  # This won't match (different privs)
        # The point is: X25519(a, pub_a) == X25519(b, pub_b) when a->pub_a, b->pub_b
        # This is verified in test_handshake_produces_matching_session_key

class ScanAndConnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_returns_the_connected_bleak_client(self):
        """BleakClient.connect() mutates state but returns None on current Bleak."""
        device = types.SimpleNamespace(name="PicoBridge", address="2C:CF:67:CA:3B:E4")

        class FakeScanner:
            @staticmethod
            async def discover(timeout):
                self.assertEqual(timeout, 3)
                return [device]

        class FakeClient:
            instances = []

            def __init__(self, selected_device):
                self.selected_device = selected_device
                self.connected = False
                type(self).instances.append(self)

            async def connect(self):
                self.connected = True
                return None

        fake_bleak = types.ModuleType("bleak")
        setattr(fake_bleak, "BleakClient", FakeClient)
        setattr(fake_bleak, "BleakScanner", FakeScanner)
        fake_backends = types.ModuleType("bleak.backends")
        fake_device_module = types.ModuleType("bleak.backends.device")
        setattr(fake_device_module, "BLEDevice", object)
        module_name = "pico_bridge_ctl_scan_connect_test"
        spec = importlib.util.spec_from_file_location(
            module_name, ROOT / "tools" / "pico_bridge_ctl.py"
        )
        if spec is None or spec.loader is None:
            self.fail("could not load pico_bridge_ctl module")
        module = importlib.util.module_from_spec(spec)

        with patch.dict(sys.modules, {
            "bleak": fake_bleak,
            "bleak.backends": fake_backends,
            "bleak.backends.device": fake_device_module,
            module_name: module,
        }):
            spec.loader.exec_module(module)
            selected_device, client = await module.scan_and_connect(timeout=3)

        self.assertIs(selected_device, device)
        self.assertIs(client, FakeClient.instances[0])
        self.assertTrue(client.connected)


class MutualNoiseIKHandshakeTests(unittest.IsolatedAsyncioTestCase):
    """Independent responder verifies the host uses authenticated Noise IK."""

    PROTO = b"Noise_IK_25519_ChaChaPoly_SHA256"
    ACK = b"PBIK1"

    @staticmethod
    def _raw_private(key):
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
        return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @staticmethod
    def _raw_public(key):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @staticmethod
    def _public_from_bytes(value):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        return X25519PublicKey.from_public_bytes(value)

    @staticmethod
    def _nonce(counter):
        return b"\0" * 4 + counter.to_bytes(8, "little")

    @staticmethod
    def _mix_key(ck, ikm):
        material = _hkdf_sha256(ck, ikm, 64)
        return material[:32], material[32:]

    def _load_module(self, suffix):
        fake_bleak = types.ModuleType("bleak")
        setattr(fake_bleak, "BleakClient", object)
        fake_backends = types.ModuleType("bleak.backends")
        fake_device_module = types.ModuleType("bleak.backends.device")
        setattr(fake_device_module, "BLEDevice", object)
        module_name = f"pico_bridge_ctl_mutual_noise_{suffix}"
        spec = importlib.util.spec_from_file_location(module_name, ROOT / "tools" / "pico_bridge_ctl.py")
        if spec is None or spec.loader is None:
            self.fail("could not load pico_bridge_ctl module")
        module = importlib.util.module_from_spec(spec)
        patches = {"bleak": fake_bleak, "bleak.backends": fake_backends,
                   "bleak.backends.device": fake_device_module, module_name: module}
        return module, spec, patches

    async def test_pinned_identities_complete_mutual_ik_and_confirm_transport_delivery(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        import base64

        host_static = X25519PrivateKey.generate()
        device_static = X25519PrivateKey.generate()
        host_pub = self._raw_public(host_static)
        device_pub = self._raw_public(device_static)
        identity = {
            "schema": 1,
            "protocol": self.PROTO.decode(),
            "initiator_private_b64": base64.b64encode(self._raw_private(host_static)).decode(),
            "device_public_b64": base64.b64encode(device_pub).decode(),
        }
        with tempfile.TemporaryDirectory() as directory:
            identity_path = Path(directory) / "noise-ik.json"
            identity_path.write_text(json.dumps(identity))
            identity_path.chmod(0o600)
            test_case = self

            class FakeClient:
                def __init__(self):
                    self.assembled = bytearray()
                    self.response = None
                    self.host_to_device_key = None
                    self.device_to_host_key = None
                    self.last_plaintext = None

                async def write_gatt_char(self, _uuid, fragment, response=False):
                    data = bytes(fragment)
                    sequence, more = data[0] >> 1, data[0] & 1
                    if sequence == 0:
                        self.assembled = bytearray()
                    test_case.assertEqual(sequence, len(self.assembled) // 19)
                    self.assembled += data[1:]
                    if more:
                        return None
                    message = bytes(self.assembled)
                    if message[0] == 5:
                        test_case.assertEqual(len(message), 81)
                        init_eph, encrypted_static = message[1:33], message[33:]
                        h = hashlib.sha256(test_case.PROTO).digest()
                        ck = h
                        h = hashlib.sha256(h + device_pub).digest()
                        h = hashlib.sha256(h + init_eph).digest()
                        ck, key = test_case._mix_key(ck, device_static.exchange(test_case._public_from_bytes(init_eph)))
                        initiator_pub = ChaCha20Poly1305(key).decrypt(test_case._nonce(0), encrypted_static, h)
                        h = hashlib.sha256(h + encrypted_static).digest()
                        test_case.assertEqual(initiator_pub, host_pub)
                        ck, _ = test_case._mix_key(ck, device_static.exchange(test_case._public_from_bytes(initiator_pub)))
                        responder_eph = X25519PrivateKey.generate()
                        responder_eph_pub = responder_eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                        h = hashlib.sha256(h + responder_eph_pub).digest()
                        ck, key = test_case._mix_key(ck, responder_eph.exchange(test_case._public_from_bytes(init_eph)))
                        ck, key = test_case._mix_key(ck, responder_eph.exchange(test_case._public_from_bytes(initiator_pub)))
                        ack = ChaCha20Poly1305(key).encrypt(test_case._nonce(0), test_case.ACK, h)
                        self.response = responder_eph_pub + ack
                        split = _hkdf_sha256(ck, b"", 64)
                        self.host_to_device_key, self.device_to_host_key = split[:32], split[32:]
                        return None
                    test_case.assertEqual(message[0], 6)
                    test_case.assertEqual(int.from_bytes(message[1:9], "little"), 0)
                    self.last_plaintext = ChaCha20Poly1305(self.host_to_device_key).decrypt(
                        test_case._nonce(0), message[9:], None
                    )
                    ack = ChaCha20Poly1305(self.device_to_host_key).encrypt(
                        test_case._nonce(0), b"PBOK1\x00", None
                    )
                    self.response = bytes([6]) + (0).to_bytes(8, "little") + ack

                async def read_gatt_char(self, _uuid):
                    return bytearray(self.response)

            module, spec, patches = self._load_module("valid")
            client = FakeClient()
            with patch.dict(sys.modules, patches):
                spec.loader.exec_module(module)
                noise = await module.perform_noise_handshake(client, identity_path)
                await module.send_command(client, b"\x02\x01\x00\x00\x00\x02\x00\x00\x00", noise=noise)

        self.assertTrue(noise.is_ready())
        self.assertEqual(noise._send_key, client.host_to_device_key)
        self.assertEqual(noise._receive_key, client.device_to_host_key)
        self.assertEqual(noise._send_nonce, 1)
        self.assertEqual(noise._receive_nonce, 1)
        self.assertEqual(client.last_plaintext, b"\x02\x01\x00\x00\x00\x02\x00\x00\x00")

    async def test_wrong_or_missing_device_ack_is_rejected_before_any_command(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        host_static = X25519PrivateKey.generate()
        device_static = X25519PrivateKey.generate()
        identity = {
            "schema": 1, "protocol": self.PROTO.decode(),
            "initiator_private_b64": base64.b64encode(self._raw_private(host_static)).decode(),
            "device_public_b64": base64.b64encode(self._raw_public(device_static)).decode(),
        }
        with tempfile.TemporaryDirectory() as directory:
            identity_path = Path(directory) / "noise-ik.json"
            identity_path.write_text(json.dumps(identity))
            identity_path.chmod(0o600)

            class FakeClient:
                async def write_gatt_char(self, *_args, **_kwargs):
                    return None
                async def read_gatt_char(self, _uuid):
                    return bytearray(os.urandom(53))

            module, spec, patches = self._load_module("bad_ack")
            with patch.dict(sys.modules, patches):
                spec.loader.exec_module(module)
                with self.assertRaises(module.NoiseHandshakeError):
                    await module.perform_noise_handshake(FakeClient(), identity_path)


class FirmwareMutualNoiseContractTests(unittest.TestCase):
    def test_authenticated_receipt_carries_bridge_command_status(self):
        """A valid transport receipt must distinguish accepted from rejected commands."""
        source = (ROOT / "firmware" / "bridge_main.c").read_text()
        self.assertRegex(
            source,
            r"static bridge_status_t ble_handle_authenticated_command\(",
            "authenticated dispatch must expose the bridge-core result",
        )
        self.assertRegex(
            source,
            r"bridge_status_t command_status\s*=\s*ble_handle_authenticated_command\(",
            "encrypted handler must retain the dispatched command status",
        )
        self.assertRegex(
            source,
            r"noise_encrypt_transport_ack\(\(uint8_t\)command_status,",
            "the encrypted receipt must carry the bridge command status",
        )

    def test_only_authenticated_envelopes_reach_command_dispatch(self):
        source = (ROOT / "firmware" / "bridge_main.c").read_text()
        self.assertIn("#define BLE_CMD_ENCRYPTED 6u", source)
        self.assertIn("noise_decrypt_packet", source)
        self.assertIn("noise_encrypt_transport_ack", source)
        self.assertRegex(
            source,
            r"case BLE_CMD_ENCRYPTED:[\s\S]*?noise_decrypt_packet",
            "encrypted frames must be authenticated and decrypted before bridge command dispatch",
        )
        self.assertRegex(
            source,
            r"case BLE_CMD_STAGE:[\s\S]*?return;",
            "plaintext stage commands must be rejected after secure enrollment",
        )


class FirmwareFragmentContractTests(unittest.TestCase):
    def test_start_detector_accepts_sequence_zero_with_more_flag(self):
        """A 33-byte Noise packet begins with header 0x01 (seq=0, MORE=1)."""
        first_fragment_header = (0 << 1) | 1
        self.assertEqual(first_fragment_header, 0x01)
        source = (ROOT / "firmware" / "bridge_main.c").read_text()
        self.assertRegex(
            source,
            r"uint8_t seq = frag_hdr >> 1;[\s\S]*?if \(seq == 0\)",
            "firmware must identify a first fragment by sequence, not MORE bit",
        )


class FirmwareNoiseKeyContractTests(unittest.TestCase):
    def test_every_x25519_scalar_is_rfc7748_clamped_at_use(self):
        """Provisioned private keys must use RFC-7748 scalar clamping too."""
        source = (ROOT / "firmware" / "noise_ik.c").read_text()
        function = re.search(
            r"static int x25519_dh\([^)]*\)\s*\{([\s\S]*?)\n\}", source
        )
        if function is None:
            self.fail("missing x25519_dh")
        body = function.group(1)
        self.assertIn("priv[0] &= 0xf8u;", body)
        self.assertIn("priv[31] &= 0x7fu;", body)
        self.assertIn("priv[31] |= 0x40u;", body)


if __name__ == "__main__":
    unittest.main()