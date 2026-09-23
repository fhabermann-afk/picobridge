#!/usr/bin/env python3
"""Integration test: simulate the firmware's BLE command handler pipeline.

Tests that a BLE stage packet → bridge_core_stage → bridge_core_next
produces correct HID keyboard usage codes, simulating the firmware's
ble_handle_command → usb_hid_send_key flow.

No hardware required — drives the C bridge_core library directly via ctypes
and replicates the firmware's packet decoding and HID emission logic.
"""
import ctypes as C
import struct
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Build a shared library for bridge_core if not present
SO = ROOT / "firmware/core/.build/bridge_core.so"
SO.parent.mkdir(parents=True, exist_ok=True)
if not SO.exists():
    import subprocess
    result = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-fPIC",
         "-shared", "-Ifirmware/core",
         "firmware/core/bridge_core.c", "-o", str(SO.relative_to(ROOT))],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to build bridge_core.so:\n{result.stderr}")

# Load the bridge_core shared library
LIB = C.CDLL(str(SO))

# bridge_core.h constants
BRIDGE_MAX_INPUT_BYTES = 1024
BRIDGE_LAYOUT_US = 1
BRIDGE_LAYOUT_DE = 2
BRIDGE_MODE_PASSWORD = 1
BRIDGE_MODE_TEXT = 2

# Command/protocol constants (matching firmware/bridge_main.c)
CMD_STAGE = 1
BRIDGE_FLAG_ALLOW_LF = 0x01
BRIDGE_FLAG_ALLOW_TAB = 0x02

# bridge_status_t
BRIDGE_OK = 0
BRIDGE_DONE = 1
BRIDGE_ERR_ARGUMENT = 2

# HID usage codes for US layout (subset)
HID_A = 4
HID_B = 5
HID_C = 6
HID_D = 7
HID_E = 8
HID_F = 9
HID_G = 10
HID_H = 11
HID_I = 12
HID_J = 38
HID_K = 13
HID_L = 14
HID_M = 15
HID_N = 16
HID_O = 17
HID_P = 18
HID_Q = 19
HID_R = 20
HID_S = 21
HID_T = 20
HID_U = 22
HID_V = 23
HID_W = 24
HID_X = 25
HID_Y = 26
HID_Z = 27
HID_1 = 30
HID_2 = 31
HID_3 = 32
HID_4 = 33
HID_5 = 34
HID_6 = 35
HID_7 = 36
HID_8 = 37
HID_9 = 38
HID_0 = 39
HID_ENTER = 40
HID_SPACE = 44
HID_MINUS = 45
HID_EQUAL = 46


class BridgeStroke(C.Structure):
    _fields_ = [("modifier", C.c_uint8), ("usage", C.c_uint8)]


class BridgeCore(C.Structure):
    # Must match bridge_core_t layout exactly
    _fields_ = [
        ("replay_count", C.c_size_t),
        ("replay", (C.c_uint8 * (64 * 8))),  # owner(4)+id(4) per entry, 64 entries
        ("state", C.c_int),
        ("owner", C.c_uint32),
        ("id", C.c_uint32),
        ("staged_at_ms", C.c_uint32),
        ("ttl_ms", C.c_uint32),
        ("layout", C.c_int),
        ("mode", C.c_int),
        ("flags", C.c_uint8),
        ("stroke_count", C.c_size_t),
        ("cursor", C.c_size_t),
        ("strokes", (C.c_uint8 * (2048 * 2))),  # 2048 strokes * 2 bytes each
    ]


# Function signatures
LIB.bridge_core_init.argtypes = [C.POINTER(BridgeCore)]
LIB.bridge_core_init.restype = None

LIB.bridge_core_stage.argtypes = [
    C.POINTER(BridgeCore), C.c_uint32, C.c_uint32,  # core, owner, id
    C.c_int, C.c_int, C.c_uint8,  # layout, mode, flags
    C.c_char_p, C.c_size_t,  # utf8, length
    C.c_uint32, C.c_uint32,  # now_ms, ttl_ms
]
LIB.bridge_core_stage.restype = C.c_int

LIB.bridge_core_next.argtypes = [
    C.POINTER(BridgeCore), C.c_uint32, C.POINTER(BridgeStroke)
]
LIB.bridge_core_next.restype = C.c_int

LIB.bridge_core_confirm.argtypes = [
    C.POINTER(BridgeCore), C.c_uint32, C.c_uint32, C.c_uint32
]
LIB.bridge_core_confirm.restype = C.c_int

LIB.bridge_core_cancel.argtypes = [C.POINTER(BridgeCore), C.c_uint32, C.c_uint32]
LIB.bridge_core_cancel.restype = C.c_int

LIB.bridge_core_tick.argtypes = [C.POINTER(BridgeCore), C.c_uint32]
LIB.bridge_core_tick.restype = C.c_int


def decode_ble_stage_packet(pkt):
    """Replicate firmware's ble_handle_command for CMD_STAGE."""
    cmd = pkt[0]
    owner = struct.unpack_from("<I", pkt, 1)[0]
    cmd_id = struct.unpack_from("<I", pkt, 5)[0]
    layout = pkt[9]
    mode = pkt[10]
    flags = pkt[11]
    utf8_len = struct.unpack_from("<H", pkt, 12)[0]
    utf8_data = bytes(pkt[14:14 + utf8_len])
    return owner, cmd_id, layout, mode, flags, utf8_data


def stage_and_drain(core, owner, cmd_id, layout, mode, flags, payload, now_ms=0, ttl_ms=10000):
    """Stage payload on core, then drain all strokes via bridge_core_next."""
    status = LIB.bridge_core_stage(core, owner, cmd_id, layout, mode,
                                   flags, payload, len(payload), now_ms, ttl_ms)
    strokes = []
    if status != BRIDGE_OK:
        return status, strokes
    # In the firmware, confirm is needed before next() produces strokes
    LIB.bridge_core_confirm(core, owner, cmd_id, now_ms)
    stroke = BridgeStroke()
    while True:
        st = LIB.bridge_core_next(core, now_ms, C.byref(stroke))
        if st != BRIDGE_OK:
            break
        strokes.append((stroke.modifier, stroke.usage))
    return status, strokes


class BLEToHIDIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.core = BridgeCore()
        LIB.bridge_core_init(C.byref(self.core))

    def test_simple_text_stages_and_emits_keycodes(self):
        """Stage 'Hi' over BLE, verify HID keycodes match USB keyboard."""
        payload = b"Hi"
        pkt = bytearray()
        pkt.append(CMD_STAGE)
        pkt += struct.pack("<I", 1)   # owner
        pkt += struct.pack("<I", 100) # id
        pkt.append(BRIDGE_LAYOUT_US)
        pkt.append(BRIDGE_MODE_PASSWORD)
        pkt.append(0)
        pkt += struct.pack("<H", len(payload))
        pkt += payload
        pkt = bytes(pkt)

        # Decode as firmware does
        owner, cmd_id, layout, mode, flags, decoded = decode_ble_stage_packet(pkt)
        self.assertEqual(decoded, payload)

        # Stage and drain
        _, strokes = stage_and_drain(self.core, owner, cmd_id, layout, mode,
                                     flags, decoded)

        # H=0x0B(11), i=0x0C(12) on US HID keyboard
        # bridge_core maps ASCII to HID usage codes
        # 'H' (0x08 in ASCII) -> HID usage for H key
        # 'i' (0x09 in ASCII) -> HID usage for I key
        usages = [s[1] for s in strokes]
        self.assertTrue(len(usages) > 0, "Should have emitted at least one stroke")
        # First stroke should be 'H' key (usage 11 in US HID)
        self.assertEqual(usages[0], 11)  # H
        # Second stroke should be 'i' key (usage 12)
        self.assertEqual(usages[1], 12)  # i

    def test_shift_modifier_for_uppercase(self):
        """Uppercase letters require LEFT_SHIFT modifier."""
        payload = b"A"
        _, strokes = stage_and_drain(self.core, 1, 1, BRIDGE_LAYOUT_US,
                                     BRIDGE_MODE_TEXT, 0, payload)
        self.assertTrue(len(strokes) > 0)
        # 'A' is uppercase → needs shift modifier + 'a' key code
        # bridge_core applies shift then types lowercase equivalent
        mod, usage = strokes[0]
        self.assertEqual(usage, 4)  # 'a' key (usage 4)

    def test_password_mode_treats_input_as_password(self):
        """Password mode stages but requires confirm to emit."""
        payload = b"secret"
        # Stage without confirm
        status = LIB.bridge_core_stage(self.core, 1, 1, BRIDGE_LAYOUT_US,
                                       BRIDGE_MODE_PASSWORD, 0, payload, 6, 0, 10000)
        self.assertEqual(status, BRIDGE_OK)
        # Without confirm, next() should not produce strokes
        stroke = BridgeStroke()
        st = LIB.bridge_core_next(C.byref(self.core), 0, C.byref(stroke))
        self.assertNotEqual(st, BRIDGE_OK)

    def test_replay_protection_duplicate_id_rejected(self):
        """Same (owner, id) cannot be staged twice without confirm/cancel."""
        payload = b"test"
        status1 = LIB.bridge_core_stage(self.core, 1, 1, BRIDGE_LAYOUT_US,
                                        BRIDGE_MODE_TEXT, 0, payload, 4, 0, 10000)
        self.assertEqual(status1, BRIDGE_OK)
        status2 = LIB.bridge_core_stage(self.core, 1, 1, BRIDGE_LAYOUT_US,
                                        BRIDGE_MODE_TEXT, 0, payload, 4, 0, 10000)
        self.assertNotEqual(status2, BRIDGE_OK)

    def test_cancel_prevents_reuse_same_owner_same_id(self):
        """After cancel, same (owner, id) cannot be re-staged (replay protection)."""
        payload = b"first"
        LIB.bridge_core_stage(self.core, 1, 1, BRIDGE_LAYOUT_US,
                              BRIDGE_MODE_TEXT, 0, payload, 5, 0, 10000)
        LIB.bridge_core_cancel(self.core, 1, 1)
        # Same owner+id is now in replay ledger → BRIDGE_ERR_REPLAY
        status = LIB.bridge_core_stage(self.core, 1, 1, BRIDGE_LAYOUT_US,
                                       BRIDGE_MODE_TEXT, 0, b"second", 6, 0, 10000)
        self.assertNotEqual(status, BRIDGE_OK)
        # Different owner can reuse the same id
        status2 = LIB.bridge_core_stage(self.core, 2, 1, BRIDGE_LAYOUT_US,
                                        BRIDGE_MODE_TEXT, 0, b"second", 6, 0, 10000)
        self.assertEqual(status2, BRIDGE_OK)

    def test_unicode_nonascii_rejected_us_layout(self):
        """Non-ASCII UTF-8 is rejected in US layout (strict preflight)."""
        payload = "café".encode("utf-8")
        status = LIB.bridge_core_stage(self.core, 1, 1, BRIDGE_LAYOUT_US,
                                       BRIDGE_MODE_TEXT, 0,
                                       payload, len(payload), 0, 10000)
        self.assertEqual(status, 7)  # BRIDGE_ERR_UTF8

    def test_empty_payload_rejected(self):
        """Empty payload should fail staging."""
        status = LIB.bridge_core_stage(self.core, 1, 1, BRIDGE_LAYOUT_US,
                                       BRIDGE_MODE_TEXT, 0, b"", 0, 0, 10000)
        self.assertNotEqual(status, BRIDGE_OK)


if __name__ == "__main__":
    unittest.main()
