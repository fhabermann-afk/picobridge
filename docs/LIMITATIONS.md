# Limitations — read before trusting

## Hard physical limits (cannot be patched)

### The layout ceiling
USB HID transports **keycodes** (which physical key), never characters. The
target OS decides what a keypress *means*, based on its active keyboard
layout. Consequences:

- A string is typeable only if every character in it exists on the target's
  layout. PicoBridge ships `US` (full printable ASCII) and `DE` (ASCII plus
  umlauts/ß/€, AltGr symbols, dead-key correction) maps. Anything else is
  rejected up front (`UNSUPPORTED`, status 7) — the device prefers typing
  nothing over typing something wrong.
- `ß` cannot be typed on a US-layout target. Neither can `ł`, `è`, `→`, or
  emoji. A real German keyboard plugged into that same US-configured machine
  has the identical problem — this is HID physics, not a firmware bug.
- OS-level unicode entry tricks (Ctrl+Shift+U hex on Linux, Alt+numpad on
  Windows, Unicode-hex layout on macOS) exist but are platform-,
  application- and settings-dependent and can fail **silently** (hex digits
  land in the field as literal text). A secret-typing device must not guess.
  Hence: fail closed.
- **Practical rule:** generate machine credentials from an ASCII+symbols
  charset and they can be typed on any target, anywhere.

### No feedback channel
A USB keyboard is output-only. The device cannot see which window is focused
on the target, whether the field accepted the text, or whether Caps Lock /
an IME is mangling input on the target side. The encrypted receipt proves
*the Pico scheduled the keystrokes*, nothing about what the target did with
them.

## Design limits (true today, theoretically patchable)

- **Layouts:** only `US` and `DE`. Adding a layout means a map in
  `firmware/core/bridge_core.c` + the enum + CLI flag. Contributions welcome.
- **Payload:** ≤ 1024 bytes UTF-8 per transaction; typing runs at
  keyboard-report speed (hundreds of characters fit comfortably inside the
  15 s TTL, but keep secrets reasonable).
- **One staging slot, one BLE connection:** the device serves a single
  connection and a single staged entry. No queueing, no typing while a
  controller stays connected.
- **BLE range required.** The controller must be in Bluetooth range of the
  Pico. There is no network path — deliberately (see SECURITY.md); a
  `firmware/radio/` Wi-Fi provisioning experiment exists but is unfinished,
  not built into the default target, and out of scope.
- **No emergency path without the controller.** If your BLE controller
  machine is dead/stolen, you need another enrolled controller (or the
  offline recovery admin) — a static-password USB token always works, this
  does not. Plan fallback logins accordingly.
- **Target must accept a HID keyboard boot-time.** Firmware flashing needs
  BOOTSEL (a button). Unencrypted BIOS/UEFI password fields work since the
  BIOS sees a plain HID keyboard — but if the machine ignores keyboards at
  that stage, so is the Pico.

## Known prototype status

- Developed and tested against **Linux** targets; the firmware accepts
  whatever enumerates it as a host. macOS/Windows targets have been used
  only incidentally — no compatibility matrix exists.
- The firmware's own debug interface (SWD) is **not locked**. A physical
  attacker with a debug probe can extract the device static private key from
  flash and *clone the device's identity*. This yields no password (none are
  stored) but defeats "only my device can be the keyboard" — an attacker who
  both has the board and can reach your controller's network of trust could
  impersonate the device to controllers until you revoke. Fuse-locking the
  RP2350 is possible and on the roadmap; until then, the Pico is a
  *should-not-be-stolen-easily* peripheral, not a hardened token.
- One historical firmware revision could hold a key down (missed release
  report) — fixed, regression-tested (`tests/test_hid_release_contract.py`),
  but if you see auto-repeating characters: unplug, reflash, check the target
  for the stuck modifier state.
- No external security audit of firmware or protocol has been performed.
  Noise IK itself is a standard, well-studied construction; the
  implementation around it is homegrown prototype code.
