# PicoBridge

A Raspberry Pi **Pico 2 W** that turns Bluetooth Low Energy commands into
USB-HID keystrokes on the machine it is plugged into — with end-to-end Noise
IK encryption and a strict, fail-closed design.

Use it to type a password or any other string into the focused window of the
host the Pico is attached to, without the secret ever touching that host's
clipboard, keystroke injectors, or network. The controller (a normal laptop or
phone with BLE) authenticates to the Pico over Noise `IK` and the Pico
*types*, exactly like a hardware keyboard would.

```
controller (BLE, Noise IK)            Pico 2 W                 target host
  pico-send  ────────────────────▶  bridge_core  ──USB HID──▶  focused window
```

**Why:** clipboard managers, `xdotool`, browser extension “autofill”, and
remote-desktop keystroke injection all put secrets into software layers you
may not trust on that machine. A USB keyboard is a peripheral the target OS
has to trust anyway — and PicoBridge only ever *types*, through a channel
that is mutually authenticated and encrypted before a single keystroke.

## Status

Working prototype, in daily use by its author. Tested against Linux targets.
**Not audited. Not fit for anything you would not entrust to an unaudited
prototype.** Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before use.

## Documentation

- [docs/BUILD-AND-FLASH.md](docs/BUILD-AND-FLASH.md) — build the firmware, provision identity material, flash the Pico
- [docs/PROVISIONING.md](docs/PROVISIONING.md) — identities: device, controller, recovery admin; enrollment and revocation
- [docs/USAGE.md](docs/USAGE.md) — sending strings day-to-day (`pico-send`), raw CLI, protocol reference
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — what this cannot do, and why (layout ceiling, TTL, single connection, …)
- [SECURITY.md](SECURITY.md) — security model, what the device stores, threat model, how to report issues

## Quick start

```bash
# 1. Build (see docs/BUILD-AND-FLASH.md for the Pico SDK toolchain setup)
cmake --preset pico2w-test && cmake --build --preset pico2w-test --target pico_bridge

# 2. Provision one device + its first controller (offline, prints no keys)
python3 tools/noise_ik_provision.py --out ../enroll/device-01

# 3. Flash via BOOTSEL, install the controller identity on your BLE host
#    (exact steps: docs/BUILD-AND-FLASH.md, docs/PROVISIONING.md)

# 4. Copy a secret in KeePassXC, then type it into the window you focus:
tools/pico_send.py --clipboard -d 5 --layout de
```

## Layout ceiling (read this twice)

USB HID carries **keycodes, not characters**. A string can only be typed if
the target machine's active keyboard layout can physically produce every
character in it. PicoBridge maps `US` and `DE` layouts; anything outside the
map is **rejected before the first keystroke** (device status
`UNSUPPORTED`) instead of typing something wrong. Consequences:

- Generate secrets from an ASCII + common-symbols charset and they can be
  typed on any target, anywhere.
- `ß` cannot be typed on a US-layout target. No firmware can fix physics.

Details and workarounds in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Repository layout

```
firmware/          Pico 2 W firmware (C): BLE GATT command channel, Noise IK
                   responder, controller trust store, USB-HID output, core state machine
  core/            platform-independent, unit-tested state machine (UTF-8 -> keystrokes)
tools/             Python host CLIs: pico_bridge_ctl (protocol), pico_send (daily driver),
                   noise_ik_provision (offline enrollment), controller_identity
tests/             native C tests (ASan/UBSan), host tool tests, HID release contract
docs/              build/flash, provisioning, usage, limitations
```

`vendor/` (Pico SDK, BTstack, mbedTLS, TinyUSB) is intentionally **not** in
this repository — see docs/BUILD-AND-FLASH.md for fetching it. The vendored
libraries keep their own licenses (BSD-3-Clause etc.); this repository's
0BSD grant covers only PicoBridge's own sources.

## Built by AI — all of it

This project is **100% vibe coded**. Every line of firmware, tooling, tests,
and documentation was written by an AI agent (Hermes, by Nous Research) driving
a real hardware bring-up loop, with varying LLM backends over the course of
the project, under human direction (requirements, hardware access, acceptance
decisions). No line was hand-written by a human. That is a feature and a
warning at the same time: the design intent is careful, but the implementation
has had no human line-by-line review and no external audit. You have been
told. You have been *thoroughly* told.

## License & liability

0BSD — see [LICENSE](LICENSE). Use it, fork it, sell it, don't credit
anyone. The software comes with **no warranty of any kind and the authors
accept no liability whatsoever**, to the maximum extent permitted by law —
including for any consequence of trusting it with a secret. If this project
loses you a password, an afternoon, or a house: that is on you, and legally
as well as technically, this software is provided strictly as-is.
