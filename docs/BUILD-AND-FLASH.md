# Build and Flash

Everything below was developed on Linux; the cross-toolchain is the standard
Raspberry Pi Pico SDK one (aarch32 `arm-none-eabi-gcc`).

## 1. Prerequisites

- CMake ≥ 3.20, Ninja, `python3` (≥ 3.10), `git`
- `arm-none-eabi-gcc` (10+) — distro package or the
  [official toolchain download](https://developer.arm.com/tools-downloads/open-tools-gnu-arm-embedded-toolchain)
- A **Raspberry Pi Pico 2 W** (RP2350 + CYW43). The original Pico W will not
  work (different MCU); build targets `pico2_w`.
- Python packages for the host tools: `bleak`, `cryptography`
  (`pip install bleak cryptography`)

## 2. Vendored SDK

This repository intentionally ships no dependencies. Create `vendor/pico-sdk`
with the Pico SDK (including its submodules — BTstack, mbedTLS, TinyUSB,
cyw43-driver live in `lib/`):

```bash
git clone --recurse-submodules https://github.com/raspberrypi/pico-sdk vendor/pico-sdk
# Any recent 2.x release works; the author developed against the
# September-2026 master. If you hit a BTstack/cyw43 API mismatch, pin to a
# release and retry before filing a bug.
```

`CMakeLists.txt` defaults `PICO_SDK_PATH` to `vendor/pico-sdk`; override with
`-DPICO_SDK_PATH=...` if you keep the SDK elsewhere. `PICO_TOOLCHAIN_PATH`
may be needed if your cross-compiler is not on `PATH`.

## 3. Identity headers — required before the first build

The firmware needs two generated headers that are **never** committed:

| File | Contains | Who makes it |
|---|---|---|
| `firmware/noise_ik_keys.h` | device static private key + first authorized controller's public key | `tools/noise_ik_provision.py` (see docs/PROVISIONING.md) |
| `firmware/recovery_admin_public.h` | public half of your **offline recovery admin** keypair | you, once, from your own keypair |

Both `.example`/template versions are placeholders and **refuse nothing** —
flash with the template recovery key and whoever knows that template's
private key (i.e. everyone) can enroll as recovery admin on your device.
Steps to make your own recovery keypair: see docs/PROVISIONING.md § Recovery
admin.

Copy the provisioned key header into place for the build:

```bash
cp <enrollment-dir>/noise_ik_keys.h firmware/noise_ik_keys.h   # mode 0600, never commit
```

## 4. Build

```bash
cmake --preset pico2w-test
cmake --build --preset pico2w-test --target pico_bridge
# artifact: build-pico2w-test/pico_bridge.uf2
```

Native (host-compiler) unit tests, no hardware needed:

```bash
python3 tests/core/run_native.py --sanitize    # core state machine under ASan+UBSan
python3 -m pytest tests/tools tests/integration tests/test_usb_descriptors.py -q
```

## 5. Flash

1. Put the Pico into BOOTSEL: hold the BOOTSEL button while plugging it into
   USB (or `picotool reboot -u` from a running image that supports it).
   A mass-storage volume `RP2350` appears.
2. Copy the UF2 and let go:
   ```bash
   cp build-pico2w-test/pico_bridge.uf2 /media/$USER/RP2350/
   sync
   ```
3. The Pico reboots into application mode within a few seconds. It enumerates
   as a USB HID keyboard:
   ```bash
   lsusb -d cafe:4010   # product string is shared between idle and bridge images
   ```
   (USB passthrough VMs can take longer to re-enumerate; check `dmesg` before
   assuming a fault.)

> ⚠️ Only ever flash the specific board you identified. A flash writes the
> Noise device key burned into `firmware/noise_ik_keys.h` — provision **per
> device**, one identity per board, never reuse a header across boards.

## 6. First boot

The firmware seeds its controller trust store on first boot from
`noise_ik_keys.h` (admin slot) and `recovery_admin_public.h` (immutable
recovery slot). From then on, controllers are managed over authenticated
BLE only — see docs/PROVISIONING.md.
