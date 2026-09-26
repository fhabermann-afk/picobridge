# Provisioning: identities, enrollment, revocation

Three kinds of identity exist. Keep them strictly separate:

1. **Device identity** — the Pico's Noise `IK` static keypair. Burned into
   the firmware image at build time (`firmware/noise_ik_keys.h`). The public
   half is what controllers pin; the private half never leaves the device.
2. **Controller identities** — the BLE clients that may command the device
   (your laptop, your phone). Up to 4 daily slots + 1 immutable recovery
   slot. A controller can be *admin* (may enroll/revoke others) or *operator*
   (may only type).
3. **Recovery admin** — an offline keypair whose **private half lives only in
   your password manager / an offline vault**. Its public half is baked into
   `firmware/recovery_admin_public.h` and it occupies slot 0, which can never
   be revoked over BLE. It is the only way back if daily controllers are lost.

## 0. Recovery admin (once, before your first flash)

Generate a keypair offline and put the **public** half into
`firmware/recovery_admin_public.h` (replace the template!), the **private**
half into your password manager as a string:

```python
# run on a machine you trust; prints both halves once — store them yourself
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
k = X25519PrivateKey.generate()
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
print("private_b64:", base64.b64encode(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
print("public_b64 :", base64.b64encode(k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode())
```

Convert the public base64 to a C array:
`python3 -c "import base64;print(', '.join(f'0x{b:02x}' for b in base64.b64decode('PUBLIC_B64')))"`

**Do not flash the template key in the repository.** Anyone can compute its
private half.

## 1. Device + first controller enrollment (offline)

```bash
mkdir -p ../enrollment && chmod 700 ../enrollment
python3 tools/noise_ik_provision.py --out ../enrollment/device-01
```

Creates `../enrollment/device-01/` (0700) containing:

- `noise_ik_keys.h` — copy to `firmware/` before building this device's
  firmware (see docs/BUILD-AND-FLASH.md)
- `noise-ik.json` — the matching **first controller** identity; install on
  the BLE host as `~/.config/pico-bridge/noise-ik.json` (0600, dir 0700).
  On first boot the firmware auto-imports its public half into admin slot 1,
  so the very first controller is bootstrapped without needing an existing
  admin.

Prints no key material. Everything stays in the 0700 directory.

## 2. Additional controllers

On the **new** controller machine:

```bash
python3 tools/controller_identity.py --out ~/picobridge/device-01 --label laptop-02
```

This writes `identity-private.json` (keep, 0600 — becomes this machine's
`~/.config/pico-bridge/noise-ik.json`) and `enrollment.json` (**public key
only** — safe to transfer to an existing admin over any channel).

On an **existing admin** machine, with the Pico advertising:

```bash
python3 tools/pico_bridge_ctl.py controller add \
    --public path/from/enrollment.json --role operator
```

The Pico answers with an encrypted receipt; slot assignment is the device's.
Revocation (admin only, slot numbers are printed by the device):

```bash
python3 tools/pico_bridge_ctl.py controller revoke --slot 2
```

Rules the firmware enforces:

- Slot 0 (recovery admin) cannot be revoked, and an active session cannot
  revoke its own slot — closing the post-revocation command window.
- Revocation takes effect immediately: the revoked key fails the Noise
  handshake itself (0-byte response), not just command authorization.
- The roster persists across reboots and firmware updates in dedicated flash
  sectors (power-fail safe, versioned, CRC-checked). A corrupted store never
  auto-reseeds — that would be a silent reset of trust.

## 3. Recovery procedure

If all daily controllers are lost/stolen: on a machine with BLE, restore the
recovery admin private key from your vault into
`~/.config/pico-bridge/noise-ik.json` and use it as the `--noise-identity`
for `controller add/revoke`. If the recovery private key itself is lost,
the device is a brick for secret-typing purposes (by design; reflashing is
not possible without BOOTSEL and would reset the trust store only after a
full flash erase).

## 4. What the device does *not* store

No passwords, no keystroke history, no secrets of any kind survive a command
on the device: staged strings live in RAM, are wiped after typing/cancel/TTL,
and are never written to flash. Stealing the Pico yields its device key —
enough to *look like* the device to your controller, but never enough to
recover any password. Keep controller identities on the controller.

## 5. Wi-Fi provisioning (SET_RADIO)

Devices built with Wi-Fi support join a WPA2-PSK network so controllers can
reach them over the network instead of BLE. Credentials are provisioned over
the same authenticated Noise channel — never over the air unauthenticated,
never via a mass-storage file:

```
python3 tools/pico_bridge_ctl.py set-radio --ssid MyNetwork
# passphrase is prompted hidden, or read from a 0600 file via --psk-file
python3 tools/pico_bridge_ctl.py clear-radio
```

Rules enforced by the firmware:

- **Admin only.** Operator-role controllers cannot change radio settings.
- **Bench only.** The command is rejected while a USB host is mounted
  (`tud_mounted()`): rotating credentials requires someone physically at the
  device, and a relayed BLE session cannot reconfigure a deployed bridge.
- Schema 2 record (`PBRAD02`) in a dedicated flash sector: SSID 1–32 bytes,
  PSK 8–63 bytes, printable ASCII only, CRC32-checked, written and verified
  byte-for-byte before the command acknowledges. `clear-radio` erases it.
- An invalid or absent record means **no radio**: the device never falls back
  to an open network.

The stored record is link credentials only; the Noise controller identities
are unaffected. Rotating Wi-Fi passwords is one `set-radio` away.
