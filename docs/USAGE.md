# Usage

## Daily driver: `tools/pico_send.py` (`pico-send`)

Type a secret into whatever window you focus after the countdown:

```bash
pico-send                          # hidden password prompt, 5 s countdown, Enter after
pico-send --clipboard              # read the password copied by KeePassXC/KeepassX
pico-send -t "https://example.com" # visible text mode (NOT for secrets), Enter after
pico-send -d 10 --no-enter         # 10 s to focus the window, no trailing Enter
echo pw | pico-send --stdin        # pipe a secret in
printf %s "$pw" | pico-send --stdin --mode password --layout us
```

Behaviour that matters:

- **`--clipboard`** reads the graphical clipboard directly (KeePassXC,
  KeepassX, etc.), so the secret never appears in shell history or argv. It
  deliberately **does not clear the clipboard**: password managers already
  clear it on their configured timeout, while clearing it here could destroy
  a newer copy made after this command started. On Wayland it uses
  `wl-paste` (package `wl-clipboard`); on X11 it uses `xclip` or
  `xsel`. Run it in the relevant graphical session.
- **Never pass secrets as argv** — shell history and `/proc/<pid>/cmdline`
  leak them. Use the hidden prompt, `--stdin`, or a 0600 file.
- **`--layout us|de` must match the keyboard layout of the *target*
  machine.** If any character is not typeable in that layout, the device
  rejects the whole command (`status 7 = UNSUPPORTED`) and types nothing —
  you will never receive a silently mangled password. See
  [LIMITATIONS.md](LIMITATIONS.md).
- The countdown runs *before* the BLE connection so staging + confirmation
  happen back-to-back inside the device's 15-second staging TTL; your window
  focus is captured when you finish the countdown.
- `OK: typed N characters` confirms the device **accepted and scheduled** the
  keystrokes (encrypted, device-authenticated receipt). It is not a proof of
  delivery into a specific field — for that, watch the field, or capture
  `/dev/input/event<N>` on Linux targets.
- Identity discovery: `~/.config/pico-bridge/noise-ik.json`, then
  `private/noise-ik-current/noise-ik.json`; or pass `--identity PATH`.
  The file must be a regular file, 0600, owned by you — running the tool via
  `sudo` against a user-owned identity fails by design. Give yourself an ACL
  on the event node instead when you need to capture events while sending.

## Low-level CLI: `tools/pico_bridge_ctl.py`

Everything the device speaks, one subcommand per protocol operation:

```bash
# stage + immediately type in one authenticated connection:
python3 tools/pico_bridge_ctl.py stage --stdin --mode password --owner $UID --id 101 --auto-confirm

# two-phase (stage now, confirm from anywhere within the TTL):
python3 tools/pico_bridge_ctl.py stage --text "otp" --owner $UID --id 102 --no-confirm
python3 tools/pico_bridge_ctl.py confirm --owner $UID --id 102   # or: cancel
```

Owner/ID are your own namespace (uint32). IDs are replay-protected: reusing a
recent ID gets `status 12 = REPLAY`. Use a fresh random ID per transaction
(what `pico-send` does).

## Protocol reference (firmware ↔ controller)

- BLE: name `PicoBridge`, one 128-bit service, one characteristic
  (write-without-response + dynamic read). `tools/pico_bridge_ctl.py` holds
  the exact UUIDs.
- Handshake: `Noise_IK_25519_ChaChaPoly_SHA256`; initiator pins the device
  static key from its identity file, device verifies the initiator against
  the enrolled controller store. Unknown keys → 0-byte response, no retry
  oracle.
- Commands are `CMD_ENCRYPTED || nonce64 || ChaChaPoly(frame, tag)` after the
  handshake, fragmented at BLE-MTU size with a (seq, more) header; plaintext
  command frames are rejected unconditionally.
- Every accepted command returns an encrypted receipt carrying the
  `bridge_core` status byte; the CLI throws on any non-zero status.
- Staged payload lives in RAM for max 15 s (TTL), is wiped after execution,
  cancellation, or expiry, and never reaches flash.
- Layout maps (`US`, `DE`) and the password-mode control-character policy
  (LF/TAB and every other control char rejected in password mode, fail
  closed) are enforced in firmware — a malicious controller cannot make the
  device press combinations the policy forbids.

## Verifying output on a Linux target (optional, paranoid mode)

```bash
# find the node once:
grep -il cafe /sys/class/input/*/device/uevent
# capture while you send (note: the capture grabs the device exclusively —
# keystrokes during capture will NOT reach your desktop; that is normal):
sudo evtest /dev/input/event<N>
```

Expect a `value 1`/`value 0` pair per character. Repeated `value 2` means a
stuck key — stop and reflash (known failure mode of pre-fix images, see
docs/LIMITATIONS.md).
