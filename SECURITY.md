# Security Model & Liability

## What problem this solves

Typing a secret into an untrusted machine through software (clipboard,
keystroke injection, remote desktop, browser autofill) exposes the secret to
that machine's software. PicoBridge moves the last meter to hardware: a
co-processor presents the secret to the target strictly as USB-HID keycodes,
while the secret travels over an over-the-air channel that is mutually
authenticated and encrypted with Noise `IK` (X25519 + ChaCha20-Poly1305 +
SHA-256).

## What the device stores

- Its Noise static private key (device identity).
- The enrolled controller public-key roster + recovery-admin public key.
- **Nothing else.** No passwords, no keystroke history, no caches. Staged
  secrets live in RAM, are wiped after execution/cancel/TTL, and never touch
  flash. Confiscating the Pico reveals zero user secrets — it is not a
  password vault, it is a keyboard with a bouncer.

## Trust boundaries

| Threat | Handling |
|---|---|
| BLE eavesdropper | All post-handshake traffic is ChaCha20-Poly1305; handshake is standard `Noise_IK_25519_ChaChaPoly_SHA256`. Passive sniffing yields nothing beyond BLE metadata. |
| Unknown BLE controller | Rejected at the Noise handshake against the enrolled roster (0-byte response — no oracle, no retry signalling). Plaintext commands are unconditionally discarded. |
| Stolen/leaked controller identity | Admin revokes the slot over an authenticated session; revoked keys fail the handshake immediately, even across reboots (flash-persisted roster). |
| Stolen Pico | Yields the device private key at best (see SWD caveat below). No user secrets stored. Controllers still require the user's controller identity to type anything. |
| Rollback of trust store | Store sectors are versioned, CRC-checked, power-fail safe; a corrupted store never auto-reseeds. |
| Replay of captured commands | Per-command IDs with a replay ledger + strictly increasing transport nonces. |
| Malicious controller forcing weird keystrokes | Firmware-side policy: password mode rejects control characters, layout maps reject unrepresentable characters — the core state machine, not the caller, is the enforcement point. |

## Known gaps (not vulnerabilities we are hiding)

- **SWD is not fused off**: physical attackers can extract the device private
  key and impersonate the device toward controllers. No user secrets leak,
  but device-identity trust is degraded. Roadmap: RP2350 fuse configuration.
- No secure boot / firmware integrity verification: a physical attacker can
  replace the firmware entirely. As with any keyboard, a tampered device is
  game over for *typing into it what you see on it* — inspect hardware you
  type secrets into, same as with any USB token.
- The Wi-Fi experiment under `firmware/radio/` is not part of the security
  story; do not build or flash radio variants for secrets.
- No third-party audit. Treat everything as prototype-grade.

## Reporting issues

Open a GitHub issue for ordinary bugs. For suspected **security** problems,
prefer a private disclosure (GitHub private security advisory on the
repository). Expect prototype-maintainer response times, and no bug bounty —
there is no money here, only a keyboard made by robots.

## Liability — read this, it is the entire license

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

Concretely: do not use this to protect anything whose loss you cannot accept,
do not store your only copy of anything behind it, and keep a fallback login
path for every secret you type with it. The authors accept **no liability
whatsoever** for any use or misuse of this software, including secret loss,
account lockout, data loss, or any downstream consequence — categorically
and to the maximum extent any legal system permits. Using this project means
you accept that.
