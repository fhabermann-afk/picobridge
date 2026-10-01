# Multiple Picos (fleet targeting)

Every bridge advertises a suffix of its board unique ID:

- BLE name: `PicoBridge-ab12`
- DHCP hostname: `picobridge-ab12`
- `pico_bridge_ctl.py discover` lists all bridges with suffix, MAC and alias

Target any of them:

```bash
python3 tools/pico_tcp_send.py picobridge-ab12 --mode password   # mDNS
python3 tools/pico_tcp_send.py 192.0.2.34 --mode password        # literal IP
python3 tools/pico_send.py --device ab12                         # BLE suffix
python3 tools/pico_send.py                                       # pre-fleet devices still work
```

## fleet.json

`~/.config/pico-bridge/fleet.json` (0600; contains no secrets, only paths):

```json
{
  "office": {"host": "192.0.2.34", "ble": "AA:BB:CC:DD:EE:01",
               "identity": "~/.config/pico-bridge/pico-01.json"},
  "lab":      {"host": "picobridge-ab12.local",
               "identity": "~/.config/pico-bridge/pico-02.json"}
}
```

Alias usage: `pico_tcp_send.py lab --mode password`,
`pico_send.py --device lab`. An entry may define `host` (TCP), `ble`
(BLE MAC or suffix) and `identity` (Noise identity file for **that**
device). An explicit `--identity`/`--noise-identity` flag always overrides
the fleet entry.

## Per-device Noise identities

Each bridge should carry its own Noise IK keypair (one
`noise_ik_provision.py` run per device, per-device UF2 build, per-device
host identity file). Compromise of one bridge's static key then cannot
impersonate another. The identity chosen for a target is resolved:
CLI flag → fleet entry → `~/.config/pico-bridge/noise-ik.json`.

## Rolling out

1. Flash the device-specific UF2 (keys baked in).
2. `discover` to read its suffix/MAC.
3. Add an alias + identity path to `fleet.json`.
4. Provision its Wi-Fi record (`set-radio`) if it should answer over TCP.

Devices running pre-fleet firmware keep advertising `PicoBridge` and match
any selector, so mixed fleets work during migration.
