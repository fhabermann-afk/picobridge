# PicoBridge — Client

Der Client schickt Befehle an einen PicoBridge-Pico 2 W, der sie als
USB-Tastatur auf dem Zielrechner tippt — Ende-zu-Ende verschlüsselt
(Noise IK). Der Rechner, auf dem du dieses Tool startest, ist der
**Controller**; der Pico tippt auf dem Rechner, an dem **er** per USB hängt.

Enthalten:

| Datei | Zweck |
|---|---|
| `tools/pico_tcp_send.py` | Befehle übers **WLAN** (TCP 44901) |
| `tools/pico_send.py` | Befehle übers **Bluetooth LE** |
| `tools/pico_bridge_ctl.py` | low-level CLI + Provisionierung/ Diagnose |
| `pico_bridge_net.uf2` | Firmware mit WLAN-Endpunkt (nur zum Flashen nötig) |
| `USAGE.md`, `PROVISIONING.md` | Detail-Dokumentation |

## 1. Python-Umgebung ausrollen

Python ≥ 3.10. Ein venv hält die Abhängigkeiten sauber:

```fish
# im entpackten Paketverzeichnis, z.B. ~/picobridge
python3 -m venv ~/picobridge-venv
~/picobridge-venv/bin/python -m pip install --upgrade pip
~/picobridge-venv/bin/python -m pip install -r requirements.txt
```

Falls `python3 -m venv` meckert (Debian/Ubuntu): `sudo apt install python3-venv`.
Verifizieren:

```fish
~/picobridge-venv/bin/python -c "import bleak, cryptography; print('ok')"
```

`bleak` (Bluetooth) wird auch für reine WLAN-Kommandos importiert — es ist
klein und erspart zwei Codepfade. Für `--clipboard` zusätzlich:
Wayland → `wl-clipboard`, X11 → `xclip` oder `xsel`.

## 2. Noise-Identität ablegen

Ohne eine im Pico eingetragene Identität antwortet der Pico auf **keinen**
Handshake. Datei selbst anlegen und Rechte geben:

```fish
mkdir -p ~/.config/pico-bridge
# noise-ik.json an diese Stelle kopieren (vom Geräte-Eigentümer erhalten)
chmod 600 ~/.config/pico-bridge/noise-ik.json
```

Anforderungen: reguläre Datei, Modus 0600, dir gehört. `sudo` mit der
Identität eines anderen Users wird bewusst abgelehnt.
Neue Controller erzeugen: `tools/noise_ik_provision.py` bzw. `PROVISIONING.md`.

## 3. Pico-IP finden

- Router-DHCP-Tabelle: Hostname `picobridge`
- oder über Bluetooth (funktioniert auch ohne WLAN):

```fish
~/picobridge-venv/bin/python tools/pico_bridge_ctl.py net-debug
# zeigt: Link-Status, DHCP-Phase, IP, Scan, RSSI
```

## 4. Tippen

Sichtbarer Test (landet im **fokussierten Fenster des Zielrechners**):

```fish
~/picobridge-venv/bin/python tools/pico_tcp_send.py 192.168.1.185 \
    -t "Hallo" --mode text
```

Passphrase / Passwort — **niemals** mit `-t` (landet in der History):

```fish
~/picobridge-venv/bin/python tools/pico_tcp_send.py 192.168.1.185 \
    --clipboard --mode password        # aus KeePassXC & co
~/picobridge-venv/bin/python tools/pico_tcp_send.py 192.168.1.185 \
    --mode password                    # versteckter Prompt
wl-paste --no-newline | tools/... --stdin   # oder explizit pipe
```

Wichtige TCP-Schalter: `--layout us|de` (Default `us` — Bootloader denken
US), `--no-enter` und `-d <sek>` (Countdown zum Fenster-Fokussieren).

Bluetooth statt WLAN: `tools/pico_send.py`. Sein Default-Layout ist `de`;
für GELI/ZFSBootMenu daher stets `--layout us` angeben. BLE bietet darüber
hinaus `--rescan`, `--timeout` und `--retries`; Details: `USAGE.md`.

## 5. Firmware flashen (nur einmal / bei Update)

BOOTSEL halten → Pico einstecken → loslassen, dann:

```fish
picotool load -v -x pico_bridge_net.uf2
```

Der WLAN-Zugang (Radio-Datensatz) liegt in einem reservierten Flash-Sektor
und überlebt das Flashen. Anderes WLAN gefällig?

```fish
~/picobridge-venv/bin/python tools/pico_bridge_ctl.py set-radio --ssid MeinNetz
# Pico muss dafür ohne USB-Host an Strom hängen (Bench-Gate), Details: PROVISIONING.md
```

## Troubleshooting

| Symptom | Ursache / Lösung |
|---|---|
| `no PicoBridge device found` | BLE: Adapter an (`rfkill`), Pico nah genug; `--rescan` |
| Handshake bleibt stumm | Identität fehlt/nicht eingetragen → Schritt 2 |
| `status=4 (BUSY)` | Pico tippt noch — Tools warten jetzt automatisch |
| `status=7 (UNSUPPORTED)` | Zeichen im Ziel-Layout nicht tipbar (z. B. ß auf US) |
| TCP verbindet nicht | IP geändert? Pico im gleichen Netz? `net-debug` nutzen |

Limits und Bedrohungsmodell: github.com/fhabermann-afk/picobridge →
`docs/LIMITATIONS.md`, `SECURITY.md`.
