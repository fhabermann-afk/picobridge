#!/usr/bin/env python3
"""Fleet registry: give every PicoBridge a name your tools can target.

File: ~/.config/pico-bridge/fleet.json (0600 recommended; never contains
secrets — identity files are referenced by path only):

    {
      "szczecin":  {"host": "192.168.1.185",
                    "ble": "2C:CF:67:CA:3B:E4",
                    "identity": "~/.config/pico-bridge/pico-01.json"},
      "workshop":  {"host": "picobridge-ab12.local",
                    "identity": "~/.config/pico-bridge/pico-02.json"}
    }

Every fleet device advertises BLE and DHCP under the suffix of its board
unique ID: name "PicoBridge-ab12", hostname "picobridge-ab12". An alias is
purely local convenience; the Noise identity remains the security boundary.
"""
import json
import os
import re
from pathlib import Path

FLEET_PATH = Path.home() / ".config" / "pico-bridge" / "fleet.json"
BRIDGE_PREFIX = "PicoBridge-"
_SUFFIX_RE = re.compile(r"[0-9a-fA-F]{1,4}\Z")
_ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\Z")
MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\Z")


def load_fleet(path=None):
    path = Path(path) if path is not None else FLEET_PATH
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(raw, dict):
        return {}
    fleet = {}
    for alias, entry in raw.items():
        if not _ALIAS_RE.fullmatch(str(alias)) or not isinstance(entry, dict):
            continue
        clean = {}
        for key in ("host", "ble", "identity"):
            value = entry.get(key)
            if isinstance(value, str) and value.strip():
                clean[key] = value.strip()
        if clean:
            fleet[str(alias)] = clean
    return fleet


def looks_like_host(token):
    """Distinguish a literal host:port from an alias lookup."""
    host = token.partition(":")[0]
    if MAC_RE.fullmatch(host):
        return True
    # IPv4 dotted quad or anything with dots (hostname/MDNS) is literal
    return "." in host


def resolve(token, path=None):
    """Alias -> entry dict; anything else -> None (caller treats as literal)."""
    if token is None:
        return None
    if looks_like_host(token):
        return None
    return load_fleet(path).get(token)


def ble_matches(device_name, selector):
    """True if a BLE advertisement belongs to the selected device.

    selector: None (any bridge), a 1-4 hex suffix, a full
    "PicoBridge-xxxx" name, a MAC address, or a fleet alias' ble field.
    The classic unsuffixed "PicoBridge" (pre-fleet firmware) matches any
    bridge selector so old devices keep working during a rollout.
    """
    name = device_name or ""
    if selector is None:
        return name.startswith("PicoBridge")
    if MAC_RE.fullmatch(selector):
        return False  # address matching happens against the scan entry, not name
    if name == selector:
        return True
    if _SUFFIX_RE.fullmatch(selector):
        if name == "PicoBridge":
            return True
        suffix = name[len(BRIDGE_PREFIX):] if name.startswith(BRIDGE_PREFIX) else ""
        return suffix.lower().endswith(selector.lower())
    return False


def expand_path(value):
    return str(Path(value).expanduser()) if value else value


def fleet_file_mode_ok(path=None):
    """Advisory only: warn (return False) when the fleet file is group/world readable."""
    path = Path(path) if path is not None else FLEET_PATH
    try:
        return not (os.stat(path).st_mode & 0o077)
    except OSError:
        return True
