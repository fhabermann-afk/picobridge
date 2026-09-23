"""Offline provisioning tests for mutually authenticated Noise IK credentials."""
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

ROOT = Path(__file__).resolve().parents[2]


def module():
    path = ROOT / "tools" / "noise_ik_provision.py"
    assert path.exists(), "Noise IK provisioning implementation is missing"
    spec = importlib.util.spec_from_file_location("noise_ik_provision", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generated_bundle_has_distinct_mutually_pinned_x25519_identities():
    mod = module()
    bundle = mod.generate_bundle()
    assert set(bundle) == {"firmware_header", "host_identity"}

    header = bundle["firmware_header"]
    host = bundle["host_identity"]
    assert host["schema"] == 1
    assert host["protocol"] == "Noise_IK_25519_ChaChaPoly_SHA256"
    assert "device_id" not in host

    host_priv = X25519PrivateKey.from_private_bytes(mod.b64decode_key(host["initiator_private_b64"]))
    device_pub = X25519PublicKey.from_public_bytes(mod.b64decode_key(host["device_public_b64"]))
    assert len(host_priv.exchange(device_pub)) == 32

    # Firmware contains different device private material and authorizes this exact host public key.
    device_priv = X25519PrivateKey.from_private_bytes(mod.header_key(header, "PICO_BRIDGE_DEVICE_STATIC_PRIVATE"))
    allowed_host = mod.header_key(header, "PICO_BRIDGE_AUTHORIZED_INITIATOR_PUBLIC")
    assert device_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == mod.b64decode_key(host["device_public_b64"])
    assert allowed_host == host_priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert mod.header_key(header, "PICO_BRIDGE_DEVICE_STATIC_PRIVATE") != mod.b64decode_key(host["initiator_private_b64"])


def test_private_bundle_files_are_exclusive_and_cli_never_prints_key_material(tmp_path):
    mod = module()
    tmp_path.chmod(0o700)
    output = tmp_path / "credentials"
    mod.write_bundle(output, mod.generate_bundle())
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert {entry.name for entry in output.iterdir()} == {"noise_ik_keys.h", "noise-ik.json"}
    for entry in output.iterdir():
        assert stat.S_IMODE(entry.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        mod.write_bundle(output, mod.generate_bundle())

    cli_out = tmp_path / "cli"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "noise_ik_provision.py"), "--out", str(cli_out)],
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    identity = json.loads((cli_out / "noise-ik.json").read_text())
    assert identity["initiator_private_b64"] not in combined
    assert identity["device_public_b64"] not in combined
    assert "PICO_BRIDGE_DEVICE_STATIC_PRIVATE" not in combined
