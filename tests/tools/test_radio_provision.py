"""Only generated/dummy local fixtures; never reads actual device credentials."""
import importlib.util
from pathlib import Path
import struct
import zlib

ROOT = Path(__file__).resolve().parents[2]


def module():
    path = ROOT / "tools/radio_provision.py"
    assert path.exists(), "Radio provisioning implementation is missing"
    spec = importlib.util.spec_from_file_location("radio_provision", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sector_matches_documented_binary_abi():
    mod = module()
    ssid, psk = "Pico-Keyboard-test", "dummy-only-test-passphrase-123"
    cert, key = b"dummy-cert", b"dummy-key"
    sector = mod.pack_sector(ssid, psk, cert, key)
    assert len(sector) == 4096
    assert sector[:8] == b"PBRAD01\x00"
    version, length, crc, *sizes = struct.unpack_from("<HHIHHHH", sector, 8)
    payload = ssid.encode() + psk.encode() + cert + key
    assert version == 1
    assert sizes == [len(ssid), len(psk), len(cert), len(key)]
    assert length == 24 + len(payload)
    assert sector[24:length] == payload
    assert crc == zlib.crc32(sector[16:length])
    assert sector[length:] == b"\xff" * (4096 - length)


def test_reject_invalid_record_fields_without_echoing_them():
    import pytest
    mod = module()
    good = ["Pico-Keyboard-test", "dummy-only-test-passphrase-123", b"cert", b"key"]
    bad_fields = [(0, ""), (0, "s" * 33), (0, "bad\x00ssid"), (0, "ä"),
                  (1, "short"), (1, "p" * 64), (1, "p" * 20 + "\n"),
                  (2, b""), (2, b"c" * 2049), (3, b""), (3, b"k" * 1025)]
    for index, value in bad_fields:
        fields = good.copy()
        fields[index] = value
        with pytest.raises(ValueError) as error:
            mod.pack_sector(*fields)
        assert good[1] not in str(error.value)


def test_generated_bundle_has_matching_p256_key_and_ip_certificate():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID
    import ipaddress
    import pytest
    mod = module()
    bundle = mod.generate_bundle("0123456789ABCDEF")
    sector = bundle["sector"]
    lengths = struct.unpack_from("<HHHH", sector, 16)
    offset = 24
    fields = []
    for length in lengths:
        fields.append(sector[offset:offset+length])
        offset += length
    ssid, passphrase, cert_der, key_der = fields
    cert = x509.load_der_x509_certificate(cert_der)
    ca = x509.load_pem_x509_certificate(bundle["ca_pem"])
    key = serialization.load_der_private_key(key_der, None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    assert isinstance(key.curve, ec.SECP256R1)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    cert.verify_directly_issued_by(ca)
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("192.168.4.1")]
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    assert ExtendedKeyUsageOID.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert len(passphrase) >= 32
    assert passphrase.decode() == bundle["enrollment"]["wpa2_passphrase"]
    assert ssid.decode() == bundle["enrollment"]["ssid"]
    assert bundle["enrollment"]["leaf_sha256"] == cert.fingerprint(hashes.SHA256()).hex()
    assert set(bundle) == {"sector", "ca_pem", "enrollment"}, "Never retain CA signing key"
    other = mod.generate_bundle("0123456789ABCDEF")
    assert other["sector"] != sector
    assert other["enrollment"]["wpa2_passphrase"] != passphrase.decode()
    for invalid in ("", "0123456789abcdef", "123", "../../example"):
        with pytest.raises(ValueError):
            mod.generate_bundle(invalid)


def test_bundle_files_are_private_exclusive_and_cli_never_prints_secrets(tmp_path):
    import json
    import os
    import stat
    import subprocess
    import sys
    import pytest
    mod = module()
    os.chmod(tmp_path, 0o700)
    bundle = mod.generate_bundle("0123456789ABCDEF")
    out = tmp_path / "bundle"
    mod.write_bundle(out, bundle)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert {p.name for p in out.iterdir()} == {"sector.bin", "ca.pem", "enrollment.json"}
    for path in out.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    before = (out / "sector.bin").read_bytes()
    assert before == bundle["sector"]
    with pytest.raises(FileExistsError):
        mod.write_bundle(out, mod.generate_bundle("0123456789ABCDEF"))
    assert (out / "sector.bin").read_bytes() == before
    (tmp_path / "link").symlink_to(out, target_is_directory=True)
    with pytest.raises(OSError):
        mod.write_bundle(tmp_path / "link", bundle)
    os.chmod(tmp_path, 0o755)
    with pytest.raises(PermissionError):
        mod.write_bundle(tmp_path / "unsafe", bundle)
    os.chmod(tmp_path, 0o700)
    cli_out = tmp_path / "cli"
    command = [sys.executable, str(ROOT / "tools/radio_provision.py"), "--serial", "0123456789ABCDEF", "--out", str(cli_out)]
    result = subprocess.run(command, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    enrollment = json.loads((cli_out / "enrollment.json").read_text())
    assert enrollment["wpa2_passphrase"] not in result.stdout + result.stderr
    assert "PRIVATE KEY" not in result.stdout + result.stderr
    repeat = subprocess.run(command, text=True, capture_output=True, timeout=10)
    assert repeat.returncode != 0
    assert enrollment["wpa2_passphrase"] not in repeat.stdout + repeat.stderr


def test_generated_cert_enforces_trust_and_ip_in_real_tls(tmp_path):
    import socket
    import ssl
    import threading
    import pytest
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    mod = module()
    bundle = mod.generate_bundle("0123456789ABCDEF")
    sizes = struct.unpack_from("<HHHH", bundle["sector"], 16)
    start = 24 + sizes[0] + sizes[1]
    cert_der = bundle["sector"][start:start+sizes[2]]
    key_der = bundle["sector"][start+sizes[2]:start+sizes[2]+sizes[3]]
    cert_path, key_path = tmp_path / "leaf.pem", tmp_path / "key.pem"
    cert_path.write_bytes(x509.load_der_x509_certificate(cert_der).public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(serialization.load_der_private_key(key_der, None).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.chmod(0o600)
    key_path.chmod(0o600)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.maximum_version = ssl.TLSVersion.TLSv1_2
    server_context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
    server_context.load_cert_chain(cert_path, key_path)
    outcomes = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(3)
        listener.settimeout(5)
        def serve():
            for _ in range(3):
                try:
                    raw, _ = listener.accept()
                    raw.settimeout(5)
                    with raw:
                        with server_context.wrap_socket(raw, server_side=True) as tls:
                            outcomes.append(tls.recv(16))
                            tls.sendall(b"ok")
                except ssl.SSLError:
                    outcomes.append(b"rejected")
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        cases = [(bundle["ca_pem"], "192.168.4.1", True),
                 (mod.generate_bundle("0123456789ABCDEF")["ca_pem"], "192.168.4.1", False),
                 (bundle["ca_pem"], "192.168.4.2", False)]
        for ca_pem, name, expected in cases:
            context = ssl.create_default_context(cadata=ca_pem.decode())
            with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                if expected:
                    with context.wrap_socket(raw, server_hostname=name) as tls:
                        assert tls.version() == "TLSv1.2"
                        assert tls.cipher()[0] == "ECDHE-ECDSA-AES128-GCM-SHA256"
                        tls.sendall(b"dummy-health")
                        assert tls.recv(2) == b"ok"
                else:
                    with pytest.raises(ssl.SSLCertVerificationError):
                        context.wrap_socket(raw, server_hostname=name)
        worker.join(6)
        assert not worker.is_alive()
    assert outcomes == [b"dummy-health", b"rejected", b"rejected"]


def test_partial_write_failure_removes_only_new_bundle(tmp_path, monkeypatch):
    import pytest
    mod = module()
    tmp_path.chmod(0o700)
    target = tmp_path / "new"
    def fail_fsync(_):
        raise OSError("injected I/O failure")
    monkeypatch.setattr(mod.os, "fsync", fail_fsync)
    with pytest.raises(OSError):
        mod.write_bundle(target, mod.generate_bundle("0123456789ABCDEF"))
    assert not target.exists()
