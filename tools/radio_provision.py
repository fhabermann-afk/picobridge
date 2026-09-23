#!/usr/bin/env python3
"""Offline radio-diagnostic provisioning. No device I/O, no secret stdout."""
import struct
import zlib
import ipaddress
import re
import secrets
import argparse
import json
import os
import stat
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SECTOR_SIZE = 4096
FLASH_OFFSET = 0x003FF000
MAGIC = b"PBRAD01\x00"


def pack_sector(ssid, passphrase, cert_der, key_der):
    """Encode the versioned radio record (CRC detects corruption, not forgery)."""
    for value, low, high in ((ssid, 1, 32), (passphrase, 20, 63)):
        if (not isinstance(value, str) or not low <= len(value) <= high
                or any(not 32 <= ord(char) <= 126 for char in value)):
            raise ValueError("Invalid radio credential format")
    for value, high in ((cert_der, 2048), (key_der, 1024)):
        if not isinstance(value, bytes) or not 1 <= len(value) <= high:
            raise ValueError("Invalid DER field length")
    parts = (ssid.encode("ascii"), passphrase.encode("ascii"), cert_der, key_der)
    lengths = struct.pack("<HHHH", *(len(part) for part in parts))
    payload = lengths + b"".join(parts)
    total = 16 + len(payload)
    header = MAGIC + struct.pack("<HHI", 1, total, zlib.crc32(payload))
    return header + payload + b"\xff" * (SECTOR_SIZE - total)


def generate_bundle(serial):
    """Generate a diagnostic-only CA/leaf and random AP key entirely offline.

    The CA signing key is transient and never serialized. Renewal requires new
    enrollment. Python/cryptography memory erasure is not guaranteed.
    """
    if not isinstance(serial, str) or re.fullmatch(r"[0-9A-F]{16}", serial) is None:
        raise ValueError("Expected exact 16-character uppercase hexadecimal serial")
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PicoBridge diagnostic CA " + serial)])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PicoBridge diagnostic " + serial)])
    cert = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("192.168.4.1"))]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    cert.verify_directly_issued_by(ca)
    ssid = "Pico-Keyboard-" + serial[-8:]
    passphrase = secrets.token_urlsafe(24)
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    key_der = leaf_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return {
        "sector": pack_sector(ssid, passphrase, cert_der, key_der),
        "ca_pem": ca.public_bytes(serialization.Encoding.PEM),
        "enrollment": {
            "schema": 1, "purpose": "radio-diagnostic-no-typing", "serial": serial,
            "ssid": ssid, "wpa2_passphrase": passphrase,
            "url": "https://192.168.4.1/", "flash_offset": FLASH_OFFSET,
            "ca_sha256": ca.fingerprint(hashes.SHA256()).hex(),
            "leaf_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "expires_utc": cert.not_valid_after_utc.isoformat(),
        },
    }


def write_bundle(directory, bundle):
    """Create a new private directory, exclusively; never overwrite enrollment.

    Intended for the Linux provisioning host. The existing parent must be owned
    by this user and inaccessible to group/other. No CA private key is stored.
    """
    directory = Path(directory)
    if directory.name in ("", ".", ".."):
        raise ValueError("Invalid output directory")
    files = {
        "sector.bin": bundle["sector"],
        "ca.pem": bundle["ca_pem"],
        "enrollment.json": (json.dumps(bundle["enrollment"], indent=2) + "\n").encode("utf-8"),
    }
    parent_fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_fd = None
    created = []
    made_directory = False
    try:
        info = os.fstat(parent_fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("Output parent must be private and owned by the current user")
        os.mkdir(directory.name, mode=0o700, dir_fd=parent_fd)
        made_directory = True
        directory_fd = os.open(directory.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        for name, content in files.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            created.append(name)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(directory_fd)
        os.fsync(parent_fd)
    except BaseException:
        if directory_fd is not None:
            for name in created:
                os.unlink(name, dir_fd=directory_fd)
        if made_directory:
            os.rmdir(directory.name, dir_fd=parent_fd)
        raise
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)


def main():
    parser = argparse.ArgumentParser(description="Generate offline diagnostic enrollment; does not flash hardware.")
    parser.add_argument("--serial", required=True, help="Exact 16-character uppercase USB serial")
    parser.add_argument("--out", required=True, type=Path, help="New directory under an existing private (0700) parent")
    args = parser.parse_args()
    try:
        write_bundle(args.out, generate_bundle(args.serial))
    except (ValueError, OSError):
        print("Provisioning failed: invalid serial or output path; require a new directory under a private writable parent.", file=sys.stderr)
        return 1
    print("Created diagnostic enrollment. No hardware changed; credentials are only in the private output directory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
