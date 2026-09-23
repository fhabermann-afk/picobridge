#!/usr/bin/env python3
"""Create an offline X25519 identity for a future PicoBridge controller.

The private file stays on the controller owner's workstation. The public
``enrollment.json`` is safe to hand to an already-authorised PicoBridge admin
when multi-controller firmware is deployed. This program never contacts BLE
hardware and never prints private key material.
"""
import argparse
import base64
import json
import os
import re
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

PROTOCOL = "Noise_IK_25519_ChaChaPoly_SHA256"
SCHEMA = 1
LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,31}\Z")


def raw_private(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def raw_public(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def write_identity(out_dir: Path, label: str) -> tuple[Path, Path]:
    """Write private/public identity artifacts without following symlinks."""
    if not LABEL_RE.fullmatch(label):
        raise ValueError("label must be 1–32 printable ASCII characters")
    out_dir = Path(out_dir)
    if out_dir.name in ("", ".", ".."):
        raise ValueError("invalid output directory")
    parent_fd = os.open(out_dir.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created_dir = False
    output_fd = None
    try:
        parent_stat = os.fstat(parent_fd)
        if parent_stat.st_uid != os.geteuid() or stat.S_IMODE(parent_stat.st_mode) & 0o077:
            raise PermissionError("output parent must be private (0700) and owned by this user")
        os.mkdir(out_dir.name, 0o700, dir_fd=parent_fd)
        created_dir = True
        output_fd = os.open(out_dir.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        key = X25519PrivateKey.generate()
        private_doc = {
            "schema": SCHEMA,
            "protocol": PROTOCOL,
            "kind": "picobridge-controller-private",
            "label": label,
            "initiator_private_b64": b64(raw_private(key)),
        }
        public_doc = {
            "schema": SCHEMA,
            "protocol": PROTOCOL,
            "kind": "picobridge-controller-enrollment",
            "label": label,
            "initiator_public_b64": b64(raw_public(key)),
        }
        for name, document, mode in (("identity-private.json", private_doc, 0o600),
                                     ("enrollment.json", public_doc, 0o644)):
            data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         mode, dir_fd=output_fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        os.fsync(output_fd)
        os.fsync(parent_fd)
        return out_dir / "identity-private.json", out_dir / "enrollment.json"
    except BaseException:
        if output_fd is not None:
            for name in ("identity-private.json", "enrollment.json"):
                try:
                    os.unlink(name, dir_fd=output_fd)
                except FileNotFoundError:
                    pass
        if created_dir:
            os.rmdir(out_dir.name, dir_fd=parent_fd)
        raise
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an offline PicoBridge controller identity.")
    parser.add_argument("--out", required=True, type=Path,
                        help="new directory below an existing private 0700 parent")
    parser.add_argument("--label", required=True, help="controller label (1–32 ASCII characters)")
    args = parser.parse_args()
    try:
        private_path, public_path = write_identity(args.out, args.label)
    except (ValueError, OSError, PermissionError) as exc:
        print(f"Identity generation failed: {exc}", file=sys.stderr)
        return 1
    print("Created an offline controller identity. No private key was printed.")
    print(f"Private vault import: {private_path}")
    print(f"Public enrollment file: {public_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
