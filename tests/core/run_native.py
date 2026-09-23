#!/usr/bin/env python3
"""Build/run real native core tests; optional append-only TDD evidence."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--sanitize", action="store_true")
parser.add_argument("--filter")
parser.add_argument("--label", help="Append actual commands/output to core-test-log.md")
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
build = root / "tests/core/.build"
build.mkdir(exist_ok=True)
binary = build / ("test_bridge_core_sanitized" if args.sanitize else "test_bridge_core")
cmd = shlex.split(os.environ.get("CC", "cc")) + [
    "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-O1", "-g",
    "-Ifirmware/core", "tests/core/test_bridge_core.c",
    "firmware/core/bridge_core.c", "-o", str(binary.relative_to(root)),
]
if args.sanitize:
    cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
transcript = []

def run(command):
    transcript.append("$ " + shlex.join(command))
    result = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=60)
    transcript.append(result.stdout.rstrip())
    transcript.append("exit=" + str(result.returncode))
    return result.returncode

code = run(cmd)
if code == 0:
    code = run([str(binary)] + ([args.filter] if args.filter else []))
text = "\n".join(transcript) + "\n"
print(text, end="")
if args.label:
    log = root / "docs/core-test-log.md"
    if not log.exists():
        log.write_text("# Core native TDD execution log\n\nActual compiler/test output. Synthetic, non-secret fixtures only.\n", encoding="utf-8")
    with log.open("a", encoding="utf-8") as out:
        out.write("\n## " + args.label + "\n\n```text\n" + text + "```\n")
sys.exit(code)
