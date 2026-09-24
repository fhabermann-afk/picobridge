#!/usr/bin/env python3
"""Tests for pico-send clipboard plumbing; no BLE hardware or GUI required."""
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pico_send", ROOT / "tools" / "pico_send.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load pico_send.py")
pico_send = importlib.util.module_from_spec(SPEC)
sys.modules["pico_send"] = pico_send
SPEC.loader.exec_module(pico_send)


class ClipboardTests(unittest.TestCase):
    def test_xclip_is_selected_for_an_x11_session(self):
        with patch.dict(os.environ, {"DISPLAY": ":0"}, clear=True), \
             patch.object(pico_send.shutil, "which", side_effect=lambda name: "/usr/bin/xclip" if name == "xclip" else None):
            self.assertEqual(pico_send.clipboard_backend(), "xclip")

    def test_wayland_wins_when_both_tools_exist(self):
        with patch.dict(os.environ, {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"}, clear=True), \
             patch.object(pico_send.shutil, "which", return_value="/usr/bin/tool"):
            self.assertEqual(pico_send.clipboard_backend(), "wayland")

    def test_read_strips_only_copy_newlines(self):
        completed = subprocess.CompletedProcess([], 0, b"secret\r\n", b"")
        with patch.object(pico_send.subprocess, "run", return_value=completed) as run:
            self.assertEqual(pico_send.clipboard_read("xclip"), b"secret")
            self.assertEqual(run.call_args.args[0], ["xclip", "-selection", "clipboard", "-o"])

    def test_read_failure_is_loud(self):
        completed = subprocess.CompletedProcess([], 1, b"", b"no display")
        with patch.object(pico_send.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(SystemExit, "clipboard read failed"):
                pico_send.clipboard_read("xclip")


if __name__ == "__main__":
    unittest.main()
