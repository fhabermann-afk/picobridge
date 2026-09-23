"""Regression contract for the HID press/release transaction.

TinyUSB only accepts the release after the press interrupt transfer has
completed.  Queuing both reports back-to-back leaves keys held on the host.
The target code cannot run natively, so this verifies the C transaction shape.
"""
from pathlib import Path

SOURCE = Path(__file__).parents[1] / "firmware" / "bridge_main.c"


def test_hid_press_waits_for_ready_before_zero_release():
    source = SOURCE.read_text()
    press = "tud_hid_keyboard_report(0, stroke.modifier, keys)"
    wait = "while (!tud_hid_ready() && usb_now_ms < deadline)"
    release = "tud_hid_keyboard_report(0, 0, released)"

    assert "uint8_t keys[6] = {stroke.usage, 0, 0, 0, 0, 0}" in source
    assert press in source
    assert wait in source
    assert release in source
    assert source.index(press) < source.index(wait) < source.index(release)
