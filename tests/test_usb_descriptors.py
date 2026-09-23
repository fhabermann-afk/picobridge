"""Native descriptor contract; no hardware needed for this test."""
import ctypes
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class UsbDescriptorTests(unittest.TestCase):
    def test_boot_keyboard_only_no_debug_interfaces(self):
        source = ROOT / 'firmware/usb_descriptors.c'
        self.assertTrue(source.is_file(), 'USB descriptor implementation is missing')
        with tempfile.TemporaryDirectory() as d:
            lib = pathlib.Path(d) / 'descriptors.so'
            subprocess.run(['cc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(source), '-o', str(lib)], check=True)
            usb = ctypes.CDLL(str(lib))
            for name in ('tud_descriptor_device_cb', 'tud_descriptor_configuration_cb',
                         'tud_hid_descriptor_report_cb'):
                getattr(usb, name).restype = ctypes.POINTER(ctypes.c_uint8)
            dev = bytes(usb.tud_descriptor_device_cb()[:18])
            self.assertEqual(dev[:2], b'\x12\x01')
            self.assertEqual(dev[17], 1)
            cfg = bytes(usb.tud_descriptor_configuration_cb(0)[:34])
            self.assertEqual(cfg[:5], bytes([9, 2, 34, 0, 1]))
            self.assertEqual(cfg[9:18], bytes([9, 4, 0, 0, 1, 3, 1, 1, 0]))
            self.assertEqual(cfg[27:34], bytes([7, 5, 0x81, 3, 8, 0, 10]))
            length = int.from_bytes(cfg[25:27], 'little')
            report = bytes(usb.tud_hid_descriptor_report_cb(0)[:length])
            self.assertEqual(report[:6], bytes([5, 1, 9, 6, 0xa1, 1]))
            self.assertEqual(report[-1], 0xc0)
            self.assertNotIn(b'\x85', report, 'boot reports must have no report ID')
            self.assertEqual(report.count(b'\x81\x02'), 1, 'modifier input')
            self.assertEqual(report.count(b'\x81\x00'), 1, 'key array input')
            self.assertEqual(report.count(b'\x91\x02'), 1, 'keyboard LEDs output')

    def test_serial_and_radio_status_strings_are_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            lib = pathlib.Path(d) / 'descriptors.so'
            subprocess.run(['cc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(ROOT / 'firmware/usb_descriptors.c'), '-o', str(lib)], check=True)
            usb = ctypes.CDLL(str(lib))
            self.assertTrue(hasattr(usb, 'bridge_usb_set_identity'), 'device identity setter missing')
            usb.bridge_usb_set_identity.argtypes = [ctypes.c_char_p, ctypes.c_bool]
            usb.tud_descriptor_string_cb.restype = ctypes.POINTER(ctypes.c_uint16)
            usb.bridge_usb_set_identity(b'0123456789ABCDEF', True)
            def text(index):
                q = usb.tud_descriptor_string_cb(index, 0x409)
                return ''.join(chr(q[k]) for k in range(1, (q[0] & 255)//2))
            self.assertEqual(text(3), '0123456789ABCDEF')
            self.assertIn('CYW43 OK', text(2))
            usb.bridge_usb_set_identity(b'A'*1000, False)
            self.assertLessEqual(len(text(3)), 32)
            self.assertIn('CYW43 FAIL', text(2))
            self.assertFalse(usb.tud_descriptor_string_cb(255, 0x409))
            self.assertFalse(usb.tud_descriptor_string_cb(1, 0x9999))
            self.assertEqual(usb.tud_descriptor_string_cb(0, 0)[1], 0x409)


if __name__ == '__main__':
    unittest.main()
