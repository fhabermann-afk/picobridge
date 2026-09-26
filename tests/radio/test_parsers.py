import ctypes as C
import pathlib
import struct
import unittest
import zlib

HERE = pathlib.Path(__file__).resolve().parent
LIB = C.CDLL(str(HERE / '.build/parsers.so'))
class Config(C.Structure):
    _fields_ = [('ssid', C.c_char * 33), ('psk', C.c_char * 64),
                ('cert', C.c_void_p), ('key', C.c_void_p),
                ('cert_len', C.c_size_t), ('key_len', C.c_size_t)]
LIB.radio_config_parse.argtypes = [C.c_void_p, C.c_size_t, C.POINTER(Config)]
LIB.radio_config_parse.restype = C.c_bool
LIB.radio_config_parse2.argtypes = [C.c_void_p, C.c_size_t, C.POINTER(Config)]
LIB.radio_config_parse2.restype = C.c_bool
LIB.radio_config_build2.argtypes = [C.c_char_p, C.c_size_t, C.c_char_p, C.c_size_t,
                                    C.POINTER(C.c_ubyte * 4096)]
LIB.radio_config_build2.restype = C.c_bool

def sector(ssid=b'Radio test', psk=b'test-only-passphrase-12345', cert=b'cert', key=b'key'):
    payload = struct.pack('<4H',len(ssid),len(psk),len(cert),len(key))+ssid+psk+cert+key
    h=b'PBRAD01\0'+struct.pack('<HHI',1,16+len(payload),zlib.crc32(payload))
    return bytearray((h+payload).ljust(4096,b'\xff'))
def crc(s):
    n=struct.unpack_from('<H',s,10)[0]
    struct.pack_into('<I',s,12,zlib.crc32(s[16:n]))
def parse(s):
    b=C.create_string_buffer(bytes(s))
    o=Config()
    C.memset(C.byref(o),0xa5,C.sizeof(o))
    return LIB.radio_config_parse(b,len(s),C.byref(o)),o

class ProvisionTests(unittest.TestCase):
    def test_valid_abi_record(self):
        ok,o=parse(sector())
        self.assertTrue(ok)
        self.assertEqual(o.ssid,b'Radio test')
        self.assertEqual(o.psk,b'test-only-passphrase-12345')
        self.assertEqual((o.cert_len,o.key_len),(4,3))

class CorruptionTests(unittest.TestCase):
    def test_crc_corruption_fails_and_clears_output(self):
        s=sector(); s[25]^=1
        ok,o=parse(s)
        self.assertFalse(ok)
        self.assertEqual(bytes(o), bytes(C.sizeof(o)))
    def test_standard_zlib_crc_fixture(self):
        s=sector(cert=bytes(range(256)))
        self.assertTrue(parse(s)[0])
        s[12]^=1
        self.assertFalse(parse(s)[0])

class BoundsTests(unittest.TestCase):
    def test_identity_version_length_and_padding(self):
        for off,val in [(0,0),(7,1),(8,2),(9,1),(10,23),(11,255),(4095,0)]:
            with self.subTest(offset=off):
                s=sector(); s[off]=val
                self.assertFalse(parse(s)[0])
        for size in (0,8,16,23,4095,4097):
            self.assertFalse(parse(bytes(size))[0])
        self.assertFalse(parse(bytes([255])*4096)[0])
    def test_field_constraints(self):
        for name,values in {'ssid':[b'',b'x'*33,b'x\0x',b'x\x7f',b'\x80'],
                            'psk':[b'x'*19,b'x'*64,b'x'*20+b'\n'],
                            'cert':[b'',b'x'*2049], 'key':[b'',b'x'*1025]}.items():
            for value in values:
                with self.subTest(name=name,size=len(value)):
                    self.assertFalse(parse(sector(**{name:value}))[0])
        self.assertTrue(parse(sector(ssid=b'x'*32,psk=b'x'*63,cert=b'x'*2048,key=b'x'*1024))[0])
    def test_length_sum_even_with_valid_crc(self):
        s=sector(); struct.pack_into('<H',s,20,5); crc(s)
        self.assertFalse(parse(s)[0])
        s=sector(); struct.pack_into('<H',s,22,65535); crc(s)
        self.assertFalse(parse(s)[0])

LIB.radio_http_parse.argtypes=[C.c_void_p,C.c_size_t]
LIB.radio_http_parse.restype=C.c_int
def http(s): return LIB.radio_http_parse(s,len(s))
class HTTPTests(unittest.TestCase):
    def test_routes_fragmentation(self):
        for route,code in [(b'/',1),(b'/health',2)]:
            s=b'GET '+route+b' HTTP/1.1\r\nHost: 192.168.4.1\r\n\r\n'
            for i in range(len(s)): self.assertEqual(http(s[:i]),0)
            self.assertEqual(http(s),code)

class HTTPErrorTests(unittest.TestCase):
    def test_methods_routes_and_versions(self):
        for line,code in [(b'POST /',405),(b'PUT /',405),(b'HEAD /',405),
                          (b'GET /missing',404),(b'GET /?text=secret',404),
                          (b'GET https://192.168.4.1/',400),(b'GET / HTTP/1.0',400)]:
            if b'HTTP/' not in line: line+=b' HTTP/1.1'
            self.assertEqual(http(line+b'\r\nHost: 192.168.4.1\r\n\r\n'),code)
    def test_framing_and_host(self):
        bad=[b'',b'Host: attacker',b'Host: 192.168.4.1\r\nHost: 192.168.4.1',
             b'Host : 192.168.4.1',b'Host: 192.168.4.1\r\n folded: yes',
             b'Host: 192.168.4.1\r\nTransfer-Encoding: chunked',
             b'Host: 192.168.4.1\r\nContent-Length: 1',
             b'Host: 192.168.4.1\r\nContent-Length: -1',
             b'Host: 192.168.4.1\r\nContent-Length: 9999999999999999999',
             b'Host: 192.168.4.1\r\nContent-Length: 0\r\nContent-Length: 0',
             b'Host: 192.168.4.1\r\nExpect: 100-continue',
             b'Host: 192.168.4.1\r\nUpgrade: h2c',
             b'Host: 192.168.4.1\r\nX: a\x00b']
        for headers in bad:
            with self.subTest(headers=headers):
                self.assertEqual(http(b'GET / HTTP/1.1\r\n'+headers+b'\r\n\r\n'),400)
        good=b'GET /health HTTP/1.1\r\nhOsT: 192.168.4.1:443\r\nContent-Length: 0\r\nAccept: */*\r\n\r\n'
        self.assertEqual(http(good),2)
        self.assertEqual(http(good+b'X'),400)
        self.assertEqual(http(good+good),400)
        self.assertEqual(http(b'GET / HTTP/1.1\nHost: 192.168.4.1\n\n'),400)
    def test_oversize_and_illegal_octets(self):
        self.assertEqual(http(b'x'*1024),431)
        self.assertEqual(http(b'x'*1025),431)
        for octet in (0,1,127,128,255):
            self.assertEqual(http(b'GET /'+bytes([octet])),400)

LIB.radio_dhcp_parse.argtypes=[C.c_void_p,C.c_size_t,C.c_void_p]
LIB.radio_dhcp_parse.restype=C.c_bool
def dhcp_packet(opts=b'\x35\x01\x01\xff'):
    p=bytearray(240); p[:3]=b'\x01\x01\x06'; p[28:34]=b'BBCDEF'; p[236:240]=b'\x63\x82\x53\x63'
    return p+opts
def dhcp(p):
    out=C.create_string_buffer(64)
    return LIB.radio_dhcp_parse(bytes(p),len(p),out),out.raw
class DHCPTests(unittest.TestCase):
    def test_discover_and_pad(self):
        for opts in (b'\x35\x01\x01\xff',b'\0\0\x35\x01\x01\0\xff'):
            ok,o=dhcp(dhcp_packet(opts))
            self.assertTrue(ok); self.assertEqual(o[0],1); self.assertEqual(o[1:7],b'BBCDEF')
    def test_request_renewal(self):
        p=dhcp_packet(b'\x35\x01\x03\xff'); p[12:16]=bytes([192,168,4,16])
        self.assertTrue(dhcp(p)[0])

class DHCPRejectTests(unittest.TestCase):
    def test_header_and_bounds(self):
        for off,val in [(0,2),(1,2),(2,16),(3,1),(24,1),(236,0),(28,1)]:
            p=dhcp_packet(); p[off]=val
            self.assertFalse(dhcp(p)[0],(off,val))
        for n in (0,239,240,241,242,243,577):
            p=dhcp_packet()[:n] if n<=244 else dhcp_packet()+bytes(n-244)
            self.assertFalse(dhcp(p)[0],n)
    def test_bad_options(self):
        for opts in (b'',b'\xff',b'\x35',b'\x35\x02\x01\xff',
                     b'\x35\x01\x01',b'\x35\x01\x09\xff',
                     b'\x35\x01\x01\x35\x01\x03\xff',
                     b'\x35\x01\x01\x32\x03abc\xff',
                     b'\x35\x01\x01\x36\x01x\xff',
                     b'\x35\x01\x01\x34\x01\x01\xff',
                     b'\x35\x01\x01\x01\xff\xff'):
            self.assertFalse(dhcp(dhcp_packet(opts))[0],opts)

RNG=C.CFUNCTYPE(C.c_int,C.c_void_p,C.POINTER(C.c_uint64))
LIB.radio_entropy_fill.argtypes=[C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t),RNG,C.c_void_p]
class EntropyTests(unittest.TestCase):
    def test_canaries_and_lengths(self):
        def word(ctx,out): out[0]=0x123456789abcdef0; return 0
        rng=RNG(word)
        for n in (0,1,7,8,9,15,16,17,31,32,33,64):
            out=(C.c_ubyte*(n+16))(*([0xa5]*(n+16))); olen=C.c_size_t(999)
            self.assertEqual(LIB.radio_entropy_fill(C.byref(out,8),n,C.byref(olen),rng,None),0)
            self.assertEqual(olen.value,n)
            self.assertEqual(bytes(out[:8]),b'\xa5'*8)
            self.assertEqual(bytes(out[8+n:]),b'\xa5'*8)
            self.assertEqual(bytes(out[8:8+n]),(bytes.fromhex('f0debc9a78563412')*8)[:n])
    def test_rng_failure_is_propagated(self):
        rng=RNG(lambda ctx,out:-1); olen=C.c_size_t(999); out=C.create_string_buffer(10)
        self.assertNotEqual(LIB.radio_entropy_fill(out,10,C.byref(olen),rng,None),0)
        self.assertEqual(olen.value,0)

class Schema2Tests(unittest.TestCase):
    def build(self, ssid=b'StudioWLAN', psk=b'hunter2-secret-pass'):
        buf = (C.c_ubyte * 4096)()
        ok = LIB.radio_config_build2(ssid, len(ssid), psk, len(psk), C.byref(buf))
        return bool(ok), buf

    def parse2(self, buf):
        o = Config()
        C.memset(C.byref(o), 0xa5, C.sizeof(o))
        return LIB.radio_config_parse2(bytes(buf), 4096, C.byref(o)), o

    def test_builder_output_parses_round_trip(self):
        ok, buf = self.build()
        self.assertTrue(ok)
        good, o = self.parse2(buf)
        self.assertTrue(good)
        self.assertEqual(o.ssid.rstrip(b'\0'), b'StudioWLAN')
        self.assertEqual(o.psk.rstrip(b'\0'), b'hunter2-secret-pass')
        self.assertEqual((o.cert_len, o.key_len), (0, 0))

    def test_builder_rejects_invalid_lengths_and_chars(self):
        for ssid, psk in [(b'', b'x' * 20), (b'x' * 33, b'x' * 20),
                          (b'S', b'x' * 7), (b'S', b'x' * 64),
                          (b'S\n', b'x' * 20), (b'S', b'x' * 19 + b'\x7f'),
                          (b'S', b'\x80' + b'x' * 19)]:
            with self.subTest(ssid=len(ssid), psk=len(psk)):
                buf = (C.c_ubyte * 4096)()
                self.assertFalse(LIB.radio_config_build2(ssid, len(ssid), psk, len(psk), C.byref(buf)))

    def test_schema2_rejects_schema1_bytes(self):
        s = sector()
        self.assertFalse(self.parse2(s)[0])

    def test_schema1_rejects_schema2_bytes(self):
        ok, buf = self.build()
        self.assertTrue(ok)
        o = Config()
        self.assertFalse(LIB.radio_config_parse(bytes(buf), 4096, C.byref(o)))

    def test_psk_min_8_accepted(self):
        ok, buf = self.build(psk=b'abcdefgh')
        self.assertTrue(ok)
        self.assertTrue(self.parse2(buf)[0])
        ok, buf = self.build(psk=b'abcdefg')
        self.assertFalse(ok)

    def test_crc_corruption_and_trailing_junk(self):
        ok, buf = self.build()
        self.assertTrue(ok)
        view = bytearray(bytes(buf))
        view[25] ^= 1
        self.assertFalse(LIB.radio_config_parse2(bytes(view), 4096, C.byref(Config())))
        view = bytearray(bytes(buf)); view[3000] = 0
        self.assertFalse(LIB.radio_config_parse2(bytes(view), 4096, C.byref(Config())))

    def test_cert_len_nonzero_without_key_fails(self):
        ok, buf = self.build()
        self.assertTrue(ok)
        view = bytearray(bytes(buf))
        view[20] = 5  # cert length nonzero, key length stays 0
        self.assertFalse(LIB.radio_config_parse2(bytes(view), 4096, C.byref(Config())))


if __name__=='__main__': unittest.main()
