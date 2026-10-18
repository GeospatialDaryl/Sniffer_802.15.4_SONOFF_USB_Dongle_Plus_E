import json, os, sys, threading, time, unittest, urllib.request
from http.server import ThreadingHTTPServer

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scanner"))
import zbparse, state as st, server  # noqa: E402


def frame(body: bytes) -> bytes:
    return body + zbparse.fcs16(body).to_bytes(2, "little")


def hexf(body):
    return frame(body).hex().upper()


# MAC data (v0, PAN compression, short src/dst) carrying a NWK link-status command
LINK = bytes([0x41, 0x88, 9, 0xCD, 0xAB, 0xFF, 0xFF, 0x00, 0x00]) + \
    bytes([0x09, 0x00, 0xFC, 0xFF, 0x00, 0x00, 0x01, 0x05, 0x08, 0x40])
# secured NWK data with ext-nonce aux header from D8:D5:B9:00:0E:CB
EXT = bytes.fromhex("D8D5B9000000CB0E")[::-1]
SECURED = bytes([0x41, 0x88, 10, 0xCD, 0xAB, 0x34, 0x12, 0x00, 0x00]) + \
    bytes([0x08, 0x02, 0x00, 0x00, 0x34, 0x12, 0x1E, 0x07]) + bytes([0x28, 1, 0, 0, 0]) + EXT + bytes([0]) + b"\xAA" * 6
# beacon: assoc-permit set, Zigbee PRO, ext PAN 11:22:..:88
BEACON = bytes([0, 0x80, 7, 0xCD, 0xAB, 0x00, 0x00]) + bytes([0xFF, 0xCF, 0, 0, 0, 0x22, 0x84]) + \
    bytes.fromhex("1122334455667788")[::-1] + b"\xff\xff\xff\x00"


class Parse(unittest.TestCase):
    def test_fcs_kermit_check_value(self):
        self.assertEqual(zbparse.fcs16(b"123456789"), 0x2189)

    def test_link_status(self):
        f = zbparse.parse(frame(LINK))
        self.assertTrue(f["fcs_ok"])
        self.assertEqual((f["type"], f["pan"], f["src"], f["seq"]), ("data", 0xABCD, "0x0000", 9))
        self.assertEqual(f["nwk"]["cmd"], "link-status")
        self.assertEqual(f["src_nwk"], "0x0000")

    def test_secured_nwk_reveals_ext_addr(self):
        f = zbparse.parse(frame(SECURED))
        self.assertTrue(f["nwk"]["secure"])
        self.assertEqual(f["nwk"]["src_ext"], "D8:D5:B9:00:00:00:CB:0E")

    def test_beacon(self):
        f = zbparse.parse(frame(BEACON))
        self.assertEqual(f["type"], "beacon")
        self.assertTrue(f["permit_join"])
        self.assertEqual(f["zb_ext_pan"], "11:22:33:44:55:66:77:88")
        self.assertEqual(f["zb_stack_profile"], 2)

    def test_bad_fcs_and_garbage_never_raise(self):
        raw = bytearray(frame(LINK)); raw[-1] ^= 1
        self.assertFalse(zbparse.parse(bytes(raw))["fcs_ok"])
        for n in range(0, 40):
            zbparse.parse(os.urandom(n))
        for cut in range(len(frame(LINK))):
            zbparse.parse(frame(LINK)[:cut])


class Aggregation(unittest.TestCase):
    def make(self):
        t = [1000.0]
        return st.ScanState(clock=lambda: t[0]), t

    def test_counts_and_rainforest_detection(self):
        s, t = self.make()
        s.set_channel(20, "scan")
        s.add({"C": 20, "R": -80, "Q": 200, "S": hexf(LINK)})
        s.add({"C": 20, "R": -70, "Q": 200, "S": hexf(SECURED)})
        t[0] += 5
        snap = s.snapshot()
        ch = {c["channel"]: c for c in snap["channels"]}[20]
        self.assertEqual((ch["frames"], ch["avg_rssi"], ch["dwell_s"]), (2, -75.0, 5.0))
        self.assertEqual(len(snap["networks"]), 1)
        self.assertTrue(snap["networks"][0]["secured"])
        rf = [n for n in snap["nodes"] if n.get("rainforest")]
        self.assertEqual(len(rf), 1)
        self.assertEqual(rf[0]["addr"], "0x1234")

    def test_bad_fcs_counted_not_attributed(self):
        s, _ = self.make()
        raw = bytearray(frame(LINK)); raw[-1] ^= 1
        s.add({"C": 15, "R": -60, "S": bytes(raw).hex()})
        snap = s.snapshot()
        self.assertEqual({c["channel"]: c for c in snap["channels"]}[15]["bad_fcs"], 1)
        self.assertEqual(snap["networks"], [])

    def test_invalid_messages_ignored(self):
        s, _ = self.make()
        for m in ({}, {"S": "ZZ"}, {"C": 5, "S": hexf(LINK)}, {"C": "x", "S": hexf(LINK)}):
            self.assertIsNone(s.add(m))

    def test_beacon_sets_ext_pan(self):
        s, _ = self.make()
        s.add({"C": 11, "R": -50, "S": hexf(BEACON)})
        n = s.snapshot()["networks"][0]
        self.assertEqual((n["ext_pan"], n["permit_join"]), ("11:22:33:44:55:66:77:88", True))


class Controller(unittest.TestCase):
    def test_scan_hops_and_lock(self):
        s = st.ScanState(); seen = []
        c = server.Controller(s, seen.append)
        c.configure(mode="scan", dwell=1, channels=[11, 12])
        time.sleep(0.3)
        self.assertEqual(seen[0], 11)
        c.configure(mode="lock", channel=25)
        time.sleep(0.3)
        self.assertEqual(seen[-1], 25)
        self.assertEqual(s.snapshot()["current_channel"], 25)
        c.configure(channel=99, dwell=-5)   # invalid channel ignored, dwell clamped
        self.assertEqual((c.cfg["channel"], c.cfg["dwell"]), (25, 1.0))


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state = st.ScanState()
        cls.seen = []
        cls.ctl = server.Controller(cls.state, cls.seen.append)
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(cls.state, cls.ctl))
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_index_and_state(self):
        self.assertIn(b"Zigbee Scanner", urllib.request.urlopen(self.url + "/").read())
        d = json.load(urllib.request.urlopen(self.url + "/api/state"))
        self.assertEqual(len(d["channels"]), 16)
        self.assertIn("config", d)

    def test_config_post_and_bad_input(self):
        req = urllib.request.Request(self.url + "/api/config", data=b'{"mode":"lock","channel":18}', method="POST")
        self.assertEqual(json.load(urllib.request.urlopen(req))["channel"], 18)
        bad = urllib.request.Request(self.url + "/api/config", data=b"not json", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(bad)
        self.assertEqual(cm.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.url + "/nope")
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
