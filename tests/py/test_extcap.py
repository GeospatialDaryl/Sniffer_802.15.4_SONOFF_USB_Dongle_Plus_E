import importlib.machinery, importlib.util, io, json, os, struct, sys, tempfile, unittest
from contextlib import redirect_stdout
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "Wireshark", "zigbee_dongle_json_sniffer")


def load():
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader("extcap", SCRIPT)
    spec = importlib.util.spec_from_loader("extcap", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


ext = load()


class Stop(Exception):
    """Raised by the fake serial port to leave capture()'s infinite loop."""


class FakeSerial:
    def __init__(self, lines):
        self.lines = list(lines)
        self.written = []

    def readline(self):
        if not self.lines:
            raise Stop()
        return self.lines.pop(0)

    def write(self, data):
        self.written.append(data)


def run_capture(lines, channel_filter=None):
    """Run capture() against fake serial lines; return (pcap bytes, FakeSerial)."""
    ser = FakeSerial(lines)
    with tempfile.TemporaryDirectory() as d:
        fifo = os.path.join(d, "fifo")
        with mock.patch.object(ext.serial, "Serial", return_value=ser), \
                redirect_stdout(io.StringIO()):
            try:
                ext.capture(fifo, "/dev/null", 1000000, channel_filter)
            except Stop:
                pass
        with open(fifo, "rb") as f:
            return f.read(), ser


def records(pcap):
    """Split pcap bytes into (global header fields, [(hdr fields, data)])."""
    gh = struct.unpack("<IHHIIII", pcap[:24])
    out, off = [], 24
    while off < len(pcap):
        ts_s, ts_us, incl, orig = struct.unpack("<IIII", pcap[off:off + 16])
        out.append(((ts_s, ts_us, incl, orig), pcap[off + 16:off + 16 + incl]))
        off += 16 + incl
    return gh, out


def jline(**kw):
    return (json.dumps(kw) + "\n").encode()


FRAME = "4188A31E48FFFF"


class ChannelFreq(unittest.TestCase):
    def test_2_4ghz(self):
        self.assertEqual(ext.channel_to_freq_mhz(11), 2405)
        self.assertEqual(ext.channel_to_freq_mhz(15), 2425)
        self.assertEqual(ext.channel_to_freq_mhz(26), 2480)

    def test_sub_ghz_and_invalid(self):
        self.assertEqual(ext.channel_to_freq_mhz(0), 868.3)
        self.assertEqual(ext.channel_to_freq_mhz(1), 908)
        self.assertEqual(ext.channel_to_freq_mhz(10), 926)
        self.assertEqual(ext.channel_to_freq_mhz(27), -1)
        self.assertEqual(ext.channel_to_freq_mhz(-5), -1)


class ExtcapCommands(unittest.TestCase):
    def call(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ext.main(list(argv))
        return buf.getvalue()

    def test_interfaces(self):
        out = self.call("--extcap-interfaces")
        self.assertIn("extcap {version=", out)
        self.assertIn("{value=zb_dongle_json_sniffer}", out)

    def test_dlts_is_tap(self):
        self.assertIn("{number=283}", self.call("--extcap-dlts", "--extcap-interface", "x"))

    def test_config_lists_channels_11_to_26(self):
        out = self.call("--extcap-config", "--extcap-interface", "x")
        vals = [int(l.split("{value=")[1].split("}")[0]) for l in out.splitlines() if l.startswith("value ")]
        self.assertEqual(vals, list(range(11, 27)))
        self.assertIn("--device", out)
        self.assertIn("--baud", out)

    def test_capture_requires_fifo(self):
        with self.assertRaises(SystemExit), redirect_stdout(io.StringIO()), \
                mock.patch("sys.stderr", io.StringIO()):
            ext.main(["--capture"])

    def test_unknown_wireshark_args_ignored(self):
        out = self.call("--extcap-interfaces", "--extcap-version=4.2")
        self.assertIn("extcap", out)


class Capture(unittest.TestCase):
    def test_pcap_global_header(self):
        pcap, _ = run_capture([])
        magic, maj, minor, zone, sig, snap, dlt = struct.unpack("<IHHIIII", pcap[:24])
        self.assertEqual((magic, maj, minor, dlt), (0xA1B2C3D4, 2, 4, 283))

    def test_record_layout(self):
        pcap, _ = run_capture([jline(L=7, Q=200, R=-80, C=15, S=FRAME)])
        _, recs = records(pcap)
        self.assertEqual(len(recs), 1)
        (_, _, incl, orig), data = recs[0]
        self.assertEqual(incl, orig)
        ver, hlen = struct.unpack("<HH", data[:4])
        self.assertEqual(ver, 0)
        self.assertEqual(data[hlen:], bytes.fromhex(FRAME))
        self.assertEqual(incl, hlen + len(FRAME) // 2)

    def test_tap_tlvs(self):
        pcap, _ = run_capture([jline(L=7, Q=200, R=-80, C=15, S=FRAME)])
        data = records(pcap)[1][0][1]
        _, hlen = struct.unpack("<HH", data[:4])
        tlvs, off = {}, 4
        while off < hlen:
            t, l = struct.unpack("<HH", data[off:off + 4])
            tlvs[t] = data[off + 4:off + 4 + l]
            off += 4 + ((l + 3) & ~3)          # values are padded to 4 bytes
        self.assertEqual(off, hlen)
        self.assertEqual(tlvs[0][0], 1)                                  # FCS type: 16-bit CRC
        self.assertEqual(struct.unpack("<H", tlvs[3][:2])[0], 15)        # channel number
        self.assertEqual(struct.unpack("<f", tlvs[1])[0], -80.0)         # RSS
        self.assertEqual(tlvs[10][0], 200)                               # LQI

    def test_defaults_when_fields_missing(self):
        pcap, _ = run_capture([jline(S=FRAME)])
        self.assertEqual(len(records(pcap)[1]), 1)

    def test_bad_lines_skipped(self):
        pcap, _ = run_capture([b"\n", b"not json\n", jline(C=11), jline(S="ZZ"),
                               jline(L=1, C=11, S=FRAME)])
        self.assertEqual(len(records(pcap)[1]), 1)

    def test_channel_filter(self):
        lines = [jline(C=11, S=FRAME), jline(C=15, S=FRAME), jline(C=15, S=FRAME)]
        pcap, _ = run_capture(lines, channel_filter=15)
        self.assertEqual(len(records(pcap)[1]), 2)

    def test_timestamp_usec_in_range(self):
        pcap, _ = run_capture([jline(C=11, S=FRAME)])
        (ts_s, ts_us, *_), _ = records(pcap)[1][0]
        self.assertTrue(0 <= ts_us < 1_000_000)
        self.assertGreater(ts_s, 1_600_000_000)

    def test_selected_channel_is_sent_to_dongle(self):
        _, ser = run_capture([], channel_filter=15)
        sent = b"".join(ser.written)
        self.assertEqual(sent, b'{"C":15}\r')

    def test_no_channel_command_without_selection(self):
        _, ser = run_capture([])
        self.assertEqual(ser.written, [])


if __name__ == "__main__":
    unittest.main()
