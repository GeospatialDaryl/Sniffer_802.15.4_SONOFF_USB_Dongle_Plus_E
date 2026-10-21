import os, sys, unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scanner"))
import tui  # noqa: E402


class TuiHelpers(unittest.TestCase):
    def test_sparkline_pads_and_scales(self):
        s = tui.sparkline([0, 5, 10], 6)
        self.assertEqual(len(s), 6)
        self.assertEqual(s[-1], tui.SPARK[-1])
        self.assertEqual(s[:3], "   ")

    def test_sparkline_all_zero(self):
        self.assertEqual(tui.sparkline([0, 0], 2), tui.SPARK[0] * 2)

    def test_sparkline_truncates(self):
        self.assertEqual(len(tui.sparkline(range(100), 10)), 10)

    def test_bar(self):
        self.assertEqual(tui.bar(5, 10, 4), "██··")
        self.assertEqual(tui.bar(0, 0, 3), "···")

    def test_rssi_pair(self):
        self.assertEqual([tui.rssi_pair(r) for r in (-40, -70, -90, None)], [1, 2, 3, 6])

    def test_fmt_frame(self):
        self.assertIn("beacon-request", tui.fmt_frame({"type": "mac-command", "cmd": "beacon-request", "dst": "0xFFFF"}))
        out = tui.fmt_frame({"type": "data", "src": "0x0000", "dst": "0xFFFF", "nwk": {"type": "command", "secure": True}})
        self.assertIn("nwk-command*", out)
        self.assertIn("0x0000>0xFFFF", out)

    def test_fetch_unreachable_returns_none(self):
        self.assertIsNone(tui.fetch("http://127.0.0.1:1"))


if __name__ == "__main__":
    unittest.main()
