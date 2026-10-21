#!/usr/bin/env python3
"""btop-style terminal UI for the Zigbee scanner.

    python3 scanner/server.py --device /dev/ttyUSB0      # in one terminal
    python3 scanner/tui.py                               # in another

Talks to the scanner's HTTP API (default http://127.0.0.1:8154), so it can run
alongside the web GUI. Keys: q quit | s scan | l lock | i idle | </> select
channel | enter lock selected | +/- dwell time.
"""
import argparse
import curses
import json
import locale
import urllib.request
from collections import deque

SPARK = "▁▂▃▄▅▆▇█"
CHANNELS = list(range(11, 27))


def sparkline(values, width):
    """Right-aligned block sparkline of the last `width` values."""
    vals = list(values)[-width:]
    top = max(vals) if vals else 0
    if top <= 0:
        return " " * (width - len(vals)) + SPARK[0] * len(vals)
    cells = [SPARK[min(len(SPARK) - 1, int(v / top * (len(SPARK) - 1) + 0.5))] for v in vals]
    return " " * (width - len(vals)) + "".join(cells)


def bar(value, top, width):
    n = 0 if top <= 0 else int(round(width * value / top))
    return "█" * n + "·" * (width - n)


def rssi_pair(rssi):
    """Colour pair for an RSSI: 1 strong, 2 medium, 3 weak, 6 unknown."""
    if rssi is None:
        return 6
    return 1 if rssi >= -60 else 2 if rssi >= -80 else 3


def fmt_frame(f):
    kind = f.get("cmd") or f.get("type", "?")
    nwk = f.get("nwk")
    if nwk:
        kind = "nwk-" + str(nwk.get("type", "?"))
        if nwk.get("secure"):
            kind += "*"
    src, dst = f.get("src") or f.get("src_ext") or "-", f.get("dst") or "-"
    return "%-18s %s>%s" % (kind[:18], src, dst)


def fetch(url):
    try:
        with urllib.request.urlopen(url + "/api/state", timeout=2) as r:
            return json.load(r)
    except (OSError, ValueError):
        return None


def post(url, **cfg):
    req = urllib.request.Request(url + "/api/config", json.dumps(cfg).encode(), method="POST")
    try:
        urllib.request.urlopen(req, timeout=2).read()
    except OSError:
        pass


class Tui:
    def __init__(self, scr, url, interval):
        self.scr, self.url, self.interval = scr, url, interval
        self.sel = 15
        self.state = None
        self.hist = deque(maxlen=300)
        self.last_total = None

    def put(self, y, x, text, attr=0, maxw=None):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        text = text[:max(0, min(maxw if maxw is not None else w - x, w - x))]
        try:
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def box(self, y, x, h, w, title):
        if h < 3 or w < 4:
            return
        a = curses.color_pair(4)
        self.put(y, x, "╭" + "─" * (w - 2) + "╮", a)
        for r in range(1, h - 1):
            self.put(y + r, x, "│", a)
            self.put(y + r, x + w - 1, "│", a)
        self.put(y + h - 1, x, "╰" + "─" * (w - 2) + "╯", a)
        self.put(y, x + 2, "┤", a)
        self.put(y, x + 3, title, curses.A_BOLD)
        self.put(y, x + 3 + len(title), "├", a)

    def update(self):
        s = fetch(self.url)
        self.state = s
        if s:
            total = sum(c["frames"] for c in s["channels"])
            if self.last_total is not None:
                self.hist.append(max(0, total - self.last_total))
            self.last_total = total

    def draw_status(self, w):
        s, cfg = self.state, self.state["config"]
        self.box(0, 0, 3, w, "zbscan")
        mode = s["mode"].upper()
        ch = s["current_channel"]
        total = sum(c["frames"] for c in s["channels"])
        bad = sum(c["bad_fcs"] for c in s["channels"])
        nets = [n for n in s["networks"] if n["pan"] != "0xFFFF"]
        line = "mode %s  ch %s  dwell %.0fs  frames %d  badFCS %d  nets %d  nodes %d" % (
            mode, ch if ch else "-", cfg["dwell"], total, bad, len(nets), len(s["nodes"]))
        self.put(1, 2, line, maxw=w - 4)
        gw = w - len(line) - 8
        if gw > 8:
            self.put(1, w - gw - 2, sparkline(self.hist, gw), curses.color_pair(1), gw)

    def draw_channels(self, y, w, h):
        s = self.state
        self.box(y, 0, h, w, "channels")
        by = {c["channel"]: c for c in s["channels"]}
        top = max([c["frames"] for c in s["channels"]] + [1])
        bw = max(4, w - 36)
        for i, ch in enumerate(CHANNELS):
            if i + 2 >= h:
                break
            c = by.get(ch, {"frames": 0, "bad_fcs": 0, "avg_rssi": None, "dwell_s": 0})
            cur = ch == s["current_channel"]
            mark = "▶" if cur else " "
            row = y + 1 + i
            attr = curses.A_REVERSE if ch == self.sel else 0
            self.put(row, 2, "%s%2d" % (mark, ch), attr | (curses.A_BOLD if cur else 0))
            self.put(row, 7, bar(c["frames"], top, bw), curses.color_pair(1))
            rs = c["avg_rssi"]
            self.put(row, 8 + bw, "%5d" % c["frames"])
            self.put(row, 14 + bw, ("%4ddBm" % rs) if rs is not None else "    - ", curses.color_pair(rssi_pair(rs)))
            if c["bad_fcs"]:
                self.put(row, 21 + bw, "x%d" % c["bad_fcs"], curses.color_pair(3))

    def draw_table(self, y, x, h, w, title, header, rows):
        """rows: list of (text, colour_pair)."""
        self.box(y, x, h, w, title)
        self.put(y + 1, x + 2, header, curses.A_DIM, w - 4)
        for i, (text, pair) in enumerate(rows[:max(0, h - 3)]):
            self.put(y + 2 + i, x + 2, text, curses.color_pair(pair), w - 4)

    def draw(self):
        self.scr.erase()
        H, W = self.scr.getmaxyx()
        if self.state is None:
            self.put(0, 0, "waiting for scanner at %s ... (q to quit)" % self.url)
            return
        s = self.state
        self.draw_status(W)
        ch_h = min(len(CHANNELS) + 2, max(5, H - 3 - 6))
        lw = min(W // 2, 64)
        self.draw_channels(3, lw, ch_h)
        nets = sorted((n for n in s["networks"] if n["pan"] != "0xFFFF"), key=lambda n: -n["frames"])
        rows = []
        for n in nets:
            flag = "S" if n["secured"] else "-"
            jn = "J" if n["permit_join"] else "-"
            rows.append(("%3d %-6s %5d %s%s %4s %s" % (n["channel"], n["pan"], n["frames"], flag, jn,
                                                      n["rssi"], n.get("ext_pan") or ""), rssi_pair(n["rssi"])))
        self.draw_table(3, lw, ch_h, W - lw, "networks", "ch pan    frames SJ rssi ext-pan", rows)
        y2, h2 = 3 + ch_h, H - 3 - ch_h
        nw = min(W // 2, 70)
        nodes = sorted(s["nodes"], key=lambda n: n["age_s"])
        rows = []
        for n in nodes:
            kinds = ",".join("%s:%d" % (k[:4], v) for k, v in sorted(n["kinds"].items()))
            tag = "  RAINFOREST" if n.get("rainforest") else ""
            rows.append(("%3d %-6s %-6s %-23s %4s %s%s" % (n["channel"], n["pan"], n["addr"], n.get("ext") or "-",
                                                         n["rssi"], kinds, tag), 5 if tag else rssi_pair(n["rssi"])))
        self.draw_table(y2, 0, h2, nw, "nodes", "ch pan    addr   ext                     rssi kinds", rows)
        rows = []
        for r in s["recent"]:
            f = r["f"]
            if not f.get("fcs_ok", True):
                continue
            rows.append(("%4.0fs %2d %4s  %s" % (r["age_s"], r["ch"], r["rssi"], fmt_frame(f)), rssi_pair(r["rssi"])))
        self.draw_table(y2, nw, h2, W - nw, "recent frames", "age  ch rssi  type               src>dst", rows)

    def key(self, k):
        cfg = self.state["config"] if self.state else {"dwell": 10}
        if k in (ord("q"), 27):
            return False
        if k == ord("s"):
            post(self.url, mode="scan")
        elif k == ord("i"):
            post(self.url, mode="idle")
        elif k == ord("l"):
            post(self.url, mode="lock", channel=self.sel)
        elif k in (10, 13, curses.KEY_ENTER):
            post(self.url, mode="lock", channel=self.sel)
        elif k in (curses.KEY_RIGHT, curses.KEY_DOWN, ord(">"), ord(".")):
            self.sel = min(26, self.sel + 1)
        elif k in (curses.KEY_LEFT, curses.KEY_UP, ord("<"), ord(",")):
            self.sel = max(11, self.sel - 1)
        elif k in (ord("+"), ord("=")):
            post(self.url, dwell=cfg["dwell"] + 1)
        elif k in (ord("-"), ord("_")):
            post(self.url, dwell=cfg["dwell"] - 1)
        return True


def run(scr, url, interval):
    curses.curs_set(0)
    curses.use_default_colors()
    for i, c in enumerate((curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_RED,
                           curses.COLOR_CYAN, curses.COLOR_MAGENTA, curses.COLOR_WHITE), 1):
        curses.init_pair(i, c, -1)
    scr.timeout(200)
    ui = Tui(scr, url, interval)
    tick = 0
    while True:
        if tick % max(1, int(interval / 0.2)) == 0:
            ui.update()
        ui.draw()
        scr.refresh()
        tick += 1
        k = scr.getch()
        if k != -1 and not ui.key(k):
            return


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://127.0.0.1:8154")
    ap.add_argument("--interval", type=float, default=1.0)
    a = ap.parse_args(argv)
    locale.setlocale(locale.LC_ALL, "")
    curses.wrapper(run, a.url.rstrip("/"), a.interval)


if __name__ == "__main__":
    main()
