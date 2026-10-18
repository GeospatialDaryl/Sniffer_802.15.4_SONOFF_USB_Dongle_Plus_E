#!/usr/bin/env python3
"""Web GUI for scanning 2.4 GHz Zigbee with the JSON sniffer dongle.

    python3 scanner/server.py --device /dev/ttyUSB0          # real dongle
    python3 scanner/server.py --simulate                     # no hardware

Open http://127.0.0.1:8154/ . Listens on localhost only unless --host is given.
"""
import argparse
import json
import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from state import CHANNELS, ScanState

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class Controller:
    """Owns the radio: scan (hop channels), lock (one channel) or idle."""

    def __init__(self, state, set_radio_channel):
        self.state, self.set_radio_channel = state, set_radio_channel
        self.cfg = {"mode": "scan", "dwell": 10.0, "channel": 15, "channels": CHANNELS}
        self.cv = threading.Condition()
        threading.Thread(target=self._run, daemon=True).start()

    def configure(self, mode=None, dwell=None, channel=None, channels=None):
        with self.cv:
            if mode in ("scan", "lock", "idle"):
                self.cfg["mode"] = mode
            if dwell is not None:
                self.cfg["dwell"] = min(max(float(dwell), 1.0), 300.0)
            if channel is not None and int(channel) in CHANNELS:
                self.cfg["channel"] = int(channel)
            if channels:
                self.cfg["channels"] = [c for c in map(int, channels) if c in CHANNELS] or CHANNELS
            self.cv.notify_all()

    def _tune(self, ch, mode):
        self.set_radio_channel(ch)
        self.state.set_channel(ch, mode)

    def _run(self):
        idx = 0
        while True:
            with self.cv:
                cfg = dict(self.cfg)
            if cfg["mode"] == "scan":
                chans = cfg["channels"]
                ch = chans[idx % len(chans)]
                idx += 1
                self._tune(ch, "scan")
                wait = cfg["dwell"]
            elif cfg["mode"] == "lock":
                self._tune(cfg["channel"], "lock")
                wait = 3600
            else:
                self.state.set_channel(None, "idle")
                wait = 3600
            with self.cv:
                self.cv.wait(timeout=wait)
                if self.cfg != cfg:
                    idx = 0


def serial_source(device, baud, state):
    import serial
    ser = serial.Serial(device, baud, timeout=1)

    def set_ch(c):
        ser.write(('{"C":%d}\r' % c).encode())

    def reader():
        while True:
            line = ser.readline().strip()
            if line:
                try:
                    state.add(json.loads(line))
                except ValueError:
                    pass
    threading.Thread(target=reader, daemon=True).start()
    return set_ch


def simulated_source(state):
    """Fake traffic: one secured network on channel 20 with a Rainforest-style node."""
    from zbparse import fcs16
    cur = {"c": 11}

    def frame(body):
        return (body + fcs16(body).to_bytes(2, "little")).hex().upper()

    def beacon():
        pl = bytes([0xFF, 0xCF, 0, 0]) + bytes([0, 0x22, 0x84]) + bytes.fromhex("1122334455667788")[::-1] + b"\xff\xff\xff\x00"
        return frame(bytes([0, 0x80, 7, 0xCD, 0xAB, 0x00, 0x00]) + pl)

    def link_status():
        nwk = bytes([0x09, 0x00, 0xFC, 0xFF, 0x00, 0x00, 0x01, 0x05, 0x08, 0x40])
        return frame(bytes([0x41, 0x88, 9, 0xCD, 0xAB, 0xFF, 0xFF, 0x00, 0x00]) + nwk)

    def run():
        n = 0
        while True:
            time.sleep(0.4)
            if cur["c"] == 20 and random.random() < 0.8:
                n += 1
                s = beacon() if n % 6 == 0 else link_status()
                state.add({"L": len(s) // 2, "Q": 200, "R": random.randint(-85, -70), "C": 20, "S": s})
            elif random.random() < 0.05:
                s = link_status()
                state.add({"L": len(s) // 2, "Q": 90, "R": -92, "C": cur["c"], "S": s})
    threading.Thread(target=run, daemon=True).start()
    return lambda c: cur.update(c=c)


def make_handler(state, ctl):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                with open(os.path.join(STATIC, "index.html"), "rb") as f:
                    self._send(200, f.read(), "text/html; charset=utf-8")
            elif self.path == "/api/state":
                self._send(200, json.dumps({**state.snapshot(), "config": ctl.cfg}).encode())
            else:
                self._send(404, b"{}")

        def do_POST(self):
            if self.path != "/api/config":
                return self._send(404, b"{}")
            try:
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(min(n, 4096)) or b"{}")
                ctl.configure(**{k: body[k] for k in ("mode", "dwell", "channel", "channels") if k in body})
            except (ValueError, TypeError):
                return self._send(400, b'{"error":"bad request"}')
            self._send(200, json.dumps(ctl.cfg).encode())
    return H


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--device", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=1000000)
    ap.add_argument("--simulate", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8154)
    a = ap.parse_args(argv)
    state = ScanState()
    set_ch = simulated_source(state) if a.simulate else serial_source(a.device, a.baud, state)
    ctl = Controller(state, set_ch)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(state, ctl))
    print("Zigbee scanner on http://%s:%d/ (%s)" % (a.host, a.port, "simulated" if a.simulate else a.device))
    srv.serve_forever()


if __name__ == "__main__":
    main()
