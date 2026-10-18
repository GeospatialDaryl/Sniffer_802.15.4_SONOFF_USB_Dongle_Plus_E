"""Aggregates parsed frames into per-channel, per-network and per-node views."""
import threading
import time
from collections import deque

from zbparse import RAINFOREST_OUI, parse

CHANNELS = list(range(11, 27))


class ScanState:
    def __init__(self, clock=time.time, recent=200):
        self.clock = clock
        self.lock = threading.Lock()
        self.started = clock()
        self.channels = {c: {"frames": 0, "bad_fcs": 0, "rssi_sum": 0, "last": None, "dwell_s": 0.0}
                         for c in CHANNELS}
        self.networks = {}     # (channel, pan) -> info
        self.nodes = {}        # (channel, pan, addr) -> info
        self.recent = deque(maxlen=recent)
        self.current_channel = None
        self.mode = "idle"
        self._dwell_start = None

    def set_channel(self, ch, mode=None):
        with self.lock:
            now = self.clock()
            if self.current_channel in self.channels and self._dwell_start is not None:
                self.channels[self.current_channel]["dwell_s"] += now - self._dwell_start
            self.current_channel, self._dwell_start = ch, now
            if mode:
                self.mode = mode

    def add(self, msg):
        """msg: dict from the dongle: C channel, R rssi, Q lqi, S hex frame."""
        try:
            raw = bytes.fromhex(msg["S"])
            ch = int(msg.get("C", self.current_channel or 0))
        except (KeyError, ValueError, TypeError):
            return None
        f = parse(raw)
        now = self.clock()
        rssi = msg.get("R")
        with self.lock:
            st = self.channels.get(ch)
            if st is None:
                return None
            if not f["fcs_ok"]:
                st["bad_fcs"] += 1
                return f
            st["frames"] += 1
            st["rssi_sum"] += rssi or 0
            st["last"] = now
            if f.get("pan") is not None:
                self._net(ch, f, now, rssi)
            self.recent.appendleft({"t": now, "ch": ch, "rssi": rssi, "lqi": msg.get("Q"), "f": f})
        return f

    def _net(self, ch, f, now, rssi):
        pan = "0x%04X" % f["pan"]
        n = self.networks.setdefault((ch, pan), {"channel": ch, "pan": pan, "frames": 0, "first": now,
                                                 "ext_pan": None, "permit_join": None, "secured": False})
        n.update(last=now, rssi=rssi)
        n["frames"] += 1
        if f.get("zb_ext_pan"):
            n["ext_pan"] = f["zb_ext_pan"]
            n["permit_join"] = f["permit_join"]
        if f.get("mac_secure") or f.get("nwk", {}).get("secure"):
            n["secured"] = True
        addr = f.get("src_nwk") or f.get("src") or f.get("src_ext")
        if addr:
            d = self.nodes.setdefault((ch, pan, addr), {"channel": ch, "pan": pan, "addr": addr,
                                                        "frames": 0, "first": now, "ext": None, "kinds": {}})
            d["frames"] += 1
            d.update(last=now, rssi=rssi)
            ext = f.get("src_ext") or f.get("nwk", {}).get("src_ext")
            if ext:
                d["ext"] = ext
                d["rainforest"] = ext.upper().startswith(RAINFOREST_OUI)
            kind = f.get("cmd") or f.get("nwk", {}).get("cmd") or f["type"]
            d["kinds"][kind] = d["kinds"].get(kind, 0) + 1

    def snapshot(self):
        with self.lock:
            now = self.clock()
            chans = []
            for c, s in self.channels.items():
                dwell = s["dwell_s"] + (now - self._dwell_start if c == self.current_channel and self._dwell_start else 0)
                chans.append({"channel": c, "frames": s["frames"], "bad_fcs": s["bad_fcs"],
                              "avg_rssi": round(s["rssi_sum"] / s["frames"], 1) if s["frames"] else None,
                              "age_s": round(now - s["last"], 1) if s["last"] else None,
                              "dwell_s": round(dwell, 1)})
            return {"now": now, "mode": self.mode, "current_channel": self.current_channel,
                    "channels": chans,
                    "networks": sorted(({**n, "age_s": round(now - n["last"], 1)} for n in self.networks.values()),
                                       key=lambda n: -n["frames"]),
                    "nodes": sorted(({**d, "age_s": round(now - d["last"], 1)} for d in self.nodes.values()),
                                    key=lambda d: -d["frames"])[:200],
                    "recent": [{"age_s": round(now - r["t"], 1), "ch": r["ch"], "rssi": r["rssi"], "lqi": r["lqi"],
                                "f": r["f"]} for r in list(self.recent)[:60]]}
