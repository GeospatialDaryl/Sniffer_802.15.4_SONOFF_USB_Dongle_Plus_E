"""Minimal IEEE 802.15.4 / Zigbee NWK header parser for the scanner.

Only headers are decoded. Payloads of secured frames stay opaque, but the MAC
beacon payload, NWK header, and NWK aux-header source address are readable
even on an encrypted network, which is enough to tell who is on the air.
"""
import struct

FRAME_TYPES = {0: "beacon", 1: "data", 2: "ack", 3: "mac-command"}
MAC_COMMANDS = {1: "assoc-request", 2: "assoc-response", 4: "data-request",
                5: "pan-conflict", 7: "beacon-request", 8: "coord-realign"}
NWK_COMMANDS = {1: "route-request", 2: "route-reply", 3: "network-status",
                4: "leave", 5: "route-record", 6: "rejoin-request",
                7: "rejoin-response", 8: "link-status", 9: "network-report",
                10: "network-update", 11: "end-device-timeout-req",
                12: "end-device-timeout-rsp"}
RAINFOREST_OUI = "D8:D5:B9"


def fcs16(data: bytes) -> int:
    """CRC-16/KERMIT, the 802.15.4 FCS."""
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


def eui_str(raw: bytes) -> str:
    """Little-endian on-air EUI-64 -> 'AA:BB:...' (most significant first)."""
    return ":".join("%02X" % b for b in reversed(raw))


def _le16(b, i):
    return b[i] | (b[i + 1] << 8)


def parse(raw: bytes) -> dict:
    """Parse one 802.15.4 frame including FCS. Never raises; sets 'error'."""
    out = {"len": len(raw), "fcs_ok": False}
    if len(raw) < 5:
        out["error"] = "short"
        return out
    out["fcs_ok"] = fcs16(raw[:-2]) == _le16(raw, len(raw) - 2)
    fcf = _le16(raw, 0)
    ftype = fcf & 7
    out["type"] = FRAME_TYPES.get(ftype, "type%d" % ftype)
    out["mac_secure"] = bool(fcf & 0x8)
    pan_comp = bool(fcf & 0x40)
    seq_supp = bool(fcf & 0x100)
    dmode, version, smode = (fcf >> 10) & 3, (fcf >> 12) & 3, (fcf >> 14) & 3
    body = raw[:-2]
    i = 2
    try:
        if not seq_supp:
            out["seq"] = body[i]
            i += 1
        if version == 2:
            return out | {"error": "802.15.4-2015 addressing not parsed"}
        if 1 in (dmode, smode):
            return out | {"error": "reserved addressing mode"}
        if dmode:
            out["dst_pan"] = _le16(body, i); i += 2
            if dmode == 2:
                out["dst"] = "0x%04X" % _le16(body, i); i += 2
            else:
                out["dst_ext"] = eui_str(body[i:i + 8]); i += 8
        if smode:
            if dmode and pan_comp:
                out["src_pan"] = out.get("dst_pan")
            else:
                out["src_pan"] = _le16(body, i); i += 2
            if smode == 2:
                out["src"] = "0x%04X" % _le16(body, i); i += 2
            else:
                out["src_ext"] = eui_str(body[i:i + 8]); i += 8
        out["pan"] = out.get("src_pan", out.get("dst_pan"))
        if i > len(body):
            return out | {"error": "truncated header"}
        payload = body[i:]
        if out["mac_secure"]:
            return out
        if ftype == 0:
            _beacon(out, payload)
        elif ftype == 3 and payload:
            out["cmd"] = MAC_COMMANDS.get(payload[0], "cmd%d" % payload[0])
        elif ftype == 1:
            _nwk(out, payload)
    except IndexError:
        out["error"] = "truncated"
    return out


def _beacon(out, p):
    if len(p) < 4:
        return
    sf = _le16(p, 0)
    out["permit_join"] = bool(sf & 0x8000)
    out["pan_coordinator"] = bool(sf & 0x4000)
    z = p[4:]
    if len(z) >= 15 and z[0] == 0:
        out["zb_stack_profile"] = z[1] & 0x0F
        out["zb_ext_pan"] = eui_str(z[3:11])


def _nwk(out, p):
    if len(p) < 8:
        return
    fc = _le16(p, 0)
    nwk = {"type": "command" if fc & 3 == 1 else "data" if fc & 3 == 0 else "type%d" % (fc & 3),
           "secure": bool(fc & 0x200), "dst": "0x%04X" % _le16(p, 2),
           "src": "0x%04X" % _le16(p, 4), "radius": p[6], "seq": p[7]}
    i = 8
    if fc & 0x800:
        i += 8
    if fc & 0x1000:
        nwk["src_ext"] = eui_str(p[i:i + 8]); i += 8
    if fc & 0x100:
        i += 1
    if fc & 0x400:
        i += 1 + 2 * p[i]
    out["nwk"] = nwk
    out["src_nwk"] = nwk["src"]
    if nwk["secure"]:
        # aux header: control(1) counter(4) [src ext(8) if ext-nonce] keyseq(1)
        if len(p) > i and p[i] & 0x20 and len(p) >= i + 13:
            nwk["src_ext"] = eui_str(p[i + 5:i + 13])
    elif nwk["type"] == "command" and len(p) > i:
        nwk["cmd"] = NWK_COMMANDS.get(p[i], "cmd%d" % p[i])
