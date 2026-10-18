# Zigbee web scanner

Local web GUI that hops across 2.4 GHz channels 11-26 using the JSON sniffer dongle and
summarises what it hears: frames per channel, networks (PAN), nodes, and a recent-frame log.

    pip install pyserial
    python3 scanner/server.py --device /dev/ttyUSB0     # then open http://127.0.0.1:8154/
    python3 scanner/server.py --simulate                # demo without hardware

- The dongle must run the sniffer firmware (`Output/<board>/*.gbl`). Flashing replaces its coordinator firmware, so use a spare.
- Passive only: headers are decoded, encrypted payloads are not. Secured NWK frames still expose
  short addresses and, often, the sender's EUI-64; `D8:D5:B9` (Rainforest) is highlighted.
- The server listens on localhost only. Use `--host` deliberately if you need more.
- Tests: `make -C tests test`.
