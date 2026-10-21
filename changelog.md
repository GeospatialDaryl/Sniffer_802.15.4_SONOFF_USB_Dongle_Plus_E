# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Web scanner GUI (`scanner/`) that hops channels 11-26 and summarises channels, PANs, nodes and recent frames. Highlights Rainforest (`D8:D5:B9`) addresses. Has a `--simulate` mode.
- btop-style terminal UI (`scanner/tui.py`) for the scanner: channel bars, networks, nodes, recent frames, mode/channel/dwell controls.
- Host-side test suite (`tests/`): C tests with ASan/UBSan and Python tests for the extcap script and the scanner.
- GitHub Actions workflow that runs the tests.

### Fixed
- extcap: send `{"C":n}` to the dongle when a channel is selected.
- console: widen the `snprintf` size so RSSI values from -100 to -128 are not truncated.
- `MAC_Pack`: apply PAN ID compression the same way `MAC_Unpack` does.
- `MAC_Unpack`: reject frames too short for the FCS or longer than the buffer.

### Changed
- Stop tracking Python bytecode; `__pycache__/` and `*.pyc` are ignored.


## 2026-06-19

- Added support for SONOFF LMG21.

