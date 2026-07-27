# RTK3 robot correction status

Last updated: 2026-07-27 11:35 EDT

## Confirmed facts

- The Mammotion RTK3 is expected at `192.168.2.26` with documented hardware
  MAC `C0:F5:35:CF:70:11`, but the Mac currently learns
  `AE:EA:86:A7:DC:76` for that IP. The current IP-to-device identity is
  therefore not proven.
- The RTK3 responds at link layer in earlier ESP32 evidence. ICMP and tested
  inbound TCP services, including 8883, did not respond.
- The attached ESP32-S3 is physically available at
  `/dev/cu.usbmodem5C381959331`. Esptool identifies it as an ESP32-S3 revision
  0.2 with MAC `44:1B:F6:FF:98:BC`.
- After restoring and flashing passive UART firmware, the ESP32 received DHCP
  address `192.168.2.35`. Its status API and passive baud sweep work.
- A one-second-per-baud negative-control sweep with GPIO18 unwired completed
  across 9600, 19200, 38400, 57600, 115200, 230400, 460800, and 921600 baud.
  It captured zero or one floating byte per baud and no RTCM3, UBX, or NMEA
  signatures.
- A Raspberry Pi-like SSH host is reachable at `192.168.2.15` and has a known
  host key, but none of the locally available SSH identities are accepted for
  tested users `pi`, `raspberry`, `admin`, or `ubuntu`.
- The gateway at `192.168.2.1` is a TP-Link Deco. Its local UI is reachable but
  requires the owner password; no existing in-app or Chrome session is logged
  in.

## Disproven assumptions

- `192.168.2.43` is not the ESP32's current address. It is stale/unreachable;
  the ESP32 is now `192.168.2.35`.
- The current inbound LAN probe is not a path to correction data. Repository
  history shows it replaced a more relevant passive UART implementation.
- Bytes from an unwired UART are not evidence of a transport. The negative
  control establishes the floating-input baseline.

## Hardware and network topology

```text
Internet
   |
TP-Link Deco gateway 192.168.2.1
   |
Wi-Fi LAN 192.168.2.0/24
   +-- Mac 192.168.2.20
   +-- expected RTK3 192.168.2.26 (identity currently unverified)
   +-- ESP32-S3 192.168.2.35, MAC 44:1B:F6:FF:98:BC
   |     USB: /dev/cu.usbmodem5C381959331
   |     passive UART RX: GPIO18 (TX deliberately disabled)
   +-- SSH host 192.168.2.15 (credentials unavailable)
```

## Commands executed

- Inspected all tracked files with `rg --files` and the complete visible Git
  history with `git log --all`.
- Inspected removed capture code and the UART firmware at commit `fa6fc62`.
- Enumerated serial devices, interfaces, routes, ARP, DNS, SSH host keys, and
  locally available PCAPs.
- Tested batch SSH access to `192.168.2.15` with four likely usernames.
- Inspected the TP-Link Deco UI in both available browser contexts.
- Restored `src/main.cpp`, `include/config.h`, and `platformio.ini` from the
  passive UART implementation, then repaired the current native-test layout.
- Built and flashed with:

  ```sh
  pio run -e esp32-s3-devkitc-1 -t upload \
    --upload-port /dev/cu.usbmodem5C381959331
  ```

- Verified firmware and ran the negative-control sweep through:

  ```sh
  curl http://192.168.2.35/api/status
  curl -X POST 'http://192.168.2.35/api/capture/start?seconds=1'
  curl http://192.168.2.35/api/summary
  ```

## Captures collected

- The negative-control capture is currently stored in ESP32 LittleFS as
  `/baud-<rate>.bin` plus `/summary.json`. It contains no useful signal and
  should not be preserved as correction evidence.
- No PCAP or internal RTK3 serial capture exists in the repository or the
  locally searched attachment/workspace paths.

## Protocol findings

- The repository has a streaming RTCM3 parser with CRC-24Q validation and
  message-type reporting, plus UBX sync and NMEA prefix detection.
- Native tests include a known-valid RTCM 1005 frame and an intentionally
  corrupted frame.
- No valid RTK3-originated correction frame has yet been acquired, so the
  correction transport, message set, station ID, and rates remain unknown.

## Code implemented

- Replaced the inbound reachability probe on the ESP32 with the recovered
  receive-only UART baud sweeper.
- The firmware captures bounded raw samples to LittleFS and reports validated
  RTCM3 counts/types, CRC failures, UBX markers, NMEA markers, and printable
  ratio through HTTP.
- GPIO18 is the only RTK-side signal input; no ESP32 TX pin is configured.
- New captures remove stale inbound LAN/TLS result files so they cannot be
  confused with current acquisition evidence.
- Added `scripts/rtcm_pipeline.py`, a host-side incremental RTCM3 pipeline
  which:
  - extracts and relays only complete CRC-24Q-valid frames;
  - recovers from arbitrary noise, bad reserved header bits, and corrupt CRCs;
  - reports message types and reference-station IDs without mislabeling
    satellite ephemeris payload fields;
  - reports frame rate, correction age, stale state, discarded data, and
    forwarded frame/byte counts;
  - accepts file, TCP, or serial input and file, TCP, or serial output;
  - provides nonzero acceptance-gate exits for missing frames or CRC errors.
- Added a fixed-baud receive-only live mode to the ESP32:
  - `POST /api/stream/start?baud=<rate>` selects one supported baud;
  - raw GPIO18 input is served to one TCP client on port 2101;
  - the status API reports client, byte, RTCM frame, CRC, and type counters;
  - live mode and baud-sweep capture are mutually exclusive;
  - no UART transmit pin is enabled.
- The intended live path is now:

  ```text
  RTK3 TX -> ESP32 GPIO18 -> raw TCP 2101
          -> host CRC-validating relay -> robot receiver serial
  ```

## Tests and hardware results

- `pio test -e native`: 9/9 passed.
- `pio run -e esp32-s3-devkitc-1`: passed.
- ESP32 flash: passed; image hash verified by esptool.
- ESP32 ping and `GET /api/status`: passed at `192.168.2.35`.
- Full eight-baud capture state machine: passed.
- Host tests: 13/13 passed, including chunk boundaries, corruption recovery,
  strict header validation, station-ID interpretation, valid-only extraction,
  byte-exact relay, and an empty-stream stale-state regression.
- The real one-byte unwired GPIO18 capture was passed through
  `rtcm_pipeline.py analyze --require-frames`; it reported one discarded byte,
  zero valid frames, `stale: true`, and exited 2 as required.
- Live TCP firmware test on physical ESP32 passed:
  - unsupported baud `12345` was rejected;
  - 115200-baud live mode started;
  - a Mac TCP client connected to port 2101 and appeared in status;
  - capture start during live mode was rejected with HTTP 409;
  - stream stop closed the client and returned to inactive state.
- The unwired live-stream negative control reported zero bytes and zero RTCM
  frames, as expected.
- RTCM3 acquisition: not yet passed because the capture input is unwired.
- Robot correction consumption and RTK FLOAT/FIX: not yet tested.

## Current blocker

Physical access is required to identify and tap the RTK3's internal
GNSS/controller/LoRa serial links. Router capture is an alternate blocker
because the TP-Link owner session is not authenticated. The internal serial
path remains the higher-priority next step.

## Next autonomous step

Once clear internal photos identify board labels and connectors, select the
most likely GNSS-to-controller TX line, specify a receive-only 3.3 V-safe tap,
run longer baud sweeps, download the winning raw stream, validate RTCM CRC/type
and station ID with the host pipeline, then connect its validated serial relay
to the robot receiver.

## Single physical action needed from the user

Power off and unplug the RTK3, open its enclosure without disconnecting or
probing anything, and provide sharp, straight-on photos of both sides of every
internal PCB plus close-ups of every inter-board connector and readable chip or
connector label. Keep the unit unpowered while open; do not connect the ESP32,
USB power, 3.3 V, or 5 V yet.

Expected result: the photos reveal ground and candidate TX/test-pad/connector
locations and logic-family clues. This enables one exact, voltage-safe wiring
instruction for `RTK3 GND -> ESP32 GND` and one RTK3 transmit point through a
protective series resistor to `ESP32 GPIO18`, without risking a guessed pin.

## Exact acceptance criteria remaining

- Capture RTK3-originated correction data.
- Prove its transport and protocol.
- Validate RTCM3 CRC-24Q (or equivalently validate the actual correction
  format), message types, station ID, timing, and freshness.
- Deliver the correction stream to the robot GNSS receiver.
- Prove receiver correction consumption and RTK FLOAT or RTK FIX.
- If Mammotion transport is impractical, implement and prove the best
  correction-source alternative that retains as much RTK3 GNSS/antenna
  hardware as possible.
