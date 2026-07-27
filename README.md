# Mammotion RTK3 correction acquisition

This repository is working toward extracting GNSS corrections from a Mammotion
RTK3 and delivering them to a robot receiver. The current hardware path is a
receive-only ESP32-S3 UART capture probe. See `RTK3_ROBOT_STATUS.md` for the
authoritative evidence, current blocker, and remaining acceptance criteria.
Public-source clues and a network-capture checklist are in
`docs/mammotion-transport-findings.md`.

## Safety

The ESP32 capture input is receive-only:

```text
RTK3 GND -> ESP32 GND
RTK3 TX  -> ESP32 GPIO18
```

Do not make this connection until the RTK3 signal and voltage have been
identified. Never connect ESP32 TX, 3.3 V, or 5 V while passively probing.

## What the firmware does

- Joins the configured Wi-Fi network and also exposes fallback AP `RTK3-Probe`
- Sweeps 9600 through 921600 baud on GPIO18
- Stores bounded raw samples in LittleFS
- Validates RTCM3 frames with CRC-24Q
- Reports RTCM message types, CRC errors, UBX sync markers, NMEA prefixes, and
  printable-byte ratio
- Exposes a fixed-baud, receive-only raw TCP stream on port 2101 after a baud
  has been selected explicitly
- Provides HTTP controls for capture, downloads, Wi-Fi/BLE discovery, and a
  bounded private-address TCP probe
- Configures no UART transmit pin

## Build, test, and flash

Create ignored `include/secrets.h` from `include/secrets.h.example`, setting
only the local Wi-Fi values required at runtime. Then:

```sh
pio test -e native
pio run -e esp32-s3-devkitc-1
pio run -e esp32-s3-devkitc-1 -t upload \
  --upload-port /dev/cu.usbmodem5C381959331
```

The current unit has ESP32 MAC `44:1B:F6:FF:98:BC`; its DHCP address may change.
At the time recorded in the status ledger it is `192.168.2.35`.

## Capture API

```sh
ESP32=http://192.168.2.35

curl "$ESP32/api/status"
curl -X POST "$ESP32/api/capture/start?seconds=12"
curl "$ESP32/api/summary"
curl "$ESP32/api/files"
curl -o baud-115200.bin "$ESP32/api/file?name=/baud-115200.bin"
```

Each baud is sampled for 1–60 seconds. Captures are limited to 64 KiB per baud.
Starting a capture clears earlier baud files, the summary, and obsolete
LAN/TLS-probe result files.

Other endpoints:

```text
POST /api/capture/stop
POST /api/stream/start?baud=<supported-baud>
POST /api/stream/stop
POST /api/wifi/scan
POST /api/ble/scan
POST /api/probe?ip=<private-ip>&ports=<comma-separated-ports>
```

## Validate and relay corrections

Analyze a capture, extract only valid RTCM3 frames, and fail if none exist:

```sh
python3 scripts/rtcm_pipeline.py analyze baud-115200.bin \
  --extract valid.rtcm3 \
  --require-frames
```

Use `--reject-crc-errors` when the source is expected to contain only clean
RTCM3. The JSON report includes input/discarded bytes, CRC failures, frame and
byte counts, message-type counts, reference-station IDs, correction age,
frame rate, and stale state.

Relay only validated frames to a robot receiver:

```sh
python3 -m pip install pyserial
python3 scripts/rtcm_pipeline.py relay \
  --input-serial /dev/cu.usbserial-RTK3 --input-baud 115200 \
  --output-serial /dev/cu.usbserial-ROBOT --output-baud 115200
```

File and TCP stream endpoints are also supported:

```sh
python3 scripts/rtcm_pipeline.py relay \
  --input-tcp 192.168.2.35:2101 \
  --output-serial /dev/cu.usbserial-ROBOT --output-baud 115200
```

The ESP32 TCP stream is intentionally raw so both RTCM and any newly discovered
protocol remain observable. The host relay is the validation boundary: it
never forwards noise, truncated candidates, or CRC-invalid frames.

## Analyze an outbound packet capture

Capture in classic pcap format (`tcpdump -w` does this by default), then report
ARP identity, RTK3 flows, DNS, TLS SNI, timing, byte direction, and any
CRC-valid RTCM3 visible in unencrypted packet payloads:

```sh
sudo tcpdump -i en0 -s 0 -w rtk3-outbound.pcap \
  'host 192.168.2.26 or ether host c0:f5:35:cf:70:11'

python3 scripts/pcap_transport_report.py rtk3-outbound.pcap \
  --target-ip 192.168.2.26 \
  --target-mac C0:F5:35:CF:70:11
```

Use `--require-rtcm` as an acceptance gate; it exits 2 when the capture has no
CRC-valid RTCM3. The report never treats encrypted MQTT as proof of correction
delivery. The tool accepts classic Ethernet libpcap, not pcapng.

## Evidence threshold

Random bytes or a `0xD3` preamble are not correction evidence. A useful
acquisition requires repeatable frames with valid CRC-24Q and plausible message
types/rates (or equivalent validation for a different correction protocol).
Project success additionally requires forwarding those corrections to the
robot receiver and proving RTK FLOAT or RTK FIX.
