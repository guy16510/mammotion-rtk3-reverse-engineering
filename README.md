# Mammotion RTK3 ESP32-S3 probe

Standalone ESP32-S3 firmware for passively investigating a Mammotion RTK3. No Raspberry Pi, Linux service, Node.js process, USB UART adapter, or always-on computer is required after the board is flashed.

Your Mac is only used to build, flash, monitor, and download captures.

## What it does

- Cycles through common GNSS UART baud rates
- Captures raw receive-only UART data to ESP32 flash
- Validates RTCM3 frames with CRC-24Q
- Detects RTCM message types, u-blox UBX sync markers, and NMEA prefixes
- Scans nearby Wi-Fi networks
- Scans BLE advertisements without connecting
- Runs a bounded TCP connect check against private IPv4 targets only
- Exposes a local browser interface and JSON endpoints
- Keeps working from its own Wi-Fi access point when home Wi-Fi is unavailable

It does not transmit bytes to the RTK UART, write Mammotion firmware, connect to BLE devices, scan public IP addresses, or provide a shell.

## Hardware

- ESP32-S3 development board
- Data-capable USB cable
- Two jumper wires for passive UART capture
- Optional logic analyzer for confirming voltage and baud rate

The default PlatformIO target is `esp32-s3-devkitc-1`. Change the board in `platformio.ini` if your ESP32-S3 uses a different definition.

## Wiring

Default receive pin: GPIO 18.

```text
Mammotion RTK3 GND  -> ESP32-S3 GND
Mammotion RTK3 TX   -> ESP32-S3 GPIO 18
```

Do not connect:

```text
ESP32-S3 TX -> RTK
ESP32-S3 3V3 -> RTK
ESP32-S3 5V  -> RTK
```

The firmware opens the UART with `txPin = -1`, so the capture path is receive-only. Confirm that the RTK signal is 3.3 V logic before connecting it. Do not feed 5 V UART into an ESP32-S3 GPIO.

To use a different receive pin, change `RTK_RX_PIN` in `include/config.h` or add a build flag.

## Build and flash from macOS

Install PlatformIO Core:

```bash
python3 -m pip install --user platformio
```

Clone and switch to the ESP32-S3 branch:

```bash
git clone https://github.com/guy16510/mammotion-rtk3-reverse-engineering.git
cd mammotion-rtk3-reverse-engineering
git switch codex/esp32-s3-standalone-probe
```

Optional, configure home Wi-Fi:

```bash
cp include/secrets.h.example include/secrets.h
nano include/secrets.h
```

Build, test, flash, and monitor:

```bash
pio test -e native
pio run -e esp32-s3-devkitc-1
pio run -e esp32-s3-devkitc-1 -t upload
pio device monitor -b 115200
```

If PlatformIO cannot choose the USB port, list ports and pass it explicitly:

```bash
pio device list
pio run -e esp32-s3-devkitc-1 -t upload --upload-port /dev/cu.usbmodemXXXX
```

## First boot

The ESP32-S3 always creates this fallback access point:

```text
SSID: RTK3-Probe
Password: rtk3-probe
URL: http://192.168.4.1/
```

If `include/secrets.h` contains valid credentials, the device also joins that Wi-Fi network. The serial monitor prints the assigned address.

Change the default access-point password in `include/config.h` before using the device outside a controlled environment.

## Run a passive UART sweep

1. Power the ESP32-S3 over USB.
2. Open the web interface.
3. Connect RTK GND and RTK TX using the receive-only wiring above.
4. Set seconds per baud, 12 seconds is the default.
5. Select **Start**.
6. Power-cycle or exercise the RTK while the sweep runs.
7. Open **Summary** after all eight baud rates complete.

The firmware tests:

```text
9600
19200
38400
57600
115200
230400
460800
921600
```

Each baud sample is stored as `/baud-<rate>.bin`. The default cap is 64 KiB per baud to avoid exhausting the normal ESP32 filesystem partition.

## Interpret results

A strong RTCM result looks like:

```json
{
  "baud": 115200,
  "rtcmFrames": 42,
  "rtcmCrcErrors": 0,
  "rtcmTypes": [1005, 1077, 1087]
}
```

Prioritize evidence in this order:

1. Valid RTCM3 frames with stable message types
2. Repeated UBX sync markers
3. Repeated NMEA prefixes
4. Non-empty binary data that changes with RTK activity
5. Empty samples, which usually mean the wrong wire, pin, direction, voltage, or interface

CRC-valid RTCM frames are substantially stronger evidence than merely finding `0xD3` bytes.

## HTTP endpoints

```text
GET  /healthz
GET  /api/status
POST /api/capture/start?seconds=12
POST /api/capture/stop
GET  /api/summary
GET  /api/files
GET  /api/file?name=/baud-115200.bin
POST /api/wifi/scan
POST /api/ble/scan
POST /api/probe?ip=192.168.1.123&ports=80,443,1883,8883
```

Network probing accepts private IPv4 addresses only and a maximum of 16 unique ports per request. It is a TCP connect check, not an unrestricted scanner or packet capture system.

## Automated validation

The GitHub Actions workflow runs:

```bash
pio test -e native
pio run -e esp32-s3-devkitc-1
```

The native tests validate CRC-24Q, RTCM framing across chunk boundaries, CRC rejection, UBX detection, and NMEA detection. Hardware behavior still requires the actual ESP32-S3 and RTK signal.

## Current limitations

- Internal flash stores bounded samples, not long-duration packet captures.
- Wi-Fi scanning reports access-point metadata, not full 802.11 traffic.
- BLE scanning records advertisements only.
- The firmware cannot inspect encrypted Mammotion application traffic by itself.
- Pin 18 is only a default and may need to change for your board.
- This branch does not expose an MCP server directly from the microcontroller.

## Safety and privacy

Captured files can contain device identifiers, network names, local addresses, and location-related GNSS data. Review files before publishing them. Only probe equipment and networks you own or are authorized to test.
