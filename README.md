# Mammotion RTK3 ESP32-S3 direct probe

Standalone ESP32-S3 firmware for probing one known Mammotion RTK3 on your home network.

You provide the RTK3 IP address and LoRa ID once. The ESP32 stores them, connects directly to that IP, and repeats a bounded evidence-gathering probe without scanning the rest of your network.

No Raspberry Pi, always-on Mac, UART wiring, subnet discovery, power-cycle comparison, Node.js service, or manually repeated target entry is required after setup.

## What it does

- Joins your home Wi-Fi
- Stores one RTK3 private IPv4 address
- Stores the RTK3 LoRa identifier
- Automatically probes the configured RTK3 after boot
- Sends one ICMP reachability check
- Checks a bounded list of likely TCP ports
- Records TCP connection latency
- Reads passive service banners when a service sends one
- Sends `GET /` only on common plaintext HTTP ports
- Searches returned evidence for the configured LoRa ID
- Saves the latest result to ESP32 flash
- Exposes a browser interface and JSON API
- Keeps a fallback access point available for configuration

It does not scan every IP on the LAN, connect to UART, write firmware, expose a shell, or probe public addresses.

## Default ports

```text
22,53,80,443,554,123,1883,2101,5000,5001,5353,8000,8080,8443,8883,9000,10000,50001,50002,50003
```

The list can be edited from the browser before running a probe.

## Build and flash from macOS

```bash
git clone https://github.com/guy16510/mammotion-rtk3-reverse-engineering.git
cd mammotion-rtk3-reverse-engineering
git switch codex/esp32-s3-standalone-probe

python3 -m pip install --user platformio
pio test -e native
pio run -e esp32-s3-devkitc-1 -t upload
pio device monitor -b 115200
```

If PlatformIO cannot determine the USB port:

```bash
pio device list
pio run -e esp32-s3-devkitc-1 -t upload --upload-port /dev/cu.usbmodemXXXX
```

## One-time setup

The ESP32 always creates a fallback access point:

```text
SSID: RTK3-Probe
Password: rtk3-probe
URL: http://192.168.4.1/
```

1. Connect your phone or Mac to `RTK3-Probe`.
2. Open `http://192.168.4.1/`.
3. Enter your home Wi-Fi credentials.
4. Enter the known RTK3 IP address.
5. Enter the RTK3 LoRa ID.
6. Save the target.
7. Save Wi-Fi and allow the ESP32 to restart.
8. Reconnect to your normal home Wi-Fi.
9. Open `http://rtk3-probe.local/`.

The ESP32 automatically probes the saved RTK3 after joining Wi-Fi. Select **Probe RTK3 now** to repeat it.

You can alternatively place compile-time defaults in `include/secrets.h`:

```cpp
#define WIFI_SSID "your-home-wifi"
#define WIFI_PASSWORD "your-password"
#define RTK3_IP "192.168.1.123"
#define RTK3_LORA_ID "your-lora-id"
```

Runtime values saved from the browser override compile-time defaults.

## Result example

```json
{
  "completed": true,
  "targetIp": "192.168.1.123",
  "loraId": "1234567890",
  "ping": true,
  "rttMs": 4,
  "loraObserved": false,
  "durationMs": 5160,
  "ports": [
    {
      "port": 80,
      "open": true,
      "connectMs": 8,
      "receivedBytes": 182,
      "loraMatch": false,
      "evidence": "HTTP/1.1 200 OK..."
    }
  ]
}
```

`loraObserved: true` is strong evidence that a returned local service exposes the configured LoRa identifier. `false` does not mean the IP is wrong. The device may not expose the identifier through an inbound plaintext service.

## Browser and API

```text
GET  /healthz
GET  /api/status
GET  /api/config
POST /api/config
POST /api/config/clear
POST /api/probe/start
POST /api/probe/stop
GET  /api/probe/status
GET  /api/probe/results
POST /api/wifi/scan
POST /api/wifi/configure
POST /api/wifi/clear
```

Target configuration uses form fields:

```text
ip=<private IPv4>
loraId=<LoRa identifier>
ports=<comma-separated TCP ports>
```

## Honest limitations

- The ESP32 can only inspect services the RTK3 exposes to the local network.
- A closed port does not prove the RTK3 is offline.
- The LoRa ID may never appear in local plaintext responses.
- A normal Wi-Fi client cannot decrypt another client's WPA-protected cloud traffic.
- If the RTK3 communicates only outbound to Mammotion cloud services, the next useful evidence source is your router, DNS logs, firewall logs, or access-point packet capture.
- The first real run still requires your ESP32-S3, RTK3 IP, LoRa ID, and home network.

## Safety and privacy

Only private IPv4 targets are accepted. Probe only equipment and networks you own or are authorized to test. Results may contain local addresses, identifiers, and service responses, so review them before publishing.
