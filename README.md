# Mammotion RTK3 ESP32-S3 network probe

Standalone ESP32-S3 firmware for finding and probing a Mammotion RTK3 that is already connected to your home Wi-Fi.

No Raspberry Pi, always-on Mac, UART wiring, USB serial adapter, Node.js service, or manually entered RTK IP is required after the ESP32-S3 is flashed.

## What it does

- Joins your home Wi-Fi
- Automatically determines its local IPv4 subnet
- Starts a bounded LAN scan after boot
- Pings local devices with a short timeout
- Checks likely embedded, MQTT, web, diagnostic, and Mammotion-related TCP ports
- Ranks likely IoT and Mammotion candidates
- Saves scan results in ESP32 flash
- Compares consecutive scans and reports devices that disappeared
- Provides a browser interface and JSON API
- Provides a fallback access point for entering or changing Wi-Fi credentials
- Restricts all automatic and manual probing to private IPv4 networks

The strongest practical identification workflow is:

1. Scan with the RTK3 powered on.
2. Power the RTK3 off.
3. Scan again.
4. Check `missingSinceLastScan`.

The IP that disappeared is the strongest RTK3 candidate.

## Important network limitation

The ESP32-S3 can discover hosts, ping them, and test local TCP services.

A normal Wi-Fi client cannot decrypt another client's WPA-protected unicast traffic. Capturing the RTK3's cloud traffic requires router-side packet capture, port mirroring, or a separate monitor-mode workflow. This firmware does not pretend otherwise.

## Hardware

- ESP32-S3 development board
- Data-capable USB cable

The default PlatformIO target is `esp32-s3-devkitc-1`. Change the board in `platformio.ini` if your board uses a different PlatformIO definition.

No connection to the RTK3 is required.

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

## First boot and Wi-Fi setup

The ESP32-S3 always creates a fallback access point:

```text
SSID: RTK3-Probe
Password: rtk3-probe
URL: http://192.168.4.1/
```

1. Connect your phone or Mac to `RTK3-Probe`.
2. Open `http://192.168.4.1/`.
3. Enter your home Wi-Fi SSID and password.
4. Select **Save and restart**.
5. Reconnect your phone or Mac to your normal home Wi-Fi.
6. Open `http://rtk3-probe.local/`.

The serial monitor also prints the ESP32's assigned home-network IP address.

You may alternatively compile credentials into `include/secrets.h`, but it is no longer required.

## Automatic discovery

Once the ESP32 joins your home network, it automatically scans the subnet.

The scanner:

- Uses the ESP32's assigned IP and subnet mask
- Caps unexpectedly large networks to the ESP32's local `/24`
- Probes at most 254 host addresses
- Uses short ICMP and TCP timeouts
- Runs in a background task so the web interface remains responsive
- Saves final results to `/lan-scan.json`

Likely candidates are ranked using reachable services. Ports `50001-50003` receive a strong Mammotion heuristic score, while MQTT ports `1883` and `8883` receive a weaker IoT score. This ranking is a lead, not proof.

## Browser workflow

Open the device page and use:

- **Scan my network** to start another scan
- **Show ranked results** to inspect discovered devices
- **Stop** to cancel a scan
- **Probe** to test a known private IP and selected ports

For reliable identification, use the power-cycle comparison instead of trusting a port heuristic alone.

## Result example

```json
{
  "completed": true,
  "localIp": "192.168.1.42",
  "gateway": "192.168.1.1",
  "hosts": [
    {
      "ip": "192.168.1.123",
      "ping": true,
      "rttMs": 4,
      "gateway": false,
      "newSinceLastScan": false,
      "score": 75,
      "classification": "strong-mammotion-candidate",
      "openPorts": [50001]
    }
  ],
  "missingSinceLastScan": []
}
```

## HTTP endpoints

```text
GET  /healthz
GET  /api/status
POST /api/lan/scan/start
POST /api/lan/scan/stop
GET  /api/lan/scan/status
GET  /api/lan/scan/results
POST /api/probe?ip=192.168.1.123&ports=80,443,1883,8883,50001,50002,50003
POST /api/wifi/scan
POST /api/wifi/configure
POST /api/wifi/clear
```

Manual probing accepts only private IPv4 addresses and a bounded number of unique ports.

## Validation

GitHub Actions runs:

```bash
pio test -e native
pio run -e esp32-s3-devkitc-1
```

The current network-first firmware compiles successfully for the generic ESP32-S3 DevKitC target. The existing portable protocol tests also remain green.

Hardware validation still requires your actual ESP32-S3 and home network. Specifically, the build cannot prove that your access point permits client-to-client traffic, that the RTK3 answers ICMP, or that it exposes an inbound TCP service.

## If the RTK3 does not appear

Possible reasons:

- Your Wi-Fi network has client isolation enabled
- The RTK3 is on a guest network or different VLAN
- The ESP32 is on a different subnet
- The RTK3 ignores ICMP and exposes no tested inbound TCP ports
- The RTK3 communicates only through outbound cloud connections

The next escalation is router-side evidence, such as DHCP leases, ARP tables, DNS logs, firewall logs, or packet capture. That is more reliable than attempting to sniff encrypted traffic from another Wi-Fi client.

## Safety and privacy

Scan output can contain local IP addresses, Wi-Fi names, and device metadata. Review results before publishing them. Probe only networks and equipment you own or are authorized to test.
