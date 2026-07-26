# Mammotion RTK3 reverse engineering

Passive capture, protocol analysis, and restricted MCP access for investigating whether a Mammotion RTK3 exposes reusable GNSS correction data.

## Safety model

The capture path is passive toward the RTK UART. The MCP server cannot accept arbitrary shell commands, write firmware, transmit serial data, or scan public IP addresses. Network probes are limited to private IPv4 targets and can be restricted to an explicit allowlist.

Captures may contain local IP addresses, hostnames, device identifiers, cloud endpoints, and Wi-Fi metadata. Do not commit raw PCAPs to this public repository without reviewing them.

## One-command Raspberry Pi install

```bash
git clone https://github.com/guy16510/mammotion-rtk3-reverse-engineering.git
cd mammotion-rtk3-reverse-engineering
sudo ./install.sh
```

Then edit:

```bash
sudo nano /etc/mammotion-rtk3-mcp.env
```

Set the RTK IP as an allowlisted target:

```text
RTK3_ALLOWED_TARGETS=192.168.1.123
```

Restart and verify:

```bash
sudo systemctl restart mammotion-rtk3-mcp
sudo systemctl status mammotion-rtk3-mcp
curl http://127.0.0.1:8787/healthz
```

The installer generates a random bearer token and stores it in `/etc/mammotion-rtk3-mcp.env`.

## Direct local capture

Connect receive-only UART wiring:

```text
RTK GND -> USB UART GND
RTK TX  -> USB UART RX
```

Do not connect USB UART TX, 3.3 V, or 5 V.

Run:

```bash
sudo ./capture.sh
```

With a known target and adapter:

```bash
sudo TARGET_IP=192.168.1.123 \
  SERIAL_DEVICES=/dev/ttyUSB0 \
  DURATION=600 \
  ./capture.sh
```

Output is written under `rtk3-captures/`. The key result is `summary.md`, which validates RTCM3 frames using CRC-24Q and also reports UBX and NMEA signatures.

## MCP tools

The server exposes only:

- `rtk3_health`
- `rtk3_list_captures`
- `rtk3_read_summary`
- `rtk3_start_capture`
- `rtk3_job_status`
- `rtk3_probe_target`

`rtk3_start_capture` can collect network, BLE, and passive serial evidence without a person logged into the Pi. It does not make ChatGPT run continuously by itself. A ChatGPT request, API call, or scheduled automation must still invoke the MCP tool.

## Remote ChatGPT connection

OpenAI custom connectors require a remotely reachable MCP server. Do not expose port 8787 directly to the Internet. Put the local service behind an authenticated HTTPS reverse proxy or tunnel, keep the bearer token enabled, and point the connector to:

```text
https://your-mcp-host.example.com/mcp
```

Configure the connector authorization header as:

```text
Authorization: Bearer <MCP_BEARER_TOKEN>
```

The service binds to `127.0.0.1` by default so it is inaccessible remotely until a tunnel or reverse proxy is intentionally configured.

## Manual MCP development

```bash
cp .env.example .env
npm install
set -a
source .env
set +a
npm start
```

Node.js 20 or newer is required.

## Important limitation

This repository gives ChatGPT a controlled way to request captures and inspect results after the MCP endpoint is connected. It cannot cause this existing chat session to autonomously keep probing indefinitely. For unattended work, schedule explicit recurring capture or analysis calls and keep the Raspberry Pi and tunnel online.
