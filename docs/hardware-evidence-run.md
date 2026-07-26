# Deterministic hardware evidence run

Use `scripts/collect_hardware_evidence.py` for the next ESP32-S3 flash and RTK3 evidence collection.

The collector uses only the Python standard library and PlatformIO. It:

1. Runs all native tests.
2. Builds the ESP32-S3 firmware.
3. Uploads without erasing NVS or the full flash.
4. Waits for the main HTTP endpoint.
5. Waits for the bounded general RTK3 probe to complete.
6. Waits for the TLS evidence endpoint on port 81.
7. Forces a new manual TLS evidence run rather than accepting persisted output from a previous boot.
8. Requires TLS evidence schema version 3 or newer.
9. Requires the completed result to have `trigger: manual-http`.
10. Optionally rejects results for an unexpected target IP.
11. Saves the main probe and TLS evidence in one atomic JSON bundle.

## Exact command for the current hardware

```bash
cd /Users/admin/Desktop/dev/mammotion-rtk3-reverse-engineering
git switch main
git pull --ff-only

python3 scripts/collect_hardware_evidence.py \
  --serial-port /dev/cu.usbmodem5C381959331 \
  --esp32-ip 192.168.2.43 \
  --target-ip 192.168.2.26 \
  --output /tmp/rtk3-hardware-evidence.json
```

The command exits nonzero when build, upload, endpoint access, probe completion, schema validation, or target validation fails. TCP port 8883 being unreachable is still a valid completed evidence result and does not by itself make the collector fail.

## Collect again without flashing

```bash
python3 scripts/collect_hardware_evidence.py \
  --skip-tests \
  --skip-build \
  --skip-upload \
  --esp32-ip 192.168.2.43 \
  --target-ip 192.168.2.26 \
  --output /tmp/rtk3-hardware-evidence-repeat.json
```

This still forces a fresh manual TLS evidence run after confirming the main probe result.

## Output structure

```json
{
  "collectorVersion": 1,
  "capturedAt": "2026-07-26T20:00:00+00:00",
  "repositoryCommit": "...",
  "serialPort": "/dev/cu.usbmodem...",
  "esp32Ip": "192.168.2.43",
  "expectedTargetIp": "192.168.2.26",
  "mainHealth": {},
  "tlsHealth": {},
  "mainProbe": {},
  "tlsEvidence": {}
}
```

The collector writes to a temporary sibling path and then replaces the requested output path. A partially written bundle is not exposed as the final file.

## Important limitations

- The collector cannot determine a changed ESP32 DHCP address. Supply the current address with `--esp32-ip`.
- It does not open a serial monitor. Upload success, HTTP health, and returned JSON are the bounded automated gates.
- It does not erase NVS or the complete flash.
- It does not authenticate to MQTT, publish, subscribe, brute force credentials, or probe any host other than the configured RTK3.
