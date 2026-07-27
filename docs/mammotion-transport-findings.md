# Mammotion RTK3 transport findings

This note records public-source evidence that can guide acquisition without
mistaking an inference for a captured correction stream. The source inspected
was [PyMammotion commit
`49f1ed0`](https://github.com/mikey0000/PyMammotion/tree/49f1ed0797a18770e1c8d9ef76c89f632a50e4bd).
No account credentials, device secrets, or private traffic were used.

## Confirmed from the public implementation

- RTK3 variants are represented as `RBS03A0`, `RBS03A1`, and `RBS03A2` in
  [`device_type.py`](https://github.com/mikey0000/PyMammotion/blob/49f1ed0797a18770e1c8d9ef76c89f632a50e4bd/pymammotion/utility/device_type.py#L123-L126).
- The base-station protobuf reports satellite count, LoRa scan/channel/location
  and network IDs, RTK status, MQTT RTK status, RTK channel, and RTK switch.
  Its app-to-base message can carry an RTK switch, URL, port, username, and
  password. See
  [`basestation.proto`](https://github.com/mikey0000/PyMammotion/blob/49f1ed0797a18770e1c8d9ef76c89f632a50e4bd/pymammotion/proto/basestation.proto).
- Mower-side protobuf distinguishes `LORA`, `INTERNET`, and `NRTK` RTK modes.
  It reports correction age, position quality, satellite counts, LoRa state,
  and MQTT RTK state. See the generated definitions in
  [`proto/__init__.py`](https://github.com/mikey0000/PyMammotion/blob/49f1ed0797a18770e1c8d9ef76c89f632a50e4bd/pymammotion/proto/__init__.py).
- The older cloud transport derives an Aliyun MQTT hostname of the form
  `{product-key}.iot-as-mqtt.{region}.aliyuncs.com`. The direct transport
  subscribes to device event/status topic families under `/sys/...`. See
  [`client.py`](https://github.com/mikey0000/PyMammotion/blob/49f1ed0797a18770e1c8d9ef76c89f632a50e4bd/pymammotion/client.py#L1417)
  and
  [`client.py` topic subscriptions](https://github.com/mikey0000/PyMammotion/blob/49f1ed0797a18770e1c8d9ef76c89f632a50e4bd/pymammotion/client.py#L1647-L1650).

## Interpretation

The public schema proves that Mammotion supports a LoRa correction path and at
least two network-labelled RTK modes. It also proves that a base station can be
configured with a correction-service endpoint. It does **not** prove that raw
RTCM is transported on the ordinary Mammotion device-control MQTT topics.

No public message inspected contains an obvious raw correction-byte field.
This makes an internal GNSS/controller/LoRa serial tap the best current
acquisition path. A router capture remains valuable for discovering whether
the RTK3 separately connects to a correction broker or caster, but encrypted
MQTT telemetry alone is not correction evidence.

The meaning and direction of the base station's `rtk_url`, `rtk_port`,
`rtk_username`, and `rtk_password` remain unresolved. They may configure an
upstream service, an Internet delivery mode, or another vendor workflow. They
must not be treated as a proven caster-output interface until observed.

## Network capture checklist

Capture the RTK3's traffic while recording exact wall-clock times for:

1. RTK3 power-on and GNSS lock.
2. Robot power-on.
3. Switching the app between LoRa, Internet, or NRTK modes, if those controls
   are exposed.
4. Robot transition between no-fix, float, and fixed states.

For the RTK3 IP/MAC flow, retain:

- DHCP and ARP, to prove device identity before interpreting traffic;
- DNS queries and answers;
- TCP destination IPs and ports;
- TLS ClientHello server-name indication and ALPN;
- packet sizes, directions, bursts, and timing;
- MQTT metadata only where it is legitimately decryptable by the owner.

Initial filters should include TCP 8883, hostnames ending in
`aliyuncs.com`, and any dynamically issued Mammotion MQTT hostname. Also look
for common correction transports such as NTRIP/HTTP and sustained binary
streams whose timing correlates with GNSS lock or the robot's RTK state.

Success still requires payload validation: repeatable CRC-24Q-valid RTCM3
frames with plausible types, station ID, rate, and freshness, or equivalent
validation of a different correction format.

The repository's `scripts/pcap_transport_report.py` automates these checks for
classic Ethernet libpcap captures. It reports observed ARP IP/MAC pairs, target
flows, DNS, TLS SNI, directional payload sizes and timing, and CRC-valid RTCM3
found in visible payloads. Its `--require-rtcm` flag provides a nonzero
acceptance gate. It intentionally does not decrypt TLS or infer corrections
from encrypted MQTT.
