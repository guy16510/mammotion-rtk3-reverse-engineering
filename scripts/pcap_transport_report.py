#!/usr/bin/env python3
"""Report RTK-relevant transport evidence from a classic libpcap file.

The parser is deliberately dependency-free and read-only. It supports Ethernet
IPv4/IPv6, ARP, UDP DNS, TCP/UDP flow accounting, TLS ClientHello SNI, and
CRC-valid RTCM3 detection in packet payloads. It does not decrypt TLS or label
encrypted MQTT traffic as correction data.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from rtcm_pipeline import RtcmParser

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


@dataclass(frozen=True)
class Packet:
    timestamp: float
    data: bytes


@dataclass
class Flow:
    protocol: str
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    first: float
    last: float
    packets: int = 0
    bytes: int = 0
    a_to_b_packets: int = 0
    a_to_b_bytes: int = 0
    b_to_a_packets: int = 0
    b_to_a_bytes: int = 0
    rtcm_parser: RtcmParser = field(default_factory=RtcmParser)
    rtcm_types: Counter[int] = field(default_factory=Counter)

    def observe(
        self, source: tuple[str, int], payload: bytes, timestamp: float
    ) -> None:
        self.last = timestamp
        self.packets += 1
        self.bytes += len(payload)
        if source == self.endpoint_a:
            self.a_to_b_packets += 1
            self.a_to_b_bytes += len(payload)
        else:
            self.b_to_a_packets += 1
            self.b_to_a_bytes += len(payload)
        for frame in self.rtcm_parser.feed(payload):
            self.rtcm_types[frame.message_type] += 1


def read_pcap(path: Path) -> Iterator[Packet]:
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in PCAP_MAGICS:
            raise ValueError("expected a classic libpcap file (pcapng is not supported)")
        endian, resolution = PCAP_MAGICS[header[:4]]
        _, _, _, _, _, network = struct.unpack(endian + "HHiiii", header[4:])
        if network != 1:
            raise ValueError(f"expected Ethernet link type 1, got {network}")
        packet_header = struct.Struct(endian + "IIII")
        while raw_header := stream.read(16):
            if len(raw_header) != 16:
                raise ValueError("truncated packet header")
            seconds, fraction, captured, _original = packet_header.unpack(raw_header)
            data = stream.read(captured)
            if len(data) != captured:
                raise ValueError("truncated packet body")
            yield Packet(seconds + fraction / resolution, data)


def mac(raw: bytes) -> str:
    return ":".join(f"{part:02X}" for part in raw)


def parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 12:
        raise ValueError("DNS compression loop")
    labels: list[str] = []
    original_end: int | None = None
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return ".".join(labels), (original_end or offset + 1)
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = parse_dns_name(data, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            return ".".join(labels), (original_end or offset + 2)
        if length & 0xC0 or offset + 1 + length > len(data):
            raise ValueError("invalid DNS name")
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    raise ValueError("truncated DNS name")


def parse_dns(data: bytes) -> dict | None:
    if len(data) < 12:
        return None
    _ident, flags, questions, answers, authorities, additionals = struct.unpack(
        "!HHHHHH", data[:12]
    )
    offset = 12
    names: list[str] = []
    records: list[dict] = []
    try:
        for _ in range(questions):
            name, offset = parse_dns_name(data, offset)
            if offset + 4 > len(data):
                return None
            qtype, _qclass = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            names.append(name)
            records.append({"kind": "query", "name": name, "type": qtype})
        for section, count in (
            ("answer", answers),
            ("authority", authorities),
            ("additional", additionals),
        ):
            for _ in range(count):
                name, offset = parse_dns_name(data, offset)
                if offset + 10 > len(data):
                    return None
                rtype, _rclass, ttl, rdlength = struct.unpack(
                    "!HHIH", data[offset : offset + 10]
                )
                offset += 10
                rdata_offset = offset
                rdata = data[offset : offset + rdlength]
                if len(rdata) != rdlength:
                    return None
                offset += rdlength
                value: str | None = None
                if rtype == 1 and len(rdata) == 4:
                    value = str(ipaddress.IPv4Address(rdata))
                elif rtype == 28 and len(rdata) == 16:
                    value = str(ipaddress.IPv6Address(rdata))
                elif rtype in (5, 12):
                    value, _ = parse_dns_name(data, rdata_offset)
                record = {
                    "kind": section,
                    "name": name,
                    "type": rtype,
                    "ttl": ttl,
                }
                if value is not None:
                    record["value"] = value
                records.append(record)
    except (ValueError, struct.error):
        return None
    return {"response": bool(flags & 0x8000), "names": names, "records": records}


def tls_client_hello_sni(data: bytes) -> str | None:
    """Return SNI when one complete TLS ClientHello is in this payload."""
    if len(data) < 9 or data[0] != 22:
        return None
    record_length = int.from_bytes(data[3:5], "big")
    record = data[5 : 5 + record_length]
    if len(record) < 4 or record[0] != 1:
        return None
    hello_length = int.from_bytes(record[1:4], "big")
    hello = record[4 : 4 + hello_length]
    if len(hello) < 34:
        return None
    offset = 34
    if offset >= len(hello):
        return None
    session_length = hello[offset]
    offset += 1 + session_length
    if offset + 2 > len(hello):
        return None
    cipher_length = int.from_bytes(hello[offset : offset + 2], "big")
    offset += 2 + cipher_length
    if offset >= len(hello):
        return None
    compression_length = hello[offset]
    offset += 1 + compression_length
    if offset + 2 > len(hello):
        return None
    extensions_length = int.from_bytes(hello[offset : offset + 2], "big")
    offset += 2
    end = min(len(hello), offset + extensions_length)
    while offset + 4 <= end:
        extension_type = int.from_bytes(hello[offset : offset + 2], "big")
        extension_length = int.from_bytes(hello[offset + 2 : offset + 4], "big")
        value = hello[offset + 4 : offset + 4 + extension_length]
        offset += 4 + extension_length
        if extension_type != 0 or len(value) < 5:
            continue
        name_length = int.from_bytes(value[3:5], "big")
        if value[2] == 0 and 5 + name_length <= len(value):
            return value[5 : 5 + name_length].decode("ascii", "replace")
    return None


def packet_layers(data: bytes) -> dict | None:
    if len(data) < 14:
        return None
    destination_mac, source_mac, ether_type = data[:6], data[6:12], data[12:14]
    offset = 14
    ether = int.from_bytes(ether_type, "big")
    if ether == 0x8100 and len(data) >= 18:
        ether = int.from_bytes(data[16:18], "big")
        offset = 18
    result = {"srcMac": mac(source_mac), "dstMac": mac(destination_mac)}
    if ether == 0x0806 and len(data) >= offset + 28:
        arp = data[offset : offset + 28]
        result.update(
            {
                "kind": "arp",
                "arpOperation": int.from_bytes(arp[6:8], "big"),
                "arpSenderMac": mac(arp[8:14]),
                "arpSenderIp": str(ipaddress.IPv4Address(arp[14:18])),
                "arpTargetMac": mac(arp[18:24]),
                "arpTargetIp": str(ipaddress.IPv4Address(arp[24:28])),
            }
        )
        return result
    if ether == 0x0800 and len(data) >= offset + 20:
        version_ihl = data[offset]
        ihl = (version_ihl & 0x0F) * 4
        if version_ihl >> 4 != 4 or ihl < 20 or len(data) < offset + ihl:
            return None
        protocol = data[offset + 9]
        source_ip = str(ipaddress.IPv4Address(data[offset + 12 : offset + 16]))
        destination_ip = str(ipaddress.IPv4Address(data[offset + 16 : offset + 20]))
        payload = data[offset + ihl :]
    elif ether == 0x86DD and len(data) >= offset + 40:
        if data[offset] >> 4 != 6:
            return None
        protocol = data[offset + 6]
        source_ip = str(ipaddress.IPv6Address(data[offset + 8 : offset + 24]))
        destination_ip = str(ipaddress.IPv6Address(data[offset + 24 : offset + 40]))
        payload = data[offset + 40 :]
    else:
        return None
    result.update({"srcIp": source_ip, "dstIp": destination_ip})
    if protocol == 17 and len(payload) >= 8:
        source_port, destination_port, length, _checksum = struct.unpack(
            "!HHHH", payload[:8]
        )
        result.update(
            {
                "kind": "udp",
                "srcPort": source_port,
                "dstPort": destination_port,
                "payload": payload[8:length],
            }
        )
    elif protocol == 6 and len(payload) >= 20:
        source_port, destination_port = struct.unpack("!HH", payload[:4])
        header_length = (payload[12] >> 4) * 4
        if header_length < 20 or len(payload) < header_length:
            return None
        result.update(
            {
                "kind": "tcp",
                "srcPort": source_port,
                "dstPort": destination_port,
                "payload": payload[header_length:],
            }
        )
    else:
        result["kind"] = "ip"
    return result


def canonical_flow(
    protocol: str, source: tuple[str, int], destination: tuple[str, int]
) -> tuple:
    endpoints = sorted((source, destination))
    return protocol, endpoints[0], endpoints[1]


def analyze(path: Path, target_ips: set[str], target_macs: set[str]) -> dict:
    flows: dict[tuple, Flow] = {}
    arp_observations: set[tuple[str, str]] = set()
    dns_events: list[dict] = []
    tls_sni: set[tuple[str, str, int]] = set()
    packet_count = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    for packet in read_pcap(path):
        packet_count += 1
        first_timestamp = packet.timestamp if first_timestamp is None else first_timestamp
        last_timestamp = packet.timestamp
        layers = packet_layers(packet.data)
        if not layers:
            continue
        if layers["kind"] == "arp":
            arp_observations.add((layers["arpSenderIp"], layers["arpSenderMac"]))
            continue
        if layers["kind"] not in ("tcp", "udp"):
            continue
        involved = (
            not target_ips
            or layers["srcIp"] in target_ips
            or layers["dstIp"] in target_ips
            or layers["srcMac"] in target_macs
            or layers["dstMac"] in target_macs
        )
        if not involved:
            continue
        source = (layers["srcIp"], layers["srcPort"])
        destination = (layers["dstIp"], layers["dstPort"])
        key = canonical_flow(layers["kind"], source, destination)
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = Flow(
                layers["kind"], key[1], key[2], packet.timestamp, packet.timestamp
            )
        payload = layers["payload"]
        flow.observe(source, payload, packet.timestamp)
        if layers["kind"] == "udp" and (
            layers["srcPort"] == 53 or layers["dstPort"] == 53
        ):
            dns = parse_dns(payload)
            if dns:
                dns_events.append(
                    {
                        "timestamp": packet.timestamp,
                        "source": layers["srcIp"],
                        **dns,
                    }
                )
        if layers["kind"] == "tcp":
            sni = tls_client_hello_sni(payload)
            if sni:
                tls_sni.add((layers["srcIp"], sni, layers["dstPort"]))

    flow_reports = []
    likely_ports = {53, 80, 443, 8883, 1883, 2101}
    for flow in sorted(flows.values(), key=lambda item: item.first):
        rtcm_frames = sum(flow.rtcm_types.values())
        report = {
            "protocol": flow.protocol,
            "endpointA": f"{flow.endpoint_a[0]}:{flow.endpoint_a[1]}",
            "endpointB": f"{flow.endpoint_b[0]}:{flow.endpoint_b[1]}",
            "firstTimestamp": flow.first,
            "lastTimestamp": flow.last,
            "durationSeconds": round(flow.last - flow.first, 6),
            "packets": flow.packets,
            "payloadBytes": flow.bytes,
            "aToB": {"packets": flow.a_to_b_packets, "bytes": flow.a_to_b_bytes},
            "bToA": {"packets": flow.b_to_a_packets, "bytes": flow.b_to_a_bytes},
            "rtcmValidFrames": rtcm_frames,
            "rtcmCrcErrors": flow.rtcm_parser.crc_errors,
            "rtcmMessageTypes": dict(sorted(flow.rtcm_types.items())),
            "candidate": rtcm_frames > 0
            or flow.endpoint_a[1] in likely_ports
            or flow.endpoint_b[1] in likely_ports,
        }
        flow_reports.append(report)

    return {
        "capture": str(path),
        "packetCount": packet_count,
        "firstTimestamp": first_timestamp,
        "lastTimestamp": last_timestamp,
        "durationSeconds": (
            None
            if first_timestamp is None or last_timestamp is None
            else round(last_timestamp - first_timestamp, 6)
        ),
        "filters": {
            "targetIps": sorted(target_ips),
            "targetMacs": sorted(target_macs),
        },
        "arpIpMacObservations": [
            {"ip": ip, "mac": address} for ip, address in sorted(arp_observations)
        ],
        "dns": dns_events,
        "tlsSni": [
            {"source": source, "serverName": name, "destinationPort": port}
            for source, name, port in sorted(tls_sni)
        ],
        "flows": flow_reports,
        "summary": {
            "flowCount": len(flow_reports),
            "candidateFlowCount": sum(item["candidate"] for item in flow_reports),
            "flowsWithValidRtcm": sum(
                item["rtcmValidFrames"] > 0 for item in flow_reports
            ),
            "validRtcmFrames": sum(item["rtcmValidFrames"] for item in flow_reports),
        },
        "limitations": [
            "TLS payloads are not decrypted.",
            "TLS SNI is detected only when a complete ClientHello is in one TCP payload.",
            "TCP retransmission/reassembly is not performed; RTCM detection is indicative.",
            "Encrypted MQTT traffic is not classified as correction data.",
        ],
    }


def normalize_mac(value: str) -> str:
    parts = value.replace("-", ":").split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise argparse.ArgumentTypeError("expected MAC address XX:XX:XX:XX:XX:XX")
    try:
        return ":".join(f"{int(part, 16):02X}" for part in parts)
    except ValueError as error:
        raise argparse.ArgumentTypeError("invalid hexadecimal MAC address") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="classic Ethernet libpcap file")
    parser.add_argument(
        "--target-ip",
        action="append",
        default=[],
        help="only include flows involving this IP (repeatable)",
    )
    parser.add_argument(
        "--target-mac",
        action="append",
        default=[],
        type=normalize_mac,
        help="only include flows involving this MAC (repeatable)",
    )
    parser.add_argument(
        "--require-rtcm",
        action="store_true",
        help="exit 2 unless at least one CRC-valid RTCM3 frame is found",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        target_ips = {str(ipaddress.ip_address(value)) for value in args.target_ip}
        report = analyze(args.pcap, target_ips, set(args.target_mac))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_rtcm and report["summary"]["validRtcmFrames"] == 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
