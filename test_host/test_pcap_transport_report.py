import importlib.util
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "pcap_transport_report.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("pcap_transport_report", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def ethernet(payload, ether_type=0x0800):
    return bytes.fromhex("001122334455c0f535cf7011") + struct.pack(
        "!H", ether_type
    ) + payload


def ipv4(payload, protocol, source="192.168.2.26", destination="1.2.3.4"):
    header = (
        b"\x45\x00"
        + struct.pack("!H", 20 + len(payload))
        + b"\x00\x01\x00\x00\x40"
        + bytes([protocol])
        + b"\x00\x00"
        + socket.inet_aton(source)
        + socket.inet_aton(destination)
    )
    return header + payload


def udp(payload, source=53000, destination=53):
    return struct.pack("!HHHH", source, destination, 8 + len(payload), 0) + payload


def tcp(payload, source=42000, destination=8883):
    return (
        struct.pack("!HHII", source, destination, 1, 0)
        + b"\x50\x18\xff\xff\x00\x00\x00\x00"
        + payload
    )


def dns_query(name):
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + encoded + b"\0\x00\x01\x00\x01"


def tls_hello(host):
    name = host.encode()
    server_name = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
    extension = b"\x00\x00" + struct.pack("!H", len(server_name)) + server_name
    hello = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extension))
        + extension
    )
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def rtcm_frame(message_type=1005, station=42):
    from rtcm_pipeline import crc24q

    payload = bytes(
        [message_type >> 4, ((message_type & 0x0F) << 4) | (station >> 8), station & 0xFF]
    )
    header = b"\xd3" + len(payload).to_bytes(2, "big")
    body = header + payload
    return body + crc24q(body).to_bytes(3, "big")


def write_pcap(path, packets):
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1")
        stream.write(struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            stream.write(struct.pack("<IIII", 100 + index, 0, len(packet), len(packet)))
            stream.write(packet)


class PcapTransportReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_dns_tls_flow_and_rtcm_detection(self):
        query = ethernet(ipv4(udp(dns_query("pk.iot-as-mqtt.example.com")), 17))
        hello = ethernet(ipv4(tcp(tls_hello("pk.iot-as-mqtt.example.com")), 6))
        correction = ethernet(ipv4(tcp(rtcm_frame(), destination=2101), 6))
        path = self.temp_path / "capture.pcap"
        write_pcap(path, [query, hello, correction])

        report = MODULE.analyze(path, {"192.168.2.26"}, set())

        self.assertEqual(report["packetCount"], 3)
        self.assertEqual(
            report["dns"][0]["names"], ["pk.iot-as-mqtt.example.com"]
        )
        self.assertEqual(
            report["tlsSni"][0]["serverName"], "pk.iot-as-mqtt.example.com"
        )
        self.assertEqual(report["summary"]["validRtcmFrames"], 1)
        rtcm_flow = next(
            flow for flow in report["flows"] if flow["rtcmValidFrames"]
        )
        self.assertEqual(rtcm_flow["rtcmMessageTypes"], {1005: 1})

    def test_arp_identity_and_filtering(self):
        arp = (
            b"\x00\x01\x08\x00\x06\x04\x00\x02"
            + bytes.fromhex("c0f535cf7011")
            + socket.inet_aton("192.168.2.26")
            + bytes.fromhex("001122334455")
            + socket.inet_aton("192.168.2.20")
        )
        unrelated = ethernet(
            ipv4(tcp(b"x"), 6, source="10.0.0.1", destination="10.0.0.2")
        )
        path = self.temp_path / "capture.pcap"
        write_pcap(path, [ethernet(arp, 0x0806), unrelated])

        report = MODULE.analyze(path, {"192.168.2.26"}, set())

        self.assertEqual(
            report["arpIpMacObservations"],
            [{"ip": "192.168.2.26", "mac": "C0:F5:35:CF:70:11"}],
        )
        self.assertEqual(report["flows"], [])

    def test_rejects_pcapng(self):
        path = self.temp_path / "capture.pcapng"
        path.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(20))
        with self.assertRaisesRegex(ValueError, "pcapng"):
            list(MODULE.read_pcap(path))
