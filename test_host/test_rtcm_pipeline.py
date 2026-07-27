import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "rtcm_pipeline.py"
SPEC = importlib.util.spec_from_file_location("rtcm_pipeline", SCRIPT_PATH)
assert SPEC and SPEC.loader
pipeline = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pipeline
SPEC.loader.exec_module(pipeline)


def make_frame(message_type: int, station_id: int, tail: bytes = b"") -> bytes:
    payload = bytes(
        [
            message_type >> 4,
            ((message_type & 0x0F) << 4) | (station_id >> 8),
            station_id & 0xFF,
        ]
    ) + tail
    header = bytes([0xD3, len(payload) >> 8, len(payload) & 0xFF])
    body = header + payload
    return body + pipeline.crc24q(body).to_bytes(3, "big")


class RtcmParserTests(unittest.TestCase):
    def test_parses_chunked_frame_and_station_id(self):
        frame = make_frame(1005, 42, b"\x01\x02")
        parser = pipeline.RtcmParser()

        self.assertEqual([], parser.feed(b"noise" + frame[:4]))
        parsed = parser.feed(frame[4:])

        self.assertEqual(1, len(parsed))
        self.assertEqual(frame, parsed[0].raw)
        self.assertEqual(1005, parsed[0].message_type)
        self.assertEqual(42, parsed[0].station_id)
        self.assertEqual(5, parser.discarded_bytes)

    def test_rejects_corruption_and_recovers_embedded_valid_frame(self):
        bad = bytearray(make_frame(1077, 7, b"\xAA"))
        bad[-1] ^= 1
        good = make_frame(1087, 9, b"\xBB")
        parser = pipeline.RtcmParser()

        parsed = parser.feed(bytes(bad) + good)

        self.assertEqual([good], [frame.raw for frame in parsed])
        self.assertEqual(1, parser.crc_errors)

    def test_rejects_nonzero_reserved_header_bits(self):
        parser = pipeline.RtcmParser()
        parsed = parser.feed(b"\xD3\xFC\x00" + make_frame(1006, 1))
        self.assertEqual(1, len(parsed))
        self.assertGreaterEqual(parser.discarded_bytes, 3)

    def test_ephemeris_bits_are_not_mislabeled_as_station(self):
        frame = make_frame(1019, 55)
        parsed = pipeline.RtcmParser().feed(frame)
        self.assertIsNone(parsed[0].station_id)


class PipelineTests(unittest.TestCase):
    def test_empty_stream_reports_stale_without_dividing_by_zero(self):
        report, frames = pipeline.analyze_stream(io.BytesIO(b""), stale_seconds=5)
        self.assertEqual([], frames)
        self.assertEqual(0.0, report["frameRateHz"])
        self.assertTrue(report["stale"])

    def test_analyze_counts_types_stations_and_crc_errors(self):
        first = make_frame(1005, 42)
        second = make_frame(1077, 42)
        bad = bytearray(make_frame(1087, 99))
        bad[-2] ^= 0x10

        report, frames = pipeline.analyze_stream(
            io.BytesIO(first + bytes(bad) + second), stale_seconds=5
        )

        self.assertEqual([first, second], frames)
        self.assertEqual(2, report["validFrames"])
        self.assertEqual(1, report["crcErrors"])
        self.assertEqual({1005: 1, 1077: 1}, report["messageTypes"])
        self.assertEqual({42: 2}, report["stationIds"])

    def test_cli_extracts_only_valid_frames_and_enforces_gate(self):
        good = make_frame(1005, 17)
        bad = bytearray(make_frame(1077, 17))
        bad[-1] ^= 1
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.bin"
            extracted = Path(directory) / "valid.rtcm3"
            source.write_bytes(b"x" + bytes(bad) + good)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "analyze",
                    str(source),
                    "--extract",
                    str(extracted),
                    "--require-frames",
                    "--reject-crc-errors",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(3, result.returncode)
            self.assertEqual(good, extracted.read_bytes())

    def test_cli_relay_is_byte_exact_and_drops_noise(self):
        first = make_frame(1005, 3)
        second = make_frame(1077, 3)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "raw.bin"
            output = Path(directory) / "relay.rtcm3"
            source.write_bytes(b"\x00noise" + first + b"\xFF" + second)

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "relay",
                    "--input-file",
                    str(source),
                    "--output-file",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(first + second, output.read_bytes())


if __name__ == "__main__":
    unittest.main()
