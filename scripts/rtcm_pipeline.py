#!/usr/bin/env python3
"""Validate, inspect, and relay RTCM3 correction streams.

Only complete frames with a valid CRC-24Q are emitted by the relay path. This
prevents UART noise, framing mistakes, or truncated captures from reaching a
GNSS receiver.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

MAX_RTCM_PAYLOAD = 1023
MAX_RTCM_FRAME = 3 + MAX_RTCM_PAYLOAD + 3

# RTCM messages whose first 24 payload bits are message number + reference
# station ID. Satellite ephemeris and network-residual message families are
# intentionally excluded because those bits have different meanings.
STATION_ID_TYPES = frozenset(
    list(range(1001, 1013))
    + [1005, 1006, 1007, 1008, 1032, 1033, 1230]
    + list(range(1071, 1078))
    + list(range(1081, 1088))
    + list(range(1091, 1098))
    + list(range(1101, 1108))
    + list(range(1111, 1118))
    + list(range(1121, 1128))
    + list(range(1131, 1138))
)


def crc24q(data: bytes | bytearray | memoryview) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


@dataclass(frozen=True)
class RtcmFrame:
    raw: bytes
    message_type: int
    station_id: int | None


class RtcmParser:
    """Incremental RTCM3 parser with recovery after noise and bad CRCs."""

    def __init__(self) -> None:
        self._buffer = bytearray()
        self.bytes_seen = 0
        self.discarded_bytes = 0
        self.crc_errors = 0

    def feed(self, data: bytes) -> list[RtcmFrame]:
        self.bytes_seen += len(data)
        self._buffer.extend(data)
        frames: list[RtcmFrame] = []

        while True:
            preamble = self._buffer.find(0xD3)
            if preamble < 0:
                self.discarded_bytes += len(self._buffer)
                self._buffer.clear()
                break
            if preamble:
                self.discarded_bytes += preamble
                del self._buffer[:preamble]
            if len(self._buffer) < 3:
                break

            # Six reserved header bits must be zero.
            if self._buffer[1] & 0xFC:
                self.discarded_bytes += 1
                del self._buffer[0]
                continue

            payload_length = ((self._buffer[1] & 0x03) << 8) | self._buffer[2]
            frame_length = payload_length + 6
            if frame_length > MAX_RTCM_FRAME:
                self.discarded_bytes += 1
                del self._buffer[0]
                continue
            if len(self._buffer) < frame_length:
                break

            raw = bytes(self._buffer[:frame_length])
            expected_crc = int.from_bytes(raw[-3:], "big")
            if crc24q(raw[:-3]) != expected_crc:
                self.crc_errors += 1
                # Drop only the candidate preamble so a valid embedded frame
                # can still be recovered.
                self.discarded_bytes += 1
                del self._buffer[0]
                continue

            del self._buffer[:frame_length]
            if payload_length < 2:
                # CRC-valid but too short to contain the 12-bit type.
                self.discarded_bytes += frame_length
                continue
            message_type = (raw[3] << 4) | (raw[4] >> 4)
            station_id = None
            if message_type in STATION_ID_TYPES and payload_length >= 3:
                station_id = ((raw[4] & 0x0F) << 8) | raw[5]
            frames.append(RtcmFrame(raw, message_type, station_id))

        return frames

    @property
    def pending_bytes(self) -> int:
        return len(self._buffer)


@dataclass
class StreamStats:
    started_monotonic: float
    first_frame_monotonic: float | None = None
    last_frame_monotonic: float | None = None
    valid_frames: int = 0
    valid_bytes: int = 0
    forwarded_frames: int = 0
    forwarded_bytes: int = 0
    types: Counter[int] = None  # type: ignore[assignment]
    stations: Counter[int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.types = Counter()
        self.stations = Counter()

    def observe(self, frame: RtcmFrame, now: float) -> None:
        if self.first_frame_monotonic is None:
            self.first_frame_monotonic = now
        self.last_frame_monotonic = now
        self.valid_frames += 1
        self.valid_bytes += len(frame.raw)
        self.types[frame.message_type] += 1
        if frame.station_id is not None:
            self.stations[frame.station_id] += 1

    def report(self, parser: RtcmParser, now: float, stale_seconds: float) -> dict:
        age = (
            None
            if self.last_frame_monotonic is None
            else max(0.0, now - self.last_frame_monotonic)
        )
        frame_rate = 0.0
        if self.first_frame_monotonic is not None:
            frame_window = max(0.001, now - self.first_frame_monotonic)
            frame_rate = self.valid_frames / frame_window
        return {
            "inputBytes": parser.bytes_seen,
            "discardedBytes": parser.discarded_bytes,
            "pendingBytes": parser.pending_bytes,
            "crcErrors": parser.crc_errors,
            "validFrames": self.valid_frames,
            "validBytes": self.valid_bytes,
            "forwardedFrames": self.forwarded_frames,
            "forwardedBytes": self.forwarded_bytes,
            "frameRateHz": round(frame_rate, 3),
            "correctionAgeSeconds": None if age is None else round(age, 3),
            "stale": age is None or age > stale_seconds,
            "messageTypes": dict(sorted(self.types.items())),
            "stationIds": dict(sorted(self.stations.items())),
        }


def parse_host_port(value: str) -> tuple[str, int]:
    try:
        host, port_text = value.rsplit(":", 1)
        port = int(port_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected HOST:PORT") from error
    if not host or not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("expected HOST:PORT with port 1..65535")
    return host, port


def iter_chunks(stream: BinaryIO, size: int = 4096) -> Iterator[bytes]:
    while chunk := stream.read(size):
        yield chunk


def open_serial(path: str, baud: int, write: bool = False):
    try:
        import serial  # type: ignore[import-not-found]
    except ImportError as error:
        raise RuntimeError(
            "serial input/output requires pyserial: python3 -m pip install pyserial"
        ) from error
    return serial.Serial(
        path,
        baudrate=baud,
        timeout=None if not write else 1,
        write_timeout=2 if write else None,
    )


def analyze_stream(stream: BinaryIO, stale_seconds: float) -> tuple[dict, list[bytes]]:
    parser = RtcmParser()
    stats = StreamStats(time.monotonic())
    frames: list[bytes] = []
    for chunk in iter_chunks(stream):
        for frame in parser.feed(chunk):
            stats.observe(frame, time.monotonic())
            frames.append(frame.raw)
    return stats.report(parser, time.monotonic(), stale_seconds), frames


def command_analyze(args: argparse.Namespace) -> int:
    with (sys.stdin.buffer if args.input == "-" else open(args.input, "rb")) as stream:
        report, frames = analyze_stream(stream, args.stale_seconds)
    if args.extract:
        with open(args.extract, "wb") as output:
            for frame in frames:
                output.write(frame)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_frames and not frames:
        return 2
    if report["crcErrors"] and args.reject_crc_errors:
        return 3
    return 0


def open_input(args: argparse.Namespace):
    if args.input_file:
        return open(args.input_file, "rb")
    if args.input_tcp:
        return socket.create_connection(args.input_tcp, timeout=10).makefile("rb")
    return open_serial(args.input_serial, args.input_baud)


def open_output(args: argparse.Namespace):
    if args.output_file:
        return open(args.output_file, "wb")
    if args.output_tcp:
        return socket.create_connection(args.output_tcp, timeout=10).makefile("wb")
    return open_serial(args.output_serial, args.output_baud, write=True)


def command_relay(args: argparse.Namespace) -> int:
    parser = RtcmParser()
    stats = StreamStats(time.monotonic())
    next_health = time.monotonic() + args.health_interval

    with open_input(args) as source, open_output(args) as destination:
        for chunk in iter_chunks(source):
            now = time.monotonic()
            for frame in parser.feed(chunk):
                stats.observe(frame, now)
                destination.write(frame.raw)
                destination.flush()
                stats.forwarded_frames += 1
                stats.forwarded_bytes += len(frame.raw)
            if now >= next_health:
                print(
                    json.dumps(stats.report(parser, now, args.stale_seconds)),
                    file=sys.stderr,
                    flush=True,
                )
                next_health = now + args.health_interval

    report = stats.report(parser, time.monotonic(), args.stale_seconds)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if stats.valid_frames else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="inspect a finite raw stream")
    analyze.add_argument("input", help="raw input path or - for stdin")
    analyze.add_argument("--extract", type=Path, help="write only valid frames")
    analyze.add_argument("--stale-seconds", type=float, default=5.0)
    analyze.add_argument("--require-frames", action="store_true")
    analyze.add_argument("--reject-crc-errors", action="store_true")
    analyze.set_defaults(func=command_analyze)

    relay = subparsers.add_parser(
        "relay", help="forward only CRC-valid frames from one stream to another"
    )
    inputs = relay.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--input-file")
    inputs.add_argument("--input-tcp", type=parse_host_port)
    inputs.add_argument("--input-serial")
    relay.add_argument("--input-baud", type=int, default=115200)
    outputs = relay.add_mutually_exclusive_group(required=True)
    outputs.add_argument("--output-file")
    outputs.add_argument("--output-tcp", type=parse_host_port)
    outputs.add_argument("--output-serial")
    relay.add_argument("--output-baud", type=int, default=115200)
    relay.add_argument("--health-interval", type=float, default=5.0)
    relay.add_argument("--stale-seconds", type=float, default=5.0)
    relay.set_defaults(func=command_relay)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.stale_seconds <= 0:
        raise SystemExit("--stale-seconds must be greater than zero")
    if getattr(args, "health_interval", 1) <= 0:
        raise SystemExit("--health-interval must be greater than zero")
    try:
        return args.func(args)
    except (OSError, RuntimeError) as error:
        print(f"rtcm_pipeline: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
