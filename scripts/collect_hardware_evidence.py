#!/usr/bin/env python3
"""Build, flash, and collect a fresh bounded RTK3 evidence bundle."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

COLLECTOR_VERSION = 1
FIRMWARE_ENV = "esp32-s3-devkitc-1"


class EvidenceError(RuntimeError):
    """Raised when a deterministic evidence run cannot be completed."""


@dataclass(frozen=True)
class HttpResult:
    status: int
    payload: dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build and optionally flash the ESP32-S3, wait for the bounded main "
            "probe, force a fresh manual TLS evidence run, and save one bundle."
        )
    )
    parser.add_argument("--esp32-ip", required=True, help="ESP32 station IPv4 address")
    parser.add_argument(
        "--serial-port",
        help="USB serial port used for upload, required unless --skip-upload is set",
    )
    parser.add_argument(
        "--target-ip",
        help="Expected RTK3 IPv4 address, rejects evidence for a different target",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/rtk3-hardware-evidence.json"),
        help="Output JSON path",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="Maximum seconds for each bounded network phase",
    )
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-upload", action="store_true")
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if not args.skip_upload and not args.serial_port:
        parser.error("--serial-port is required unless --skip-upload is set")
    return args


def run_command(command: list[str], cwd: Path) -> None:
    print(f"[collector] running: {' '.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode != 0:
        raise EvidenceError(
            f"command failed with exit code {completed.returncode}: {' '.join(command)}"
        )


def read_git_commit(repo_root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def request_json(url: str, method: str = "GET", timeout: float = 5.0) -> HttpResult:
    request = Request(
        url,
        method=method,
        headers={"Accept": "application/json", "Cache-Control": "no-cache"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return HttpResult(response.status, json.loads(body))
    except HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"error": body or str(error)}
        return HttpResult(error.code, payload)
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise EvidenceError(f"request failed for {url}: {error}") from error


def wait_until(
    description: str,
    timeout: float,
    operation: Callable[[], Any],
    accepted: Callable[[Any], bool],
    interval: float = 0.5,
) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = operation()
            if accepted(value):
                return value
        except EvidenceError as error:
            last_error = error
        time.sleep(interval)

    detail = f": {last_error}" if last_error else ""
    raise EvidenceError(f"timed out waiting for {description}{detail}")


def wait_for_health(base_url: str, timeout: float) -> dict[str, Any]:
    result = wait_until(
        f"health endpoint {base_url}/healthz",
        timeout,
        lambda: request_json(f"{base_url}/healthz"),
        lambda item: item.status == 200 and bool(item.payload.get("ok")),
    )
    return result.payload


def wait_for_main_probe(main_base: str, timeout: float) -> dict[str, Any]:
    started_at = time.monotonic()
    manual_start_attempted = False

    def poll() -> HttpResult:
        nonlocal manual_start_attempted
        status = request_json(f"{main_base}/api/probe/status")
        payload = status.payload

        if payload.get("error"):
            raise EvidenceError(f"main probe failed: {payload['error']}")

        idle_for = time.monotonic() - started_at
        if (
            not payload.get("active")
            and not payload.get("completed")
            and idle_for >= 5.0
            and not manual_start_attempted
        ):
            manual_start_attempted = True
            start = request_json(f"{main_base}/api/probe/start", method="POST")
            if start.status not in (202, 409):
                raise EvidenceError(
                    f"unable to start main probe, HTTP {start.status}: {start.payload}"
                )
        return status

    wait_until(
        "main RTK3 probe completion",
        timeout,
        poll,
        lambda item: item.status == 200 and bool(item.payload.get("completed")),
    )
    results = request_json(f"{main_base}/api/probe/results")
    if results.status != 200:
        raise EvidenceError(
            f"unable to read main probe results, HTTP {results.status}: {results.payload}"
        )
    if not results.payload.get("completed"):
        raise EvidenceError("main probe results are not marked completed")
    return results.payload


def start_fresh_tls_probe(tls_base: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        start = request_json(f"{tls_base}/probe", method="POST")
        if start.status == 202:
            break
        if start.status != 409:
            raise EvidenceError(
                f"unable to start TLS probe, HTTP {start.status}: {start.payload}"
            )
        time.sleep(0.5)
    else:
        raise EvidenceError("timed out obtaining a fresh TLS probe slot")

    def poll() -> HttpResult:
        result = request_json(tls_base)
        if result.payload.get("state") == "error":
            raise EvidenceError(f"TLS evidence task failed: {result.payload}")
        return result

    completed = wait_until(
        "fresh manual TLS evidence completion",
        timeout,
        poll,
        lambda item: item.status == 200
        and item.payload.get("state") == "completed"
        and item.payload.get("trigger") == "manual-http",
    )
    return completed.payload


def validate_tls_result(
    result: dict[str, Any], expected_target_ip: str | None
) -> None:
    if result.get("state") != "completed":
        raise EvidenceError("TLS result is not completed")
    if result.get("trigger") != "manual-http":
        raise EvidenceError("TLS result was not produced by the accepted manual run")
    if int(result.get("schemaVersion", 0)) < 3:
        raise EvidenceError("TLS result schema is older than version 3")
    if expected_target_ip and result.get("targetIp") != expected_target_ip:
        raise EvidenceError(
            f"TLS result target {result.get('targetIp')} does not match "
            f"expected target {expected_target_ip}"
        )


def write_json_atomically(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    main_base = f"http://{args.esp32_ip}"
    tls_base = f"http://{args.esp32_ip}:81"

    try:
        if not args.skip_tests:
            run_command(["pio", "test", "-e", "native"], repo_root)
        if not args.skip_build:
            run_command(["pio", "run", "-e", FIRMWARE_ENV], repo_root)
        if not args.skip_upload:
            run_command(
                [
                    "pio",
                    "run",
                    "-e",
                    FIRMWARE_ENV,
                    "-t",
                    "upload",
                    "--upload-port",
                    args.serial_port,
                ],
                repo_root,
            )

        main_health = wait_for_health(main_base, args.timeout)
        tls_health = wait_for_health(tls_base, args.timeout)
        main_result = wait_for_main_probe(main_base, args.timeout)
        tls_result = start_fresh_tls_probe(tls_base, args.timeout)
        validate_tls_result(tls_result, args.target_ip)

        bundle = {
            "collectorVersion": COLLECTOR_VERSION,
            "capturedAt": datetime.now(timezone.utc).isoformat(),
            "repositoryCommit": read_git_commit(repo_root),
            "serialPort": args.serial_port,
            "esp32Ip": args.esp32_ip,
            "expectedTargetIp": args.target_ip,
            "mainHealth": main_health,
            "tlsHealth": tls_health,
            "mainProbe": main_result,
            "tlsEvidence": tls_result,
        }
        write_json_atomically(args.output, bundle)

        print(f"[collector] evidence saved to {args.output}")
        print(
            "[collector] target="
            f"{tls_result.get('targetIp')} "
            f"arp={tls_result.get('arp', {}).get('outcome', 'unavailable')} "
            f"tcpReachable={tls_result.get('tcpReachable')} "
            f"tlsAttempted={tls_result.get('tlsAttempted')}"
        )
        return 0
    except EvidenceError as error:
        print(f"[collector] ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
