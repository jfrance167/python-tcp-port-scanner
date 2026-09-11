#!/usr/bin/env python3
"""A small, educational TCP connect port scanner.

Only scan systems that you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime
from time import perf_counter
from typing import Iterable, Sequence


MIN_PORT = 1
MAX_PORT = 65_535
DEFAULT_TIMEOUT = 0.5
DEFAULT_WORKERS = 100
MAX_WORKERS = 500
DEFAULT_BANNER_TIMEOUT = 0.75
BANNER_READ_BYTES = 256


@dataclass(frozen=True)
class ScanResult:
    """The result of one TCP connection attempt."""

    port: int
    is_open: bool
    service: str = "unknown"
    banner: str | None = None


def valid_port(value: str) -> int:
    """Convert a command-line value to a valid TCP port number."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be a whole number") from exc

    if not MIN_PORT <= port <= MAX_PORT:
        raise argparse.ArgumentTypeError(
            f"port must be between {MIN_PORT} and {MAX_PORT}"
        )
    return port


def valid_timeout(value: str) -> float:
    """Convert a command-line value to a positive timeout."""
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc

    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def valid_workers(value: str) -> int:
    """Convert a command-line value to a safe worker count."""
    try:
        workers = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("workers must be a whole number") from exc

    if not 1 <= workers <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(
            f"workers must be between 1 and {MAX_WORKERS}"
        )
    return workers


def resolve_target(target: str) -> tuple[str, int]:
    """Resolve a host name or IP address and return its numeric address and family."""
    try:
        info = socket.getaddrinfo(
            target,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"could not resolve target {target!r}: {exc}") from exc

    # Prefer IPv4 when both families are available because it is the least
    # surprising choice for a beginner-oriented local network scanner.
    info.sort(key=lambda item: item[0] != socket.AF_INET)
    family, _, _, _, address = info[0]
    numeric_address = address[0]

    # getaddrinfo should already guarantee a parseable address, but resolvers
    # and non-standard hosts entries can still hand back something odd.
    try:
        ipaddress.ip_address(numeric_address)
    except ValueError as exc:
        raise ValueError(
            f"resolver returned an unparseable address for {target!r}: "
            f"{numeric_address!r}"
        ) from exc

    return numeric_address, family


def grab_banner(address: str, family: int, port: int, timeout: float) -> str | None:
    """Read up to one short banner without sending application data."""
    endpoint: tuple[str, int] | tuple[str, int, int, int]
    endpoint = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)

    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            if client.connect_ex(endpoint) != 0:
                return None
            data = client.recv(BANNER_READ_BYTES)
    except (OSError, socket.timeout):
        return None

    if not data:
        return None

    text = data.decode("utf-8", errors="replace").strip()
    return text or None


def scan_port(
    address: str,
    family: int,
    port: int,
    timeout: float,
    grab_banners: bool = False,
    banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> ScanResult:
    """Attempt one TCP connection without sending application data."""
    endpoint: tuple[str, int] | tuple[str, int, int, int]
    endpoint = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)

    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            is_open = client.connect_ex(endpoint) == 0
    except OSError:
        is_open = False

    if not is_open:
        return ScanResult(port=port, is_open=False)

    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = "unknown"

    banner = grab_banner(address, family, port, banner_timeout) if grab_banners else None
    return ScanResult(port=port, is_open=True, service=service, banner=banner)


def scan_ports(
    address: str,
    family: int,
    ports: Iterable[int],
    timeout: float,
    workers: int,
    grab_banners: bool = False,
    banner_timeout: float = DEFAULT_BANNER_TIMEOUT,
    quiet: bool = False,
) -> list[ScanResult]:
    """Scan ports concurrently, optionally printing results as they arrive."""
    open_results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                scan_port,
                address,
                family,
                port,
                timeout,
                grab_banners,
                banner_timeout,
            ): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            if result.is_open:
                open_results.append(result)
                if not quiet:
                    line = f"[OPEN] {result.port}/tcp ({result.service})"
                    if result.banner:
                        line += f" -- {result.banner[:80]!r}"
                    print(line, flush=True)

    return sorted(open_results, key=lambda result: result.port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a permitted host for open TCP ports.",
        epilog="Only scan systems you own or have explicit permission to test.",
    )
    parser.add_argument("target", help="host name or IP address to scan")
    parser.add_argument(
        "--start-port",
        type=valid_port,
        default=1,
        help="first port in the range (default: 1)",
    )
    parser.add_argument(
        "--end-port",
        type=valid_port,
        default=1024,
        help="last port in the range (default: 1024)",
    )
    parser.add_argument(
        "--timeout",
        type=valid_timeout,
        default=DEFAULT_TIMEOUT,
        help=f"seconds to wait per connection (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--workers",
        type=valid_workers,
        default=DEFAULT_WORKERS,
        help=f"concurrent connection attempts (default: {DEFAULT_WORKERS})",
    )
    parser.add_argument(
        "--banners",
        action="store_true",
        help="attempt to read a service banner from each open port",
    )
    parser.add_argument(
        "--banner-timeout",
        type=valid_timeout,
        default=DEFAULT_BANNER_TIMEOUT,
        help=f"seconds to wait for a banner (default: {DEFAULT_BANNER_TIMEOUT})",
    )
    parser.add_argument(
        "--randomize",
        action="store_true",
        help="scan ports in random order instead of sequentially",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="print a JSON summary to stdout instead of a text report",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.start_port > args.end_port:
        parser.error("--start-port cannot be greater than --end-port")

    try:
        address, family = resolve_target(args.target)
    except ValueError as exc:
        if args.json_output:
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    ports = list(range(args.start_port, args.end_port + 1))
    if args.randomize:
        random.shuffle(ports)

    started_at = datetime.now().astimezone()
    timer_started = perf_counter()

    if not args.json_output:
        print("TCP Port Scanner")
        print(f"Target:  {args.target} ({address})")
        print(f"Ports:   {args.start_port}-{args.end_port}")
        print(f"Order:   {'randomized' if args.randomize else 'sequential'}")
        print(f"Started: {started_at.isoformat(timespec='seconds')}")
        print("-" * 50)

    try:
        open_results = scan_ports(
            address=address,
            family=family,
            ports=ports,
            timeout=args.timeout,
            workers=args.workers,
            grab_banners=args.banners,
            banner_timeout=args.banner_timeout,
            quiet=args.json_output,
        )
    except KeyboardInterrupt:
        if args.json_output:
            print(json.dumps({"error": "scan cancelled by user"}))
        else:
            print("\nScan cancelled by user.", file=sys.stderr)
        return 130

    finished_at = datetime.now().astimezone()
    elapsed = perf_counter() - timer_started

    if args.json_output:
        summary = {
            "target": args.target,
            "address": address,
            "port_range": [args.start_port, args.end_port],
            "randomized": args.randomize,
            "started_at": started_at.isoformat(timespec="seconds"),
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "duration_seconds": round(elapsed, 2),
            "ports_tested": len(ports),
            "open_ports": [asdict(result) for result in open_results],
        }
        print(json.dumps(summary, indent=2))
        return 0

    print("-" * 50)
    print("Scan summary")
    print(f"Finished:      {finished_at.isoformat(timespec='seconds')}")
    print(f"Duration:      {elapsed:.2f} seconds")
    print(f"Ports tested:  {len(ports)}")
    print(f"Open ports:    {len(open_results)}")
    print(
        "Open port list: "
        + (
            ", ".join(str(result.port) for result in open_results)
            if open_results
            else "none"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
