#!/usr/bin/env python3
"""
SecuriScan Port Scanner Module
Scans target for open TCP ports and identifies running services.
"""

from __future__ import annotations

import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from common import Finding, ScanResult, host_from_url, normalize_url, print_json_result

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
]


class PortScanner:
    def __init__(self, target: str, timeout: float = 1.0):
        self.target = target
        self.timeout = timeout
        self.open_ports: list[int] = []
        self.services: dict[int, str] = {}

    def scan_port(self, port: int) -> tuple[int, bool, str | None]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = self._grab_banner(sock, port)
                sock.close()
                return port, True, service

            sock.close()
            return port, False, None
        except OSError:
            return port, False, None

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            if port in {80, 8080, 8000, 8888}:
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            elif port in {21, 25, 110, 143}:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner if banner else "Open (no banner)"
        except OSError:
            return "Open (no banner)"

    def scan_range(self, start_port: int = 1, end_port: int = 1024, max_threads: int = 100) -> ScanResult:
        print(f"[+] Starting scan on {self.target}")
        print(f"[+] Scanning ports {start_port}-{end_port}...")

        self.open_ports = []
        self.services = {}
        ports_scanned = end_port - start_port + 1

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, port): port
                for port in range(start_port, end_port + 1)
            }

            for future in as_completed(futures):
                port, is_open, service = future.result()
                if is_open and service:
                    self.open_ports.append(port)
                    self.services[port] = service
                    print(f"[!] Port {port} OPEN - {service[:80]}")

        return self.build_result(ports_scanned)

    def scan_common_ports(self, ports: list[int] | None = None, max_threads: int = 50) -> ScanResult:
        port_list = ports or COMMON_PORTS
        print(f"[+] Starting common port scan on {self.target}")
        print(f"[+] Testing {len(port_list)} ports...")

        self.open_ports = []
        self.services = {}

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in port_list}
            for future in as_completed(futures):
                port, is_open, service = future.result()
                if is_open and service:
                    self.open_ports.append(port)
                    self.services[port] = service
                    print(f"[!] Port {port} OPEN - {service[:80]}")

        return self.build_result(len(port_list))

    def build_result(self, ports_scanned: int) -> ScanResult:
        result = ScanResult(
            target=self.target,
            scan_type="port_scan",
            metadata={
                "total_ports_scanned": ports_scanned,
                "open_ports_count": len(self.open_ports),
                "open_ports": sorted(self.open_ports),
                "services": {str(port): banner for port, banner in self.services.items()},
            },
        )

        risky_ports = {
            21: ("FTP service exposed", "medium"),
            23: ("Telnet service exposed", "high"),
            445: ("SMB service exposed", "high"),
            3389: ("RDP service exposed", "high"),
            3306: ("MySQL service exposed", "medium"),
            5432: ("PostgreSQL service exposed", "medium"),
            6379: ("Redis service exposed", "high"),
            27017: ("MongoDB service exposed", "high"),
        }

        for port in sorted(self.open_ports):
            title, severity = risky_ports.get(port, (f"Open port {port}", "info"))
            result.add(
                Finding(
                    severity=severity,
                    title=title,
                    description=f"TCP port {port} is accepting connections.",
                    evidence=self.services.get(port, "Open (no banner)"),
                    location=f"{self.target}:{port}",
                    recommendation="Close unused ports and restrict access with firewalls.",
                )
            )

        if not self.open_ports:
            result.add(
                Finding(
                    severity="info",
                    title="No open ports found",
                    description="No responding TCP ports were detected in the scanned range.",
                )
            )

        return result


def run_scan(target: str, start_port: int = 1, end_port: int = 1024, common_only: bool = False) -> ScanResult:
    url = normalize_url(target)
    host, _ = host_from_url(url)
    scanner = PortScanner(host, timeout=2)

    if common_only:
        return scanner.scan_common_ports()
    return scanner.scan_range(start_port, end_port, max_threads=100)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python port_scanner.py <target> [start_port] [end_port] [--common]")
        print("Example: python port_scanner.py example.com 1 100")
        print("Example: python port_scanner.py https://example.com --common")
        sys.exit(1)

    target = sys.argv[1]
    common_only = "--common" in sys.argv

    if common_only:
        results = run_scan(target, common_only=True)
    else:
        numeric_args = [arg for arg in sys.argv[2:] if arg.isdigit()]
        start_port = int(numeric_args[0]) if len(numeric_args) > 0 else 1
        end_port = int(numeric_args[1]) if len(numeric_args) > 1 else 100
        results = run_scan(target, start_port=start_port, end_port=end_port)

    print_json_result(results)


if __name__ == "__main__":
    main()
