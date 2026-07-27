#!/usr/bin/env python3
"""
SecuriScan Scanner Orchestrator
Runs all vulnerability scanning modules against a target and aggregates results.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from common import ScanResult, normalize_url, print_json_result

SCANNERS = {
    "port": ("port_scanner", "run_scan"),
    "sql": ("sql_injection", "run_scan"),
    "xss": ("xss_scanner", "run_scan"),
    "ssl": ("ssl_checker", "run_scan"),
    "headers": ("headers_scanner", "run_scan"),
    "tech": ("tech_fingerprint", "run_scan"),
    "files": ("sensitive_files", "run_scan"),
    "csrf": ("csrf_scanner", "run_scan"),
    "misconfig": ("http_misconfig", "run_scan"),
}

ALL_SCANNERS = list(SCANNERS.keys())


def load_runner(module_name: str, function_name: str):
    module = __import__(module_name, fromlist=[function_name])
    return getattr(module, function_name)


def aggregate_results(target: str, results: list[ScanResult]) -> dict:
    combined_findings = []
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total_findings": 0}
    scans = {}

    for result in results:
        scan_dict = result.to_dict()
        scans[result.scan_type] = scan_dict
        for finding in scan_dict["findings"]:
            combined_findings.append({"scan_type": result.scan_type, **finding})
            severity = finding.get("severity", "info").lower()
            if severity in summary:
                summary[severity] += 1
        summary["total_findings"] += scan_dict["summary"]["total_findings"]

    return {
        "target": target,
        "scan_type": "full_assessment",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "summary": summary,
        "findings": combined_findings,
        "scans": scans,
    }


def run_selected_scans(target: str, selected: list[str], port_common_only: bool = True) -> dict:
    url = normalize_url(target)
    results: list[ScanResult] = []

    for name in selected:
        module_name, function_name = SCANNERS[name]
        runner = load_runner(module_name, function_name)
        print(f"\n{'=' * 60}\n[+] Running {name} scanner...\n{'=' * 60}")

        if name == "port":
            result = runner(url, common_only=port_common_only)
        else:
            result = runner(url)

        results.append(result)
        print(f"[+] {name} complete — {result.summary()['total_findings']} finding(s)")

    return aggregate_results(url, results)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SecuriScan vulnerability scanners")
    parser.add_argument("target", help="Target URL or hostname (e.g. https://example.com)")
    parser.add_argument(
        "--scanners",
        nargs="+",
        choices=ALL_SCANNERS,
        default=ALL_SCANNERS,
        help="Scanners to run (default: all)",
    )
    parser.add_argument(
        "--port-range",
        action="store_true",
        help="Use full port range scan instead of common ports only",
    )
    parser.add_argument("--output", help="Optional path to write JSON results")

    args = parser.parse_args()

    report = run_selected_scans(
        args.target,
        args.scanners,
        port_common_only=not args.port_range,
    )

    print_json_result(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
