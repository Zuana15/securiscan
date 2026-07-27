#!/usr/bin/env python3
"""
SecuriScan SQL Injection Scanner
Detects error-based SQL injection in URL parameters and HTML forms.
"""

from __future__ import annotations

import copy
import sys

from common import (
    Finding,
    ScanResult,
    create_session,
    discover_injection_points,
    fetch_url,
    inject_query_parameter,
    normalize_url,
    response_contains_sql_errors,
    run_module_main,
)

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' AND '1'='1",
    "admin'--",
    "' UNION SELECT NULL--",
    "1' ORDER BY 10--",
    "') OR ('1'='1",
]


def test_query_point(session, point: dict, payload: str) -> tuple[bool, str, str]:
    test_url = inject_query_parameter(point["url"], point["parameter"], payload)
    response = fetch_url(session, test_url)
    if not response:
        return False, test_url, ""
    matched, label = response_contains_sql_errors(response.text)
    return matched, test_url, label


def test_form_point(session, point: dict, payload: str) -> tuple[bool, str, str]:
    data = copy.deepcopy(point["parameters"])
    for field_name in data:
        data[field_name] = payload
        break

    response = fetch_url(
        session,
        point["url"],
        method=point["method"],
        data=data if point["method"] == "POST" else None,
        params=data if point["method"] == "GET" else None,
    )
    if not response:
        return False, point["url"], ""

    matched, label = response_contains_sql_errors(response.text)
    location = f"{point['method']} {point['url']}"
    return matched, location, label


def run_scan(target: str, max_points: int = 25) -> ScanResult:
    url = normalize_url(target)
    session = create_session()
    result = ScanResult(target=url, scan_type="sql_injection")

    baseline = fetch_url(session, url)
    if not baseline:
        result.status = "failed"
        result.metadata["error"] = "Target is unreachable"
        return result

    points = discover_injection_points(session, url)[:max_points]
    result.metadata["injection_points_tested"] = len(points)

    for point in points:
        for payload in SQLI_PAYLOADS:
            if point["type"] == "form":
                matched, location, label = test_form_point(session, point, payload)
                parameter = next(iter(point["parameters"]))
            else:
                matched, location, label = test_query_point(session, point, payload)
                parameter = point["parameter"]

            if matched:
                result.add(
                    Finding(
                        severity="high",
                        title="Potential SQL Injection vulnerability",
                        description=(
                            f"Database error indicators were returned when injecting payload "
                            f"into parameter '{parameter}'."
                        ),
                        evidence=f"Payload: {payload} | Indicator: {label}",
                        location=location,
                        owasp="A03:2021-Injection",
                        cwe="CWE-89",
                        recommendation=(
                            "Use parameterized queries / prepared statements, validate input, "
                            "and disable verbose database error messages in production."
                        ),
                    )
                )
                break

    if not result.findings:
        result.add(
            Finding(
                severity="info",
                title="No SQL injection indicators detected",
                description=(
                    "No database error signatures were observed for tested parameters and forms."
                ),
                recommendation="Continue testing with authenticated flows and blind SQLi techniques.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python sql_injection.py <target_url>\n"
        "Example: python sql_injection.py https://demo.testfire.net",
    )


if __name__ == "__main__":
    main()
