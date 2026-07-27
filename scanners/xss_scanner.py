#!/usr/bin/env python3
"""
SecuriScan Cross-Site Scripting (XSS) Scanner
Detects reflected XSS in URL parameters, links, and form inputs.
"""

from __future__ import annotations

import copy
import sys
import uuid

from common import (
    Finding,
    ScanResult,
    create_session,
    discover_injection_points,
    fetch_url,
    inject_query_parameter,
    normalize_url,
    payload_reflected_unencoded,
    run_module_main,
)

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><svg/onload=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
]


def build_canary_payload() -> str:
    token = f"SECURISCAN{uuid.uuid4().hex[:8]}"
    return f"<svg id={token} onload=alert('{token}')>"


def test_query_point(session, point: dict, payload: str) -> tuple[bool, str, str]:
    test_url = inject_query_parameter(point["url"], point["parameter"], payload)
    response = fetch_url(session, test_url)
    if not response:
        return False, test_url, ""
    if payload_reflected_unencoded(response.text, payload):
        return True, test_url, payload
    return False, test_url, ""


def test_form_point(session, point: dict, payload: str) -> tuple[bool, str, str]:
    data = copy.deepcopy(point["parameters"])
    target_field = next(iter(data))
    data[target_field] = payload

    response = fetch_url(
        session,
        point["url"],
        method=point["method"],
        data=data if point["method"] == "POST" else None,
        params=data if point["method"] == "GET" else None,
    )
    if not response:
        return False, point["url"], ""

    if payload_reflected_unencoded(response.text, payload):
        location = f"{point['method']} {point['url']} (field: {target_field})"
        return True, location, payload
    return False, point["url"], ""


def run_scan(target: str, max_points: int = 25) -> ScanResult:
    url = normalize_url(target)
    session = create_session()
    result = ScanResult(target=url, scan_type="xss")

    baseline = fetch_url(session, url)
    if not baseline:
        result.status = "failed"
        result.metadata["error"] = "Target is unreachable"
        return result

    points = discover_injection_points(session, url)[:max_points]
    result.metadata["injection_points_tested"] = len(points)

    canary = build_canary_payload()
    all_payloads = [canary] + XSS_PAYLOADS

    for point in points:
        for payload in all_payloads:
            if point["type"] == "form":
                matched, location, evidence = test_form_point(session, point, payload)
                parameter = next(iter(point["parameters"]))
            else:
                matched, location, evidence = test_query_point(session, point, payload)
                parameter = point["parameter"]

            if matched:
                result.add(
                    Finding(
                        severity="high",
                        title="Reflected Cross-Site Scripting (XSS)",
                        description=(
                            f"User-supplied input in parameter '{parameter}' is reflected "
                            "in the response without proper encoding."
                        ),
                        evidence=f"Payload reflected: {evidence}",
                        location=location,
                        owasp="A03:2021-Injection",
                        cwe="CWE-79",
                        recommendation=(
                            "Contextually encode all output, deploy Content-Security-Policy, "
                            "and validate input on the server side."
                        ),
                    )
                )
                break

    if not result.findings:
        result.add(
            Finding(
                severity="info",
                title="No reflected XSS detected",
                description="Tested parameters did not reflect payloads without encoding.",
                recommendation="Review stored XSS and DOM-based XSS manually in client-side code.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python xss_scanner.py <target_url>\n"
        "Example: python xss_scanner.py https://demo.testfire.net",
    )


if __name__ == "__main__":
    main()
