#!/usr/bin/env python3
"""
SecuriScan Security Headers Scanner
Audits HTTP security headers against OWASP Secure Headers guidance.
"""

from __future__ import annotations

import sys

from common import Finding, ScanResult, create_session, fetch_url, normalize_url, run_module_main

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HTTP Strict Transport Security (HSTS) is not set.",
        "recommendation": "Add Strict-Transport-Security with max-age >= 31536000; includeSubDomains.",
        "owasp": "A02:2021-Cryptographic Failures",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Content Security Policy (CSP) header is missing.",
        "recommendation": "Define a restrictive CSP to mitigate XSS and data injection attacks.",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header is missing.",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking.",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options header is missing.",
        "recommendation": "Set X-Content-Type-Options: nosniff.",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header is missing.",
        "recommendation": "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
        "owasp": "A05:2021-Security Misconfiguration",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header is missing.",
        "recommendation": "Restrict browser features with Permissions-Policy.",
        "owasp": "A05:2021-Security Misconfiguration",
    },
}

INFORMATIONAL_HEADERS = [
    "X-XSS-Protection",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]


def run_scan(target: str) -> ScanResult:
    url = normalize_url(target)
    session = create_session()
    result = ScanResult(target=url, scan_type="security_headers")

    response = fetch_url(session, url)
    if not response:
        result.status = "failed"
        result.metadata["error"] = "Target is unreachable"
        return result

    headers = {key.lower(): value for key, value in response.headers.items()}
    result.metadata["response_headers"] = dict(response.headers)

    for header, config in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            result.add(
                Finding(
                    severity=config["severity"],
                    title=f"Missing security header: {header}",
                    description=config["description"],
                    location=url,
                    owasp=config["owasp"],
                    recommendation=config["recommendation"],
                )
            )

    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts.replace(" ", ""):
        result.add(
            Finding(
                severity="medium",
                title="HSTS explicitly disabled",
                description="Strict-Transport-Security is present but max-age=0 disables HSTS.",
                evidence=hsts,
                recommendation="Use a positive max-age or remove the header if HSTS is not desired.",
            )
        )

    csp = headers.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp:
        result.add(
            Finding(
                severity="low",
                title="Permissive CSP allows unsafe-inline",
                description="Content-Security-Policy includes unsafe-inline.",
                evidence=csp[:200],
                recommendation="Remove unsafe-inline and use nonces or hashes where possible.",
            )
        )

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server or powered_by:
        result.add(
            Finding(
                severity="info",
                title="Technology disclosure in headers",
                description="Server response reveals software/version information.",
                evidence=", ".join(filter(None, [f"Server: {server}" if server else "", f"X-Powered-By: {powered_by}" if powered_by else ""])),
                recommendation="Remove or genericize Server and X-Powered-By headers.",
            )
        )

    present = [header for header in INFORMATIONAL_HEADERS if header.lower() in headers]
    if present:
        result.metadata["additional_headers_present"] = present

    if not any(f.severity in {"critical", "high", "medium", "low"} for f in result.findings):
        result.add(
            Finding(
                severity="info",
                title="Security headers look good",
                description="All recommended security headers appear to be configured.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python headers_scanner.py <target_url>\n"
        "Example: python headers_scanner.py https://example.com",
    )


if __name__ == "__main__":
    main()
