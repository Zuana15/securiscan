#!/usr/bin/env python3
"""
SecuriScan HTTP Misconfiguration Scanner
Checks dangerous HTTP methods, open redirects, and cookie security flags.
"""

from __future__ import annotations

import sys
from urllib.parse import urljoin

from common import Finding, ScanResult, create_session, fetch_url, normalize_url, run_module_main

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


def run_scan(target: str) -> ScanResult:
    url = normalize_url(target)
    session = create_session()
    result = ScanResult(target=url, scan_type="http_misconfiguration")

    response = fetch_url(session, url)
    if not response:
        result.status = "failed"
        result.metadata["error"] = "Target is unreachable"
        return result

    allowed_methods: list[str] = []
    for method in ["GET", "POST", "OPTIONS"] + DANGEROUS_METHODS:
        probe = fetch_url(session, url, method=method, allow_redirects=False)
        if probe and probe.status_code not in {405, 501}:
            allowed_methods.append(method)

    result.metadata["allowed_methods"] = allowed_methods

    for method in DANGEROUS_METHODS:
        if method in allowed_methods:
            severity = "high" if method == "TRACE" else "medium"
            result.add(
                Finding(
                    severity=severity,
                    title=f"Dangerous HTTP method allowed: {method}",
                    description=f"The server responded to an HTTP {method} request.",
                    location=url,
                    owasp="A05:2021-Security Misconfiguration",
                    cwe="CWE-650",
                    recommendation=f"Disable HTTP {method} at the web server or application layer.",
                )
            )

    options = fetch_url(session, url, method="OPTIONS", allow_redirects=False)
    if options and "allow" in options.headers:
        result.metadata["allow_header"] = options.headers.get("Allow", "")

    redirect_probe = fetch_url(
        session,
        urljoin(url, "/?url=https://evil.example"),
        allow_redirects=False,
    )
    if redirect_probe and redirect_probe.status_code in {301, 302, 303, 307, 308}:
        location = redirect_probe.headers.get("Location", "")
        if "evil.example" in location:
            result.add(
                Finding(
                    severity="medium",
                    title="Potential open redirect",
                    description="Untrusted URL parameter may control redirect destination.",
                    evidence=f"Location: {location}",
                    owasp="A01:2021-Broken Access Control",
                    cwe="CWE-601",
                    recommendation="Allowlist redirect destinations; never redirect to user-supplied URLs.",
                )
            )

    set_cookie_headers = response.headers.get("Set-Cookie", "")
    if set_cookie_headers:
        cookie_issues = []
        lower = set_cookie_headers.lower()
        if "secure" not in lower and url.startswith("https://"):
            cookie_issues.append("Missing Secure flag")
        if "httponly" not in lower:
            cookie_issues.append("Missing HttpOnly flag")
        if "samesite" not in lower:
            cookie_issues.append("Missing SameSite attribute")

        if cookie_issues:
            result.add(
                Finding(
                    severity="medium",
                    title="Insecure cookie configuration",
                    description="Session or application cookies may lack recommended security attributes.",
                    evidence="; ".join(cookie_issues),
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-614",
                    recommendation="Set Secure, HttpOnly, and SameSite=Lax/Strict on sensitive cookies.",
                )
            )

    cors_header = response.headers.get("Access-Control-Allow-Origin", "")
    if cors_header == "*":
        result.add(
            Finding(
                severity="low",
                title="Permissive CORS policy",
                description="Access-Control-Allow-Origin is set to wildcard (*).",
                evidence=cors_header,
                recommendation="Restrict CORS origins to trusted domains only.",
            )
        )

    if not any(f.severity in {"critical", "high", "medium", "low"} for f in result.findings):
        result.add(
            Finding(
                severity="info",
                title="No major HTTP misconfigurations detected",
                description="Dangerous methods, cookies, and redirect checks did not flag issues.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python http_misconfig.py <target_url>\n"
        "Example: python http_misconfig.py https://example.com",
    )


if __name__ == "__main__":
    main()
