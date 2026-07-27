#!/usr/bin/env python3
"""
SecuriScan Sensitive Files Scanner
Probes for exposed configuration files, backups, and admin interfaces.
"""

from __future__ import annotations

import sys

from common import Finding, ScanResult, create_session, fetch_url, normalize_url, run_module_main

SENSITIVE_PATHS = [
    ("/.env", "Environment configuration file", "critical"),
    ("/.git/config", "Git repository metadata", "critical"),
    ("/.git/HEAD", "Git repository HEAD reference", "high"),
    ("/backup.zip", "Backup archive", "high"),
    ("/backup.sql", "Database backup", "critical"),
    ("/db.sql", "Database dump", "critical"),
    ("/config.php", "PHP configuration file", "high"),
    ("/wp-config.php.bak", "WordPress config backup", "critical"),
    ("/phpinfo.php", "PHP information disclosure", "high"),
    ("/server-status", "Apache server status page", "medium"),
    ("/.DS_Store", "macOS directory metadata", "low"),
    ("/admin/", "Admin interface", "medium"),
    ("/administrator/", "Admin interface", "medium"),
    ("/debug/", "Debug endpoint", "medium"),
    ("/api/swagger", "API documentation", "info"),
    ("/swagger-ui.html", "Swagger UI", "info"),
    ("/.aws/credentials", "AWS credentials file", "critical"),
    ("/web.config", "IIS web configuration", "high"),
    ("/crossdomain.xml", "Flash cross-domain policy", "low"),
]

CONTENT_INDICATORS = {
    "/.env": ["APP_KEY=", "DB_PASSWORD=", "SECRET"],
    "/.git/config": ["[core]", "repositoryformatversion"],
    "/backup.sql": ["INSERT INTO", "CREATE TABLE"],
    "/phpinfo.php": ["phpinfo()", "PHP Version"],
}


def path_is_exposed(path: str, response_text: str, status_code: int) -> bool:
    if status_code >= 400:
        return False

    indicators = CONTENT_INDICATORS.get(path, [])
    if indicators:
        return any(indicator.lower() in response_text.lower() for indicator in indicators)

    if status_code == 200 and len(response_text.strip()) > 0:
        return True

    return status_code in {401, 403}


def run_scan(target: str) -> ScanResult:
    url = normalize_url(target)
    base = url.rstrip("/")
    session = create_session()
    result = ScanResult(target=url, scan_type="sensitive_files")

    baseline = fetch_url(session, url)
    if not baseline:
        result.status = "failed"
        result.metadata["error"] = "Target is unreachable"
        return result

    tested = 0
    for path, description, severity in SENSITIVE_PATHS:
        probe_url = base + path
        response = fetch_url(session, probe_url)
        tested += 1
        if not response:
            continue

        body = response.text or ""
        if path_is_exposed(path, body, response.status_code):
            result.add(
                Finding(
                    severity=severity,
                    title=f"Potentially exposed resource: {path}",
                    description=description,
                    evidence=f"HTTP {response.status_code} at {probe_url}",
                    location=probe_url,
                    owasp="A01:2021-Broken Access Control",
                    cwe="CWE-538",
                    recommendation=(
                        "Block public access to sensitive paths, remove backups from web roots, "
                        "and verify authorization controls."
                    ),
                )
            )

    result.metadata["paths_tested"] = tested

    if not any(f.severity in {"critical", "high", "medium"} for f in result.findings):
        result.add(
            Finding(
                severity="info",
                title="No sensitive files discovered",
                description="Common sensitive paths were not publicly accessible.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python sensitive_files.py <target_url>\n"
        "Example: python sensitive_files.py https://example.com",
    )


if __name__ == "__main__":
    main()
