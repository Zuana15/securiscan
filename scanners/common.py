"""
Shared utilities and result schema for SecuriScan vulnerability modules.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = (
    "SecuriScan/1.0 (+https://github.com/securiscan; authorized-security-assessment)"
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    evidence: str = ""
    location: str = ""
    owasp: str = ""
    cwe: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, str]:
        data = asdict(self)
        return {key: value for key, value in data.items() if value}


@dataclass
class ScanResult:
    target: str
    scan_type: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "completed"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary(self) -> dict[str, int]:
        counts = {level: 0 for level in SEVERITY_ORDER}
        for finding in self.findings:
            level = finding.severity.lower()
            if level in counts:
                counts[level] += 1
        counts["total_findings"] = len(self.findings)
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "status": self.status,
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))


def host_from_url(url: str) -> tuple[str, int]:
    parsed = urlparse(normalize_url(url))
    host = parsed.hostname or ""
    if parsed.scheme == "https":
        port = parsed.port or 443
    else:
        port = parsed.port or 80
    return host, port


def create_session(timeout: int = DEFAULT_TIMEOUT) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    session.timeout = timeout
    return session


def fetch_url(
    session: requests.Session,
    url: str,
    method: str = "GET",
    params: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    allow_redirects: bool = True,
) -> requests.Response | None:
    try:
        response = session.request(
            method=method.upper(),
            url=url,
            params=params,
            data=data,
            allow_redirects=(
                allow_redirects
                and os.environ.get("SECURISCAN_REQUIRE_PUBLIC_TARGETS") != "1"
            ),
            timeout=session.timeout,
            verify=True,
        )
        return response
    except requests.RequestException:
        return None


def discover_injection_points(session: requests.Session, url: str) -> list[dict[str, Any]]:
    """Collect URL query parameters and HTML form inputs from a page."""
    points: list[dict[str, Any]] = []
    parsed = urlparse(url)

    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        points.append(
            {
                "type": "query",
                "url": url,
                "parameter": name,
                "baseline_value": value,
            }
        )

    response = fetch_url(session, url)
    if not response or not response.text:
        return points

    soup = BeautifulSoup(response.text, "html.parser")
    for form in soup.find_all("form"):
        action = form.get("action") or url
        form_url = urljoin(url, action)
        method = (form.get("method") or "GET").upper()
        inputs: dict[str, str] = {}

        for element in form.find_all(["input", "textarea", "select"]):
            name = element.get("name")
            if not name:
                continue
            input_type = (element.get("type") or "text").lower()
            if input_type in {"submit", "button", "image", "reset", "file"}:
                continue
            inputs[name] = element.get("value") or ""

        if inputs:
            points.append(
                {
                    "type": "form",
                    "url": form_url,
                    "method": method,
                    "parameters": inputs,
                }
            )

    for link in soup.find_all("a", href=True):
        href = urljoin(url, link["href"])
        link_parsed = urlparse(href)
        if link_parsed.netloc and link_parsed.netloc != parsed.netloc:
            continue
        for name, value in parse_qsl(link_parsed.query, keep_blank_values=True):
            points.append(
                {
                    "type": "link",
                    "url": href,
                    "parameter": name,
                    "baseline_value": value,
                }
            )

    return dedupe_points(points)


def dedupe_points(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for point in points:
        if point["type"] == "form":
            key = f"form:{point['url']}:{point['method']}:{','.join(sorted(point['parameters']))}"
        else:
            key = f"{point['type']}:{point['url']}:{point['parameter']}"
        if key not in seen:
            seen.add(key)
            unique.append(point)
    return unique


def inject_query_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[parameter] = value
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def response_contains_sql_errors(text: str) -> tuple[bool, str]:
    patterns = [
        (r"SQL syntax.*MySQL", "MySQL syntax error"),
        (r"you have an error in your SQL syntax", "MySQL syntax error"),
        (r"Warning.*mysql_", "MySQL warning"),
        (r"PostgreSQL.*ERROR", "PostgreSQL error"),
        (r"ORA-\d{5}", "Oracle DB error"),
        (r"Microsoft SQL Native Client error", "Microsoft SQL Server error"),
        (r"SQLite/JDBCDriver", "SQLite error"),
        (r"Unclosed quotation mark", "Unclosed quotation mark"),
        (r"quoted string not properly terminated", "Quoted string termination error"),
        (r"syntax error at or near", "SQL syntax error"),
        (r"SQLSTATE\[", "SQLSTATE error"),
        (r"ODBC SQL Server Driver", "ODBC SQL Server error"),
        (r"pg_query\(\)", "PostgreSQL query error"),
    ]
    for pattern, label in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return True, label
    return False, ""


def payload_reflected_unencoded(response_text: str, payload: str) -> bool:
    if payload not in response_text:
        return False
    encoded_variants = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace('"', "&quot;"),
        payload.replace("'", "&#x27;"),
        payload.replace("'", "&#39;"),
    ]
    return not any(variant in response_text for variant in encoded_variants if variant)


def print_json_result(result: ScanResult | dict[str, Any]) -> None:
    payload = result.to_dict() if isinstance(result, ScanResult) else result
    print("\n--- RESULTS (JSON) ---")
    print(json.dumps(payload, indent=2))


def run_module_main(run_scan, usage: str) -> None:
    if len(sys.argv) < 2:
        print(usage)
        sys.exit(1)
    target = sys.argv[1]
    result = run_scan(target)
    print_json_result(result)
