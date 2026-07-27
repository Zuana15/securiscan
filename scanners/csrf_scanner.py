#!/usr/bin/env python3
"""
SecuriScan CSRF Scanner
Checks HTML forms for missing anti-CSRF tokens on state-changing requests.
"""

from __future__ import annotations

import re
import sys

from bs4 import BeautifulSoup

from common import Finding, ScanResult, create_session, fetch_url, normalize_url, run_module_main

CSRF_TOKEN_NAMES = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|__requestverificationtoken|csrfmiddlewaretoken)",
    re.IGNORECASE,
)

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def form_has_csrf_token(form) -> bool:
    for element in form.find_all(["input", "meta"]):
        name = element.get("name") or element.get("id") or ""
        if CSRF_TOKEN_NAMES.search(name):
            return True
        if element.get("type", "").lower() == "hidden" and element.get("value"):
            if CSRF_TOKEN_NAMES.search(name):
                return True
    return False


def run_scan(target: str) -> ScanResult:
    url = normalize_url(target)
    session = create_session()
    result = ScanResult(target=url, scan_type="csrf")

    response = fetch_url(session, url)
    if not response:
        result.status = "failed"
        result.metadata["error"] = "Target is unreachable"
        return result

    soup = BeautifulSoup(response.text or "", "html.parser")
    forms = soup.find_all("form")
    result.metadata["forms_found"] = len(forms)

    for index, form in enumerate(forms, start=1):
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or url
        if method not in STATE_CHANGING_METHODS:
            continue

        if not form_has_csrf_token(form):
            inputs = [
                element.get("name")
                for element in form.find_all(["input", "textarea", "select"])
                if element.get("name")
            ]
            result.add(
                Finding(
                    severity="medium",
                    title="Form missing CSRF token",
                    description=(
                        f"State-changing form #{index} ({method}) does not include "
                        "a recognizable CSRF token field."
                    ),
                    evidence=f"Fields: {', '.join(inputs[:8])}",
                    location=action,
                    owasp="A01:2021-Broken Access Control",
                    cwe="CWE-352",
                    recommendation=(
                        "Add unpredictable CSRF tokens to all state-changing forms and "
                        "validate them server-side."
                    ),
                )
            )

    if not any(f.title.startswith("Form missing") for f in result.findings):
        result.add(
            Finding(
                severity="info",
                title="No obvious CSRF issues in discovered forms",
                description="POST/PUT/PATCH/DELETE forms include token-like fields or none were found.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python csrf_scanner.py <target_url>\n"
        "Example: python csrf_scanner.py https://example.com",
    )


if __name__ == "__main__":
    main()
