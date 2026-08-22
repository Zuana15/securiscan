#!/usr/bin/env python3
"""
SecuriScan Technology Fingerprint Scanner
Identifies web technologies from headers, HTML, cookies, and common paths.
"""

from __future__ import annotations

import re
import sys

from bs4 import BeautifulSoup

from common import Finding, ScanResult, create_session, fetch_url, normalize_url, run_module_main

TECH_SIGNATURES = {
    "WordPress": [
        r"/wp-content/",
        r"/wp-includes/",
        r"<meta name=\"generator\" content=\"WordPress",
    ],
    "Drupal": [r"/sites/default/files/", r"Drupal.settings", r"<meta name=\"Generator\" content=\"Drupal"],
    "Joomla": [r"/components/com_", r"<meta name=\"generator\" content=\"Joomla"],
    "React": [r"react\.production\.min\.js", r"__NEXT_DATA__", r"id=\"__next\""],
    "Next.js": [r"__NEXT_DATA__", r"/_next/static/"],
    "Angular": [r"ng-version=", r"angular\.min\.js"],
    "Vue.js": [r"vue\.min\.js", r"data-v-"],
    "jQuery": [r"jquery[\.\-][0-9\.]+\.min\.js", r"jquery\.js"],
    "Bootstrap": [r"bootstrap[\.\-][0-9\.]+\.min\.css", r"bootstrap\.min\.js"],
    "PHP": [r"\.php", r"X-Powered-By: PHP"],
    "ASP.NET": [r"__VIEWSTATE", r"aspnet", r"X-AspNet-Version"],
    "Apache": [r"Apache/", r"Server: Apache"],
    "nginx": [r"nginx/", r"Server: nginx"],
    "IIS": [r"Server: Microsoft-IIS", r"X-Powered-By: ASP\.NET"],
    "Cloudflare": [r"cf-ray", r"cloudflare"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Laravel": [r"laravel_session", r"<meta name=\"csrf-token\"", r"/vendor/laravel/"],
}

COMMON_PATHS = {
    "/robots.txt": "Robots exclusion file",
    "/sitemap.xml": "Sitemap",
    "/.well-known/security.txt": "Security contact file",
    "/favicon.ico": "Favicon",
}


def detect_from_text(text: str, headers: dict[str, str]) -> dict[str, list[str]]:
    combined = text + "\n" + "\n".join(f"{key}: {value}" for key, value in headers.items())
    detected: dict[str, list[str]] = {}

    for technology, patterns in TECH_SIGNATURES.items():
        matches = []
        for pattern in patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                matches.append(pattern)
        if matches:
            detected[technology] = matches

    return detected


def run_scan(target: str) -> ScanResult:
    url = normalize_url(target)
    session = create_session()
    result = ScanResult(target=url, scan_type="tech_fingerprint")

    response = fetch_url(session, url)
    if not response:
        result.status = "failed"
        result.metadata["error"] = "Target is unreachable"
        return result

    headers = dict(response.headers)
    html = response.text or ""
    soup = BeautifulSoup(html, "html.parser")

    detected = detect_from_text(html, headers)
    result.metadata["technologies"] = detected
    result.metadata["server"] = headers.get("Server", "")
    result.metadata["x_powered_by"] = headers.get("X-Powered-By", "")

    meta_generator = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
    if meta_generator and meta_generator.get("content"):
        result.metadata["meta_generator"] = meta_generator["content"]
        result.add(
            Finding(
                severity="info",
                title="Meta generator disclosed",
                description="HTML meta generator tag reveals application information.",
                evidence=meta_generator["content"],
                recommendation="Remove generator meta tags from production builds.",
            )
        )

    for technology in detected:
        result.add(
            Finding(
                severity="info",
                title=f"Technology detected: {technology}",
                description=f"Fingerprint matched signatures for {technology}.",
                evidence=", ".join(detected[technology][:2]),
            )
        )

    cookies = response.cookies.get_dict()
    if cookies:
        result.metadata["cookies"] = list(cookies.keys())
        cookie_hints = {
            "PHPSESSID": "PHP",
            "JSESSIONID": "Java",
            "ASP.NET_SessionId": "ASP.NET",
            "laravel_session": "Laravel",
            "connect.sid": "Express.js/Node.js",
        }
        for cookie_name, stack in cookie_hints.items():
            if cookie_name.lower() in {name.lower() for name in cookies}:
                result.add(
                    Finding(
                        severity="info",
                        title=f"Session cookie suggests {stack}",
                        description=f"Cookie '{cookie_name}' indicates {stack} stack.",
                        evidence=cookie_name,
                    )
                )

    for path, description in COMMON_PATHS.items():
        probe_url = url.rstrip("/") + path
        probe = fetch_url(session, probe_url)
        if probe and probe.status_code < 400:
            result.metadata.setdefault("discovered_paths", []).append(
                {"path": path, "status": probe.status_code, "description": description}
            )

    scripts = [script.get("src", "") for script in soup.find_all("script", src=True)]
    if scripts:
        result.metadata["external_scripts"] = scripts[:15]

    if not detected:
        result.add(
            Finding(
                severity="info",
                title="No major technology fingerprints matched",
                description="Could not confidently identify the application stack from passive signals.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python tech_fingerprint.py <target_url>\n"
        "Example: python tech_fingerprint.py https://example.com",
    )


if __name__ == "__main__":
    main()
