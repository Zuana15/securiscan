#!/usr/bin/env python3
"""
SecuriScan SSL/TLS Scanner
Analyzes certificate validity, protocol support, and common TLS misconfigurations.
"""

from __future__ import annotations

import socket
import ssl
import sys
from datetime import datetime, timezone

from common import Finding, ScanResult, host_from_url, normalize_url, run_module_main

WEAK_PROTOCOLS = [
    ("SSLv3", ssl.PROTOCOL_SSLv23),
    ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
    ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None),
]


def parse_cert_date(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def check_protocol_support(host: str, port: int, protocol_name: str, protocol: int | None) -> bool:
    if protocol is None:
        return False
    context = ssl.SSLContext(protocol)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def run_scan(target: str) -> ScanResult:
    url = normalize_url(target)
    host, port = host_from_url(url)
    result = ScanResult(target=url, scan_type="ssl_tls")

    if url.startswith("http://"):
        result.add(
            Finding(
                severity="medium",
                title="Site served over HTTP",
                description="Target URL uses HTTP instead of HTTPS.",
                location=url,
                owasp="A02:2021-Cryptographic Failures",
                cwe="CWE-319",
                recommendation="Enforce HTTPS and redirect all HTTP traffic to HTTPS.",
            )
        )
        result.metadata["note"] = "Certificate checks skipped for non-HTTPS target"
        return result

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
                cipher = secure.cipher()
                protocol = secure.version()
    except ssl.SSLError as exc:
        result.status = "failed"
        result.metadata["error"] = str(exc)
        result.add(
            Finding(
                severity="high",
                title="TLS handshake failed",
                description="Could not establish a secure TLS connection to the target.",
                evidence=str(exc),
                recommendation="Verify certificate chain, hostname, and TLS configuration.",
            )
        )
        return result
    except OSError as exc:
        result.status = "failed"
        result.metadata["error"] = str(exc)
        return result

    if cert:
        not_before = parse_cert_date(cert["notBefore"])
        not_after = parse_cert_date(cert["notAfter"])
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        result.metadata["certificate"] = {
            "subject": dict(x[0] for x in cert.get("subject", ())),
            "issuer": dict(x[0] for x in cert.get("issuer", ())),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "san": [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"],
        }

        if now < not_before:
            result.add(
                Finding(
                    severity="high",
                    title="Certificate not yet valid",
                    description="The server certificate start date is in the future.",
                    evidence=f"Valid from: {not_before.isoformat()}",
                    recommendation="Install a currently valid certificate.",
                )
            )
        elif days_remaining < 0:
            result.add(
                Finding(
                    severity="critical",
                    title="Expired SSL/TLS certificate",
                    description="The server certificate has expired.",
                    evidence=f"Expired on: {not_after.isoformat()}",
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-298",
                    recommendation="Renew and deploy a valid certificate immediately.",
                )
            )
        elif days_remaining <= 30:
            result.add(
                Finding(
                    severity="medium",
                    title="Certificate expiring soon",
                    description=f"Certificate expires in {days_remaining} days.",
                    evidence=f"Expiry: {not_after.isoformat()}",
                    recommendation="Renew the certificate before expiry to avoid outages.",
                )
            )
        else:
            result.add(
                Finding(
                    severity="info",
                    title="Valid certificate detected",
                    description=f"Certificate is valid for another {days_remaining} days.",
                    evidence=f"Issuer: {result.metadata['certificate']['issuer']}",
                )
            )

        if host not in result.metadata["certificate"]["san"] and f"*.{host.split('.', 1)[-1]}" not in result.metadata["certificate"]["san"]:
            if result.metadata["certificate"]["subject"].get("commonName") != host:
                result.add(
                    Finding(
                        severity="medium",
                        title="Possible hostname mismatch",
                        description="Certificate may not match the requested hostname.",
                        evidence=f"Requested: {host}",
                        recommendation="Ensure certificate SAN/CN includes the served hostname.",
                    )
                )

    if cipher:
        cipher_name = cipher[0]
        result.metadata["cipher"] = cipher_name
        if any(weak in cipher_name for weak in ("RC4", "DES", "NULL", "EXPORT", "anon")):
            result.add(
                Finding(
                    severity="high",
                    title="Weak cipher suite in use",
                    description="Server negotiated a weak or deprecated cipher.",
                    evidence=cipher_name,
                    owasp="A02:2021-Cryptographic Failures",
                    cwe="CWE-327",
                    recommendation="Disable weak ciphers and prefer modern AEAD suites.",
                )
            )

    result.metadata["negotiated_protocol"] = protocol
    if protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
        result.add(
            Finding(
                severity="high",
                title="Deprecated TLS protocol negotiated",
                description=f"Server negotiated deprecated protocol: {protocol}.",
                recommendation="Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
            )
        )

    for name, proto in WEAK_PROTOCOLS:
        if check_protocol_support(host, port, name, proto):
            result.add(
                Finding(
                    severity="high",
                    title=f"Legacy protocol supported: {name}",
                    description=f"The server accepts connections using {name}.",
                    recommendation=f"Disable {name} support on the web server.",
                )
            )

    if len(result.findings) == 0:
        result.add(
            Finding(
                severity="info",
                title="No critical SSL/TLS issues detected",
                description="Basic certificate and protocol checks passed.",
            )
        )

    return result


def main() -> None:
    run_module_main(
        run_scan,
        "Usage: python ssl_checker.py <target_url>\n"
        "Example: python ssl_checker.py https://example.com",
    )


if __name__ == "__main__":
    main()
