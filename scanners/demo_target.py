#!/usr/bin/env python3
"""A local-only, intentionally vulnerable target for SecuriScan demonstrations."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8080

SENSITIVE_RESPONSES = {
    "/.env": "APP_KEY=demo-only-key\nDB_PASSWORD=demo-password\n",
    "/.git/config": "[core]\nrepositoryformatversion = 0\n",
    "/.git/HEAD": "ref: refs/heads/main\n",
    "/backup.sql": "CREATE TABLE users (id INT, email TEXT);\nINSERT INTO users VALUES (1, 'demo@example.test');\n",
    "/config.php": "<?php $db_password = 'demo-password'; ?>",
    "/phpinfo.php": "phpinfo()\nPHP Version 8.2-demo",
    "/admin/": "<h1>Demo administration console</h1>",
    "/api/swagger": "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"Demo API\"}}",
}


class DemoTargetHandler(BaseHTTPRequestHandler):
    server_version = "SecuriScanDemo/1.0"
    sys_version = "PHP/8.2-demo"

    def send_demo_headers(self, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Powered-By", "PHP/8.2-demo")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Set-Cookie", "session=demo-session")
        self.end_headers()

    def send_text(self, body: str, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_demo_headers(status, content_type)
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path in SENSITIVE_RESPONSES:
            self.send_text(SENSITIVE_RESPONSES[parsed.path])
            return

        if parsed.path == "/search":
            value = query.get("q", [""])[0]
            sql_error = "You have an error in your SQL syntax" if "'" in value or '"' in value else ""
            self.send_text(
                f"<h1>Search results</h1><p>{value}</p><pre>{sql_error}</pre>",
            )
            return

        if parsed.path == "/" and "url" in query:
            self.send_response(302)
            self.send_header("Location", query["url"][0])
            self.end_headers()
            return

        if parsed.path != "/":
            self.send_text("Not found", 404)
            return

        self.send_text(
            """<!doctype html>
<html><head>
<meta name="generator" content="WordPress 6.0 Demo">
<title>SecuriScan Demonstration Target</title>
<script src="/_next/static/chunks/app.js"></script>
<script src="/jquery-3.7.1.min.js"></script>
</head><body id="__next">
<h1>Intentionally vulnerable SecuriScan demo</h1>
<form action="/search" method="GET"><label>Search <input name="q"></label><button>Search</button></form>
<form action="/transfer" method="POST"><label>Recipient <input name="recipient"></label><button>Transfer</button></form>
</body></html>""",
        )

    def do_POST(self) -> None:
        self.send_text("<p>Transfer accepted without CSRF protection.</p>")

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, PUT, DELETE, TRACE, CONNECT, PATCH")
        self.end_headers()

    def do_PUT(self) -> None:
        self.send_text("PUT accepted")

    def do_DELETE(self) -> None:
        self.send_text("DELETE accepted")

    def do_TRACE(self) -> None:
        self.send_text("TRACE accepted")

    def do_CONNECT(self) -> None:
        self.send_text("CONNECT accepted")

    def do_PATCH(self) -> None:
        self.send_text("PATCH accepted")

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), DemoTargetHandler)
    print(f"SecuriScan demo target running at http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
