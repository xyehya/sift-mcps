#!/usr/bin/env python3
"""
Mission Control — local dev server for Fedora.
Serves index-standalone.html and exposes /api/read + /api/write.

Usage:
    cd /home/yk/AI/SIFTHACK/sift-mcps/mission-control
    python3 server.py

Then open: http://localhost:8787
"""

import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

PORT = 8787
HERE = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(HERE, "index-standalone.html")

# Only allow reads/writes inside this directory tree
ALLOWED_ROOT = os.path.realpath("/home/yk/AI/SIFTHACK/sift-mcps")


def checked_path(raw: str) -> str:
    real = os.path.realpath(raw)
    if not real.startswith(ALLOWED_ROOT):
        raise PermissionError(f"Path outside allowed root: {raw!r}")
    return real


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        p = urlparse(self.path)
        if p.path in ("/", "/index.html", "/index-standalone.html"):
            self._serve_file(HTML_FILE, "text/html; charset=utf-8")
        elif p.path == "/api/read":
            qs = parse_qs(p.query)
            path = unquote(qs.get("path", [""])[0])
            self._read_file(path)
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/api/write":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            self._write_file(body.get("path", ""), body.get("content", ""))
        else:
            self._send(404, "text/plain", b"Not found")

    def _read_file(self, path: str):
        try:
            real = checked_path(path)
            with open(real, "r", encoding="utf-8") as f:
                content = f.read()
            self._send(200, "text/plain; charset=utf-8", content.encode())
        except FileNotFoundError:
            self._send(404, "text/plain", f"Not found: {path}".encode())
        except PermissionError as e:
            self._send(403, "text/plain", str(e).encode())
        except Exception as e:
            self._send(500, "text/plain", str(e).encode())

    def _write_file(self, path: str, content: str):
        try:
            real = checked_path(path)
            os.makedirs(os.path.dirname(real), exist_ok=True)
            with open(real, "w", encoding="utf-8") as f:
                f.write(content)
            self._send(200, "text/plain", b"ok")
        except PermissionError as e:
            self._send(403, "text/plain", str(e).encode())
        except Exception as e:
            self._send(500, "text/plain", str(e).encode())

    def _serve_file(self, path: str, ctype: str):
        try:
            with open(path, "rb") as f:
                body = f.read()
            self._send(200, ctype, body)
        except Exception as e:
            self._send(500, "text/plain", str(e).encode())

    def _send(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")


if __name__ == "__main__":
    print(f"Mission Control  →  http://localhost:{PORT}")
    print(f"Repo root        →  {ALLOWED_ROOT}")
    print(f"HTML             →  {HTML_FILE}")
    print()
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
