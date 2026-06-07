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
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

PORT = 8787
HERE = os.path.dirname(os.path.abspath(__file__))
HTML_FILE = os.path.join(HERE, "index-standalone.html")

# Only allow reads/writes inside this directory tree
ALLOWED_ROOT = os.path.realpath("/home/yk/AI/SIFTHACK/sift-mcps")

# Docs served by /md  (in order)
DOCS_ROOT = os.path.join(ALLOWED_ROOT, "docs/migration")
MD_DOCS = [
    ("MIGRATION_STATE.md",     "Current state, active objective, run history"),
    ("REGISTER.md",            "Open forks (F#) and backlog (B#)"),
    ("00_migration_charter.md","Locked decisions (D#)"),
]


def read_doc(filename: str) -> str:
    path = os.path.join(DOCS_ROOT, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def extract_section(text: str, start_re, end_re=r"\n## ") -> str:
    """Return the block starting at start_re up to the next heading."""
    import re
    m = re.search(start_re, text)
    if not m:
        return ""
    rest = text[m.start():]
    end = re.search(end_re, rest[1:])
    return rest if end is None else rest[: end.start() + 1]


def summarize_run(heading: str, body: str) -> str:
    """Heading + first action lines + Next: section only."""
    import re
    lines = body.splitlines()

    # Grab up to 6 non-empty lines from the top (Created/Committed summary)
    intro = []
    for line in lines:
        if not line.strip():
            if intro:           # stop at first blank after we've collected something
                break
            continue
        intro.append(line.rstrip())
        if len(intro) >= 6:
            break

    # Find "Next recommended run:" or "Next:" block — take first 4 bullet lines
    next_lines = []
    in_next = False
    for line in lines:
        if re.match(r"^Next\b", line.strip(), re.IGNORECASE):
            in_next = True
            next_lines.append(line.rstrip())
            continue
        if in_next:
            if line.strip().startswith("-") or line.strip().startswith("*"):
                next_lines.append(line.rstrip())
                if len(next_lines) >= 5:
                    break
            elif line.strip() and not next_lines[-1].strip().startswith(("-", "*")):
                # continuation of the Next: paragraph
                next_lines.append(line.rstrip())
            elif line.strip() and not line.startswith(" "):
                break  # new top-level section

    parts = [heading]
    if intro:
        parts.append("\n".join(intro))
    if next_lines:
        parts.append("\n".join(next_lines))
    return "\n".join(parts)


def extract_runs(text: str, n: int = 5) -> str:
    """Return the latest n ## Run N blocks, summarized."""
    import re
    pattern = re.compile(r"^(## Run (\d+).*?)$", re.MULTILINE)
    matches = list(pattern.finditer(text))
    if not matches:
        return ""

    # Collect (run_number, heading, body)
    runs = []
    for i, m in enumerate(matches):
        num = int(m.group(2))
        heading = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        runs.append((num, heading, body))

    # Sort by run number descending, take latest n, re-sort ascending for display
    runs.sort(key=lambda x: x[0], reverse=True)
    latest = sorted(runs[:n], key=lambda x: x[0])

    return "\n\n".join(summarize_run(h, b) for _, h, b in latest)


def filter_open_table_rows(block: str, status_col: int, open_val: str) -> str:
    """Keep header rows and only data rows where status_col matches open_val."""
    lines = block.splitlines(keepends=True)
    out = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("|"):
            out.append(line)
            continue
        cols = [c.strip() for c in stripped.split("|")[1:-1]]
        # header or separator rows pass through
        if not cols or all(set(c) <= set("-: ") for c in cols):
            out.append(line)
            continue
        # data row: check status column
        if len(cols) > status_col and open_val.lower() in cols[status_col].lower():
            out.append(line)
    return "".join(out)


def build_md_bundle() -> str:
    import re
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [f"<!-- sift migration context — {ts} -->\n"]

    state = read_doc("MIGRATION_STATE.md")
    register = read_doc("REGISTER.md")

    # 1. Current Objective (last session update + next task)
    objective = extract_section(state, r"## Current Objective")
    if objective:
        parts.append("\n## Current Objective\n")
        parts.append(objective.replace("## Current Objective", "").strip())
        parts.append("\n")

    # 2. Open Forks (F#)
    forks_block = extract_section(register, r"## Forks \(F#\)")
    if forks_block:
        open_forks = filter_open_table_rows(forks_block, status_col=3, open_val="OPEN")
        parts.append("\n## Open Forks (F#)\n")
        parts.append(open_forks.replace("## Forks (F#)", "").strip())
        parts.append("\n")

    # 3. Open Backlog (B#)
    backlog_block = extract_section(register, r"## Backlog \(B#\)")
    if backlog_block:
        open_bl = filter_open_table_rows(backlog_block, status_col=3, open_val="OPEN")
        parts.append("\n## Open Backlog (B#)\n")
        parts.append(open_bl.replace("## Backlog (B#)", "").strip())
        parts.append("\n")

    # 4. Latest 5 runs
    runs = extract_runs(state, n=5)
    if runs:
        parts.append("\n## Recent Runs (latest 5)\n\n")
        parts.append(runs)
        parts.append("\n")

    return "\n".join(parts)


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
        elif p.path == "/md":
            body = build_md_bundle().encode("utf-8")
            self._send(200, "text/markdown; charset=utf-8", body)
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
    print(f"Markdown feed    →  http://localhost:{PORT}/md")
    print(f"Repo root        →  {ALLOWED_ROOT}")
    print(f"HTML             →  {HTML_FILE}")
    print()
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
