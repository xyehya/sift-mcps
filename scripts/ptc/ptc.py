#!/usr/bin/env python3
"""PTC (programmatic tool calling) host-side bridge for the SIFT gateway.

Runs in the LOCAL terminal (this host), NOT in the run_command jail. It speaks
MCP-over-HTTPS to the gateway, chains tool calls, and saves full results to local
disk so the bulk never enters the agent's context window — the agent reads only a
slim summary + a path it can grep/jq locally.

Bridge + auth are reused from this session's .mcp.json (url + Authorization header),
the same proven path as scripts/phase2_gate_test.py.

CLI:
  python3 scripts/ptc/ptc.py call <tool> '<json-args>'   # one call, save + summarize
  python3 scripts/ptc/ptc.py tools                       # list tool names + count

Library:
  from ptc import MCP
  mcp = MCP()
  res = mcp.call("opensearch_search", {"query": "event.code:4624", "limit": 200})
  # res is the parsed dict; full JSON also saved under scripts/ptc/out/
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import time
import http.client
import urllib.parse
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
MCP_JSON = REPO / ".mcp.json"
PTC_DIR = Path(__file__).resolve().parent
OUT_DIR = PTC_DIR / "out"
OUT_DIR.mkdir(parents=True, exist_ok=True)
_CALL_SEQ = 0  # disambiguates same-second saves within one process
# Secure-by-default TLS: pin the gateway's CA (fetch once from the VM:
#   scp sansforensics@192.168.122.81:~/.sift/tls/ca-cert.pem scripts/ptc/ca-cert.pem
# Override path with PTC_CA_CERT. Only PTC_INSECURE_TLS=1 disables verification
# (lab escape hatch — not for anything but a trusted local VM).
CA_CERT = Path(os.environ.get("PTC_CA_CERT") or (PTC_DIR / "ca-cert.pem"))


def _make_ssl_ctx() -> ssl.SSLContext:
    if os.environ.get("PTC_INSECURE_TLS") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if CA_CERT.exists():
        ctx = ssl.create_default_context(cafile=str(CA_CERT))
        # Lab cert is bound to the VM IP; chain is verified, hostname binding is
        # relaxed only because IP-SAN coverage varies. Chain verification still
        # defeats MITM with an untrusted cert.
        ctx.check_hostname = False
        return ctx
    raise SystemExit(
        f"PTC: no CA cert at {CA_CERT}. Fetch it once:\n"
        f"  scp sansforensics@192.168.122.81:~/.sift/tls/ca-cert.pem {CA_CERT}\n"
        f"or set PTC_INSECURE_TLS=1 to skip verification (trusted local VM only)."
    )


def _load_cfg(server: str = "") -> tuple[str, dict[str, str]]:
    """Return (url, headers) for the live gateway MCP server.

    Prefers ~/.claude.json (the session's live, OAuth-refreshed config for this
    project) and falls back to the repo .mcp.json. The Authorization header is the
    session's own bearer token; it is read at call time and never written out.
    """
    # 1) live per-project config in ~/.claude.json
    claude_json = Path.home() / ".claude.json"
    if claude_json.exists():
        try:
            proj = json.loads(claude_json.read_text()).get("projects", {}).get(str(REPO), {})
            servers = proj.get("mcpServers", {})
            spec = servers.get(server) if server else next(
                (s for s in servers.values() if s.get("type") == "http"), None)
            if spec and spec.get("headers", {}).get("Authorization"):
                return spec["url"], dict(spec["headers"])
        except Exception:
            pass
    # 2) fallback: repo .mcp.json
    servers = json.loads(MCP_JSON.read_text()).get("mcpServers", {})
    spec = servers[server] if server else next(
        s for s in servers.values() if s.get("type") == "http")
    return spec["url"], dict(spec.get("headers", {}))


class MCP:
    """Minimal MCP-over-HTTPS client with on-disk result capture."""

    def __init__(self, server: str = ""):
        self.url, self._hdrs = _load_cfg(server)
        u = urllib.parse.urlparse(self.url)
        self.host = u.hostname or ""
        self.port = u.port or 443
        self.path = u.path if u.path.endswith("/") else u.path + "/"
        self._ctx = _make_ssl_ctx()
        self.session_id = self._init_session()

    def _post(self, body: Any) -> tuple[dict, dict]:
        data = json.dumps(body).encode()
        hdrs = {
            **self._hdrs,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if getattr(self, "session_id", None):
            hdrs["Mcp-Session-Id"] = self.session_id
        conn = http.client.HTTPSConnection(self.host, self.port, context=self._ctx, timeout=120)
        try:
            conn.request("POST", self.path, body=data, headers=hdrs)
            r = conn.getresponse()
            rhdrs = {k.lower(): v for k, v in r.getheaders()}
            raw = r.read().decode("utf-8", errors="replace")
        finally:
            conn.close()
        if "text/event-stream" in rhdrs.get("content-type", ""):
            for line in raw.splitlines():
                s = line.strip()
                if s.startswith("data:"):
                    try:
                        return json.loads(s[5:].strip()), rhdrs
                    except json.JSONDecodeError:
                        continue
            return {"error": f"SSE parse fail: {raw[:200]}"}, rhdrs
        try:
            return json.loads(raw), rhdrs
        except json.JSONDecodeError:
            return {"error": f"non-JSON: {raw[:200]}"}, rhdrs

    def _init_session(self) -> str:
        self.session_id = ""
        _, hdrs = self._post({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "ptc", "version": "1.0"}},
        })
        sid = hdrs.get("mcp-session-id", "")
        self.session_id = sid
        if sid:
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        return sid

    def list_tools(self) -> list[dict]:
        resp, _ = self._post({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
        return resp.get("result", {}).get("tools", [])

    def call_raw(self, name: str, args: dict) -> dict:
        """Call a tool; return the raw JSON-RPC response."""
        resp, _ = self._post({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": name, "arguments": args},
        })
        return resp

    def call(self, name: str, args: dict | None = None, save: bool = True) -> Any:
        """Call a tool and return the parsed result payload.

        The gateway returns tool output as text content; we parse JSON when possible.
        When save=True the full payload is written to scripts/ptc/out/ and is NOT
        what you print — print a summary and grep/jq the file.
        """
        resp = self.call_raw(name, args or {})
        if "error" in resp and "result" not in resp:
            return {"_ptc_error": resp["error"]}
        content = resp.get("result", {}).get("content", [])
        text = "".join(c.get("text", "") for c in content if isinstance(c, dict))
        # Gateway tool results are often payload + a trailing case_context block
        # (multiple JSON objects). Extract them all; the first is the real payload.
        objs: list[Any] = []
        dec = json.JSONDecoder()
        i, n = 0, len(text)
        while i < n:
            while i < n and text[i] in " \t\r\n":
                i += 1
            if i >= n:
                break
            try:
                obj, end = dec.raw_decode(text, i)
            except json.JSONDecodeError:
                break
            objs.append(obj)
            i = end
        if objs:
            payload: Any = objs[0]
            if len(objs) > 1 and isinstance(payload, dict):
                payload["_ptc_envelope"] = objs[1:]
        else:
            payload = {"_text": text}
        if save:
            global _CALL_SEQ
            _CALL_SEQ += 1
            ts = time.strftime("%Y%m%d_%H%M%S")
            p = OUT_DIR / f"{name}_{ts}_{_CALL_SEQ:03d}.json"
            p.write_text(json.dumps(payload, indent=2))
            if isinstance(payload, dict):
                payload.setdefault("_ptc_saved", str(p.relative_to(REPO)))
        return payload


def family(index: str) -> str:
    """Reduce a verbose case index name to its artifact family.

    'case-case-rocba-case-06132304-vol-netscan-rocba' -> 'vol-netscan-rocba'.
    Strips the longest leading 'case-...-<id>-' prefix heuristically.
    """
    if not index:
        return "?"
    parts = index.split("-")
    # drop leading 'case' segments and the numeric case-id token
    for i, seg in enumerate(parts):
        if seg.isdigit() and len(seg) >= 6:
            return "-".join(parts[i + 1:]) or index
    return index


def _summary(payload: Any) -> str:
    """One-screen summary of a payload without dumping it."""
    if isinstance(payload, dict):
        keys = list(payload.keys())
        size = len(json.dumps(payload))
        head = {k: payload[k] for k in keys[:6] if not isinstance(payload[k], (list, dict))}
        return (f"keys={keys}\n  bytes={size}  saved={payload.get('_ptc_saved','-')}\n"
                f"  scalars={json.dumps(head)[:400]}")
    return str(payload)[:400]


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "tools":
        mcp = MCP()
        ts = mcp.list_tools()
        print(f"{len(ts)} tools:", ", ".join(sorted(t["name"] for t in ts)))
    elif len(sys.argv) >= 3 and sys.argv[1] == "call":
        tool = sys.argv[2]
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        mcp = MCP()
        out = mcp.call(tool, args)
        print(_summary(out))
    else:
        print(__doc__)
        sys.exit(2)
