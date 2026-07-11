#!/usr/bin/env python3
"""Authenticated live proof for the canonical Qwen RAG MCP surface."""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any

EXPECTED_MODEL = "Qwen/Qwen3-Embedding-0.6B"
EXPECTED_CHUNKS = 22_268
EXPECTED_SOURCES = 67
ABSOLUTE_PATH = re.compile(r"(^|\s)/(home|root|mnt|media|evidence|cases?|var|opt|srv)/")


def response_json(response) -> dict[str, Any]:
    return json.loads(response.read().decode("utf-8"))


def parse_mcp(raw: str, content_type: str) -> dict[str, Any]:
    if not raw.strip():
        return {}
    if "text/event-stream" in content_type:
        for line in raw.splitlines():
            if line.strip().startswith("data:"):
                return json.loads(line.split("data:", 1)[1].strip())
        raise RuntimeError("mcp_sse_response_missing_data")
    return json.loads(raw)


def tool_payload(response: dict[str, Any]) -> dict[str, Any]:
    if response.get("error"):
        raise RuntimeError("mcp_tool_call_failed")
    result = response.get("result") or {}
    if result.get("isError"):
        raise RuntimeError("mcp_tool_returned_error")
    text = "".join(
        item.get("text", "")
        for item in result.get("content", [])
        if isinstance(item, dict)
    )
    decoder = json.JSONDecoder()
    payload, _end = decoder.raw_decode(text.lstrip())
    if not isinstance(payload, dict):
        raise RuntimeError("mcp_tool_payload_invalid")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--password-stdin", action="store_true", required=True)
    args = parser.parse_args()
    password = sys.stdin.read().strip() if args.password_stdin else ""
    if not password:
        raise SystemExit("operator password is required on stdin")

    context = ssl.create_default_context(cafile="/var/lib/sift/.sift/tls/ca-cert.pem")
    cookies = http.cookiejar.CookieJar()
    portal = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookies),
        urllib.request.HTTPSHandler(context=context),
    )

    def portal_request(method: str, path: str, payload: dict[str, Any] | None = None):
        request = urllib.request.Request(
            "https://localhost:4508/portal" + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with portal.open(request, timeout=60) as response:
            return response_json(response)

    login = portal_request(
        "POST",
        "/api/auth/login",
        {"email": "examiner@operators.sift.local", "password": password},
    )
    if login.get("must_reset"):
        raise RuntimeError("operator_forced_reset_incomplete")

    issued: dict[str, Any] | None = None
    try:
        issued = portal_request(
            "POST",
            "/api/auth/principals",
            {
                "kind": "service",
                "display_name": "Qwen RAG verifier " + secrets.token_hex(4),
                "tool_scopes": ["namespace:kb"],
                "password": password,
            },
        )
        token = str(issued.get("access_token") or "")
        principal_id = str(issued.get("principal_id") or "")
        if not token or not principal_id:
            raise RuntimeError("temporary_principal_issue_failed")

        session_id = ""

        def mcp(body: dict[str, Any]) -> dict[str, Any]:
            headers = {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            if session_id:
                headers["Mcp-Session-Id"] = session_id
            request = urllib.request.Request(
                "https://localhost:4508/mcp",
                data=json.dumps(body).encode(),
                method="POST",
                headers=headers,
            )
            try:
                with urllib.request.urlopen(request, context=context, timeout=120) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                    return parse_mcp(raw, response.headers.get("Content-Type", ""))
            except urllib.error.HTTPError as exc:
                return {"http_error": exc.code}

        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "sift-qwen-live-proof", "version": "1"},
            },
        }
        # Initialize separately to capture the session header.
        request = urllib.request.Request(
            "https://localhost:4508/mcp",
            data=json.dumps(init_request).encode(),
            method="POST",
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        with urllib.request.urlopen(request, context=context, timeout=120) as response:
            raw = response.read().decode("utf-8", errors="replace")
            initialized = parse_mcp(raw, response.headers.get("Content-Type", ""))
            session_id = response.headers.get("Mcp-Session-Id", "")
        if initialized.get("error") or not session_id:
            raise RuntimeError("mcp_initialize_failed")
        mcp({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

        listed = mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = {tool.get("name") for tool in listed.get("result", {}).get("tools", [])}
        required = {
            "kb_get_knowledge_stats",
            "kb_list_knowledge_sources",
            "kb_search_knowledge",
        }
        if not required.issubset(names):
            raise RuntimeError("kb_tools_not_advertised")

        def call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
            return mcp(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            )

        stats = tool_payload(call("kb_get_knowledge_stats", {}))
        sources = tool_payload(call("kb_list_knowledge_sources", {}))
        search_started = time.perf_counter()
        search = tool_payload(
            call(
                "kb_search_knowledge",
                {"query": "LSASS credential dumping detection", "top_k": 3},
            )
        )
        search_ms = round((time.perf_counter() - search_started) * 1000, 1)
        filtered_started = time.perf_counter()
        filtered = tool_payload(
            call(
                "kb_search_knowledge",
                {
                    "query": "PowerShell archive data before exfiltration",
                    "top_k": 3,
                    "source_ids": ["atomic"],
                },
            )
        )
        filtered_ms = round((time.perf_counter() - filtered_started) * 1000, 1)
        if (
            stats.get("chunk_count") != EXPECTED_CHUNKS
            or stats.get("embedding_dim") != 1024
            or stats.get("embedding_model") != EXPECTED_MODEL
        ):
            raise RuntimeError("kb_stats_mismatch")
        if sources.get("count") != EXPECTED_SOURCES:
            raise RuntimeError("kb_source_count_mismatch")
        hits = search.get("results") or []
        if len(hits) != 3:
            raise RuntimeError("kb_search_result_count_mismatch")
        for hit in hits:
            if hit.get("case_id") is not None or ABSOLUTE_PATH.search(
                json.dumps(hit, ensure_ascii=False)
            ):
                raise RuntimeError("kb_case_or_path_leak")
        filtered_hits = filtered.get("results") or []
        if not filtered_hits or filtered_hits[0].get("document_title") != (
            "Compress Data for Exfiltration With PowerShell"
        ):
            raise RuntimeError("kb_source_filtered_ranking_mismatch")

        denied = call("case_info", {})
        if denied.get("result") and not denied.get("result", {}).get("isError"):
            raise RuntimeError("kb_scope_accessed_case_tool")

        print(
            json.dumps(
                {
                    "status": "ok",
                    "advertised_kb_tools": len(required),
                    "chunk_count": stats["chunk_count"],
                    "source_count": sources["count"],
                    "top_titles": [hit.get("document_title") for hit in hits],
                    "search_ms": search_ms,
                    "filtered_search_ms": filtered_ms,
                    "case_tool_denied": True,
                },
                sort_keys=True,
            )
        )
    finally:
        if issued and issued.get("principal_id"):
            portal_request(
                "DELETE",
                f"/api/auth/principals/service/{issued['principal_id']}",
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
