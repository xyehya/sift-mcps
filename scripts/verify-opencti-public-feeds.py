#!/usr/bin/env python3
"""Bounded readiness proof for the pinned public OpenCTI feed baseline."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

EXPECTED = {
    "OPENCTI_CONNECTOR_MITRE_ID": "MITRE ATT&CK",
    "OPENCTI_CONNECTOR_CISA_KEV_ID": "CISA KEV",
    "OPENCTI_CONNECTOR_THREATFOX_ID": "ThreatFox",
    "OPENCTI_CONNECTOR_URLHAUS_ID": "Abuse.ch URLhaus",
}


def fail(message: str) -> None:
    print(f"FATAL: {message}", file=sys.stderr)
    raise SystemExit(1)


def query(token: str) -> dict:
    document = """query PublicFeedReadiness {
      connectors { id name active connector_type }
      attackPatterns(first: 1) { pageInfo { globalCount } }
      vulnerabilities(first: 1) { pageInfo { globalCount } }
      indicators(first: 1) { pageInfo { globalCount } }
      stixCyberObservables(first: 1) { pageInfo { globalCount } }
    }"""
    request = urllib.request.Request(
        "http://127.0.0.1:8080/graphql",
        data=json.dumps({"query": document}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except (OSError, urllib.error.HTTPError) as exc:
        fail(f"OpenCTI readiness request failed ({getattr(exc, 'code', 'connection')})")
    if payload.get("errors"):
        codes = sorted(
            {error.get("extensions", {}).get("code", "UNKNOWN") for error in payload["errors"]}
        )
        fail(f"OpenCTI readiness query rejected ({','.join(codes)})")
    return payload["data"]


def main() -> None:
    token = os.environ.get("OPENCTI_ADMIN_TOKEN", "")
    if not token:
        fail("OPENCTI_ADMIN_TOKEN is required through the root-only stack environment")
    expected = {os.environ.get(key, ""): name for key, name in EXPECTED.items()}
    if "" in expected:
        fail("stable connector IDs are missing from the root-only connector environment")
    timeout = int(os.environ.get("SIFT_OPENCTI_FEED_READY_TIMEOUT", "1800"))
    if timeout < 30 or timeout > 3600:
        fail("SIFT_OPENCTI_FEED_READY_TIMEOUT must be between 30 and 3600 seconds")
    deadline = time.monotonic() + timeout
    last_summary = "no response"
    while time.monotonic() < deadline:
        data = query(token)
        live = {
            item["id"]: item
            for item in data["connectors"]
            if item.get("connector_type") == "EXTERNAL_IMPORT"
        }
        connector_ok = all(
            connector_id in live
            and live[connector_id].get("name") == name
            and live[connector_id].get("active") is True
            for connector_id, name in expected.items()
        )
        counts = {
            key: data[key]["pageInfo"]["globalCount"]
            for key in (
                "attackPatterns",
                "vulnerabilities",
                "indicators",
                "stixCyberObservables",
            )
        }
        # The immutable ATT&CK v17.1 Enterprise bundle contains 679 current
        # techniques. A merely non-zero count would accept a truncated import.
        data_ok = counts["attackPatterns"] >= 675 and all(
            counts[key] > 0
            for key in ("vulnerabilities", "indicators", "stixCyberObservables")
        )
        last_summary = f"active={sum(cid in live and live[cid].get('active') is True for cid in expected)}/4 counts={counts}"
        if connector_ok and data_ok:
            print(f"OpenCTI public-feed readiness passed: {last_summary}")
            return
        time.sleep(10)
    fail(f"OpenCTI public-feed readiness timed out: {last_summary}")


if __name__ == "__main__":
    main()
