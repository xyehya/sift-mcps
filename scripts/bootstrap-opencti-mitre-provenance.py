#!/usr/bin/env python3
"""Resolve MITRE ATT&CK's cyclic Identity/Marking bootstrap dependency."""

from __future__ import annotations

import copy
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any, Never

from pycti import OpenCTIApiClient

SOURCE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/d4a34a19eb60dcd0a9d15a456da842a42e1003fc/enterprise-attack/enterprise-attack.json"
IDENTITY_ID = "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
MARKING_ID = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
MAX_BYTES = 64 * 1024 * 1024


def fail(message: str) -> Never:
    print(f"FATAL: {message}", file=sys.stderr)
    raise SystemExit(1)


def fetch_bundle() -> dict[str, Any]:
    request = urllib.request.Request(SOURCE, headers={"User-Agent": "sift-mcps/mitre-bootstrap"})
    try:
        with urllib.request.urlopen(
            request, context=ssl.create_default_context(), timeout=120
        ) as response:
            declared = int(response.headers.get("Content-Length", "0") or "0")
            if declared > MAX_BYTES:
                fail("MITRE bundle exceeds the 64 MiB safety limit")
            raw = response.read(MAX_BYTES + 1)
    except (OSError, urllib.error.HTTPError) as exc:
        fail(f"MITRE provenance fetch failed ({getattr(exc, 'code', 'connection')})")
    if len(raw) > MAX_BYTES:
        fail("MITRE bundle exceeds the 64 MiB safety limit")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        fail("MITRE provenance source returned invalid JSON")
    if payload.get("type") != "bundle" or not isinstance(payload.get("objects"), list):
        fail("MITRE provenance source is not a STIX bundle")
    return payload


def main() -> None:
    token = os.environ.get("OPENCTI_WORKER_TOKEN", "")
    if not token:
        fail("OPENCTI_WORKER_TOKEN is required through the root-only stack environment")
    objects: dict[str, dict[str, Any]] = {
        item["id"]: item
        for item in fetch_bundle()["objects"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    identity = objects.get(IDENTITY_ID)
    marking = objects.get(MARKING_ID)
    if not isinstance(identity, dict) or not isinstance(marking, dict):
        fail("MITRE bundle is missing the pinned provenance objects")
    if (
        identity.get("type") != "identity"
        or identity.get("name") != "The MITRE Corporation"
        or identity.get("object_marking_refs") != [MARKING_ID]
        or marking.get("type") != "marking-definition"
        or marking.get("definition_type") != "statement"
        or marking.get("created_by_ref") != IDENTITY_ID
    ):
        fail("MITRE provenance objects do not match the accepted identity/marking contract")

    client = OpenCTIApiClient("http://127.0.0.1:8080", token, log_level="error")
    unmarked_identity = copy.deepcopy(identity)
    unmarked_identity.pop("object_marking_refs", None)
    client.stix2.import_object(unmarked_identity, update=True)
    client.stix2.import_object(marking, update=True)
    client.stix2.import_object(identity, update=True)
    print("MITRE ATT&CK provenance bootstrap passed.")


if __name__ == "__main__":
    main()
