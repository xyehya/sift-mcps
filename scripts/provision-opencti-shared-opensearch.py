#!/usr/bin/env python3
"""Provision and prove the dedicated shared-target OpenSearch identity."""

from __future__ import annotations

import base64
import json
import os
import pwd
import secrets
import ssl
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from pathlib import Path

import yaml


def fail(message: str) -> None:
    print(f"FATAL: {message}", file=sys.stderr)
    raise SystemExit(1)


def request(
    base_url: str,
    context: ssl.SSLContext,
    user: str,
    password: str,
    method: str,
    path: str,
    body: Mapping[str, object] | None = None,
) -> tuple[int, bytes]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def parse_env(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


def main() -> None:
    if os.geteuid() != 0:
        fail("run this provisioner as root")
    repo = Path(os.environ.get("SIFT_MCPS_ROOT", Path(__file__).resolve().parents[1]))
    config_path = Path(os.environ.get("SIFT_OPENSEARCH_CONFIG", "/var/lib/sift/.sift/opensearch.yaml"))
    output_path = Path(os.environ.get("SIFT_OPENCTI_SHARED_ENV", "/var/lib/sift/.sift/opencti-shared.env"))
    role_path = repo / "configs/opensearch/security/opencti-platform-role.yml"
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    role_document = yaml.safe_load(role_path.read_text(encoding="utf-8"))
    role_name = "sift_opencti_platform"
    role = role_document.get(role_name)
    if not isinstance(role, dict):
        fail("OpenCTI role document is invalid")
    for forbidden in ("reserved", "hidden"):
        role.pop(forbidden, None)

    base_url = str(config.get("host") or "")
    admin_user = str(config.get("user") or "")
    admin_password = str(config.get("password") or "")
    ca_path = str(config.get("ca_certs") or "")
    if not base_url.startswith("https://") or not admin_user or not admin_password or not ca_path:
        fail("secure OpenSearch admin configuration is incomplete")
    context = ssl.create_default_context(cafile=ca_path)

    existing = parse_env(output_path)
    platform_user = existing.get("OPENCTI_OPENSEARCH_USER", "sift_opencti")
    platform_password = existing.get("OPENCTI_OPENSEARCH_PASSWORD") or secrets.token_urlsafe(48)

    operations = (
        ("PUT", f"/_plugins/_security/api/roles/{role_name}", role),
        (
            "PUT",
            f"/_plugins/_security/api/internalusers/{platform_user}",
            {"password": platform_password, "backend_roles": [role_name]},
        ),
        (
            "PUT",
            f"/_plugins/_security/api/rolesmapping/{role_name}",
            {"backend_roles": [role_name], "users": [platform_user]},
        ),
    )
    for method, path, body in operations:
        status, _ = request(
            base_url, context, admin_user, admin_password, method, path, body
        )
        if status not in {200, 201}:
            fail(f"OpenSearch Security provisioning failed ({status})")

    proof_index = f"opencti-security-proof-{secrets.token_hex(6)}"
    positive, _ = request(
        base_url, context, platform_user, platform_password, "PUT", f"/{proof_index}"
    )
    if positive not in {200, 201}:
        fail("OpenCTI identity cannot create an opencti* index")
    try:
        negative, _ = request(
            base_url,
            context,
            platform_user,
            platform_password,
            "PUT",
            "/case-security-negative-proof",
        )
        if negative not in {401, 403}:
            fail("OpenCTI identity was not denied access to case-* indices")
    finally:
        request(
            base_url,
            context,
            platform_user,
            platform_password,
            "DELETE",
            f"/{proof_index}",
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f".{output_path.name}.{secrets.token_hex(6)}")
    temp_path.write_text(
        "\n".join(
            (
                f"OPENCTI_OPENSEARCH_CA={ca_path}",
                f"OPENCTI_OPENSEARCH_USER={platform_user}",
                f"OPENCTI_OPENSEARCH_PASSWORD={platform_password}",
                "OPENCTI_OPENSEARCH_CHECK_URL=https://127.0.0.1:9200",
                "",
            )
        ),
        encoding="utf-8",
    )
    os.chmod(temp_path, 0o600)
    os.replace(temp_path, output_path)
    service_account = pwd.getpwnam(
        os.environ.get("SIFT_GATEWAY_SERVICE_USER", "sift-service")
    )
    os.chown(output_path, service_account.pw_uid, service_account.pw_gid)
    print("Dedicated OpenCTI OpenSearch identity provisioned and least-privilege proof passed.")


if __name__ == "__main__":
    main()
