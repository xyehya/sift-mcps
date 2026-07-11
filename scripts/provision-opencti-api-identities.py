#!/usr/bin/env python3
"""Create distinct OpenCTI worker and query-only service identities."""

from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Never


def fail(message: str) -> Never:
    print(f"FATAL: {message}", file=sys.stderr)
    raise SystemExit(1)


def graphql(
    token: str,
    query: str,
    variables: dict[str, object] | None = None,
    operation: str = "request",
) -> dict:
    for attempt in range(5):
        request = urllib.request.Request(
            "http://127.0.0.1:8080/graphql",
            data=json.dumps({"query": query, "variables": variables or {}}).encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (OSError, urllib.error.HTTPError) as exc:
            fail(f"OpenCTI API request failed ({getattr(exc, 'code', 'connection')})")
        errors = payload.get("errors") or []
        codes = {error.get("extensions", {}).get("code", "UNKNOWN") for error in errors}
        if not errors:
            return payload["data"]
        if codes == {"LOCK_ERROR"} and attempt < 4:
            time.sleep(2)
            continue
        fail(f"OpenCTI API rejected {operation} ({','.join(sorted(codes))})")
    fail("OpenCTI API lock retry exhausted")


def parse_env(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                result[key] = value
    return result


def atomic_env(path: Path, values: dict[str, str], uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for key, value in values.items():
                if "\n" in value or "\r" in value:
                    fail(f"invalid newline in {key}")
                handle.write(f"{key}={value}\n")
        os.chown(name, uid, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main() -> None:
    if os.geteuid() != 0:
        fail("run this provisioner as root")
    stack_path = Path(os.environ.get("SIFT_OPENCTI_STACK_ENV", "/var/lib/sift/.sift/opencti-stack.env"))
    query_path = Path(os.environ.get("SIFT_OPENCTI_QUERY_ENV", "/var/lib/sift/.sift/opencti-query.env"))
    stack = parse_env(stack_path)
    admin_token = stack.get("OPENCTI_ADMIN_TOKEN", "")
    if not admin_token:
        fail("OpenCTI admin bootstrap token is missing")

    capabilities_data = graphql(admin_token, "query { capabilities { edges { node { id name } } } }", operation="capability read")
    capabilities = {edge["node"]["name"]: edge["node"]["id"] for edge in capabilities_data["capabilities"]["edges"]}
    roles_data = graphql(admin_token, "query { roles(first: 100) { edges { node { id name capabilities { id name } } } } }", operation="role read")
    roles = {edge["node"]["name"]: edge["node"] for edge in roles_data["roles"]["edges"]}
    role_add = "mutation RoleAdd($input: RoleAddInput!) { roleAdd(input: $input) { id name capabilities { id name } } }"
    role_cap = "mutation RoleCap($id: ID!, $input: InternalRelationshipAddInput!) { roleEdit(id: $id) { relationAdd(input: $input) { id } } }"

    def ensure_role(name: str, expected: set[str]) -> dict:
        missing = expected - capabilities.keys()
        if missing:
            fail(f"required OpenCTI capabilities are missing: {','.join(sorted(missing))}")
        role = roles.get(name)
        if role is None:
            role = graphql(admin_token, role_add, {"input": {"name": name, "description": "SIFT managed; do not edit"}}, "role create")["roleAdd"]
        current = {cap["name"] for cap in role.get("capabilities", [])}
        if current - expected:
            fail(f"managed role {name} has unexpected capabilities")
        for capability in sorted(expected - current):
            graphql(admin_token, role_cap, {"id": role["id"], "input": {"relationship_type": "has-capability", "toId": capabilities[capability]}}, "role capability add")
        return role

    worker_role = ensure_role("SIFT Worker", {"BYPASS", "APIACCESS", "APIACCESS_USETOKEN"})
    query_role = ensure_role("SIFT MCP Readonly", {"KNOWLEDGE", "APIACCESS", "APIACCESS_USETOKEN"})
    groups_data = graphql(admin_token, "query { groups(first: 100) { edges { node { id name roles { edges { node { id name capabilities { name } } } } } } } }", operation="group read")
    groups = {edge["node"]["name"]: edge["node"] for edge in groups_data["groups"]["edges"]}
    group_add = "mutation GroupAdd($input: GroupAddInput!) { groupAdd(input: $input) { id name } }"
    group_role = "mutation GroupRole($groupId: ID!, $roleId: ID!) { groupEdit(id: $groupId) { relationAdd(input: {toId: $roleId, relationship_type: \"has-role\"}) { id } } }"

    def ensure_group(name: str, role: dict) -> dict:
        group = groups.get(name)
        if group is None:
            group = graphql(admin_token, group_add, {"input": {"name": name, "description": "SIFT managed; do not edit", "default_assignation": False, "no_creators": True, "restrict_delete": True, "auto_new_marking": False, "group_confidence_level": {"max_confidence": 100, "overrides": []}}}, "group create")["groupAdd"]
            graphql(admin_token, group_role, {"groupId": group["id"], "roleId": role["id"]}, "group role add")
        return group

    worker_group = ensure_group("SIFT Workers", worker_role)
    query_group = ensure_group("SIFT MCP Readonly", query_role)

    users_data = graphql(admin_token, "query { users(first: 500) { edges { node { id user_email } } } }", operation="user read")
    users = {edge["node"]["user_email"]: edge["node"] for edge in users_data["users"]["edges"]}
    add = """mutation UserAdd($input: UserAddInput!) { userAdd(input: $input) { id user_email } }"""
    token_add = """mutation TokenAdd($userId: ID!, $input: UserTokenAddInput!) { userAdminTokenAdd(userId: $userId, input: $input) { plaintext_token } }"""

    def ensure(email: str, name: str, group: dict, token_key: str) -> str:
        user = users.get(email)
        if user is None:
            user = graphql(admin_token, add, {"input": {"name": name, "user_email": email, "password": secrets.token_urlsafe(64), "groups": [group["id"]], "user_service_account": True}}, "user create")["userAdd"]
            # A fresh OpenCTI datastore invalidates any locally retained token
            # from a previous disposable deployment.
            token = ""
        else:
            token = stack.get(token_key, "")
        if not token:
            token = graphql(admin_token, token_add, {"userId": user["id"], "input": {"name": "sift-managed", "duration": "UNLIMITED"}}, "token create")["userAdminTokenAdd"]["plaintext_token"]
        me = graphql(token, "query { me { id user_email capabilities { name } } }", operation="token verify")["me"]
        if me["user_email"] != email:
            fail(f"stored token does not belong to {email}")
        return token

    # OpenCTI 7 officially requires workers to use a BYPASS administrator
    # identity. Keep it distinct from the bootstrap administrator for blast
    # radius and audit attribution; do not mislabel it as least privilege.
    if stack.get("OPENCTI_IDENTITIES_PROVISIONED") != "1":
        stack.pop("OPENCTI_WORKER_TOKEN", None)
        stack.pop("OPENCTI_QUERY_TOKEN", None)
    worker = ensure("sift-worker@sift.local", "SIFT OpenCTI Worker", worker_group, "OPENCTI_WORKER_TOKEN")
    query = ensure("sift-query@sift.local", "SIFT OpenCTI Query", query_group, "OPENCTI_QUERY_TOKEN")
    if len({admin_token, worker, query}) != 3:
        fail("OpenCTI admin, worker, and query tokens must be distinct")
    stack["OPENCTI_WORKER_TOKEN"] = worker
    stack["OPENCTI_QUERY_TOKEN"] = query
    stack["OPENCTI_IDENTITIES_PROVISIONED"] = "1"
    atomic_env(stack_path, stack, 0, 0)
    import pwd
    account = pwd.getpwnam(os.environ.get("SIFT_GATEWAY_SERVICE_USER", "sift-service"))
    atomic_env(query_path, {"SIFT_OPENCTI_URL": "http://127.0.0.1:8080", "SIFT_OPENCTI_TOKEN": query}, account.pw_uid, account.pw_gid)
    print("Distinct OpenCTI worker and query-only identities provisioned.")


if __name__ == "__main__":
    main()
