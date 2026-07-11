#!/usr/bin/env python3
"""Create distinct OpenCTI worker, query, and public-feed identities."""

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
    connectors_path = Path(
        os.environ.get(
            "SIFT_OPENCTI_CONNECTORS_ENV", "/var/lib/sift/.sift/opencti-connectors.env"
        )
    )
    stack = parse_env(stack_path)
    connectors = parse_env(connectors_path)
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

    connector_capabilities = {
        "APIACCESS",
        "APIACCESS_USETOKEN",
        "CONNECTORAPI",
        "KNOWLEDGE",
        "KNOWLEDGE_KNUPDATE",
        "KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS",
        "KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE",
        "MODULES",
        "SETTINGS_SETKILLCHAINPHASES",
        "SETTINGS_SETLABELS",
        "SETTINGS_SETMARKINGS",
        "SETTINGS_SETVOCABULARIES",
    }
    worker_role = ensure_role("SIFT Worker", connector_capabilities | {"BYPASS"})
    query_role = ensure_role("SIFT MCP Readonly", {"KNOWLEDGE", "APIACCESS", "APIACCESS_USETOKEN"})
    connector_role = ensure_role("SIFT Public Feed Connector", connector_capabilities)
    groups_data = graphql(admin_token, "query { groups(first: 100) { edges { node { id name auto_new_marking allowed_marking { id } roles { edges { node { id name capabilities { name } } } } } } } }", operation="group read")
    groups = {edge["node"]["name"]: edge["node"] for edge in groups_data["groups"]["edges"]}
    group_add = "mutation GroupAdd($input: GroupAddInput!) { groupAdd(input: $input) { id name } }"
    group_role = "mutation GroupRole($groupId: ID!, $roleId: ID!) { groupEdit(id: $groupId) { relationAdd(input: {toId: $roleId, relationship_type: \"has-role\"}) { id } } }"

    group_patch = "mutation GroupPatch($id: ID!, $input: [EditInput!]!) { groupEdit(id: $id) { fieldPatch(input: $input) { id name auto_new_marking } } }"

    def ensure_group(name: str, role: dict, auto_new_marking: bool) -> dict:
        group = groups.get(name)
        if group is None:
            group = graphql(admin_token, group_add, {"input": {"name": name, "description": "SIFT managed; do not edit", "default_assignation": False, "no_creators": True, "restrict_delete": True, "auto_new_marking": auto_new_marking, "group_confidence_level": {"max_confidence": 100, "overrides": []}}}, "group create")["groupAdd"]
            graphql(admin_token, group_role, {"groupId": group["id"], "roleId": role["id"]}, "group role add")
        else:
            current_roles = {
                edge["node"]["name"] for edge in group.get("roles", {}).get("edges", [])
            }
            if current_roles != {role["name"]}:
                fail(f"managed group {name} has unexpected role membership")
            if group.get("auto_new_marking") is not auto_new_marking:
                graphql(
                    admin_token,
                    group_patch,
                    {
                        "id": group["id"],
                        "input": [
                            {
                                "key": "auto_new_marking",
                                "value": [str(auto_new_marking).lower()],
                            }
                        ],
                    },
                    "group marking policy update",
                )
        return group

    worker_group = ensure_group("SIFT Workers", worker_role, True)
    query_group = ensure_group("SIFT MCP Readonly", query_role, False)
    connector_group = ensure_group("SIFT Public Feed Connectors", connector_role, True)
    markings_data = graphql(
        admin_token,
        "query { markingDefinitions(first: 100) { edges { node { id } } } }",
        operation="marking read",
    )
    marking_ids = {
        edge["node"]["id"] for edge in markings_data["markingDefinitions"]["edges"]
    }
    group_marking = "mutation GroupMarking($groupId: ID!, $markingId: ID!) { groupEdit(id: $groupId) { relationAdd(input: {toId: $markingId, relationship_type: \"accesses-to\"}) { id } } }"

    def ensure_existing_markings(group: dict) -> None:
        current = {item["id"] for item in group.get("allowed_marking", [])}
        for marking_id in sorted(marking_ids - current):
            graphql(
                admin_token,
                group_marking,
                {"groupId": group["id"], "markingId": marking_id},
                "group marking grant",
            )

    ensure_existing_markings(worker_group)
    ensure_existing_markings(connector_group)

    users_data = graphql(admin_token, "query { users(first: 500) { edges { node { id user_email groups { edges { node { id name default_assignation roles { edges { node { name capabilities { name } } } } } } } } } } }", operation="user read")
    users = {edge["node"]["user_email"]: edge["node"] for edge in users_data["users"]["edges"]}
    add = """mutation UserAdd($input: UserAddInput!) { userAdd(input: $input) { id user_email } }"""
    token_add = """mutation TokenAdd($userId: ID!, $input: UserTokenAddInput!) { userAdminTokenAdd(userId: $userId, input: $input) { plaintext_token } }"""

    def ensure(
        email: str, name: str, group: dict, token_key: str, token_store: dict[str, str]
    ) -> str:
        user = users.get(email)
        if user is None:
            user = graphql(admin_token, add, {"input": {"name": name, "user_email": email, "password": secrets.token_urlsafe(64), "groups": [group["id"]], "user_service_account": True}}, "user create")["userAdd"]
            # A fresh OpenCTI datastore invalidates any locally retained token
            # from a previous disposable deployment.
            token = ""
        else:
            current_groups = [
                edge["node"] for edge in user.get("groups", {}).get("edges", [])
            ]
            group_names = {item["name"] for item in current_groups}
            unexpected = group_names - {group["name"], "Default"}
            defaults = [item for item in current_groups if item["name"] == "Default"]
            default_caps = {
                capability["name"]
                for item in defaults
                for role_edge in item.get("roles", {}).get("edges", [])
                for capability in role_edge["node"].get("capabilities", [])
            }
            if (
                unexpected
                or group["name"] not in group_names
                or any(not item.get("default_assignation") for item in defaults)
                or default_caps - {"KNOWLEDGE"}
            ):
                fail(f"managed service account {email} has unexpected group membership")
            token = token_store.get(token_key, "")
        if not token:
            token = graphql(admin_token, token_add, {"userId": user["id"], "input": {"name": "sift-managed", "duration": "UNLIMITED"}}, "token create")["userAdminTokenAdd"]["plaintext_token"]
        me = graphql(token, "query { me { id user_email capabilities { name } } }", operation="token verify")["me"]
        if me["user_email"] != email:
            fail(f"stored token does not belong to {email}")
        names = {capability["name"] for capability in me.get("capabilities", [])}
        if "BYPASS" in names and group["name"] != "SIFT Workers":
            fail(f"non-worker service account {email} unexpectedly has BYPASS")
        return token

    # OpenCTI 7 officially requires workers to use a BYPASS administrator
    # identity. Keep it distinct from the bootstrap administrator for blast
    # radius and audit attribution; do not mislabel it as least privilege.
    if stack.get("OPENCTI_IDENTITIES_PROVISIONED") != "1":
        stack.pop("OPENCTI_WORKER_TOKEN", None)
        stack.pop("OPENCTI_QUERY_TOKEN", None)
    worker = ensure("sift-worker@sift.local", "SIFT OpenCTI Worker", worker_group, "OPENCTI_WORKER_TOKEN", stack)
    query = ensure("sift-query@sift.local", "SIFT OpenCTI Query", query_group, "OPENCTI_QUERY_TOKEN", stack)
    feed_specs = (
        ("mitre", "MITRE"),
        ("cisa-kev", "CISA_KEV"),
        ("threatfox", "THREATFOX"),
        ("urlhaus", "URLHAUS"),
    )
    feed_tokens: list[str] = []
    for slug, key_slug in feed_specs:
        token_key = f"OPENCTI_CONNECTOR_{key_slug}_TOKEN"
        token = ensure(
            f"sift-connector-{slug}@sift.local",
            f"SIFT {slug} Connector",
            connector_group,
            token_key,
            connectors,
        )
        connectors[token_key] = token
        connectors.setdefault(
            f"OPENCTI_CONNECTOR_{key_slug}_ID", str(__import__("uuid").uuid4())
        )
        feed_tokens.append(token)
    all_tokens = {admin_token, worker, query, *feed_tokens}
    if len(all_tokens) != 3 + len(feed_tokens):
        fail("OpenCTI admin, worker, query, and connector tokens must be distinct")
    stack["OPENCTI_WORKER_TOKEN"] = worker
    stack["OPENCTI_QUERY_TOKEN"] = query
    stack["OPENCTI_IDENTITIES_PROVISIONED"] = "1"
    atomic_env(stack_path, stack, 0, 0)
    atomic_env(connectors_path, connectors, 0, 0)
    import pwd
    account = pwd.getpwnam(os.environ.get("SIFT_GATEWAY_SERVICE_USER", "sift-service"))
    atomic_env(query_path, {"SIFT_OPENCTI_URL": "http://127.0.0.1:8080", "SIFT_OPENCTI_TOKEN": query}, account.pw_uid, account.pw_gid)
    print("Distinct OpenCTI worker, query-only, and public-feed identities provisioned.")


if __name__ == "__main__":
    main()
