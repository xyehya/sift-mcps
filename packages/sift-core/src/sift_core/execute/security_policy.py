"""Executor security policy merging for SIFT run_command."""

from __future__ import annotations

import fnmatch
import json
import os
from copy import deepcopy
from typing import Any


SECURITY_POLICY_ENV = "SIFT_EXECUTE_SECURITY_POLICY"

DENY_FLOOR = frozenset(
    {
        "mkfs",
        "mkfs.*",
        "shutdown",
        "reboot",
        "poweroff",
        "halt",
        "init",
        "kill",
        "killall",
        "pkill",
        "env",
        "printenv",
        "nc",
        "ncat",
        "socat",
    }
)

DEFAULT_SECURITY_POLICY: dict[str, Any] = {
    "mode": "denylist",
    "allowed_binaries": [],
    "dangerous_flags": [
        "-e",
        "--exec",
        "--command",
        "-enc",
        "-encodedcommand",
        "--script",
        "--invoke",
    ],
    "tool_allowed_flags": {
        "run_bulk_extractor": ["-e", "-x"],
    },
    "tool_blocked_flags": {
        "find": ["-exec", "-execdir", "-delete", "-fls", "-fprint", "-fprint0", "-fprintf"],
        "sed": ["-i", "--in-place"],
        "tar": [
            "-x",
            "--extract",
            "--get",
            "-c",
            "--create",
            "--delete",
            "--append",
            "--checkpoint-action",
            "--use-compress-program",
            "--to-command",
        ],
        "unzip": ["-o", "-n"],
    },
    "output_flags": ["--csv", "--csvf", "-o", "--output", "--json", "--jsonl"],
    "denied_binaries": sorted(DENY_FLOOR),
}


def _as_list(value: Any, *, name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"execute.security.{name} must be a list of strings")
    return value


def _as_map(value: Any, *, name: str) -> dict[str, list[str]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"execute.security.{name} must be a mapping")
    result: dict[str, list[str]] = {}
    for key, items in value.items():
        if not isinstance(key, str):
            raise ValueError(f"execute.security.{name} keys must be strings")
        result[key] = _as_list(items, name=f"{name}.{key}")
    return result


def _dedupe_lower(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = value.lower()
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _merge_maps(base: dict[str, list[str]], overlay: dict[str, list[str]]) -> dict[str, list[str]]:
    result = {str(k): list(v) for k, v in base.items()}
    for key, values in overlay.items():
        result[key] = _dedupe_lower(result.get(key, []) + values)
    return result


def build_security_policy(
    operator_policy: dict[str, Any] | None = None,
    *,
    require_operator_policy: bool = False,
) -> dict[str, Any]:
    """Build the effective executor security policy.

    The operator-editable policy can only add restrictions. The hardcoded deny
    floor is always included, even when an operator omits or removes those
    entries from gateway.yaml.
    """
    if operator_policy is None:
        if require_operator_policy:
            raise ValueError("execute.security is required in gateway.yaml")
        operator_policy = deepcopy(DEFAULT_SECURITY_POLICY)
    elif not isinstance(operator_policy, dict):
        raise ValueError("execute.security must be a mapping")
    elif require_operator_policy and not operator_policy:
        raise ValueError("execute.security cannot be empty")

    base = deepcopy(DEFAULT_SECURITY_POLICY)
    operator = deepcopy(operator_policy)
    mode = str(operator.get("mode") or base["mode"]).strip().lower()
    if mode not in {"denylist", "allowlist"}:
        raise ValueError("execute.security.mode must be 'denylist' or 'allowlist'")

    policy = {
        "mode": mode,
        "allowed_binaries": _dedupe_lower(
            _as_list(base.get("allowed_binaries"), name="allowed_binaries")
            + _as_list(operator.get("allowed_binaries"), name="allowed_binaries")
        ),
        "dangerous_flags": _dedupe_lower(
            _as_list(base.get("dangerous_flags"), name="dangerous_flags")
            + _as_list(operator.get("dangerous_flags"), name="dangerous_flags")
        ),
        "tool_allowed_flags": _merge_maps(
            _as_map(base.get("tool_allowed_flags"), name="tool_allowed_flags"),
            _as_map(operator.get("tool_allowed_flags"), name="tool_allowed_flags"),
        ),
        "tool_blocked_flags": _merge_maps(
            _as_map(base.get("tool_blocked_flags"), name="tool_blocked_flags"),
            _as_map(operator.get("tool_blocked_flags"), name="tool_blocked_flags"),
        ),
        "output_flags": _dedupe_lower(
            _as_list(base.get("output_flags"), name="output_flags")
            + _as_list(operator.get("output_flags"), name="output_flags")
        ),
        "denied_binaries": _dedupe_lower(
            list(DENY_FLOOR)
            + _as_list(base.get("denied_binaries"), name="denied_binaries")
            + _as_list(operator.get("denied_binaries"), name="denied_binaries")
        ),
    }
    if not policy["denied_binaries"]:
        raise ValueError("execute.security.denied_binaries cannot be empty")
    if mode == "allowlist" and not policy["allowed_binaries"]:
        raise ValueError("execute.security.allowed_binaries is required in allowlist mode")
    return policy


def policy_to_env_json(policy: dict[str, Any]) -> str:
    return json.dumps(policy, sort_keys=True, separators=(",", ":"))


def load_policy_from_env() -> dict[str, Any] | None:
    raw = os.environ.get(SECURITY_POLICY_ENV)
    if not raw:
        return None
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{SECURITY_POLICY_ENV} contains invalid JSON") from exc
    return build_security_policy(doc)


def matches_denied_binary(binary_name: str, denied_binaries: set[str] | frozenset[str]) -> bool:
    binary = binary_name.lower()
    return any(fnmatch.fnmatchcase(binary, pattern.lower()) for pattern in denied_binaries)


def matches_allowed_binary(binary_name: str, allowed_binaries: set[str] | frozenset[str]) -> bool:
    binary = binary_name.lower()
    return any(fnmatch.fnmatchcase(binary, pattern.lower()) for pattern in allowed_binaries)
