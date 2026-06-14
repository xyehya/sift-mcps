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
        # Added — media/device destruction (P2.1)
        "wipefs",
        "shred",
        "blkdiscard",
        "sgdisk",
        "parted",
        "mkswap",
        "cryptsetup",
        "dmsetup",
        "hdparm",
        # Added — nested interpreters (P0.3)
        "sh",
        "bash",
        "dash",
        "zsh",
        "python",
        "python3",
        "perl",
        "ruby",
        "xargs",
        "nohup",
        "timeout",
        "stdbuf",
        # Added — additional interpreters / shell-escape vectors. These have no
        # legitimate non-interactive forensic use and each can spawn a shell or
        # execute arbitrary code (interpreters), or shell out via '!' (pagers /
        # editors, which also hang without a TTY).
        "node",
        "nodejs",
        "php",
        "lua",
        "luajit",
        "tclsh",
        "wish",
        "expect",
        "gdb",
        "lldb",
        "vi",
        "vim",
        "view",
        "nano",
        "ed",
        "ex",
        "emacs",
        "less",
        "more",
        "pg",
        "man",
        "watch",
        "script",
        "screen",
        "tmux",
    }
)

# BATCH-I1: a tight MVP allowlist of forensic tools an operator can opt into by
# setting `execute.security.mode: allowlist` and
# `execute.security.allowed_binaries: <this set>` (or a subset) in gateway.yaml.
# It is intentionally read-only / inspection-oriented: imaging and acquisition
# tooling (dd/dc3dd/mount/losetup/fdisk) is excluded because operators perform
# acquisition outside the agent session. The hardcoded DENY_FLOOR still applies
# on top of any allowlist, so an entry here can never re-enable a denied binary.
MVP_FORENSIC_ALLOWLIST = frozenset(
    {
        # Sleuth Kit / filesystem forensics (read-only inspection)
        "mmls",
        "fls",
        "fsstat",
        "istat",
        "ifind",
        "icat",
        "img_stat",
        "blkcat",
        "fcat",
        "tsk_recover",
        "mactime",
        "sorter",
        "sigfind",
        # Registry / Windows artifacts
        "rip.pl",
        "regripper",
        "evtx_dump",
        "evtxexport",
        "hayabusa",
        # Zimmerman EZ Tools (installed at /opt/zimmermantools, run natively via dotnet)
        # Invocable without extension — e.g. `evtxecmd --help` not `EvtxECmd.exe`
        "EvtxECmd",
        "evtxecmd",
        "MFTECmd",
        "mftecmd",
        "RECmd",
        "recmd",
        "PECmd",
        "pecmd",
        "AmcacheParser",
        "amcacheparser",
        "AppCompatCacheParser",
        "appcompatcacheparser",
        "JLECmd",
        "jlecmd",
        "LECmd",
        "lecmd",
        "SBECmd",
        "sbecmd",
        "RBCmd",
        "rbcmd",
        "SrumECmd",
        "srumecmd",
        "SQLECmd",
        "sqlecmd",
        "bstrings",
        "WxTCmd",
        "wxtcmd",
        # Strings / carving / signatures
        "strings",
        "bstrings",
        "bulk_extractor",
        "foremost",
        "scalpel",
        "binwalk",
        "yara",
        # Hashing / inspection
        "sha256sum",
        "sha1sum",
        "md5sum",
        "b2sum",
        "file",
        "stat",
        "xxd",
        "hexdump",
        "od",
        "exiftool",
        # Text / search (no shell-out flags; blocked flags enforced separately)
        "cat",
        "head",
        "tail",
        "grep",
        "egrep",
        "fgrep",
        "zgrep",
        "rg",
        "sort",
        "uniq",
        "wc",
        "cut",
        "tr",
        "awk",
        "sed",
        "find",
        "ls",
        "tree",
        "date",
        "echo",
        # Archives (read-only listing; mutating flags blocked per-tool)
        "tar",
        "unzip",
        "zipinfo",
        "7z",
        # EWF (Expert Witness) image inspection/extraction — read-only probes
        # plus export into the case write-jail (AUT2-B5 disk triage path).
        "ewfinfo",
        "ewfverify",
        "ewfexport",
        # Memory / network forensics
        "vol",
        "vol3",
        "volatility3",
        "tshark",
        "tcpdump",
        # Threat intel fetch (read-only; upload flags blocked per-tool)
        "curl",
        "wget",
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
        # grep -e PATTERN (pattern) and -E (extended regex) are harmless and
        # ubiquitous in forensic pipelines. They are not exec flags. The flag
        # validator lowercases, so allowing "-e" also clears "-E". egrep is the
        # -E alias and gets the same allowance.
        "grep": ["-e", "-E"],
        "egrep": ["-e", "-E"],
        "zgrep": ["-e", "-E"],
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
        # curl: block all upload/post flags — prevents exfiltration of evidence or
        # case files to external hosts. Read-only fetches (threat intel lookups) remain
        # allowed. -o/--output is already in output_flags and path-validated.
        "curl": [
            "-d", "--data", "--data-raw", "--data-binary",
            "--data-ascii", "--data-urlencode", "--data-urlencode",
            "-F", "--form", "--form-string",
            "-T", "--upload-file",
            "--json",
        ],
        # wget: block post/upload equivalents
        "wget": [
            "--post-data", "--post-file",
            "--method",
        ],
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


def _expand_allowlist_tokens(values: list[str]) -> list[str]:
    """Expand the ``@mvp_forensic`` alias into the tight MVP forensic allowlist.

    Lets an operator opt into the curated set with a single token in
    gateway.yaml (``allowed_binaries: ["@mvp_forensic"]``) instead of pasting
    ~70 binary names, while still allowing extra explicit entries alongside it.
    """
    expanded: list[str] = []
    for value in values:
        if value.strip().lower() == "@mvp_forensic":
            expanded.extend(sorted(MVP_FORENSIC_ALLOWLIST))
        else:
            expanded.append(value)
    return expanded


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
            _expand_allowlist_tokens(
                _as_list(base.get("allowed_binaries"), name="allowed_binaries")
                + _as_list(operator.get("allowed_binaries"), name="allowed_binaries")
            )
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
