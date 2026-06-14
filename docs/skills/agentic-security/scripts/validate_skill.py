#!/usr/bin/env python3
"""Validate basic Agent Skills packaging constraints without external dependencies."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def parse_frontmatter(skill_md: Path) -> tuple[dict[str, Any], str]:
    text = skill_md.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md must start with YAML frontmatter delimiter ---")
    end = text.find("\n---", 4)
    if end == -1:
        raise ValueError("SKILL.md frontmatter must end with ---")
    front = text[4:end].strip("\n")
    body = text[end + 4:].lstrip("\n")
    data: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(0, data)]
    for raw in front.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        key_value = raw.strip()
        if ":" not in key_value:
            raise ValueError(f"Unsupported frontmatter line: {raw}")
        key, value = key_value.split(":", 1)
        key = key.strip()
        value = value.strip()
        while stack and indent < stack[-1][0]:
            stack.pop()
        current = stack[-1][1]
        if value == "":
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent + 2, child))
        else:
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            current[key] = value
    return data, body


def validate(root: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    skill_md = root / "SKILL.md"
    if not skill_md.exists():
        return ["Missing SKILL.md"], warnings
    try:
        fm, body = parse_frontmatter(skill_md)
    except Exception as exc:  # noqa: BLE001 - validator should report all user-friendly errors
        return [f"Invalid frontmatter: {exc}"], warnings

    name = str(fm.get("name", ""))
    desc = str(fm.get("description", ""))
    compatibility = fm.get("compatibility")

    if not name:
        errors.append("Missing required frontmatter field: name")
    elif not NAME_RE.fullmatch(name):
        errors.append("name must use lowercase letters, numbers, and single hyphens only")
    elif len(name) > 64:
        errors.append("name must be at most 64 characters")
    elif root.name != name:
        errors.append(f"name must match parent directory name: expected {root.name!r}, got {name!r}")

    if not desc:
        errors.append("Missing required frontmatter field: description")
    elif len(desc) > 1024:
        errors.append(f"description is {len(desc)} characters; max is 1024")

    if compatibility is not None:
        comp = str(compatibility)
        if not comp or len(comp) > 500:
            errors.append("compatibility must be 1-500 characters when present")

    # Common anti-injection hardening for frontmatter.
    for key in ("name", "description", "compatibility"):
        value = str(fm.get(key, ""))
        if "<" in value or ">" in value:
            warnings.append(f"frontmatter field {key!r} contains angle brackets; avoid them in skill metadata")

    body_lines = body.splitlines()
    if len(body_lines) > 500:
        warnings.append(f"SKILL.md body has {len(body_lines)} lines; recommended max is 500")
    approx_tokens = max(1, len(body.split()) * 4 // 3)
    if approx_tokens > 5000:
        warnings.append(f"SKILL.md body is approximately {approx_tokens} tokens; recommended max is 5000")

    for dirname in ("scripts", "references", "assets"):
        p = root / dirname
        if p.exists() and not p.is_dir():
            errors.append(f"{dirname} exists but is not a directory")

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a local Agent Skill folder.")
    parser.add_argument("path", nargs="?", default=".", help="Skill directory path")
    args = parser.parse_args()
    root = Path(args.path).expanduser().resolve()
    errors, warnings = validate(root)
    if warnings:
        print("Warnings:")
        for warning in warnings:
            print(f"  - {warning}")
    if errors:
        print("Errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"OK: {root} looks like a valid Agent Skill folder")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
