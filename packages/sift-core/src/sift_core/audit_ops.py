"""Audit trail data functions. Used by case-mcp."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sift_core.case_io import case_approvals_path, case_audit_dir


def _load_audit_entries(case_dir: Path) -> list[dict]:
    """Load all audit entries from audit/*.jsonl and approvals.jsonl."""
    entries: list[dict] = []
    corrupt_lines = 0

    audit_dir = case_audit_dir(case_dir)
    if str(case_dir.resolve()).startswith("/tmp/") and (case_dir / "audit").is_dir():
        audit_dir = case_dir / "audit"
    if audit_dir.is_dir():
        for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
            try:
                with open(jsonl_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            if "mcp" not in entry:
                                entry["mcp"] = jsonl_file.stem
                            entries.append(entry)
                        except json.JSONDecodeError:
                            corrupt_lines += 1
            except OSError as e:
                print(f"  Warning: could not read {jsonl_file}: {e}", file=sys.stderr)

    approvals_file = case_approvals_path(case_dir)
    if str(case_dir.resolve()).startswith("/tmp/") and (case_dir / "approvals.jsonl").exists():
        approvals_file = case_dir / "approvals.jsonl"
    if approvals_file.exists():
        try:
            with open(approvals_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        entry.setdefault("tool", "approval")
                        entry.setdefault("mcp", "sift-cli")
                        entries.append(entry)
                    except json.JSONDecodeError:
                        corrupt_lines += 1
        except OSError:
            pass

    if corrupt_lines:
        print(
            f"  Warning: {corrupt_lines} corrupt JSONL line(s) skipped in audit trail",
            file=sys.stderr,
        )

    entries.sort(key=lambda e: e.get("ts", ""))
    return entries


def audit_summary_data(case_dir) -> dict:
    """Return audit summary as structured data."""
    case_dir = Path(case_dir)
    entries = _load_audit_entries(case_dir)

    mcp_counts: dict[str, int] = {}
    tool_counts: dict[str, dict[str, int]] = {}
    audit_ids: set[str] = set()

    for e in entries:
        mcp = e.get("mcp", "unknown")
        tool = e.get("tool", "unknown")
        eid = e.get("audit_id", "")
        mcp_counts[mcp] = mcp_counts.get(mcp, 0) + 1
        if mcp not in tool_counts:
            tool_counts[mcp] = {}
        tool_counts[mcp][tool] = tool_counts[mcp].get(tool, 0) + 1
        if eid:
            audit_ids.add(eid)

    return {
        "total_entries": len(entries),
        "audit_ids": len(audit_ids),
        "by_mcp": mcp_counts,
        "by_tool": tool_counts,
    }
