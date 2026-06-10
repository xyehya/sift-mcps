#!/usr/bin/env python3
"""Validate the trimmed MVP migration documentation model.

The migration docs now have two active files:

    task-batches.md
    Session-Notes.md

This script is the executable governance check for that model. Fix the docs,
not the parser, unless the operating model itself intentionally changes.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

DOCS = Path(os.environ.get("MIG_DOCS") or (Path(__file__).resolve().parent.parent / "docs" / "migration"))
BATCHES = DOCS / "task-batches.md"
NOTES = DOCS / "Session-Notes.md"
ALLOWED_DOCS = {"task-batches.md", "Session-Notes.md"}
errors: list[str] = []


def err(rule: str, msg: str) -> None:
    errors.append(f"[{rule}] {msg}")


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        err("io", f"{path.name}: cannot read ({exc})")
        return ""


def section(text: str, header: str) -> str:
    out: list[str] = []
    grab = False
    for line in text.splitlines():
        if line.strip() == header:
            grab = True
            continue
        if grab and line.startswith("## "):
            break
        if grab:
            out.append(line)
    return "\n".join(out)


def check_file_set() -> None:
    try:
        names = {path.name for path in DOCS.iterdir() if path.is_file()}
    except OSError as exc:
        err("DOCS-io", f"{DOCS}: cannot list ({exc})")
        return
    extra = sorted(names - ALLOWED_DOCS)
    missing = sorted(ALLOWED_DOCS - names)
    if extra:
        err("DOCS-set", f"docs/migration has unsupported files: {extra}")
    if missing:
        err("DOCS-set", f"docs/migration is missing required files: {missing}")


def check_batches() -> None:
    text = read(BATCHES)
    if not text:
        return
    if "## Batch Index" not in text:
        err("BATCH-head", "task-batches.md missing '## Batch Index'")
    batch_ids = re.findall(r"^- \[[ xX]\] (BATCH-[A-Z0-9]+) - .+$", text, re.M)
    if not batch_ids:
        err("BATCH-list", "task-batches.md has no grep-friendly batch checkboxes")
    duplicates = sorted({batch_id for batch_id in batch_ids if batch_ids.count(batch_id) > 1})
    if duplicates:
        err("BATCH-id", f"duplicate batch ids in Batch Index: {duplicates}")
    for batch_id in batch_ids:
        if f"## {batch_id} -" not in text:
            err("BATCH-section", f"{batch_id} has no matching details section")
    for heading in ("Dependencies:", "Scope:", "Exact work:", "Acceptance:"):
        if heading not in text:
            err("BATCH-contract", f"task-batches.md missing '{heading}' sections")


def check_notes() -> None:
    text = read(NOTES)
    if not text:
        return
    for heading in ("## Current Change Log",):
        if heading not in text:
            err("NOTE-head", f"Session-Notes.md missing heading '{heading}'")
    entries = re.findall(r"^### \d{4}-\d{2}-\d{2} - .+$", section(text, "## Current Change Log"), re.M)
    if not entries:
        err("NOTE-entry", "Session-Notes.md has no dated change entry")
    for marker in ("Status:", "Changed:", "Validation:", "Next:"):
        if marker not in text:
            err("NOTE-entry", f"Session-Notes.md missing marker '{marker}'")
    if "## Forks / Backlog / Needs Input" in text:
        row_ids = re.findall(
            r"^\|\s*((?:F|B)-MVP-\d+)\s*\|",
            section(text, "## Forks / Backlog / Needs Input"),
            re.M,
        )
        duplicates = sorted({row_id for row_id in row_ids if row_ids.count(row_id) > 1})
        if duplicates:
            err("NOTE-id", f"duplicate fork/backlog ids: {duplicates}")
        if re.search(r"^\|\s*F-MVP-\d+\s*\|\s*Fork\s*\|\s*OPEN\s*\|", text, re.M):
            err("NOTE-open", "Session-Notes.md has unresolved F-MVP fork rows")


def main() -> int:
    check_file_set()
    check_batches()
    check_notes()
    for message in errors:
        print("ERROR " + message)
    if errors:
        print(f"\nFAILED - {len(errors)} violation(s). Fix the MVP migration docs.")
        return 1
    print("OK - MVP migration docs conform to the trimmed two-file model.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
