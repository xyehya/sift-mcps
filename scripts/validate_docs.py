#!/usr/bin/env python3
"""Validate the simplified MVP migration documentation model.

The migration docs now have three active files:

    Migration-Spec.md
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
SPEC = DOCS / "Migration-Spec.md"
BATCHES = DOCS / "task-batches.md"
NOTES = DOCS / "Session-Notes.md"
ALLOWED_DOCS = {"Migration-Spec.md", "task-batches.md", "Session-Notes.md"}
SPEC_HEADINGS = [
    "## 1. OBJECTIVE & SCOPE",
    "## 2. ARCHITECTURE & DATA FLOW",
    "## 3. STEP-BY-STEP MIGRATION JOURNEY",
    "## 4. TECHNICAL CONSTRAINTS & GROUNDING RULES",
    "## 5. DEFINITION OF DONE (DoD)",
]
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


def check_spec() -> None:
    text = read(SPEC)
    if not text:
        return
    for heading in SPEC_HEADINGS:
        if heading not in text:
            err("SPEC-head", f"Migration-Spec.md missing heading '{heading}'")
    if "```mermaid" not in text:
        err("SPEC-arch", "Migration-Spec.md must include the architecture diagram as a Mermaid block")
    for phrase in (
        "Supabase/Postgres",
        "Gateway is the only policy boundary",
        "Evidence must be registered and sealed before analysis",
        "Reports include approved findings",
    ):
        if phrase not in text:
            err("SPEC-invariant", f"Migration-Spec.md missing invariant phrase: {phrase!r}")


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
    for heading in ("## Current Change Log", "## Forks / Backlog / Needs Input"):
        if heading not in text:
            err("NOTE-head", f"Session-Notes.md missing heading '{heading}'")
    entries = re.findall(r"^### \d{4}-\d{2}-\d{2} - .+$", section(text, "## Current Change Log"), re.M)
    if not entries:
        err("NOTE-entry", "Session-Notes.md has no dated change entry")
    for marker in ("Status:", "Changed:", "Validation:", "Next:"):
        if marker not in text:
            err("NOTE-entry", f"Session-Notes.md missing marker '{marker}'")
    row_ids = re.findall(r"^\|\s*((?:F|B)-MVP-\d+)\s*\|", section(text, "## Forks / Backlog / Needs Input"), re.M)
    if not row_ids:
        err("NOTE-table", "Session-Notes.md has no F-MVP/B-MVP rows")
    duplicates = sorted({row_id for row_id in row_ids if row_ids.count(row_id) > 1})
    if duplicates:
        err("NOTE-id", f"duplicate fork/backlog ids: {duplicates}")
    if re.search(r"^\|\s*F-MVP-\d+\s*\|\s*Fork\s*\|\s*OPEN\s*\|", text, re.M):
        err("NOTE-open", "Session-Notes.md has unresolved F-MVP fork rows")


def main() -> int:
    check_file_set()
    check_spec()
    check_batches()
    check_notes()
    for message in errors:
        print("ERROR " + message)
    if errors:
        print(f"\nFAILED - {len(errors)} violation(s). Fix the MVP migration docs.")
        return 1
    print("OK - MVP migration docs conform to the simplified three-file model.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
