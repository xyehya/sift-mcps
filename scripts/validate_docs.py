#!/usr/bin/env python3
"""Enforce the [V] rules in docs/migration/CONVENTIONS.md.

These docs are parsed by tooling (dashboards, other agents), so their structure
is a contract. This script is the executable form of that contract and is a
Definition-of-Done gate. Fix the doc, not the parser.

Stdlib only. Usage:
    python3 scripts/validate_docs.py
    MIG_DOCS=/path/to/docs/migration python3 scripts/validate_docs.py   # override

Exit 0 = contract holds; 1 = violations (printed). Each message cites the
CONVENTIONS rule it enforces.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

DOCS = Path(os.environ.get("MIG_DOCS") or (Path(__file__).resolve().parent.parent / "docs" / "migration"))
STATE = DOCS / "MIGRATION_STATE.md"
REGISTER = DOCS / "REGISTER.md"
CHARTER = DOCS / "00_migration_charter.md"

FORK_STATUS = {"OPEN", "RESOLVED"}
BACKLOG_STATUS = {"OPEN", "DONE"}
FORK_COLS = 7
BACKLOG_COLS = 5
errors: list[str] = []


def err(rule: str, msg: str) -> None:
    errors.append(f"[{rule}] {msg}")


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        err("io", f"{path.name}: cannot read ({exc})")
        return ""


def clean(cell: str) -> str:
    return cell.replace("**", "").replace("`", "").strip()


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


def rows(block: str, prefix: str) -> list[list[str]]:
    result = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith(f"| {prefix}"):
            result.append([clean(cell) for cell in stripped.split("|")[1:-1]])
    return result


def check_register() -> None:
    text = read(REGISTER)
    if not text:
        return

    for heading in ("## Forks (F#)", "## Backlog (B#)"):
        if heading not in text:
            err("REG-head", f"REGISTER.md missing heading '{heading}'")

    seen_f: set[str] = set()
    becomes_b: list[str] = []
    for cells in rows(section(text, "## Forks (F#)"), "F-"):
        fid = cells[0] if cells else "?"
        if len(cells) != FORK_COLS:
            err("REG-F", f"fork {fid}: {len(cells)} cols, need {FORK_COLS} (ID|Question|Raised|Status|Decision|Becomes|Affects)")
            continue
        if fid in seen_f:
            err("REG-id", f"duplicate fork {fid}")
        seen_f.add(fid)
        status = cells[3].upper()
        decision = cells[4].strip()
        becomes = cells[5].strip()
        if status not in FORK_STATUS:
            err("REG-F", f"fork {fid}: Status '{cells[3]}' not in {sorted(FORK_STATUS)}")
        if status == "OPEN" and (decision or becomes):
            err("REG-F", f"fork {fid}: OPEN but Decision/Becomes is not empty")
        if status == "RESOLVED" and not decision:
            err("REG-F", f"fork {fid}: RESOLVED but Decision is empty")
        if status == "RESOLVED" and not becomes:
            err("REG-F", f"fork {fid}: RESOLVED but Becomes is empty")
        if status == "RESOLVED" and not re.search(r"\b(D\d+[a-z]?|B-\d+|rejected)\b", becomes, re.I):
            err("REG-F", f"fork {fid}: RESOLVED Becomes must cite D#, B#, or rejected")
        becomes_b += re.findall(r"B-\d+", becomes)
    if not seen_f:
        err("REG-F", "no fork rows ('| F-<n> |')")

    seen_b: set[str] = set()
    for cells in rows(section(text, "## Backlog (B#)"), "B-"):
        bid = cells[0] if cells else "?"
        if len(cells) != BACKLOG_COLS:
            err("REG-B", f"backlog {bid}: {len(cells)} cols, need {BACKLOG_COLS} (ID|Deferred work|Source|Status|Do-by)")
            continue
        if bid in seen_b:
            err("REG-id", f"duplicate backlog {bid}")
        seen_b.add(bid)
        if cells[3].upper() not in BACKLOG_STATUS:
            err("REG-B", f"backlog {bid}: Status '{cells[3]}' not in {sorted(BACKLOG_STATUS)}")
    if not seen_b:
        err("REG-B", "no backlog rows ('| B-<n> |')")

    for ref in becomes_b:
        if ref not in seen_b:
            err("REG-xref", f"a fork 'becomes {ref}' but no such backlog row exists")


def check_state() -> None:
    text = read(STATE)
    if not text:
        return

    objective_count = len(re.findall(r"^## Current Objective\s*$", text, re.M))
    if objective_count != 1:
        err("ST-obj", f"MIGRATION_STATE.md: expected exactly one '## Current Objective', found {objective_count}")
    if not re.search(r"\*\*Next:?\*\*", section(text, "## Current Objective")):
        err("ST-next", "MIGRATION_STATE.md: Current Objective has no '**Next:**' line")
    next_markers = re.findall(r"\*\*Next:?\*\*", text)
    if len(next_markers) != 1:
        err("ST-next", f"MIGRATION_STATE.md: expected exactly one global '**Next:**' marker, found {len(next_markers)}")
    if re.search(r"^## Next Recommended Run\s*$", text, re.M):
        err("ST-next", "MIGRATION_STATE.md: standalone '## Next Recommended Run' section is not allowed")

    run_numbers = [int(number) for number in re.findall(r"^## Run (\d+)\s*[-–—]\s*.+$", text, re.M)]
    if not run_numbers:
        err("ST-run", "MIGRATION_STATE.md: no '## Run <n> - <title>' headers")
    duplicates = sorted({number for number in run_numbers if run_numbers.count(number) > 1})
    if duplicates:
        err("ST-run", f"MIGRATION_STATE.md: duplicate run numbers {duplicates}")


def check_charter() -> None:
    text = read(CHARTER)
    if not text:
        return

    decision_ids = re.findall(r"^\|\s*(D\d+[ab]?)\s*\|", text, re.M)
    if not decision_ids:
        err("CH-D", "00_migration_charter.md: no decision rows ('| D<n> |')")
    duplicates = sorted({decision_id for decision_id in decision_ids if decision_ids.count(decision_id) > 1})
    if duplicates:
        err("CH-id", f"00_migration_charter.md: duplicate decision ids {duplicates}")
    if "## Cutover Order" not in text:
        err("CH-cut", "00_migration_charter.md: no '## Cutover Order' section")
    if "## Current Migration Status" in text:
        err("CH-state", "00_migration_charter.md: charter must not carry volatile '## Current Migration Status'")
    if re.search(r"\bNext planned session\b|\bnext recommended\b", text, re.I):
        err("CH-state", "00_migration_charter.md: charter must not carry next-session handoff text")


def main() -> int:
    check_register()
    check_state()
    check_charter()
    for message in errors:
        print("ERROR " + message)
    if errors:
        print(f"\nFAILED - {len(errors)} violation(s). Fix the docs to match CONVENTIONS.md.")
        return 1
    print("OK - docs conform to CONVENTIONS.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
