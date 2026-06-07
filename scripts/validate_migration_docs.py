#!/usr/bin/env python3
"""Validate the load-bearing structure of the SIFT migration docs.

These documents are not just prose: downstream tooling (e.g. the Migration
Mission Control dashboard) parses them mechanically. This script is the
executable expression of the "Machine-readable conventions (load-bearing)"
contract in `OPERATING_MODEL.md`. If it fails, the docs have drifted away from
a shape tools depend on — fix the doc, not the parser.

Stdlib only. Run from anywhere:

    python3 scripts/validate_migration_docs.py

Exit code 0 = contract holds; 1 = one or more violations (printed).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs" / "migration"
STATE = DOCS / "MIGRATION_STATE.md"
REGISTER = DOCS / "REGISTER.md"
CHARTER = DOCS / "00_migration_charter.md"

# Allowed Status vocabularies (case-insensitive, ** stripped).
FORK_STATUS = {"OPEN", "RESOLVED"}
BACKLOG_STATUS = {"OPEN", "DONE"}

FORK_COLS = 7      # ID | Question | Raised | Status | Decision | Becomes | Affects
BACKLOG_COLS = 5   # ID | Deferred work | Source | Status | Do-by

errors: list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        err(f"{path.name}: cannot read ({exc})")
        return None


def clean(cell: str) -> str:
    return cell.replace("**", "").replace("`", "").strip()


def section(text: str, header: str) -> str:
    """Return text from a '## header' line up to the next '## ' line."""
    lines = text.splitlines()
    out: list[str] = []
    grabbing = False
    for line in lines:
        if line.strip() == header:
            grabbing = True
            continue
        if grabbing and line.startswith("## "):
            break
        if grabbing:
            out.append(line)
    return "\n".join(out)


def table_rows(block: str, id_prefix: str) -> list[tuple[int, list[str]]]:
    rows = []
    for i, line in enumerate(block.splitlines()):
        t = line.strip()
        if not t.startswith(f"| {id_prefix}"):
            continue
        cells = [clean(c) for c in t.split("|")[1:-1]]
        rows.append((i, cells))
    return rows


# ---------------------------------------------------------------- REGISTER
def check_register() -> None:
    text = read(REGISTER)
    if text is None:
        return

    for header in ("## Forks (F#)", "## Backlog (B#)"):
        if header not in text:
            err(f"REGISTER.md: missing required section '{header}'")

    # Forks
    fblock = section(text, "## Forks (F#)")
    frows = table_rows(fblock, "F-")
    if not frows:
        err("REGISTER.md: no fork rows ('| F-<n> | ...') found")
    seen_f = set()
    fork_becomes_b: list[str] = []
    for _, cells in frows:
        fid = cells[0] if cells else "?"
        if len(cells) != FORK_COLS:
            err(f"REGISTER.md fork {fid}: expected {FORK_COLS} columns, got {len(cells)} "
                f"(ID|Question|Raised|Status|Decision|Becomes|Affects)")
            continue
        if fid in seen_f:
            err(f"REGISTER.md: duplicate fork id {fid}")
        seen_f.add(fid)
        status = cells[3].upper()
        if status not in FORK_STATUS:
            err(f"REGISTER.md fork {fid}: Status '{cells[3]}' not in {sorted(FORK_STATUS)}")
        decision = cells[4].strip()
        becomes = cells[5].strip()
        if status == "OPEN" and (decision or becomes):
            err(f"REGISTER.md fork {fid}: OPEN but Decision/Becomes is not empty")
        if status == "RESOLVED" and not decision:
            err(f"REGISTER.md fork {fid}: RESOLVED but Decision column is empty")
        if status == "RESOLVED" and not becomes:
            err(f"REGISTER.md fork {fid}: RESOLVED but 'Becomes' is empty")
        if status == "RESOLVED" and not re.search(r"\b(D\d+[a-z]?|B-\d+|rejected)\b", becomes, re.I):
            err(f"REGISTER.md fork {fid}: RESOLVED Becomes must cite D#, B#, or rejected")
        for m in re.findall(r"B-\d+", cells[5]):
            fork_becomes_b.append(m)

    # Backlog
    bblock = section(text, "## Backlog (B#)")
    brows = table_rows(bblock, "B-")
    if not brows:
        err("REGISTER.md: no backlog rows ('| B-<n> | ...') found")
    seen_b = set()
    for _, cells in brows:
        bid = cells[0] if cells else "?"
        if len(cells) != BACKLOG_COLS:
            err(f"REGISTER.md backlog {bid}: expected {BACKLOG_COLS} columns, got {len(cells)} "
                f"(ID|Deferred work|Source|Status|Do-by)")
            continue
        if bid in seen_b:
            err(f"REGISTER.md: duplicate backlog id {bid}")
        seen_b.add(bid)
        if cells[3].upper() not in BACKLOG_STATUS:
            err(f"REGISTER.md backlog {bid}: Status '{cells[3]}' not in {sorted(BACKLOG_STATUS)}")

    # Cross-ref: a fork that 'becomes B-n' must point at a real backlog row.
    for ref in fork_becomes_b:
        if ref not in seen_b:
            err(f"REGISTER.md: a fork references '{ref}' which has no backlog row")


# ----------------------------------------------------------- MIGRATION_STATE
def check_state() -> None:
    text = read(STATE)
    if text is None:
        return

    objs = re.findall(r"^## Current Objective\s*$", text, re.M)
    if len(objs := objs) != 1:
        err(f"MIGRATION_STATE.md: expected exactly one '## Current Objective' H2, found {len(objs)}")

    obj_block = section(text, "## Current Objective")
    if not re.search(r"\*\*Next:?\*\*", obj_block):
        err("MIGRATION_STATE.md: Current Objective has no '**Next:**' line "
            "(the dashboard derives the current stage from it)")
    next_markers = re.findall(r"\*\*Next:?\*\*", text)
    if len(next_markers) != 1:
        err(f"MIGRATION_STATE.md: expected exactly one global '**Next:**' marker, found {len(next_markers)}")
    if re.search(r"^## Next Recommended Run\s*$", text, re.M):
        err("MIGRATION_STATE.md: stale standalone '## Next Recommended Run' section is not allowed; "
            "use '## Current Objective' for live handoff")

    runs = re.findall(r"^## Run (\d+)\s*[-–—]\s*.+$", text, re.M)
    if not runs:
        err("MIGRATION_STATE.md: no '## Run <n> — <title>' headers found")
    nums = [int(n) for n in runs]
    dupes = {n for n in nums if nums.count(n) > 1}
    if dupes:
        err(f"MIGRATION_STATE.md: duplicate run numbers {sorted(dupes)}")


# ----------------------------------------------------------------- CHARTER
def check_charter() -> None:
    text = read(CHARTER)
    if text is None:
        return
    drows = re.findall(r"^\|\s*(D\d+[ab]?)\s*\|", text, re.M)
    if not drows:
        err("00_migration_charter.md: no decision rows ('| D<n> | ... |') found")
    dupes = {d for d in drows if drows.count(d) > 1}
    if dupes:
        err(f"00_migration_charter.md: duplicate decision ids {sorted(dupes)}")
    if "## Cutover Order" not in text:
        warn("00_migration_charter.md: no '## Cutover Order' section")
    if "## Current Migration Status" in text:
        err("00_migration_charter.md: charter must not carry volatile '## Current Migration Status'; "
            "use MIGRATION_STATE.md")
    if re.search(r"\bNext planned session\b|\bnext recommended\b", text, re.I):
        err("00_migration_charter.md: charter must not carry next-session handoff text; "
            "use MIGRATION_STATE.md")


def main() -> int:
    check_register()
    check_state()
    check_charter()

    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")

    if errors:
        print(f"\nFAILED — {len(errors)} error(s), {len(warnings)} warning(s).")
        return 1
    print(f"OK — migration docs conform to the format contract "
          f"({len(warnings)} warning(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
