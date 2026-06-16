#!/usr/bin/env python3
"""Backfill consumed CASE.yaml metadata into app.cases without overwrites."""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
from typing import Any

import yaml

from sift_gateway.active_case import plan_case_yaml_backfill

LOGGER = logging.getLogger("backfill_case_metadata")


def _jsonb(value: dict[str, Any]):
    try:
        from psycopg.types.json import Jsonb
    except ImportError:  # pragma: no cover - dependency is present in runtime
        return value
    return Jsonb(value)


def _load_case_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as exc:
        LOGGER.warning("skip case metadata backfill: cannot read %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _case_yaml_path(row: dict[str, Any]) -> Path | None:
    explicit = row.get("legacy_case_yaml_path")
    if explicit:
        return Path(str(explicit))
    legacy_dir = row.get("legacy_case_dir")
    if legacy_dir:
        return Path(str(legacy_dir)) / "CASE.yaml"
    return None


def _case_rows(conn) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select id::text, case_key, title, description, status,
                   legacy_case_dir, legacy_case_yaml_path, metadata
            from app.cases
            order by created_at, case_key
            """
        )
        rows = cur.fetchall()
    return [
        {
            "id": row[0],
            "case_key": row[1],
            "title": row[2],
            "description": row[3],
            "status": row[4],
            "legacy_case_dir": row[5],
            "legacy_case_yaml_path": row[6],
            "metadata": row[7] or {},
        }
        for row in rows
    ]


def backfill_case_metadata(conn, *, dry_run: bool = False) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "scanned": 0,
        "updated": 0,
        "skipped": 0,
        "divergences": [],
    }
    for row in _case_rows(conn):
        summary["scanned"] += 1
        yaml_path = _case_yaml_path(row)
        if yaml_path is None:
            summary["skipped"] += 1
            LOGGER.warning("skip case %s: no legacy CASE.yaml path", row["case_key"])
            continue
        case_meta = _load_case_yaml(yaml_path)
        if not case_meta:
            summary["skipped"] += 1
            continue
        plan = plan_case_yaml_backfill(row, case_meta)
        for divergence in plan["divergences"]:
            record = {"case_key": row["case_key"], **divergence}
            summary["divergences"].append(record)
            LOGGER.warning("case metadata divergence: %s", json.dumps(record, sort_keys=True))
        if not plan["changed"]:
            continue
        summary["updated"] += 1
        if dry_run:
            LOGGER.info("dry-run: would update case %s", row["case_key"])
            continue
        with conn.cursor() as cur:
            cur.execute(
                """
                update app.cases
                set case_key = coalesce(%s, case_key),
                    title = coalesce(%s, title),
                    description = coalesce(%s, description),
                    status = coalesce(%s, status),
                    metadata = %s,
                    updated_at = now()
                where id = %s
                """,
                (
                    plan["updates"].get("case_key"),
                    plan["updates"].get("title"),
                    plan["updates"].get("description"),
                    plan["updates"].get("status"),
                    _jsonb(plan["metadata"]),
                    row["id"],
                ),
            )
    if not dry_run:
        conn.commit()
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dsn",
        default=os.environ.get("SIFT_CONTROL_PLANE_DSN", ""),
        help="Postgres DSN. Defaults to SIFT_CONTROL_PLANE_DSN.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print machine-readable summary.")
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or SIFT_CONTROL_PLANE_DSN is required")
    import psycopg

    with psycopg.connect(args.dsn) as conn:
        summary = backfill_case_metadata(conn, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(summary, sort_keys=True))
    else:
        LOGGER.info("case metadata backfill summary: %s", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
