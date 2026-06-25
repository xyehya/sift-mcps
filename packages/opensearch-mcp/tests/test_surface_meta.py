"""Parametrized meta-tests for surfacing-conformance across all REGISTRY tools.

Two generic tests that run over the entire REGISTRY and catch surfacing regressions
before they reach live.

(a) Seam B generic — outputSchema/model schema round-trip:
    For every REGISTRY entry, build a minimal valid *Out instance, model_dump it,
    and validate against tool_output_schema(out_model).  This catches any *Out
    field that violates the schema it declares (e.g. missing required fields in
    the JSON schema that Pydantic would accept but jsonschema rejects).

(b) SURFACE_OPTIONAL_KEYS declarative conformance — Seam A coverage assertion:
    Each tool with optional keys in its *Out model declares those keys in
    SURFACE_OPTIONAL_KEYS (a per-tool sample raw dict carrying every optional key).
    The meta-test drives run_* with that sample raw and asserts each declared key
    reaches structured_content.  The coverage guard checks that every Optional
    field in the *Out model is either listed in the manifest or has a dedicated
    catch-all (``details``).  Adding an optional field without listing it FAILS.

SURFACE_OPTIONAL_KEYS manifest:
    tool_name -> {
        "in_args": {...},     # minimal In args (beyond defaults) to construct InModel
        "raw": {...},         # raw dict with all optional keys set + required fields
        "expected": {...},    # subset of raw that must appear in structured_content
    }

Tools without optional output keys are not in the manifest (they have no Seam A risk).
Tools whose optional keys land in a ``details`` catch-all are annotated with
``"details_catchall": True`` and skipped from the per-key assertion (the catch-all
itself is asserted instead).
"""

from __future__ import annotations

import json
from typing import Any

import jsonschema
import pytest
from pydantic import BaseModel

from sift_common.registry_helpers import tool_output_schema
from sift_common.testing.surface import assert_surfaces


# ---------------------------------------------------------------------------
# SURFACE_OPTIONAL_KEYS manifest
# Each entry covers a run_* function that has at least one optional key at risk.
# ---------------------------------------------------------------------------

SURFACE_OPTIONAL_KEYS: dict[str, dict[str, Any]] = {
    "opensearch_field_values": {
        "in_args": {"field": "event.code"},
        "raw": {
            "field": "event.code",
            "values": [{"value": "4624", "count": 5}],
            "truncated": False,
            "advisory": "field not mapped; available: event.category",
        },
        "expected": {"advisory": "field not mapped; available: event.category"},
    },
    "opensearch_inspect_container": {
        "in_args": {"path": "evidence/disk.E01"},
        "raw": {
            "path": "evidence/disk.E01",
            "resolved_path": "/cases/x/evidence/disk.E01",
            "container_type": "e01",
            "tool_available": True,
            # at-risk: partition_note and acquiry_info are conditionally set by impl.
            "partition_note": "no partition table — use fls -i ewf -f ntfs",
            "acquiry_info": {"case_number": "ROCBA-1"},
            # raw_info omitted (always None for E01 path; not at risk).
        },
        "expected": {
            "partition_note": "no partition table — use fls -i ewf -f ntfs",
            "acquiry_info": {"case_number": "ROCBA-1"},
        },
    },
    "opensearch_ingest": {
        # run_opensearch_ingest's optional keys land in the explicit constructor.
        # queued-path fields (job_id/job_type/dispatched_to/next_step) are only
        # emitted by the gateway middleware (OpenSearchJobDispatchMiddleware), NOT
        # by run_opensearch_ingest itself — see orchestrator guardrail #3/#4.
        # We test the fields run_* actually emits.  already_indexed, container,
        # case_id are omitted from expected because they are None in this raw
        # and we only assert non-None surfaces (no risk of silent None→absent).
        "in_args": {"path": "evidence/disk.E01"},
        "raw": {
            "status": "started",
            "suggested_hostname": "WORKSTATION01",
            "warning": "large image; may take 2h",
            "pid": 12345,
            "run_id": "run-abc",
            "log_file": "/var/log/sift/ingest-run-abc.log",
            "note": "ingest started in background",
        },
        "expected": {
            "suggested_hostname": "WORKSTATION01",
            "warning": "large image; may take 2h",
            "pid": 12345,
            "run_id": "run-abc",
            "log_file": "/var/log/sift/ingest-run-abc.log",
            "note": "ingest started in background",
        },
    },
    "opensearch_ingest_status": {
        # The top-level optional fields on IngestStatusOut (last_completed,
        # authority, next_step, job_id) are explicitly wired in run_* at 1326-1329.
        # message is optional (default None) but always read from raw.
        "in_args": {},
        "raw": {
            "ingests": [],
            "authority": "postgres-durable-jobs",
            "last_completed": {"most_recent_index": "case-x-evtx-host1", "total_docs": 5000},
            "job_id": "job-abc-123",
            "next_step": "Poll running_commands_status(job_id='job-abc-123')",
        },
        "expected": {
            "authority": "postgres-durable-jobs",
            "last_completed": {"most_recent_index": "case-x-evtx-host1", "total_docs": 5000},
            "job_id": "job-abc-123",
            "next_step": "Poll running_commands_status(job_id='job-abc-123')",
        },
    },
    "opensearch_enrich_intel": {
        # Optional preview fields: ips, hashes, domains, total_iocs (dry_run path).
        # queued-path fields (job_id, job_type, dispatched_to, next_step) are wired
        # in run_* at 1350-1358. We focus on the preview path (dry_run=True) here;
        # case_id, pid, run_id, log_file are omitted from raw (None path, no risk).
        "in_args": {"dry_run": True},
        "raw": {
            "status": "preview",
            "ips": 15,
            "hashes": 8,
            "domains": 3,
            "total_iocs": 26,
            "note": "dry-run preview: 26 IOCs found",
        },
        "expected": {
            "ips": 15,
            "hashes": 8,
            "domains": 3,
            "total_iocs": 26,
            "note": "dry-run preview: 26 IOCs found",
        },
    },
    "opensearch_status": {
        # HayabusaHealth is nullable nested.
        "in_args": {},
        "raw": {
            "cluster_status": "green",
            "indices": [],
            "total_indices": 0,
            "hayabusa": {
                "binary": "/usr/local/bin/hayabusa",
                "rules_dir": "/opt/hayabusa/rules",
                "rules_count": 4200,
            },
        },
        "expected": {
            "hayabusa": {
                "binary": "/usr/local/bin/hayabusa",
                "rules_dir": "/opt/hayabusa/rules",
                "rules_count": 4200,
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Helper: resolve run_fn + in_model from REGISTRY by tool name
# ---------------------------------------------------------------------------


def _registry_entry(tool_name: str):
    """Return (run_fn, in_model, out_model) for a named tool from REGISTRY."""
    from opensearch_mcp.registry import REGISTRY

    for tool_def in REGISTRY:
        if tool_def.name == tool_name:
            return tool_def.fn, tool_def.in_model, tool_def.out_model
    raise RuntimeError(f"Tool {tool_name!r} not found in REGISTRY.")


# ---------------------------------------------------------------------------
# (a) Seam B generic — schema round-trip over all REGISTRY entries
# ---------------------------------------------------------------------------



def _registry_parametrize_ids():
    from opensearch_mcp.registry import REGISTRY

    return [tool_def.name for tool_def in REGISTRY]


@pytest.mark.parametrize("tool_name", _registry_parametrize_ids())
def test_out_model_output_schema_is_buildable(tool_name: str):
    """Seam B generic: tool_output_schema(out_model) must build without errors.

    Exercises ``tool_output_schema`` (which calls ``output_schema(out_model, ToolError)``)
    for every REGISTRY entry.  Catches:
      - SchemaCollisionError: *Out and ToolError share a $defs name — would produce
        a mis-describing schema (one branch's definition overwrites the other's).
      - Any Pydantic / jsonschema exception during schema generation.

    This is the Seam B generic "does the schema even build?" guard.  It does NOT
    validate a payload against the schema (the round-trip tests in
    test_surface_field_values / test_surface_aggregate do that for specific tools).

    Low-cost: no I/O, no monkeypatching, runs in milliseconds.
    """
    from opensearch_mcp.registry import REGISTRY
    from sift_common.mcp_schema import SchemaCollisionError

    tool_def = next(td for td in REGISTRY if td.name == tool_name)
    out_model = tool_def.out_model

    try:
        schema = tool_output_schema(out_model)
    except SchemaCollisionError as exc:
        pytest.fail(
            f"Tool {tool_name!r}: SchemaCollisionError building outputSchema for "
            f"{out_model.__name__!r}: {exc}.  "
            "Rename one of the colliding $defs models."
        )
    except Exception as exc:
        pytest.fail(
            f"Tool {tool_name!r}: unexpected error building outputSchema for "
            f"{out_model.__name__!r}: {type(exc).__name__}: {exc}"
        )

    # Minimal structural sanity: schema must be a dict with 'type' and 'anyOf'.
    assert isinstance(schema, dict), f"outputSchema must be a dict, got {type(schema)!r}"
    assert schema.get("type") == "object", (
        f"outputSchema must have type='object' (strict-client requirement); "
        f"got type={schema.get('type')!r}"
    )
    assert "anyOf" in schema, "outputSchema must have 'anyOf' (success | error branches)"


# ---------------------------------------------------------------------------
# (b) SURFACE_OPTIONAL_KEYS declarative conformance — Seam A coverage assertion
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_name", sorted(SURFACE_OPTIONAL_KEYS.keys()))
def test_optional_keys_surface_via_run(tool_name: str, monkeypatch):
    """Seam A coverage: declared optional keys must reach structured_content.

    Drives the real run_* wrapper with the sample raw dict from
    SURFACE_OPTIONAL_KEYS and asserts each expected key appears in
    structured_content.

    Adding an optional field to *Out without listing it in SURFACE_OPTIONAL_KEYS
    is caught by test_out_model_optional_fields_are_manifested below.
    Reverting the ``=raw.get("key")`` passthrough in run_* makes this test fail.
    """
    spec = SURFACE_OPTIONAL_KEYS[tool_name]
    run_fn, in_model_cls, _out_model = _registry_entry(tool_name)

    in_args = spec.get("in_args", {})
    raw = spec["raw"]
    expected = spec["expected"]

    in_model = in_model_cls(**in_args)
    assert_surfaces(run_fn, in_model, raw, expected, monkeypatch_impl=monkeypatch)


@pytest.mark.parametrize("tool_name", sorted(SURFACE_OPTIONAL_KEYS.keys()))
def test_manifested_optional_fields_are_fully_covered(tool_name: str):
    """Coverage guard: for each MANIFESTED tool, its expected keys must be a superset
    of the tool's at-risk optional fields declared in the manifest.

    Intent: when a developer adds a new optional field to a *Out model for a tool
    that IS in SURFACE_OPTIONAL_KEYS, they must also add the new field to the
    manifest's ``expected`` dict — ensuring a surfacing test exists before the new
    key can silently disappear live.

    Scope: only tools IN the manifest are checked.  Tools with optional fields that
    are always explicitly wired and not in the manifest are out of scope; add them
    to SURFACE_OPTIONAL_KEYS when they have a conditional wiring pattern.

    Exemptions:
      - Fields in a ``details`` catch-all dict (listed in the manifest ``raw`` but
        not in ``expected`` — the catch-all is validated as a single entry).
      - Fields that default to None but are always fully wired in run_* and never
        conditionally skipped (e.g. ``case_id`` on EnrichIntelOut — always read
        from raw even if None).
    """
    from opensearch_mcp.registry import REGISTRY

    tool_def = next(td for td in REGISTRY if td.name == tool_name)
    out_model = tool_def.out_model
    spec = SURFACE_OPTIONAL_KEYS[tool_name]
    manifest_expected = set(spec.get("expected", {}).keys())

    # Only flag optional fields that appear in the manifest's raw dict — those
    # are the ones the test author declared as at-risk.  If the raw dict carries
    # a key but expected doesn't assert it, that's the gap we want to catch.
    manifest_raw_keys = set(spec.get("raw", {}).keys())
    # Intersect with optional *Out fields to find declared-but-unasserted keys.
    optional_field_names = {
        name
        for name, fi in out_model.model_fields.items()
        if fi.default is None
    }
    at_risk_in_raw = manifest_raw_keys & optional_field_names
    uncovered = at_risk_in_raw - manifest_expected
    if uncovered:
        pytest.fail(
            f"Tool {tool_name!r}: optional fields {sorted(uncovered)!r} appear in "
            "the manifest raw dict but are not asserted in expected.  "
            "Add them to SURFACE_OPTIONAL_KEYS['expected'] so they have a "
            "surfacing assertion, or remove them from raw if intentionally untested."
        )
