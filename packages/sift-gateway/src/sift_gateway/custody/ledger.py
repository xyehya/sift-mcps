"""Custody ledger: chain verification, derived export, optional anchoring.

FROZEN INTERFACE (P4.23 CP1, 2026-07-20). CP2B implements the bodies against the
frozen tables (``evidence_custody_events`` hash chain, ``custody_exports``,
``solana_receipts``) and the ``app.custody_record_export`` / ``custody_record_anchor``
RPCs. This module absorbs the as-built ``custody_proof.py`` / ``custody_anchor.py``
with the signing remnants removed (SPEC §Custody Ledger — no installation-held
Ed25519 key, signature latch, key rotation, or trusted-key registry).

* **Verify Ledger** deterministically recomputes the per-case append-only SHA-256
  hash chain and reports structural inconsistency WITHOUT mutating it.
* **Export** is a one-way derived artifact from one authenticated PostgreSQL
  snapshot: a versioned canonical-JSON document ``custody_export_v1`` (sorted keys,
  reproducible digest) containing ledger events, manifests, evidence digests,
  verification results, the schema version, and optional Solana receipts. SIFT
  never imports an export and never uses it for authority or recovery; without an
  external anchor it demonstrates internal structural consistency only.
* **Anchoring** is optional, disabled by default, non-authoritative, and
  nonblocking (SPEC §Solana). It lives behind the small :class:`Anchorer`
  interface so the ledger core never depends on a Solana client; anchor failure
  records a failure and never rolls back custody, blocks the gate, or prevents
  report generation. The browser and MCP may not supply an arbitrary digest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from sift_gateway.custody.reauth import OperatorSession

EXPORT_SCHEMA_VERSION = "custody_export_v1"


@dataclass(frozen=True, slots=True)
class LedgerVerification:
    """The deterministic result of recomputing a case's custody hash chain."""

    consistent: bool
    head_seq: int
    head_hash: str
    broken_at_seq: int | None = None


@dataclass(frozen=True, slots=True)
class CustodyExport:
    """A derived, non-authoritative custody export (``custody_export_v1``)."""

    schema_version: str
    export_digest: str
    source_ledger_head: str
    document: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AnchorReceipt:
    """A recorded Solana anchoring attempt (never authoritative or blocking)."""

    status: str  # pending | confirmed | failed
    tx_signature: str | None
    anchored_head_digest: str | None
    error_category: str | None


class Anchorer(Protocol):
    """The small optional anchoring interface (Solana lives behind this).

    The ledger core depends only on this Protocol, never on a concrete Solana
    client, so anchoring is a leaf dependency that can be disabled without
    touching custody logic.
    """

    def anchor_head(self, *, case_id: str, head_digest: str) -> AnchorReceipt: ...


def verify_ledger(*, case_id: str, dsn: str | None) -> LedgerVerification:
    """Recompute and check a case's custody hash chain (read-only).

    NOT IMPLEMENTED in CP1 — CP2B implements the deterministic recomputation over
    ``evidence_custody_events``. The read-only, non-mutating contract is frozen.
    """
    raise NotImplementedError("CP2B implements Verify Ledger")


def generate_export(
    *, session: OperatorSession, case_id: str, dsn: str | None
) -> CustodyExport:
    """Produce the canonical ``custody_export_v1`` and record its metadata.

    Read-only (no fresh password, same class as Full Verify); records the export
    digest + source ledger head via ``app.custody_record_export``.

    NOT IMPLEMENTED in CP1 — CP2B implements the canonical-JSON serialization.
    """
    raise NotImplementedError("CP2B implements custody export")


def anchor_manifest_head(
    *,
    case_id: str,
    dsn: str | None,
    anchorer: Anchorer | None = None,
) -> AnchorReceipt | None:
    """Anchor the server-selected current ledger/manifest head (optional).

    Returns ``None`` when anchoring is disabled. Records the receipt via
    ``app.custody_record_anchor``; a failure is recorded but never blocks custody.

    NOT IMPLEMENTED in CP1 — CP2B implements the optional anchoring flow behind
    :class:`Anchorer`. The nonblocking contract is frozen here.
    """
    raise NotImplementedError("CP2B implements optional Solana anchoring")
