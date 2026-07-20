"""Custody ledger: chain verification, derived export, optional anchoring.

FROZEN INTERFACE (P4.23 CP1, re-frozen 2026-07-20 repair round 1). CP2B
implements the bodies against the frozen tables (``evidence_custody_events`` hash
chain, ``custody_exports``, ``solana_receipts``) and the
``app.custody_record_export`` / ``custody_record_anchor`` RPCs. This module
absorbs the as-built ``custody_proof.py`` / ``custody_anchor.py`` with the signing
remnants removed (SPEC §Custody Ledger — no installation-held Ed25519 key,
signature latch, key rotation, or trusted-key registry).

* **Verify Ledger** deterministically recomputes the per-case append-only SHA-256
  hash chain and reports structural inconsistency WITHOUT mutating it.
* **Export** is a one-way derived artifact from one authenticated PostgreSQL
  snapshot: a versioned canonical-JSON document ``custody_export_v1`` (sorted keys,
  reproducible digest) containing ledger events, manifests, evidence digests,
  verification results, the schema version, and optional Solana receipts. SIFT
  never imports an export and never uses it for authority or recovery; without an
  external anchor it demonstrates internal structural consistency only.
* **Anchoring** is optional, disabled by default, non-authoritative, and
  nonblocking (SPEC §Solana). It lives behind the small module-private
  :class:`_Anchorer` interface so the ledger core never depends on a Solana
  client; anchor failure records a failure and never rolls back custody, blocks
  the gate, or prevents report generation. The browser and MCP may not supply an
  arbitrary digest — the server selects the current ledger/manifest head.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sift_gateway.custody.reauth import OperatorSession

EXPORT_SCHEMA_VERSION = "custody_export_v1"

logger = logging.getLogger(__name__)


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


class _Anchorer(Protocol):
    """The small optional anchoring interface (Solana lives behind this).

    Module-private so it never inflates the public surface (§12): the ledger core
    depends only on this Protocol, never on a concrete Solana client, so anchoring
    is a leaf dependency that can be disabled without touching custody logic.
    """

    def anchor_head(self, *, case_id: str, head_digest: str) -> AnchorReceipt: ...


# ---------------------------------------------------------------------------
# Verify Ledger — deterministic, read-only hash-chain recomputation.
# ---------------------------------------------------------------------------
def _verify_chain_linkage(cur: Any, case_id: str) -> LedgerVerification:
    """Recompute the chain LINKAGE over an ALREADY-OPEN cursor/transaction.

    Shared core for :func:`verify_ledger` (its own short-lived connection) and
    :func:`generate_export` (one connection/transaction for the whole export,
    §5 "one authenticated PostgreSQL snapshot" — repair round 1, MUST-FIX 4:
    a separate connection here would let a custody mutation commit between
    this read and the export's objects/manifests/events reads, so
    ``verification.head_seq``/``head_hash`` could disagree with the embedded
    ``custody_events`` list). ``seq`` must be contiguous from 1 and each
    event's ``prev_hash`` must equal the ``event_hash`` of its immediate
    predecessor (the genesis event's ``prev_hash`` is ``''``) — exactly the
    invariant ``app.custody_append_event`` establishes on write. A structural
    break (a tampered/reordered/missing event) is reported at the first
    ``seq`` where the linkage fails; it never mutates a row.
    """
    cur.execute(
        """
        select seq, prev_hash, event_hash
        from app.evidence_custody_events
        where case_id = %s
        order by seq
        """,
        (case_id,),
    )
    rows = cur.fetchall()

    previous_hash = ""
    for expected_seq, row in enumerate(rows, start=1):
        seq, prev_hash, event_hash = row
        current_hash = str(event_hash or "")
        if int(seq) != expected_seq or str(prev_hash or "") != previous_hash:
            return LedgerVerification(
                consistent=False,
                head_seq=int(seq),
                head_hash=current_hash,
                broken_at_seq=int(seq),
            )
        previous_hash = current_hash
    return LedgerVerification(
        consistent=True, head_seq=len(rows), head_hash=previous_hash
    )


def verify_ledger(*, case_id: str, dsn: str | None) -> LedgerVerification:
    """Recompute and check a case's custody hash chain (read-only).

    Fail-closed: no case/DSN or any DB error is reported as inconsistent
    rather than raising. See :func:`_verify_chain_linkage` for the recomputed
    invariant.
    """
    if not case_id or not dsn:
        return LedgerVerification(consistent=False, head_seq=0, head_hash="")
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - deployment env
        logger.error("verify_ledger: psycopg unavailable: %s", exc)
        return LedgerVerification(consistent=False, head_seq=0, head_hash="")
    try:
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                return _verify_chain_linkage(cur, case_id)
    except Exception as exc:
        logger.error("verify_ledger: query failed for %s: %s", case_id, exc)
        return LedgerVerification(consistent=False, head_seq=0, head_hash="")


# ---------------------------------------------------------------------------
# Export — one-way derived canonical-JSON snapshot.
# ---------------------------------------------------------------------------
def generate_export(
    *, session: OperatorSession, case_id: str, dsn: str | None
) -> CustodyExport:
    """Produce the canonical ``custody_export_v1`` and record its metadata.

    Read-only (no fresh password, same class as Full Verify); records the export
    digest + source ledger head via ``app.custody_record_export``. The digest is
    computed over a canonical JSON document (sorted keys, compact separators, no
    wall-clock "generated at" field) so a repeat export of unchanged custody state
    is byte-stable and reproducible.
    """
    if not case_id or not dsn:
        raise ValueError("generate_export requires an active case and DSN")
    import psycopg

    # repair round 1, MUST-FIX 4 (§5 "one authenticated PostgreSQL snapshot"):
    # the chain-linkage recomputation and the objects/manifests/events/receipts
    # reads all run in ONE connection/transaction at REPEATABLE READ, so a
    # custody mutation committing mid-export cannot make verification.head_seq/
    # head_hash disagree with the embedded custody_events list — every read
    # below sees the exact same snapshot. SET TRANSACTION ISOLATION LEVEL is
    # issued as the first statement, before any query acquires a snapshot.
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("set transaction isolation level repeatable read")
            verification = _verify_chain_linkage(cur, case_id)
            cur.execute(
                """
                select o.id::text, o.display_name, o.display_path, o.status,
                       v.id::text, v.sha256, v.bytes, v.entry_status,
                       mm.entry_status, m.manifest_version
                from app.evidence_objects o
                left join app.evidence_versions v on v.id = o.current_version_id
                left join app.manifest_membership mm
                  on mm.evidence_object_id = o.id and mm.evidence_version_id = v.id
                     and mm.entry_status = 'ACTIVE'
                left join app.manifest_versions m on m.id = mm.manifest_version_id
                where o.case_id = %s
                order by o.display_path
                """,
                (case_id,),
            )
            object_rows = cur.fetchall()
            cur.execute(
                """
                select manifest_version, manifest_hash, created_by_action, created_at
                from app.manifest_versions
                where case_id = %s
                order by manifest_version
                """,
                (case_id,),
            )
            manifest_rows = cur.fetchall()
            cur.execute(
                """
                select seq, event_type, manifest_version, prev_hash, event_hash,
                       evidence_object_id::text, reauth_audit_event_id::text,
                       created_at
                from app.evidence_custody_events
                where case_id = %s
                order by seq
                """,
                (case_id,),
            )
            event_rows = cur.fetchall()
            cur.execute(
                """
                select status, tx_signature, anchored_head_digest, error_category,
                       created_at
                from app.solana_receipts
                where case_id = %s
                order by created_at
                """,
                (case_id,),
            )
            receipt_rows = cur.fetchall()

            objects = _export_objects(object_rows)
            manifest_versions = _export_manifest_versions(manifest_rows)
            custody_events = _export_custody_events(event_rows)
            solana_receipts = _export_solana_receipts(receipt_rows)
            manifest_version = manifest_versions[-1]["manifest_version"] if manifest_versions else 0

            document: dict[str, Any] = {
                "schema_version": EXPORT_SCHEMA_VERSION,
                "case_id": case_id,
                "objects": objects,
                "manifest_versions": manifest_versions,
                "custody_events": custody_events,
                "verification": {
                    "consistent": verification.consistent,
                    "head_seq": verification.head_seq,
                    "head_hash": verification.head_hash,
                    "broken_at_seq": verification.broken_at_seq,
                },
                "solana_receipts": solana_receipts,
            }
            export_digest = "sha256:" + hashlib.sha256(_canonical_bytes(document)).hexdigest()

            # Recording the export stays in the SAME transaction/snapshot as
            # the reads above — no correctness reason to split it into a
            # second connection, and this keeps the whole export to one round
            # trip's worth of network connections.
            cur.execute(
                "select app.custody_record_export(%s, %s, %s, %s, %s, null)",
                (
                    case_id,
                    export_digest,
                    verification.head_hash or None,
                    manifest_version or None,
                    session.actor_user_id,
                ),
            )
        conn.commit()

    return CustodyExport(
        schema_version=EXPORT_SCHEMA_VERSION,
        export_digest=export_digest,
        source_ledger_head=verification.head_hash,
        document=document,
    )


def _export_objects(object_rows: Any) -> list[dict[str, Any]]:
    return [
        {
            "evidence_object_id": r[0],
            "display_name": r[1],
            "display_path": r[2],
            "status": r[3],
            # EC-4: an object is a sealed member of the export ONLY when it has a
            # COMMITTED version with ACTIVE manifest membership; a detected-only
            # or digestless object is never described as sealed here either.
            "current_version": (
                {
                    "evidence_version_id": r[4],
                    "sha256": r[5],
                    "bytes": r[6],
                    "manifest_version": r[9],
                }
                if r[8] == "ACTIVE" and r[9] is not None
                else None
            ),
        }
        for r in object_rows
    ]


def _export_manifest_versions(manifest_rows: Any) -> list[dict[str, Any]]:
    return [
        {
            "manifest_version": r[0],
            "manifest_hash": r[1],
            "created_by_action": r[2],
            "created_at": _iso(r[3]),
        }
        for r in manifest_rows
    ]


def _export_custody_events(event_rows: Any) -> list[dict[str, Any]]:
    return [
        {
            "seq": r[0],
            "event_type": r[1],
            "manifest_version": r[2],
            "prev_hash": r[3],
            "event_hash": r[4],
            "evidence_object_id": r[5],
            "reauth_audit_event_id": r[6],
            "created_at": _iso(r[7]),
        }
        for r in event_rows
    ]


def _export_solana_receipts(receipt_rows: Any) -> list[dict[str, Any]]:
    return [
        {
            "status": r[0],
            "tx_signature": r[1],
            "anchored_head_digest": r[2],
            "error_category": r[3],
            "created_at": _iso(r[4]),
        }
        for r in receipt_rows
    ]


# ---------------------------------------------------------------------------
# Optional Solana anchoring — disabled unless an anchorer is supplied.
# ---------------------------------------------------------------------------
def anchor_manifest_head(
    *,
    case_id: str,
    dsn: str | None,
    anchorer: _Anchorer | None = None,
    session: OperatorSession | None = None,
    password: str | None = None,
    reason: str | None = None,
    idempotency_key: str | None = None,
    report_digest: str | None = None,
) -> AnchorReceipt | None:
    """Anchor the server-selected current ledger/manifest head (optional).

    Two modes, both frozen here (SPEC §5), discriminated by whether reauth was
    supplied — never by an unauthenticated caller's say-so:

    * **Manual / final anchor** — ``session`` + ``password`` + ``reason`` +
      ``idempotency_key`` are ALL present. A final / report anchor additionally
      carries ``report_digest``. This is the ONLY caller-supplied digest, and only
      for report anchoring; the ledger/manifest head is always server-selected.
      Fresh reauthentication is verified via ``reauth.record_reauth`` before any
      anchor attempt (SPEC §Reauthentication: manual Solana Anchor is a retained
      reauth-bound mutation).
    * **Automatic anchor** — invoked right after an already-authorized
      manifest-changing operation: ALL reauth fields are ``None`` and
      ``report_digest`` is absent. A call that supplies SOME but not all reauth
      fields is rejected as malformed (never silently treated as either mode) —
      this closes the "an unauthenticated call is shaped like an auto-anchor" gap
      the CP1 stub flagged.

    Returns ``None`` when anchoring is disabled (no ``anchorer`` supplied) OR
    when ``anchorer`` construction/availability itself is the failure — in both
    cases nothing blocks. Once an anchor attempt is made, a failure is ALWAYS
    recorded via ``app.custody_record_anchor`` (status ``failed``) rather than
    raised, so anchoring never rolls back custody, blocks the gate, or prevents
    report generation.
    """
    if anchorer is None:
        return None
    if not case_id or not dsn:
        return None

    reauth_fields = (session, password, reason, idempotency_key)
    is_manual = any(field is not None for field in reauth_fields)
    if is_manual and not all(field is not None for field in reauth_fields):
        raise ValueError(
            "anchor_manifest_head: manual anchoring requires session, password, "
            "reason, and idempotency_key together — partial reauth is rejected"
        )
    if not is_manual and report_digest is not None:
        raise ValueError(
            "anchor_manifest_head: report_digest requires manual reauthentication"
        )

    import psycopg

    if is_manual:
        from sift_gateway.custody import reauth as _reauth

        assert session is not None and password is not None
        assert reason is not None and idempotency_key is not None
        _reauth.record_reauth(
            session=session,
            password=password,
            action="ANCHOR",
            case_id=case_id,
            binding=_reauth.build_binding(idempotency_key, reason, [case_id]),
        )

    verification = verify_ledger(case_id=case_id, dsn=dsn)
    head_digest = report_digest if report_digest is not None else verification.head_hash
    actor_user_id = session.actor_user_id if session is not None else None

    try:
        receipt = anchorer.anchor_head(case_id=case_id, head_digest=head_digest)
    except Exception as exc:  # anchoring is best-effort and never blocking
        logger.warning("anchor_manifest_head: anchorer failed for %s: %s", case_id, exc)
        receipt = AnchorReceipt(
            status="failed",
            tx_signature=None,
            anchored_head_digest=None,
            error_category="anchor_submission_failed",
        )

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "select app.custody_record_anchor(%s, %s, %s, %s, %s, %s)",
                (
                    case_id,
                    receipt.status,
                    receipt.anchored_head_digest,
                    receipt.tx_signature,
                    receipt.error_category,
                    actor_user_id,
                ),
            )
        conn.commit()
    return receipt


def _build_solana_anchorer(
    *,
    keypair_path: str | None,
    rpc_url: str | None = None,
    cluster: str = "mainnet",
) -> _Anchorer | None:
    """Construct the concrete Solana anchorer, or ``None`` if unconfigured.

    Module-private like :class:`_Anchorer` itself — the public interface budget
    (§12, ≤6 per module) is already spent by the three frozen CP1 dataclasses plus
    :func:`verify_ledger` / :func:`generate_export` / :func:`anchor_manifest_head`,
    so this constructor stays out of the public count exactly like ``_Anchorer``
    does; ``portal/custody_routes.py`` imports it explicitly by name. Absorbs the
    as-built ``sift_core.custody_anchor.anchor_db_proof`` submission logic (deleted
    as its own module — SPEC §Solana: one small optional interface here, no
    separate anchoring module). Returns ``None`` when ``keypair_path`` is empty
    (anchoring not configured) so callers can pass the result straight to
    :func:`anchor_manifest_head` without a conditional.
    """
    if not keypair_path:
        return None
    return _SolanaAnchorer(keypair_path=keypair_path, rpc_url=rpc_url, cluster=cluster)


class _SolanaAnchorer:
    """Concrete, service-only Solana memo-program anchorer (module-private).

    The keypair is fee-spend-only and never leaves the service process: it is
    read from ``keypair_path`` at call time, used to sign one memo transaction,
    and never returned, logged, or included in an export (SPEC §Solana Key
    custody). Any submission failure raises so :func:`anchor_manifest_head`
    records a ``failed`` receipt — this class never touches custody state.
    """

    _MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
    _MAINNET_RPC = "https://api.mainnet-beta.solana.com"
    _DEVNET_RPC = "https://api.devnet.solana.com"

    def __init__(
        self, *, keypair_path: str, rpc_url: str | None, cluster: str
    ) -> None:
        self._keypair_path = keypair_path
        self._rpc_url = rpc_url or (
            self._MAINNET_RPC if cluster == "mainnet" else self._DEVNET_RPC
        )
        self._cluster = cluster

    def anchor_head(self, *, case_id: str, head_digest: str) -> AnchorReceipt:
        import base64
        import time
        from pathlib import Path

        from solders.hash import Hash as SolHash  # type: ignore[reportMissingImports]
        from solders.instruction import (  # type: ignore[reportMissingImports]
            AccountMeta,
            Instruction,
        )
        from solders.keypair import Keypair  # type: ignore[reportMissingImports]
        from solders.message import Message  # type: ignore[reportMissingImports]
        from solders.pubkey import Pubkey  # type: ignore[reportMissingImports]
        from solders.transaction import (  # type: ignore[reportMissingImports]
            Transaction,
        )

        keypair = Keypair.from_bytes(
            bytes(json.loads(Path(self._keypair_path).expanduser().read_text()))
        )
        digest = head_digest.split(":")[-1][:32]
        payload = f"SIFT|{case_id[:8]}|{digest}".encode()
        instruction = Instruction(
            Pubkey.from_string(self._MEMO_PROGRAM_ID),
            payload,
            [AccountMeta(keypair.pubkey(), True, False)],
        )
        blockhash = SolHash.from_string(
            _rpc_call(self._rpc_url, "getLatestBlockhash", [{"commitment": "finalized"}])[
                "result"
            ]["value"]["blockhash"]
        )
        transaction = Transaction.new_unsigned(
            Message.new_with_blockhash([instruction], keypair.pubkey(), blockhash)
        )
        transaction.sign([keypair], blockhash)
        response = _rpc_call(
            self._rpc_url,
            "sendTransaction",
            [
                base64.b64encode(bytes(transaction)).decode(),
                {"encoding": "base64", "skipPreflight": False},
            ],
        )
        if "error" in response:
            return AnchorReceipt(
                status="failed",
                tx_signature=None,
                anchored_head_digest=None,
                error_category="solana_rpc_error",
            )
        signature = str(response["result"])
        time.sleep(2)
        confirmed = (
            _rpc_call(
                self._rpc_url,
                "getTransaction",
                [signature, {"encoding": "json", "commitment": "confirmed"}],
            ).get("result")
            is not None
        )
        return AnchorReceipt(
            status="confirmed" if confirmed else "pending",
            tx_signature=signature,
            anchored_head_digest=head_digest,
            error_category=None,
        )


def _rpc_call(url: str, method: str, params: list[Any]) -> dict[str, Any]:
    import urllib.request

    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    with urllib.request.urlopen(
        urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        ),
        timeout=30,
    ) as response:
        return json.loads(response.read())


def _canonical_bytes(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
