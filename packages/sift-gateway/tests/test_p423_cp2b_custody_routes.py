"""P4.23 CP2B — portal/custody_routes.py acceptance tests (EC-3, EC-4, auth).

Two layers of coverage:

1. **Fake-app route tests** (``_client`` below): a bare Starlette app with no
   auth middleware, domain layer replaced by fakes — these prove the
   parse/shape/EC-3/EC-4 logic in isolation, cheaply, with no database.
2. **Real-auth composition tests** (repair round 1, MUST-FIX 1): the SAME
   route table wrapped in the REAL ``case_dashboard.auth.PortalSessionMiddleware``
   — exactly how ``server.py`` mounts it in production — proving an
   unauthenticated caller is REJECTED before custody_status ever runs, and an
   authenticated "examiner" session reaches the domain call on a write route.
   This is the composition the fake-app tests above cannot catch (they have no
   AuthMiddleware/PortalSessionMiddleware at all, which is exactly how the
   unauth-read exposure this round fixes slipped through the first time).
"""

from __future__ import annotations

from case_dashboard.auth import PortalSessionMiddleware
from case_dashboard.session_jwt import (
    SESSION_ENVELOPE_COOKIE_NAME,
    generate_session_envelope,
)
from sift_gateway.custody import actions, admission, ledger
from sift_gateway.portal.custody_routes import custody_routes_list
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient


# ---------------------------------------------------------------------------
# Layer 1 — fake-app route tests (parse/shape/EC-3/EC-4, no auth plumbing).
# ---------------------------------------------------------------------------
class _ActiveCase:
    def __init__(self, case_id: str, artifact_path: str | None = None) -> None:
        self.case_id = case_id
        self.artifact_path = artifact_path


class _CaseService:
    def __init__(self, case: _ActiveCase | None) -> None:
        self._case = case

    def get_active_case(self, _principal):
        if self._case is None:
            from sift_gateway.active_case import ActiveCaseError

            raise ActiveCaseError("no_active_case", http_status=404)
        return self._case


class _EvidenceService:
    def __init__(self, inventory: list[dict]) -> None:
        self._inventory = inventory
        self.list_evidence_calls: list[str] = []

    def list_evidence(self, case_id: str):
        self.list_evidence_calls.append(case_id)
        return self._inventory


class _RaisingEvidenceService:
    def list_evidence(self, case_id: str):
        raise RuntimeError('duplicate key value violates unique constraint "x" CONTEXT: PL/pgSQL')


class _StampRoleMiddleware:
    """Stamp request.state.role/.principal directly — NOT a stand-in for real
    auth (see Layer 2 below for that). Layer 1 tests exist to exercise
    business logic (EC-4 bucketing, EC-3 shaping, case resolution) in
    isolation; most need SOME role to clear the (now mandatory) auth gate, but
    exercising PortalSessionMiddleware itself is Layer 2's job. ``role=None``
    stamps no session at all, for the one Layer 1 test that specifically
    covers the no-role-set denial path."""

    def __init__(self, app, *, role: str | None) -> None:
        self.app = app
        self._role = role

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self._role is not None:
            from starlette.requests import Request

            request = Request(scope)
            request.state.role = self._role
            request.state.principal = _EXAMINER_PRINCIPAL
        await self.app(scope, receive, send)


def _client(gateway, *, role: str | None = "examiner") -> TestClient:
    app = Starlette(
        routes=custody_routes_list(),
        middleware=[Middleware(_StampRoleMiddleware, role=role)],
    )
    app.state.gateway = gateway
    return TestClient(app, raise_server_exceptions=False)


class _Gateway:
    def __init__(self, *, case, evidence_service):
        self.control_plane_dsn = "postgresql://unused"
        self.active_case_service = _CaseService(case)
        self.evidence_service = evidence_service


def test_custody_status_buckets_ec4_correctly(monkeypatch):
    # EC-4 (route-level): a detected-only/digestless entry never lands in the
    # "sealed" bucket; only an entry the service already classified "sealed"
    # (COMMITTED version + ACTIVE manifest membership, per EvidenceAuthorityService
    # .list_evidence's EC-4-compliant join) does.
    monkeypatch.setattr(
        admission,
        "reconcile",
        lambda *a, **k: {"gate_state": "BLOCKED_PENDING", "manifest_version": 0, "issues": []},
    )
    inventory = [
        {"evidence_id": "1", "status": "sealed", "sha256": "sha256:" + "a" * 64},
        {"evidence_id": "2", "status": "detected", "sha256": None},
        {"evidence_id": "3", "status": "registered", "sha256": None},
        {"evidence_id": "4", "status": "ignored", "sha256": None},
        {"evidence_id": "5", "status": "retired", "sha256": None},
    ]
    evidence_service = _EvidenceService(inventory)
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=evidence_service))

    response = client.get("/status")

    assert response.status_code == 200
    body = response.json()
    assert [item["evidence_id"] for item in body["sealed"]] == ["1"]
    assert {item["evidence_id"] for item in body["pending"]} == {"2", "3"}
    assert [item["evidence_id"] for item in body["ignored"]] == ["4"]
    assert [item["evidence_id"] for item in body["retired"]] == ["5"]
    assert body["gate_state"] == "BLOCKED_PENDING"
    assert evidence_service.list_evidence_calls == ["case-1"]


def test_custody_status_without_active_case_is_shaped_not_a_stack_trace():
    client = _client(_Gateway(case=None, evidence_service=_EvidenceService([])))

    response = client.get("/status")

    assert response.status_code == 404
    body = response.json()
    assert set(body["error"]) == {"code", "message", "audit_id"}
    assert body["error"]["code"] == "invalid_request"
    assert body["error"]["audit_id"]  # non-empty


def test_ec3_shaped_error_never_leaks_raw_sqlstate_and_carries_a_real_audit_id(
    monkeypatch,
):
    # EC-3 fail-on-revert: an unmapped exception (here, a raw PL/pgSQL-shaped
    # message like the as-built engine leaked) is NEVER echoed verbatim; the
    # catch-all shapes it to custody_internal with a fresh, non-empty audit id.
    monkeypatch.setattr(admission, "reconcile", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_RaisingEvidenceService()))

    response = client.get("/status")

    assert response.status_code == 500
    body = response.json()
    error = body["error"]
    assert error["code"] == "custody_internal"
    assert error["audit_id"]
    assert error["audit_id"] != ""
    raw_diagnostics = ("SQLSTATE", "PL/pgSQL", "constraint", "CONTEXT:")
    assert not any(marker in error["message"] for marker in raw_diagnostics)


def test_custody_seal_denies_without_an_examiner_role_before_touching_seal_module():
    # No role stamped at all, so _require_examiner denies at the auth gate
    # BEFORE body parsing or _operator_session ever run — the route never
    # imports/calls into custody.seal (which would raise NotImplementedError
    # from CP2A's still-frozen stub if reached).
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_EvidenceService([])), role=None)

    response = client.post(
        "/seal",
        json={"phase": "begin", "idempotency_key": "k1", "password": "pw", "reason": "why"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "invalid_request"




# ---------------------------------------------------------------------------
# Layer 2 — real-auth composition (repair round 1, MUST-FIX 1).
# ---------------------------------------------------------------------------
_SESSION_SECRET = "00" * 32  # 32-byte hex, matches session_jwt's bytes.fromhex
_EXAMINER_PRINCIPAL = {
    "principal_type": "operator",
    "principal_id": "22222222-2222-2222-2222-222222222222",
    "auth_user_id": "auth-user-1",
    "display_name": "Test Examiner",
    "email": "examiner@example.com",
    "system_role": "operator",
    "status": "active",
    "case_memberships": [],
}
_READONLY_PRINCIPAL = {**_EXAMINER_PRINCIPAL, "system_role": "readonly"}


class _FakeSupabaseAuth:
    """Mirrors SupabaseAuthCallbacks.resolve's async (token) -> principal|None
    contract PortalSessionMiddleware calls — no real Supabase involved."""

    def __init__(self, tokens: dict[str, dict]) -> None:
        self._tokens = tokens

    async def resolve(self, access_token: str, source_ip: str | None = None):
        return self._tokens.get(access_token)


def _real_auth_app(gateway, *, tokens: dict[str, dict]) -> TestClient:
    app = Starlette(
        routes=custody_routes_list(),
        middleware=[
            Middleware(
                PortalSessionMiddleware,
                session_secret=_SESSION_SECRET,
                api_keys={},
                session_max_age=28800,
                supabase_auth=_FakeSupabaseAuth(tokens),
            ),
        ],
    )
    app.state.gateway = gateway
    return TestClient(app, raise_server_exceptions=False)


def _envelope_cookie(access_token: str) -> str:
    return generate_session_envelope(
        access_token=access_token,
        refresh_token="",
        expires_at=9999999999,
        sub="auth-user-1",
        fingerprint="fp",
        secret=_SESSION_SECRET,
    )


def test_unauthenticated_custody_status_is_rejected_not_served(monkeypatch):
    # The exact exposure this round fixes: an unauthenticated caller must never
    # see custody inventory. No cookie at all -> PortalSessionMiddleware sets
    # role=None -> _require_authenticated_operator denies before admission.
    # reconcile or evidence_service.list_evidence are ever called.
    reconcile_calls: list[str] = []
    monkeypatch.setattr(
        admission,
        "reconcile",
        lambda *a, **k: reconcile_calls.append(a[0]) or {"gate_state": "OPEN", "manifest_version": 1, "issues": []},
    )
    evidence_service = _EvidenceService([{"evidence_id": "1", "status": "sealed", "sha256": "x"}])
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _real_auth_app(
        _Gateway(case=case, evidence_service=evidence_service),
        tokens={"valid-token": _EXAMINER_PRINCIPAL},
    )

    response = client.get("/status")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_request"
    assert reconcile_calls == []
    assert evidence_service.list_evidence_calls == []


def test_authenticated_examiner_reads_custody_status():
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    evidence_service = _EvidenceService([{"evidence_id": "1", "status": "sealed", "sha256": "x"}])
    client = _real_auth_app(
        _Gateway(case=case, evidence_service=evidence_service),
        tokens={"valid-token": _EXAMINER_PRINCIPAL},
    )
    client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope_cookie("valid-token"))

    response = client.get("/status")

    assert response.status_code == 200
    assert evidence_service.list_evidence_calls == ["case-1"]


def test_readonly_session_may_read_but_not_reach_a_write_route():
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _real_auth_app(
        _Gateway(case=case, evidence_service=_EvidenceService([])),
        tokens={"ro-token": _READONLY_PRINCIPAL},
    )
    client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope_cookie("ro-token"))

    read_response = client.get("/status")
    write_response = client.post(
        "/resolve",
        json={"password": "pw", "reason": "why", "batch_key": "k1", "dispositions": []},
    )

    assert read_response.status_code == 200
    assert write_response.status_code == 403
    assert write_response.json()["error"]["code"] == "invalid_request"


def test_authenticated_examiner_write_reaches_the_domain_call(monkeypatch):
    # MUST-FIX 1's second half: writes were dead (deterministic 401 for every
    # caller, since request.state.identity was never set). With a real
    # examiner session, resolve_findings must reach custody.actions.resolve —
    # proven by monkeypatching it and asserting it was actually called with a
    # real operator session (not a spurious 401/403 before it).
    calls: list[dict] = []

    def _fake_resolve(*, session, case_id, password, reason, dispositions, batch_key):
        calls.append(
            {
                "actor_user_id": session.actor_user_id,
                "case_id": case_id,
                "password": password,
                "reason": reason,
                "batch_key": batch_key,
                "dispositions": dispositions,
            }
        )
        return ()

    monkeypatch.setattr(actions, "resolve", _fake_resolve)
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _real_auth_app(
        _Gateway(case=case, evidence_service=_EvidenceService([])),
        tokens={"valid-token": _EXAMINER_PRINCIPAL},
    )
    client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope_cookie("valid-token"))

    response = client.post(
        "/resolve",
        json={
            "password": "hunter2",
            "reason": "post-triage",
            "batch_key": "batch-1",
            "dispositions": [{"verb": "IGNORE", "target": "evidence/temp.log"}],
        },
    )

    assert response.status_code == 200
    assert len(calls) == 1
    assert calls[0]["actor_user_id"] == _EXAMINER_PRINCIPAL["principal_id"]
    assert calls[0]["case_id"] == "case-1"
    assert calls[0]["password"] == "hunter2"


def test_authenticated_examiner_seal_rejects_malformed_body_as_invalid_request():
    # Past the (now real) auth gate, body validation still applies.
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _real_auth_app(
        _Gateway(case=case, evidence_service=_EvidenceService([])),
        tokens={"valid-token": _EXAMINER_PRINCIPAL},
    )
    client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope_cookie("valid-token"))

    response = client.post("/seal", content=b"not json")

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"


def test_anchor_route_empty_body_requires_reauth_without_writing_receipt(monkeypatch):
    """F3 fail-on-revert: POST {} can never select the internal auto-anchor mode."""
    calls: list[dict] = []
    monkeypatch.setattr(
        ledger, "anchor_manifest_head", lambda **kwargs: calls.append(kwargs)
    )
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_EvidenceService([])))

    response = client.post("/anchor", json={})

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "reauth_required"
    assert calls == []


def test_anchor_route_partial_reauth_is_invalid_without_writing_receipt(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        ledger, "anchor_manifest_head", lambda **kwargs: calls.append(kwargs)
    )
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_EvidenceService([])))

    response = client.post(
        "/anchor", json={"reason": "finalize", "idempotency_key": "anchor-1"}
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_request"
    assert calls == []


def test_anchor_route_full_reauth_reaches_manual_anchor(monkeypatch):
    calls: list[dict] = []
    anchorer = object()
    monkeypatch.setattr(
        ledger, "_build_solana_anchorer", lambda **_kwargs: anchorer
    )

    def _anchor(**kwargs):
        calls.append(kwargs)
        return ledger.AnchorReceipt(
            status="confirmed",
            tx_signature="tx-1",
            anchored_head_digest="sha256:" + "a" * 64,
            error_category=None,
        )

    monkeypatch.setattr(ledger, "anchor_manifest_head", _anchor)
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _client(_Gateway(case=case, evidence_service=_EvidenceService([])))

    response = client.post(
        "/anchor",
        json={
            "password": "correct horse battery staple",
            "reason": "final custody anchor",
            "idempotency_key": "anchor-1",
        },
    )

    assert response.status_code == 200
    assert response.json()["anchored"] is True
    assert len(calls) == 1
    assert calls[0]["anchorer"] is anchorer
    assert calls[0]["session"].actor_user_id == _EXAMINER_PRINCIPAL["principal_id"]
    assert calls[0]["password"] == "correct horse battery staple"


def test_readonly_session_may_use_read_class_verify_and_export(monkeypatch):
    """A-F3: observation/export appends stay read-class, not examiner mutations."""
    verify_calls: list[str] = []
    export_calls: list[str] = []

    def _verify(*, session, case_id):
        verify_calls.append(case_id)
        return actions.VerifyResult(
            gate_state="OPEN",
            verified=True,
            verification_id="verify-1",
        )

    def _export(*, session, case_id, dsn):
        export_calls.append(case_id)
        return ledger.CustodyExport(
            schema_version="custody_export_v1",
            export_digest="sha256:" + "b" * 64,
            source_ledger_head="sha256:" + "c" * 64,
            document={"case_id": case_id},
        )

    monkeypatch.setattr(actions, "full_verify", _verify)
    monkeypatch.setattr(ledger, "generate_export", _export)
    case = _ActiveCase("case-1", artifact_path="/cases/case-1")
    client = _real_auth_app(
        _Gateway(case=case, evidence_service=_EvidenceService([])),
        tokens={"ro-token": _READONLY_PRINCIPAL},
    )
    client.cookies.set(SESSION_ENVELOPE_COOKIE_NAME, _envelope_cookie("ro-token"))

    verify_response = client.post("/verify")
    export_response = client.get("/export")

    assert verify_response.status_code == 200
    assert export_response.status_code == 200
    assert verify_calls == ["case-1"]
    assert export_calls == ["case-1"]
