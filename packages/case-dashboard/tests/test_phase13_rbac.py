"""Phase 13 portal route RBAC guards.

Drivers: SIFT-MCPS-PLAN.md Phase 13 / TASKS.md 13c.
"""

from __future__ import annotations

import secrets
from types import SimpleNamespace

from case_dashboard.routes import _require_examiner_role
from case_dashboard.session_jwt import generate_jwt, verify_jwt

_SECRET = secrets.token_hex(32)


def _request_for_role(role: str):
    return SimpleNamespace(state=SimpleNamespace(role=role))


def test_readonly_cookie_role_is_rejected_by_write_guard():
    token = generate_jwt("reader", "readonly", _SECRET)
    payload = verify_jwt(token, _SECRET)

    err = _require_examiner_role(_request_for_role(payload["role"]))

    assert err is not None
    assert err.status_code == 403


def test_examiner_cookie_role_is_allowed_by_write_guard():
    token = generate_jwt("alice", "examiner", _SECRET)
    payload = verify_jwt(token, _SECRET)

    err = _require_examiner_role(_request_for_role(payload["role"]))

    assert err is None
