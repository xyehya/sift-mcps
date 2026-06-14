"""Tests for case_dashboard.session_jwt — Phase 12a.

Drivers: SIFT-MCPS-PLAN.md §Phase 12 / TASKS.md §12a.
"""

from __future__ import annotations

import secrets
import time

import pytest

from case_dashboard.session_jwt import (
    generate_jwt,
    verify_jwt,
)

_SECRET = secrets.token_hex(32)  # 32 bytes = 64 hex chars


class TestGenerateJwt:
    def test_returns_three_part_string(self):
        token = generate_jwt("alice", "examiner", _SECRET)
        assert len(token.split(".")) == 3

    def test_payload_sub_and_role(self):
        token = generate_jwt("alice", "examiner", _SECRET)
        payload = verify_jwt(token, _SECRET)
        assert payload is not None
        assert payload["sub"] == "alice"
        assert payload["role"] == "examiner"

    def test_payload_exp_in_future(self):
        token = generate_jwt("alice", "examiner", _SECRET, max_age=3600)
        payload = verify_jwt(token, _SECRET)
        assert payload is not None
        assert payload["exp"] > time.time()

    def test_payload_iat_approximately_now(self):
        before = int(time.time())
        token = generate_jwt("alice", "examiner", _SECRET)
        after = int(time.time())
        payload = verify_jwt(token, _SECRET)
        assert payload is not None
        assert before <= payload["iat"] <= after

    def test_jti_is_unique_across_calls(self):
        t1 = generate_jwt("alice", "examiner", _SECRET)
        t2 = generate_jwt("alice", "examiner", _SECRET)
        p1 = verify_jwt(t1, _SECRET)
        p2 = verify_jwt(t2, _SECRET)
        assert p1 is not None and p2 is not None
        assert p1["jti"] != p2["jti"]

    def test_readonly_role_preserved(self):
        token = generate_jwt("bob", "readonly", _SECRET)
        payload = verify_jwt(token, _SECRET)
        assert payload is not None
        assert payload["role"] == "readonly"

    def test_max_age_controls_expiry(self):
        token = generate_jwt("alice", "examiner", _SECRET, max_age=7200)
        payload = verify_jwt(token, _SECRET)
        assert payload is not None
        # exp should be ~7200s from now (within 5s for test speed)
        assert abs(payload["exp"] - (payload["iat"] + 7200)) <= 1


class TestVerifyJwt:
    """verify_jwt must return None on any invalid input — never raise."""

    def test_roundtrip_passes(self):
        token = generate_jwt("alice", "examiner", _SECRET)
        payload = verify_jwt(token, _SECRET)
        assert payload is not None
        assert payload["sub"] == "alice"

    def test_wrong_secret_returns_none(self):
        token = generate_jwt("alice", "examiner", _SECRET)
        other_secret = secrets.token_hex(32)
        assert verify_jwt(token, other_secret) is None

    def test_tampered_signature_returns_none(self):
        token = generate_jwt("alice", "examiner", _SECRET)
        parts = token.split(".")
        # Flip the last char of the signature
        bad_sig = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
        tampered = f"{parts[0]}.{parts[1]}.{bad_sig}"
        assert verify_jwt(tampered, _SECRET) is None

    def test_tampered_payload_returns_none(self):
        """Changing the payload invalidates the signature."""
        import base64, json as _json
        token = generate_jwt("alice", "examiner", _SECRET)
        parts = token.split(".")
        # Decode and modify payload
        pad = 4 - len(parts[1]) % 4
        raw = base64.urlsafe_b64decode(parts[1] + ("=" * pad if pad != 4 else ""))
        payload = _json.loads(raw)
        payload["sub"] = "evil"
        new_payload_b64 = base64.urlsafe_b64encode(
            _json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        tampered = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
        assert verify_jwt(tampered, _SECRET) is None

    def test_expired_token_returns_none(self):
        """max_age=0 produces a token that expires immediately."""
        token = generate_jwt("alice", "examiner", _SECRET, max_age=0)
        # exp == iat == now; by the time verify runs, exp <= time.time()
        assert verify_jwt(token, _SECRET) is None

    def test_malformed_not_three_parts(self):
        assert verify_jwt("notavalidtoken", _SECRET) is None
        assert verify_jwt("only.two", _SECRET) is None
        assert verify_jwt("a.b.c.d", _SECRET) is None

    def test_empty_string_returns_none(self):
        assert verify_jwt("", _SECRET) is None

    def test_garbage_input_returns_none(self):
        assert verify_jwt("!!!.@@@.###", _SECRET) is None

    def test_never_raises_on_any_input(self):
        """verify_jwt must not raise regardless of input."""
        for bad in ["", "x", "x.y.z", "a.b.c.d", "\x00\x01\x02"]:
            result = verify_jwt(bad, _SECRET)
            assert result is None or isinstance(result, dict)
