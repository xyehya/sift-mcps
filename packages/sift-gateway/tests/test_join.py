"""Tests for sift_gateway.join — join code management and rate limiting."""

from __future__ import annotations

import json
import time
from unittest import mock

from sift_gateway.join import (
    _FAILURE_WINDOW_SECONDS,
    _JOIN_CHARSET,
    _MAX_FAILURES,
    _load_state,
    _save_state,
    check_join_rate_limit,
    generate_join_code,
    mark_code_used,
    record_join_failure,
    store_join_code,
    validate_join_code,
)


class TestGenerateJoinCode:
    def test_format(self):
        code = generate_join_code()
        assert len(code) == 9  # 4 + '-' + 4
        assert code[4] == "-"

    def test_only_valid_chars(self):
        for _ in range(50):
            code = generate_join_code()
            chars = code.replace("-", "")
            assert all(c in _JOIN_CHARSET for c in chars)

    def test_uniqueness(self):
        codes = {generate_join_code() for _ in range(100)}
        assert len(codes) > 90  # very unlikely collision in 100


class TestStateManagement:
    def test_load_state_empty(self, tmp_path):
        state_file = tmp_path / ".join_state.json"
        with mock.patch("sift_gateway.join._STATE_FILE", state_file):
            state = _load_state()
            assert state["codes"] == {}
            assert state["failures"] == {}

    def test_save_and_load(self, tmp_path):
        state_dir = tmp_path / ".sift"
        state_dir.mkdir()
        state_file = state_dir / ".join_state.json"
        with mock.patch("sift_gateway.join._STATE_DIR", state_dir), \
             mock.patch("sift_gateway.join._STATE_FILE", state_file):
            state = {"codes": {"abc": {"used": False, "expires_ts": time.time() + 3600}}, "failures": {}}
            _save_state(state)
            loaded = _load_state()
            assert "abc" in loaded["codes"]

    def test_load_prunes_expired(self, tmp_path):
        state_dir = tmp_path / ".sift"
        state_dir.mkdir()
        state_file = state_dir / ".join_state.json"
        expired_state = {
            "codes": {
                "old": {"used": False, "expires_ts": time.time() - 100},
                "valid": {"used": False, "expires_ts": time.time() + 3600},
            },
            "failures": {},
        }
        state_file.write_text(json.dumps(expired_state))
        with mock.patch("sift_gateway.join._STATE_FILE", state_file):
            state = _load_state()
            assert "old" not in state["codes"]
            assert "valid" in state["codes"]

    def test_load_prunes_used(self, tmp_path):
        state_dir = tmp_path / ".sift"
        state_dir.mkdir()
        state_file = state_dir / ".join_state.json"
        used_state = {
            "codes": {
                "used-hash": {"used": True, "expires_ts": time.time() + 3600},
            },
            "failures": {},
        }
        state_file.write_text(json.dumps(used_state))
        with mock.patch("sift_gateway.join._STATE_FILE", state_file):
            state = _load_state()
            assert "used-hash" not in state["codes"]

    def test_corrupt_state_file(self, tmp_path):
        state_file = tmp_path / ".join_state.json"
        state_file.write_text("not json")
        with mock.patch("sift_gateway.join._STATE_FILE", state_file):
            state = _load_state()
            assert state["codes"] == {}


class TestStoreAndValidateJoinCode:
    def test_store_and_validate(self, tmp_path):
        state_dir = tmp_path / ".sift"
        state_dir.mkdir()
        state_file = state_dir / ".join_state.json"
        with mock.patch("sift_gateway.join._STATE_DIR", state_dir), \
             mock.patch("sift_gateway.join._STATE_FILE", state_file):
            code = generate_join_code()
            store_join_code(code, expires_hours=1)
            result = validate_join_code(code)
            assert result is not None

    def test_wrong_code_fails_validation(self, tmp_path):
        state_dir = tmp_path / ".sift"
        state_dir.mkdir()
        state_file = state_dir / ".join_state.json"
        with mock.patch("sift_gateway.join._STATE_DIR", state_dir), \
             mock.patch("sift_gateway.join._STATE_FILE", state_file):
            code = generate_join_code()
            store_join_code(code)
            result = validate_join_code("XXXX-YYYY")
            assert result is None

    def test_mark_used_prevents_reuse(self, tmp_path):
        state_dir = tmp_path / ".sift"
        state_dir.mkdir()
        state_file = state_dir / ".join_state.json"
        with mock.patch("sift_gateway.join._STATE_DIR", state_dir), \
             mock.patch("sift_gateway.join._STATE_FILE", state_file):
            code = generate_join_code()
            store_join_code(code)
            mark_code_used(code)
            result = validate_join_code(code)
            assert result is None


class TestJoinRateLimit:
    def setup_method(self):
        # Clear in-memory state between tests
        import sift_gateway.join as jmod
        jmod._join_failures.clear()

    def test_under_limit_allowed(self):
        assert check_join_rate_limit("10.0.0.1") is True

    def test_at_limit_blocked(self):
        for _ in range(_MAX_FAILURES):
            record_join_failure("10.0.0.2")
        assert check_join_rate_limit("10.0.0.2") is False

    def test_different_ips_independent(self):
        for _ in range(_MAX_FAILURES):
            record_join_failure("10.0.0.3")
        assert check_join_rate_limit("10.0.0.4") is True

    def test_expired_failures_cleared(self):
        import sift_gateway.join as jmod
        # Insert old failures
        old_time = time.monotonic() - _FAILURE_WINDOW_SECONDS - 10
        jmod._join_failures["10.0.0.5"] = [old_time] * _MAX_FAILURES
        assert check_join_rate_limit("10.0.0.5") is True
