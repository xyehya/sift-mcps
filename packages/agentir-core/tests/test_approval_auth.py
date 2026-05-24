"""Tests for agentir_core.approval_auth module."""

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from agentir_core.approval_auth import (
    _LOCKOUT_SECONDS,
    _MAX_PASSWORD_ATTEMPTS,
    _MIN_PASSWORD_LENGTH,
    _check_lockout,
    _clear_failures,
    _load_password_entry,
    _recent_failure_count,
    _record_failure,
    _validate_examiner_name,
    AuthError,
    LockoutError,
    get_analyst_salt,
    has_password,
    require_confirmation,
    require_tty_confirmation,
    reset_password,
    setup_password,
    verify_password,
)


@pytest.fixture
def config_path(tmp_path):
    """Config file path in a temp directory."""
    return tmp_path / ".agentir" / "config.yaml"


@pytest.fixture
def passwords_dir(tmp_path, monkeypatch):
    """Temp passwords directory (replaces /var/lib/agentir/passwords)."""
    d = tmp_path / "passwords"
    d.mkdir()
    monkeypatch.setattr("agentir_core.approval_auth._PASSWORDS_DIR", d)
    return d


class TestPasswordSetup:
    def test_setup_password_writes_to_passwords_dir(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "steve", passwords_dir=passwords_dir)
        pw_file = passwords_dir / "steve.json"
        assert pw_file.exists()
        data = json.loads(pw_file.read_text())
        assert "hash" in data
        assert "salt" in data
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text())
            assert "passwords" not in (config or {})

    def test_setup_password_fails_when_dir_not_writable(self, config_path, tmp_path):
        """When passwords_dir can't be created, raises PermissionError."""
        blocker = tmp_path / "blocker"
        blocker.write_text("file")
        bad_passwords = blocker / "passwords"
        with (
            patch(
                "agentir_core.approval_auth.getpass_prompt",
                side_effect=["mypasswd1", "mypasswd1"],
            ),
        ):
            with pytest.raises(PermissionError):
                setup_password(config_path, "steve", passwords_dir=bad_passwords)
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text()) or {}
            assert "passwords" not in config

    def test_setup_password_verify_roundtrip(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        assert verify_password(
            config_path, "analyst1", "mypasswd1", passwords_dir=passwords_dir
        )

    def test_wrong_password_fails(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["correctpw", "correctpw"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        assert not verify_password(
            config_path, "analyst1", "wrong", passwords_dir=passwords_dir
        )

    def test_has_password_false_when_no_config(self, config_path, passwords_dir):
        assert not has_password(config_path, "analyst1", passwords_dir=passwords_dir)

    def test_has_password_true_after_setup(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        assert has_password(config_path, "analyst1", passwords_dir=passwords_dir)

    def test_setup_password_mismatch_exits(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["password1", "password2"],
        ):
            with pytest.raises(AuthError):
                setup_password(config_path, "analyst1", passwords_dir=passwords_dir)

    def test_setup_password_empty_exits(self, config_path, passwords_dir):
        with patch("agentir_core.approval_auth.getpass_prompt", side_effect=["", ""]):
            with pytest.raises(AuthError):
                setup_password(config_path, "analyst1", passwords_dir=passwords_dir)

    def test_setup_password_too_short_exits(self, config_path, passwords_dir):
        short = "x" * (_MIN_PASSWORD_LENGTH - 1)
        with patch("agentir_core.approval_auth.getpass_prompt", side_effect=[short, short]):
            with pytest.raises(AuthError):
                setup_password(config_path, "analyst1", passwords_dir=passwords_dir)

    def test_setup_password_exact_min_length_ok(self, config_path, passwords_dir):
        pw = "x" * _MIN_PASSWORD_LENGTH
        with patch("agentir_core.approval_auth.getpass_prompt", side_effect=[pw, pw]):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        assert has_password(config_path, "analyst1", passwords_dir=passwords_dir)

    def test_setup_password_preserves_existing_config(self, config_path, passwords_dir):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump({"examiner": "steve"}, f)
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "steve", passwords_dir=passwords_dir)
        config = yaml.safe_load(config_path.read_text())
        assert config["examiner"] == "steve"
        assert "passwords" not in config

    def test_password_file_permissions(self, config_path, passwords_dir):
        """Password file has 0o600 permissions."""
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "steve", passwords_dir=passwords_dir)
        pw_file = passwords_dir / "steve.json"
        assert (pw_file.stat().st_mode & 0o777) == 0o600


class TestExaminerNameValidation:
    def test_reject_path_traversal_dotdot(self):
        with pytest.raises(ValueError, match="Invalid examiner name"):
            _validate_examiner_name("../etc/passwd")

    def test_reject_forward_slash(self):
        with pytest.raises(ValueError, match="Invalid examiner name"):
            _validate_examiner_name("alice/bob")

    def test_reject_backslash(self):
        with pytest.raises(ValueError, match="Invalid examiner name"):
            _validate_examiner_name("alice\\bob")

    def test_accept_normal_names(self):
        _validate_examiner_name("alice")
        _validate_examiner_name("bob-smith")
        _validate_examiner_name("analyst1")


class TestPasswordReset:
    def test_reset_password_requires_current(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["oldpasswd", "oldpasswd"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        with patch("agentir_core.approval_auth.getpass_prompt", side_effect=["wrong"]):
            with pytest.raises(AuthError):
                reset_password(config_path, "analyst1", passwords_dir=passwords_dir)

    def test_reset_password_success(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["oldpasswd", "oldpasswd"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["oldpasswd", "newpasswd", "newpasswd"],
        ):
            reset_password(config_path, "analyst1", passwords_dir=passwords_dir)
        assert verify_password(
            config_path, "analyst1", "newpasswd", passwords_dir=passwords_dir
        )
        assert not verify_password(
            config_path, "analyst1", "oldpasswd", passwords_dir=passwords_dir
        )

    def test_reset_no_password_exits(self, config_path, passwords_dir):
        with pytest.raises(AuthError):
            reset_password(config_path, "analyst1", passwords_dir=passwords_dir)


class TestGetAnalystSalt:
    def test_salt_from_passwords_dir(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        salt = get_analyst_salt(config_path, "analyst1", passwords_dir=passwords_dir)
        assert isinstance(salt, bytes)
        assert len(salt) == 32

    def test_salt_missing_raises(self, config_path, passwords_dir):
        with pytest.raises(ValueError, match="No salt found"):
            get_analyst_salt(config_path, "nobody", passwords_dir=passwords_dir)


class TestRequireConfirmation:
    def test_password_mode_correct(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        with patch("agentir_core.approval_auth.getpass_prompt", return_value="mypasswd1"):
            mode, password = require_confirmation(config_path, "analyst1")
        assert mode == "password"
        assert password == "mypasswd1"

    def test_password_mode_wrong_exits(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        with patch("agentir_core.approval_auth.getpass_prompt", return_value="wrong"):
            with pytest.raises(AuthError):
                require_confirmation(config_path, "analyst1")

    def test_no_password_configured_exits(self, config_path, passwords_dir):
        """require_confirmation with no password configured raises AuthError."""
        with pytest.raises(AuthError, match="No approval password configured"):
            require_confirmation(config_path, "analyst1")


class TestTtyConfirmation:
    def test_tty_y_returns_true(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "y\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is True

    def test_tty_n_returns_false(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "n\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is False

    def test_tty_empty_returns_false(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is False

    def test_no_tty_exits(self):
        with patch("builtins.open", side_effect=OSError("No tty")):
            with pytest.raises(AuthError):
                require_tty_confirmation("Confirm? ")


@pytest.fixture(autouse=True)
def isolate_lockout_file(tmp_path, monkeypatch):
    """Point lockout file to temp dir and clean between tests."""
    lockout = tmp_path / ".password_lockout"
    monkeypatch.setattr("agentir_core.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


class TestPasswordLockout:
    def test_three_failures_triggers_lockout(self):
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        with pytest.raises(LockoutError, match="Password locked"):
            _check_lockout("analyst1")

    def test_lockout_expires_after_timeout(self, monkeypatch):
        import time as time_mod

        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            call_count[0] += 1
            if call_count[0] <= _MAX_PASSWORD_ATTEMPTS:
                return base_time
            return base_time + _LOCKOUT_SECONDS + 1

        monkeypatch.setattr(time_mod, "time", mock_time)
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        _check_lockout("analyst1")

    def test_successful_auth_clears_failure_count(self, config_path):
        _record_failure("analyst1")
        _record_failure("analyst1")
        assert _recent_failure_count("analyst1") == 2
        _clear_failures("analyst1")
        assert _recent_failure_count("analyst1") == 0

    def test_failures_do_not_cross_contaminate(self):
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        _check_lockout("analyst2")
        assert _recent_failure_count("analyst2") == 0

    def test_under_threshold_no_lockout(self):
        for _ in range(_MAX_PASSWORD_ATTEMPTS - 1):
            _record_failure("analyst1")
        _check_lockout("analyst1")

    def test_require_confirmation_records_failure_on_wrong_password(
        self, config_path, passwords_dir
    ):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        with patch("agentir_core.approval_auth.getpass_prompt", return_value="wrong"):
            with pytest.raises(AuthError):
                require_confirmation(config_path, "analyst1")
        assert _recent_failure_count("analyst1") == 1

    def test_require_confirmation_clears_on_success(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        _record_failure("analyst1")
        assert _recent_failure_count("analyst1") == 1
        with patch("agentir_core.approval_auth.getpass_prompt", return_value="mypasswd1"):
            mode, password = require_confirmation(config_path, "analyst1")
        assert mode == "password"
        assert password == "mypasswd1"
        assert _recent_failure_count("analyst1") == 0

    def test_lockout_blocks_require_confirmation(self, config_path, passwords_dir):
        with patch(
            "agentir_core.approval_auth.getpass_prompt",
            side_effect=["mypasswd1", "mypasswd1"],
        ):
            setup_password(config_path, "analyst1", passwords_dir=passwords_dir)
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        with pytest.raises(LockoutError):
            require_confirmation(config_path, "analyst1")

    def test_lockout_persists_across_clear(self, isolate_lockout_file):
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        assert isolate_lockout_file.exists()
        data = json.loads(isolate_lockout_file.read_text())
        assert len(data["analyst1"]) == _MAX_PASSWORD_ATTEMPTS
        assert _recent_failure_count("analyst1") == _MAX_PASSWORD_ATTEMPTS

    def test_lockout_file_corrupt_treated_as_empty(self, isolate_lockout_file):
        isolate_lockout_file.parent.mkdir(parents=True, exist_ok=True)
        isolate_lockout_file.write_text("not valid json {{{")
        assert _recent_failure_count("analyst1") == 0

    def test_lockout_file_permissions(self, isolate_lockout_file):
        """Lockout file has 0o600 permissions."""
        _record_failure("analyst1")
        assert isolate_lockout_file.exists()
        assert (isolate_lockout_file.stat().st_mode & 0o777) == 0o600
