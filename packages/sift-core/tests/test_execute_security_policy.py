import pytest

from sift_core.execute.security_policy import build_security_policy, matches_denied_binary


def test_operator_config_cannot_weaken_deny_floor():
    policy = build_security_policy({"denied_binaries": ["echo"]}, require_operator_policy=True)

    denied = set(policy["denied_binaries"])
    assert "echo" in denied
    assert "env" in denied
    assert "kill" in denied
    assert "mkfs.*" in denied
    assert matches_denied_binary("mkfs.ext2", denied)


def test_empty_operator_policy_is_rejected():
    with pytest.raises(ValueError, match="cannot be empty"):
        build_security_policy({}, require_operator_policy=True)


def test_default_policy_preserves_current_denylist_behavior():
    policy = build_security_policy()
    denied = set(policy["denied_binaries"])

    for binary in ("mkfs.ext4", "shutdown", "reboot", "killall", "env", "printenv", "nc", "ncat"):
        assert matches_denied_binary(binary, denied)

    assert "-exec" in policy["tool_blocked_flags"]["find"]
    assert "-o" in policy["output_flags"]
