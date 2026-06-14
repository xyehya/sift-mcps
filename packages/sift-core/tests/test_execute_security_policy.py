import pytest

from sift_core.execute.security_policy import (
    build_security_policy,
    matches_allowed_binary,
    matches_denied_binary,
)


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
    assert policy["mode"] == "denylist"
    assert policy["allowed_binaries"] == []
    denied = set(policy["denied_binaries"])

    for binary in (
        "mkfs.ext4",
        "shutdown",
        "reboot",
        "killall",
        "env",
        "printenv",
        "nc",
        "ncat",
    ):
        assert matches_denied_binary(binary, denied)

    assert "-exec" in policy["tool_blocked_flags"]["find"]
    assert "-o" in policy["output_flags"]


def test_allowlist_mode_preserves_operator_allowlist():
    policy = build_security_policy(
        {"mode": "allowlist", "allowed_binaries": ["date", "fls*"]},
        require_operator_policy=True,
    )

    allowed = set(policy["allowed_binaries"])
    assert policy["mode"] == "allowlist"
    assert matches_allowed_binary("date", allowed)
    assert matches_allowed_binary("fls", allowed)
    assert matches_allowed_binary("fls-mactime", allowed)
    assert not matches_allowed_binary("cat", allowed)


def test_allowlist_mode_still_enforces_deny_floor():
    policy = build_security_policy(
        {"mode": "allowlist", "allowed_binaries": ["date", "env", "mkfs.ext4"]},
        require_operator_policy=True,
    )

    denied = set(policy["denied_binaries"])
    allowed = set(policy["allowed_binaries"])
    assert matches_allowed_binary("env", allowed)
    assert matches_allowed_binary("mkfs.ext4", allowed)
    assert matches_denied_binary("env", denied)
    assert matches_denied_binary("mkfs.ext4", denied)


def test_allowlist_mode_requires_allowed_binaries():
    with pytest.raises(ValueError, match="allowed_binaries is required"):
        build_security_policy({"mode": "allowlist"}, require_operator_policy=True)


def test_invalid_policy_mode_is_rejected():
    with pytest.raises(ValueError, match="mode must be"):
        build_security_policy({"mode": "blocklist"}, require_operator_policy=True)


def test_grep_e_and_E_flags_are_allowed():
    """grep -e/-E are harmless pattern/regex flags, not exec flags.

    The arg validator lowercases flags (so -E maps to -e). grep/egrep/zgrep
    must allow -e via tool_allowed_flags while -e stays globally dangerous for
    exec-style tools (sed/xargs).
    """
    from sift_core.execute.security import sanitize_extra_args

    # grep allowance: -e PATTERN, -E (extended regex), and combined with -i.
    assert sanitize_extra_args(["-e", "foo"], tool_name="grep") == ["-e", "foo"]
    assert sanitize_extra_args(["-E", "a|b"], tool_name="grep") == ["-E", "a|b"]
    assert sanitize_extra_args(["-i", "-e", "x"], tool_name="egrep") == ["-i", "-e", "x"]


def test_e_flag_still_blocked_for_exec_style_tools():
    """-e must remain blocked where it is exec-style (not allowlisted)."""
    import pytest as _pytest

    from sift_core.execute.security import sanitize_extra_args

    for tool in ("sed", "xargs"):
        with _pytest.raises(ValueError, match="dangerous flag"):
            sanitize_extra_args(["-e", "payload"], tool_name=tool)
