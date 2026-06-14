import pytest

from sift_core.execute.security_policy import (
    build_security_policy,
    matches_allowed_binary,
    matches_denied_binary,
    policy_to_env_json,
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


def test_default_policy_is_allowlist_with_contained_unlisted_tier():
    policy = build_security_policy()
    assert policy["mode"] == "allowlist"
    assert policy["unlisted_policy"] == "contained"
    assert matches_allowed_binary("mmls", policy["allowed_binaries"])
    assert matches_allowed_binary("strings", policy["allowed_binaries"])
    assert not matches_allowed_binary("ssh", policy["allowed_binaries"])
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
        "chattr",
        "lsattr",
        "setfattr",
        "getfattr",
        "setcap",
        "getcap",
        "mount",
        "umount",
        "umount2",
        "losetup",
        "qemu-nbd",
        "modprobe",
        "insmod",
        "rmmod",
        "unshare",
        "nsenter",
        "capsh",
        "dd",
        "dc3dd",
        "python3.12",
        "pypy3",
        "perl5.38",
        "ruby3.2",
        "node20",
        "php8.3",
        "lua5.4",
        "busybox",
        "fish",
    ):
        assert matches_denied_binary(binary, denied)

    assert "-exec" in policy["tool_blocked_flags"]["find"]
    assert "-e" in policy["tool_blocked_flags"]["sed"]
    assert "-x" in policy["tool_blocked_flags"]["tshark"]
    assert "-o" in policy["output_flags"]


def test_allowlist_mode_extends_seeded_forensic_allowlist():
    policy = build_security_policy(
        {"mode": "allowlist", "allowed_binaries": ["date", "fls*"]},
        require_operator_policy=True,
    )

    allowed = set(policy["allowed_binaries"])
    assert policy["mode"] == "allowlist"
    assert matches_allowed_binary("date", allowed)
    assert matches_allowed_binary("fls", allowed)
    assert matches_allowed_binary("fls-mactime", allowed)
    assert matches_allowed_binary("cat", allowed)
    assert not matches_allowed_binary("ssh", allowed)


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


def test_allowlist_mode_without_operator_allowlist_uses_mvp_seed():
    policy = build_security_policy({"mode": "allowlist"}, require_operator_policy=True)
    assert policy["mode"] == "allowlist"
    assert matches_allowed_binary("fls", policy["allowed_binaries"])


def test_invalid_unlisted_policy_is_rejected():
    with pytest.raises(ValueError, match="unlisted_policy"):
        build_security_policy({"unlisted_policy": "approve"}, require_operator_policy=True)


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


def test_allowlist_unlisted_policy_classifies_contained_or_reject(monkeypatch):
    from sift_core.execute.catalog import clear_catalog_cache
    from sift_core.execute.security import classify_binary_risk, is_allowed_by_mode

    contained = build_security_policy(
        {
            "mode": "allowlist",
            "allowed_binaries": ["date"],
            "unlisted_policy": "contained",
        },
        require_operator_policy=True,
    )
    monkeypatch.setenv("SIFT_EXECUTE_SECURITY_POLICY", policy_to_env_json(contained))
    clear_catalog_cache()
    assert classify_binary_risk("date") == "standard"
    assert classify_binary_risk("customtool") == "contained"
    assert is_allowed_by_mode("customtool") is True

    rejected = build_security_policy(
        {
            "mode": "allowlist",
            "allowed_binaries": ["date"],
            "unlisted_policy": "reject",
        },
        require_operator_policy=True,
    )
    monkeypatch.setenv("SIFT_EXECUTE_SECURITY_POLICY", policy_to_env_json(rejected))
    clear_catalog_cache()
    assert classify_binary_risk("customtool") == "reject"
    assert is_allowed_by_mode("customtool") is False


@pytest.mark.parametrize(
    ("tool", "args", "message"),
    [
        ("sed", ["s/.*/id/e", "evidence/log.txt"], "sed construct"),
        ("sqlite3", ["evidence/case.db", ".shell id"], "sqlite3 dot-command"),
        ("sqlite3", ["evidence/case.db", ".load ./evil"], "sqlite3 dot-command"),
    ],
)
def test_program_text_scanners_block_code_exec_constructs(tool, args, message):
    from sift_core.execute.security import sanitize_extra_args

    with pytest.raises(ValueError, match=message):
        sanitize_extra_args(args, tool_name=tool)


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("sed", ["--expression=s/.*/id/e"]),
        ("sqlite3", ["-cmd", ".shell id"]),
        ("tshark", ["-X", "lua_script:/tmp/x.lua"]),
        ("tshark", ["-i", "eth0"]),
        ("vol", ["--plugin-dirs", "/tmp/plugins"]),
        ("vol3", ["-p/tmp/plugins"]),
        ("exiftool", ["-config", "evil.cfg"]),
        ("exiftool", ["-execute"]),
    ],
)
def test_tool_blocked_flags_close_code_exec_primitives(tool, args):
    from sift_core.execute.security import sanitize_extra_args

    with pytest.raises(ValueError, match="Blocked dangerous flag"):
        sanitize_extra_args(args, tool_name=tool)


def test_contained_tier_blocks_program_text_and_non_o_output_flags():
    from sift_core.execute.security import sanitize_extra_args

    with pytest.raises(ValueError, match="Unlisted program-text tool"):
        sanitize_extra_args(["print $1"], tool_name="awk", risk_tier="contained")
    with pytest.raises(ValueError, match="only -o"):
        sanitize_extra_args(["--json", "out.json"], tool_name="customtool", risk_tier="contained")


class TestInCaseWritePosture:
    """Operator-approved in-case path relaxation: run_command may write anywhere
    under the ACTIVE case dir except sealed evidence + protected integrity
    records. Out-of-case and host paths stay hard-denied. Uses the DB-authority
    AuthorityContext so the active case resolves under DB authority.
    """

    def _ctx(self, case_dir):
        from sift_core.active_case_context import (
            AuthorityContext,
            use_active_case_context,
        )

        return use_active_case_context(
            AuthorityContext(
                case_id="11111111-1111-1111-1111-111111111111",
                case_key="case-x",
                artifact_path=str(case_dir),
                db_active=True,
            )
        )

    def _case(self, tmp_path):
        case = tmp_path / "case-x"
        for d in ("agent", "extractions", "tmp", "evidence", "scratch", "reports"):
            (case / d).mkdir(parents=True, exist_ok=True)
        return case

    def test_write_allowed_in_extractions(self, tmp_path):
        from sift_core.execute.security import validate_output_path

        case = self._case(tmp_path)
        with self._ctx(case):
            out = validate_output_path("extractions/hive.dat", base_dir=case)
        assert out == str((case / "extractions" / "hive.dat").resolve())

    def test_write_allowed_in_nonstandard_in_case_subdir(self, tmp_path):
        """The relaxation: a subdir that is NOT agent/extractions/tmp is allowed."""
        from sift_core.execute.security import validate_output_path

        case = self._case(tmp_path)
        with self._ctx(case):
            out = validate_output_path("scratch/notes.txt", base_dir=case)
        assert out == str((case / "scratch" / "notes.txt").resolve())

    def test_write_to_evidence_denied(self, tmp_path):
        from sift_core.execute.security import validate_output_path

        case = self._case(tmp_path)
        with self._ctx(case):
            with pytest.raises(ValueError, match="protected case|integrity|evidence"):
                validate_output_path("evidence/tamper.txt", base_dir=case)

    def test_write_to_protected_record_denied(self, tmp_path):
        from sift_core.execute.security import validate_output_path

        case = self._case(tmp_path)
        with self._ctx(case):
            with pytest.raises(ValueError, match="protected|integrity"):
                validate_output_path("evidence-manifest.json", base_dir=case)

    def test_write_out_of_case_denied(self, tmp_path):
        from sift_core.execute.security import validate_output_path

        case = self._case(tmp_path)
        other = tmp_path / "other-case"
        other.mkdir()
        with self._ctx(case):
            with pytest.raises(ValueError, match="outside the active case"):
                validate_output_path(str(other / "x.txt"))

    def test_write_to_secret_env_dir_denied(self, tmp_path):
        from sift_core.execute.security import validate_output_path

        case = self._case(tmp_path)
        with self._ctx(case):
            with pytest.raises(ValueError, match="outside the active case"):
                validate_output_path("/var/lib/sift/.sift/control-plane.env")
