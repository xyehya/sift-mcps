"""Fail-on-revert contract for destination-constrained stdio add-ons."""

from __future__ import annotations

from _installer_support import REPO_ROOT

HELPER = REPO_ROOT / "scripts" / "sift-addon-systemd-sandbox"
RELAY = REPO_ROOT / "scripts" / "sift-addon-stdio-relay"
SETUP = REPO_ROOT / "scripts" / "setup-addon-systemd-sandbox-sudoers.sh"
APPARMOR = REPO_ROOT / "configs" / "apparmor" / "sift-gateway.template"


def test_helper_is_default_deny_and_structured() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert "IPAddressDeny=any" in source
    assert "IPAddressAllow=127.0.0.0/8" in source
    assert "IPAddressAllow=::1/128" in source
    assert 'network_policy not in {"none", "loopback"}' in source
    assert "AppArmorProfile=sift-addon" in source
    assert "NoNewPrivileges=yes" in source
    assert "CapabilityBoundingSet=" in source
    assert "AmbientCapabilities=" in source
    assert "ProtectSystem=strict" in source
    for option in ("--wait", "--quiet", "--collect"):
        assert f'"{option}"' in source
    assert '"--pipe"' not in source
    assert "StandardInput=file:" in source
    assert "StandardOutput=file:" in source
    assert "StandardError=journal" in source
    assert "def validate_fifo(" in source
    assert 'path.parent != Path("/run/sift-addon-client")' in source
    assert "stat.S_ISFIFO" in source
    assert "os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC" in source
    assert "os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC" in source
    assert 'StandardInput=file:/proc/{os.getpid()}/fd/{input_fd}' in source
    assert "shell=True" not in source
    assert "subprocess.Popen(" in source
    assert 'apparmor_label != "sift-addon-broker (enforce)"' in source


def test_only_approved_backend_command_policy_pairs_exist() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert "/opt/sift-mcps/.venv/bin/opensearch-mcp" in source
    assert "/opt/sift-mcps/.venv/bin/windows-triage-mcp" in source
    assert "/opt/sift-mcps/.venv/bin/opencti-mcp" in source
    assert '"opensearch-mcp",' in source
    assert '"windows-triage-mcp",' in source
    assert '"opencti-mcp",' in source
    assert "len(sys.argv) != 11" in source


def test_secret_environment_uses_root_only_file_not_argv() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert 'prefix="environment."' in source
    assert "os.chmod(env_path, 0o600)" in source
    assert 'f"--property=EnvironmentFile={env_path}"' in source
    assert "env_path.unlink(missing_ok=True)" in source
    assert 'state == "active"' in source
    assert 'f"--unit={unit_name}"' in source
    assert "--setenv" not in source
    assert "OPENCTI_TOKEN=" not in source


def test_sudoers_grants_only_validating_helper_with_setenv() -> None:
    source = SETUP.read_text(encoding="utf-8")
    assert "NOPASSWD:SETENV: SIFT_ADDON_SANDBOX" in source
    assert "!pam_acct_mgmt, !pam_session, !pam_setcred" in source
    assert "/usr/bin/systemd-run" not in source
    assert "visudo" in source
    assert 'RELAY_DST="/usr/local/sbin/sift-addon-stdio-relay"' in source


def test_unprivileged_relay_precedes_broker_transition() -> None:
    relay = RELAY.read_text(encoding="utf-8")
    source = APPARMOR.read_text(encoding="utf-8")
    assert "os.mkfifo(input_path, 0o644)" in relay
    assert "os.mkfifo(output_path, 0o622)" in relay
    assert "os.chmod(input_path, 0o644)" in relay
    assert "os.chmod(output_path, 0o622)" in relay
    assert "secrets.token_hex(16)" in relay
    assert "target=relay" in relay
    assert 'Path("/run/sift-addon-client")' in relay
    assert "/usr/local/sbin/sift-addon-stdio-relay        rix" in source
    assert "/run/sift-addon-client/**                     rwk" in source
    assert "/run/sift-addon-client/**                 rw," in source
    assert "capability dac_override," not in source
    assert "CapabilityBoundingSet=" in HELPER.read_text(encoding="utf-8")
    assert "deny ptrace," in source
