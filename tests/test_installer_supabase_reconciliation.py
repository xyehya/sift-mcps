
from _installer_support import REPO_ROOT

EXAMINER = REPO_ROOT / "lib" / "examiner.sh"
SUPABASE_LIB = REPO_ROOT / "lib" / "supabase.sh"
SUPABASE_SETUP = REPO_ROOT / "scripts" / "setup-supabase.sh"


def test_operator_bootstrap_uses_auth_and_database_authority_not_handoff():
    source = EXAMINER.read_text(encoding="utf-8")
    body = source[source.index("bootstrap_supabase_operator() {") :]
    body = body[: body.index("# A1-BOOTSTRAP: validate the evidence/cases root")]
    assert "_auth_user_by_email" in body
    assert "_upsert_operator_profile" in body
    assert "_verify_password_grant" in body
    assert "supabase_operator_password_grant_failed" in body
    assert 'grep -q \'^supabase_operator_email=\'' not in body
    assert "Supabase operator already bootstrapped — preserving" not in body


def test_local_supabase_preflight_always_reconciles_cli_credentials():
    source = SUPABASE_LIB.read_text(encoding="utf-8")
    body = source[source.index("preflight_supabase() {") :]
    body = body[: body.index("_env_file_value()")]
    assert 'bash "$REPO_DIR/scripts/setup-supabase.sh"' in body
    assert '[[ -z "${SUPABASE_URL:-}" && -f "$REPO_DIR/scripts/setup-supabase.sh" ]]' not in body


def test_gateway_supabase_env_is_reconciled_not_preserved():
    source = SUPABASE_LIB.read_text(encoding="utf-8")
    body = source[source.index("write_supabase_env() {") :]
    body = body[: body.index("# Preflight — Supabase")]
    assert "already exists — preserving" not in body
    assert "svc_install_file" in body
    assert "SUPABASE_SERVICE_ROLE_KEY" in body


def test_jwt_secret_persists_outside_replaceable_runtime_checkout():
    source = SUPABASE_SETUP.read_text(encoding="utf-8")
    body = source[source.index("ensure_jwt_secret() {") :]
    body = body[: body.index("# ── Ensure config.toml exists")]
    assert "$HOME/.sift/supabase-project/supabase-jwt.env" in body
    assert "GOTRUE_JWT_SECRET" in body
    assert "running local Auth service" in body
    assert "legacy_env_file" in body
    assert 'install -m 600 "$tmp" "$env_file"' in body
    assert 'sudo rm -f -- "$legacy_env_file"' in body


def test_supabase_setup_never_prints_api_keys():
    source = SUPABASE_SETUP.read_text(encoding="utf-8")
    assert "ANON_KEY (first 24)" not in source
    assert "SERVICE_ROLE_KEY (24)" not in source
    assert 'supabase start --network-id "$net_id") >"$start_log" 2>&1' in source
