# shellcheck shell=bash
# =============================================================================
# lib/examiner.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_EXAMINER_SOURCED:-}" ]] && return 0
_SIFT_LIB_EXAMINER_SOURCED=1

# Phase 6 — examiner account (local PBKDF2 legacy + Supabase-first bootstrap)
# =============================================================================

write_default_examiner() {
  # SIFT_PASSWORDS_DIR is sift-service-owned 0700. The operator hashes the temp
  # password into an operator-owned temp JSON, then installs it owned sift-service
  # 0600 so the gateway can read the legacy PBKDF2 fallback credential.
  local password_file="$SIFT_PASSWORDS_DIR/$SIFT_EXAMINER.json"
  if svc_test_f "$password_file"; then
    log "Default examiner password already exists — preserving."
    TEMP_PASSWORD_CREATED=0
    TEMP_PASSWORD=""
    return
  fi
  TEMP_PASSWORD="Agentir-$(random_hex 12)"
  TEMP_PASSWORD_CREATED=1
  local tmp
  tmp="$(mktemp)"
  export SIFT_EXAMINER TEMP_PASSWORD EXAMINER_TMP_OUT="$tmp"
  "$SYSTEM_PYTHON" - <<'PY'
import hashlib, json, os, secrets

examiner = os.environ["SIFT_EXAMINER"]
password = os.environ["TEMP_PASSWORD"]
out = os.environ["EXAMINER_TMP_OUT"]
salt = secrets.token_bytes(32)
entry = {
    "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex(),
    "salt": salt.hex(),
    "must_reset_password": True,
    "created_by": "sift-mcps install.sh",
}
with open(out, "w") as handle:
    os.chmod(out, 0o600)
    json.dump(entry, handle)
    handle.flush()
    os.fsync(handle.fileno())
PY
  svc_install_file "$tmp" "$password_file" 600
  rm -f "$tmp"
  unset EXAMINER_TMP_OUT
}

# OS1-BOOTSTRAP: seed enabled add-on backends into app.mcp_backends.
# Runs after gateway is up and DB is reachable. Idempotent via upsert (ON CONFLICT).
# Only registers backends whose install-time enablement flag is "true" AND whose
# manifest file exists. Raw OpenSearch credentials, DSNs, and MCP tokens are NEVER
# stored — only env-ref metadata (env_refs pointing to gateway process env vars).
# If SIFT_CONTROL_PLANE_DSN is absent this is a no-op; core-only mode skips it.
# Seed one stdio add-on backend into app.mcp_backends (idempotent upsert).
# Args: $1 = backend name, $2 = manifest path, $3 = venv entry-point script,
#       $4 = JSON object of env_refs (gateway-env -> child-env), default "{}".
# No raw secrets are stored — only env_ref names; the gateway resolves the
# actual values from its own process environment at load time.
_seed_one_addon_backend() {
  local backend_name="$1"
  local manifest_path="$2"
  local entry_point="$3"
  local env_refs_json="${4:-}"
  [[ -n "$env_refs_json" ]] || env_refs_json="{}"

  if [[ ! -f "$manifest_path" ]]; then
    warn "seed_addon_backends: $backend_name manifest not found at $manifest_path — skipping."
    return 0
  fi

  log "Seeding $backend_name into app.mcp_backends (idempotent upsert)."
  export SIFT_CONTROL_PLANE_DSN="$SEED_CP_DSN"
  export SEED_BACKEND_NAME="$backend_name"
  export SEED_MANIFEST_PATH="$manifest_path"
  export SEED_ENTRY_POINT="$entry_point"
  export SEED_ENV_REFS_JSON="$env_refs_json"
  export SEED_UV_BIN="$UV_BIN"
  export SEED_PYTHON_BIN="$SYSTEM_PYTHON"
  export SEED_REPO_DIR="$REPO_DIR"

  if ! "$VENV_DIR/bin/python" - <<'PY'
import json, os, sys
from pathlib import Path

dsn = os.environ["SIFT_CONTROL_PLANE_DSN"]
backend_name = os.environ["SEED_BACKEND_NAME"]
manifest_path = Path(os.environ["SEED_MANIFEST_PATH"])
entry_point = os.environ["SEED_ENTRY_POINT"]
env_refs = json.loads(os.environ.get("SEED_ENV_REFS_JSON") or "{}")
repo_dir = os.environ["SEED_REPO_DIR"]
entry_script = Path(repo_dir) / ".venv" / "bin" / entry_point
if not entry_script.exists():
    print(f"seed_addon_backends: entrypoint not found: {entry_script}", file=sys.stderr)
    sys.exit(1)

try:
    from sift_gateway.mcp_backends_registry import McpBackendRegistry, normalize_connection_config
except ImportError as exc:
    print(f"seed_addon_backends: sift_gateway not importable: {exc} — skipping", file=sys.stderr)
    sys.exit(0)

manifest = json.loads(manifest_path.read_text())

# Connection config: stdio, no raw secrets — env_refs map gateway process env
# vars into the backend child process env at gateway load time.
connection = {
    "type": "stdio",
    "command": str(entry_script),
    "args": [],
    "manifest_path": str(manifest_path),
    "env_refs": env_refs,
}

try:
    registry = McpBackendRegistry(dsn)
    registry.register(
        name=backend_name,
        config=connection,
        manifest=manifest,
        actor=None,
    )
    print(f"seed_addon_backends: {backend_name} registered/updated in app.mcp_backends.")
except Exception as exc:
    print(f"seed_addon_backends: registration error: {exc}", file=sys.stderr)
    sys.exit(1)
PY
  then
    warn "seed_addon_backends: $SEED_BACKEND_NAME seeding failed — operator can register via Portal -> Backends."
    return 1
  fi
}

seed_addon_backends() {
  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"
  if [[ -z "$cp_dsn" ]]; then
    log "seed_addon_backends: no control-plane DSN — skipping DB backend seeding."
    return 0
  fi
  export SEED_CP_DSN="$cp_dsn"

  # opensearch-mcp: gated by SIFT_OPENSEARCH_ENABLED. The OPENSEARCH_CONFIG/
  # OPENSEARCH_HOST env refs are resolved by the gateway from its own env.
  if [[ "${SIFT_OPENSEARCH_ENABLED:-}" == "true" ]]; then
    if _seed_one_addon_backend \
      "opensearch-mcp" \
      "$REPO_DIR/packages/opensearch-mcp/sift-backend.json" \
      "opensearch-mcp" \
      '{"OPENSEARCH_CONFIG": "OPENSEARCH_CONFIG", "OPENSEARCH_HOST": "OPENSEARCH_HOST"}'; then
      OPENSEARCH_SEEDED=true
    fi
  else
    log "seed_addon_backends: SIFT_OPENSEARCH_ENABLED != true — skipping opensearch-mcp seeding."
  fi

  # forensic-rag-mcp (BATCH-OSX-RAG): the knowledge add-on. Gated by
  # SIFT_RAG_ENABLED. It resolves the control-plane DSN via the
  # SIFT_CONTROL_PLANE_DSN env ref to reach the pgvector knowledge corpus; no
  # raw DSN is stored in app.mcp_backends.
  if [[ "${SIFT_RAG_ENABLED:-true}" == "true" ]]; then
    if _seed_one_addon_backend \
      "forensic-rag-mcp" \
      "$REPO_DIR/packages/forensic-rag-mcp/sift-backend.json" \
      "rag-mcp" \
      '{"SIFT_CONTROL_PLANE_DSN": "SIFT_CONTROL_PLANE_DSN"}'; then
      RAG_SEEDED=true
    fi
  else
    log "seed_addon_backends: SIFT_RAG_ENABLED != true — skipping forensic-rag-mcp seeding."
  fi
}

# A1-BOOTSTRAP: create the operator in Supabase Auth (Admin API) with status=invited.
# This runs AFTER gateway config is written (so SUPABASE_URL/SERVICE_ROLE_KEY are
# available in the environment) and after the gateway is started (so the DB is live).
# It is idempotent: if the handoff file already has a supabase_operator_email line,
# the bootstrap is skipped.
bootstrap_supabase_operator() {
  local sb_url="${SUPABASE_URL:-}"
  local sb_key="${SUPABASE_SERVICE_ROLE_KEY:-}"
  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"

  if [[ -z "$sb_url" || -z "$sb_key" ]]; then
    warn "SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set — skipping Supabase operator bootstrap."
    warn "  Set these env vars and re-run ./install.sh to provision the Supabase operator account."
    SUPABASE_OPERATOR_CREATED=0
    return
  fi
  if [[ -z "$cp_dsn" ]]; then
    warn "SIFT_CONTROL_PLANE_DSN is not set — skipping Supabase operator bootstrap."
    warn "  The installer will not create an auth user without the matching app.operator_profiles row."
    warn "  Set SIFT_CONTROL_PLANE_DSN (or DATABASE_URL/POSTGRES_DSN) and re-run ./install.sh."
    SUPABASE_OPERATOR_CREATED=0
    return
  fi

  # Idempotency: skip if already bootstrapped
  if svc_test_f "$MATERIALS_FILE" && svc_read "$MATERIALS_FILE" | grep -q '^supabase_operator_email=' 2>/dev/null; then
    log "Supabase operator already bootstrapped — preserving."
    SUPABASE_OPERATOR_EMAIL="$(svc_read "$MATERIALS_FILE" | awk -F= '$1=="supabase_operator_email"{sub(/^[^=]*=/,""); print; exit}' || true)"
    if [[ -z "$SUPABASE_OPERATOR_EMAIL" ]]; then
      SUPABASE_OPERATOR_EMAIL="${SIFT_EXAMINER}@operators.sift.local"
    fi
    SUPABASE_OPERATOR_CREATED=0
    SUPABASE_OPERATOR_MAPPED=1
    export SUPABASE_OPERATOR_EMAIL SUPABASE_OPERATOR_MAPPED
    return
  fi

  # A1-BOOTSTRAP: generate one-time installer password for Supabase operator.
  # The operator MUST reset this on first login (status=invited in DB).
  local sb_temp_password
  sb_temp_password="SiftReset-$(random_hex 16)"
  local sb_email="${SIFT_EXAMINER}@operators.sift.local"

  log "Provisioning Supabase operator: $sb_email (status=invited, forced-reset on first login)."
  export SUPABASE_URL="$sb_url" SUPABASE_SERVICE_ROLE_KEY="$sb_key"
  export SIFT_CONTROL_PLANE_DSN="$cp_dsn"
  export SB_OPERATOR_EMAIL="$sb_email" SB_OPERATOR_TEMP_PW="$sb_temp_password"
  export SB_OPERATOR_EXAMINER="$SIFT_EXAMINER"

  local create_result
  create_result=$("$VENV_DIR/bin/python" - <<'PY' 2>&1
import json, os, sys, time, urllib.request, urllib.error

url = os.environ["SUPABASE_URL"].rstrip("/")
key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
dsn = os.environ["SIFT_CONTROL_PLANE_DSN"]
email = os.environ["SB_OPERATOR_EMAIL"]
password = os.environ["SB_OPERATOR_TEMP_PW"]
examiner = os.environ["SB_OPERATOR_EXAMINER"]

try:
    import psycopg
    from psycopg.types.json import Jsonb
except Exception as exc:
    print(f"error:psycopg_unavailable:{exc}")
    sys.exit(0)


def _request(method, path, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    last_exc = None
    for attempt in range(1, 7):
        req = urllib.request.Request(
            f"{url}{path}",
            data=body,
            method=method,
            headers={
                "apikey": key,
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code < 500 or attempt == 6:
                raise
            last_exc = exc
        except urllib.error.URLError as exc:
            if attempt == 6:
                raise
            last_exc = exc
        time.sleep(min(2 * attempt, 10))
    if last_exc is not None:
        raise last_exc
    return {}


def _auth_user_by_email(conn):
    with conn.cursor() as cur:
        cur.execute(
            "select id::text from auth.users where lower(email) = lower(%s) limit 1",
            (email,),
        )
        row = cur.fetchone()
        return str(row[0]) if row else None


def _profile_for(conn, auth_user_id):
    with conn.cursor() as cur:
        cur.execute(
            """
            select id::text, status
            from app.operator_profiles
            where auth_user_id = %s or lower(email) = lower(%s)
            order by created_at
            limit 1
            """,
            (auth_user_id, email),
        )
        row = cur.fetchone()
        return (str(row[0]), str(row[1])) if row else (None, None)


def _upsert_operator_profile(conn, auth_user_id, prior_status):
    target_status = "active" if prior_status == "active" else "invited"
    metadata = {
        "installer_bootstrap": True,
        "bootstrap_source": "install.sh",
        "forced_reset_required": target_status == "invited",
    }
    profile_id, _status = _profile_for(conn, auth_user_id)
    with conn.cursor() as cur:
        if profile_id:
            cur.execute(
                """
                update app.operator_profiles
                set auth_user_id = %s,
                    display_name = %s,
                    email = %s,
                    status = case when status = 'active' then 'active' else %s end,
                    system_role = 'owner',
                    legacy_examiner_id = %s,
                    metadata = coalesce(metadata, '{}'::jsonb) || %s,
                    updated_at = now()
                where id = %s
                returning id::text, status
                """,
                (
                    auth_user_id,
                    examiner,
                    email,
                    target_status,
                    examiner,
                    Jsonb(metadata),
                    profile_id,
                ),
            )
        else:
            cur.execute(
                """
                insert into app.operator_profiles
                  (auth_user_id, display_name, email, status, system_role,
                   legacy_examiner_id, metadata)
                values (%s, %s, %s, %s, 'owner', %s, %s)
                returning id::text, status
                """,
                (auth_user_id, examiner, email, target_status, examiner, Jsonb(metadata)),
            )
        row = cur.fetchone()
        return str(row[0]), str(row[1])


def _create_auth_user():
    payload = {
        "email": email,
        "password": password,
        "email_confirm": True,
        "user_metadata": {
            "sift_principal_kind": "operator",
            "display_name": examiner,
            "installer_bootstrap": True,
        },
    }
    data = _request("POST", "/auth/v1/admin/users", payload)
    return str(data.get("id") or (data.get("user") or {}).get("id") or "")


def _reset_existing_auth_user(auth_user_id):
    payload = {
        "password": password,
        "email_confirm": True,
        "user_metadata": {
            "sift_principal_kind": "operator",
            "display_name": examiner,
            "installer_bootstrap": True,
        },
    }
    _request("PUT", f"/auth/v1/admin/users/{auth_user_id}", payload)


def _delete_auth_user(auth_user_id):
    try:
        _request("DELETE", f"/auth/v1/admin/users/{auth_user_id}", None)
    except Exception:
        pass


created_auth_user = False
reset_existing_password = False
auth_user_id = ""
try:
    with psycopg.connect(dsn) as conn:
        auth_user_id = _auth_user_by_email(conn)
        prior_profile_id = None
        prior_profile_status = None
        if auth_user_id:
            prior_profile_id, prior_profile_status = _profile_for(conn, auth_user_id)
        if not auth_user_id:
            auth_user_id = _create_auth_user()
            if not auth_user_id:
                print("error:no_id_in_response")
                sys.exit(0)
            created_auth_user = True
        elif prior_profile_status != "active":
            _reset_existing_auth_user(auth_user_id)
            reset_existing_password = True
        profile_id, profile_status = _upsert_operator_profile(
            conn, auth_user_id, prior_profile_status
        )
        conn.commit()
except urllib.error.HTTPError as exc:
    body = exc.read()[:200].decode("utf-8", errors="replace")
    print(f"http_error:{exc.code}:{body}")
except Exception as exc:
    if created_auth_user and auth_user_id:
        _delete_auth_user(auth_user_id)
    print(f"error:{exc}")
else:
    print("ok:" + json.dumps({
        "auth_user_id": auth_user_id,
        "operator_profile_id": profile_id,
        "profile_status": profile_status,
        "created_auth_user": created_auth_user,
        "reset_existing_password": reset_existing_password,
    }, separators=(",", ":")))
PY
)

  local rc=$?
  if [[ "$rc" -ne 0 ]] || [[ "$create_result" == error:* ]] || [[ "$create_result" == http_error:* ]]; then
    warn "Supabase operator bootstrap FAILED: $create_result"
    warn "  The legacy local examiner password is still available as a fallback."
    SUPABASE_OPERATOR_CREATED=0
    SB_OPERATOR_USER_ID=""
    return
  fi

  local bootstrap_json sb_user_id profile_status password_handoff
  bootstrap_json="${create_result#ok:}"
  sb_user_id="$("$VENV_DIR/bin/python" -c 'import json,sys; print(json.loads(sys.argv[1])["auth_user_id"])' "$bootstrap_json")"
  profile_status="$("$VENV_DIR/bin/python" -c 'import json,sys; print(json.loads(sys.argv[1])["profile_status"])' "$bootstrap_json")"
  password_handoff="$("$VENV_DIR/bin/python" -c 'import json,sys; d=json.loads(sys.argv[1]); print("1" if d.get("created_auth_user") or d.get("reset_existing_password") else "0")' "$bootstrap_json")"
  SB_OPERATOR_USER_ID="$sb_user_id"
  SUPABASE_OPERATOR_EMAIL="$sb_email"
  SUPABASE_OPERATOR_MAPPED=1
  if [[ "$password_handoff" == "1" ]]; then
    SUPABASE_OPERATOR_CREATED=1
    SUPABASE_OPERATOR_TEMP_PASSWORD="$sb_temp_password"
    export SUPABASE_OPERATOR_TEMP_PASSWORD
  else
    SUPABASE_OPERATOR_CREATED=0
    SUPABASE_OPERATOR_TEMP_PASSWORD=""
  fi
  export SB_OPERATOR_USER_ID SUPABASE_OPERATOR_EMAIL SUPABASE_OPERATOR_MAPPED

  log "Supabase operator mapped: auth_user_id=$sb_user_id  app.status=$profile_status."
  if [[ "$password_handoff" == "1" ]]; then
    log "NOTE: The one-time Supabase login password is written to: $MATERIALS_FILE"
    log "  The operator MUST reset this password immediately after first login."
  fi

  # Unset temp password from env so it's not inherited by child processes.
  unset SB_OPERATOR_TEMP_PW
}

# A1-BOOTSTRAP: validate the evidence/cases root directory and warn if missing.
validate_evidence_root() {
  log "Validating evidence root: $SIFT_CASES_ROOT"
  if [[ ! -d "$SIFT_CASES_ROOT" ]]; then
    warn "Evidence root '$SIFT_CASES_ROOT' does not exist — creating."
    # Owned by the service user to match install_state_dirs (the gateway
    # reads/registers evidence here). Normally install_state_dirs already created
    # it; this is the defensive fallback.
    sudo_if_needed install -d -m 755 -o "$SIFT_GATEWAY_SERVICE_USER" -g "$SIFT_GATEWAY_SERVICE_USER" "$SIFT_CASES_ROOT" || \
      warn "Could not create '$SIFT_CASES_ROOT' — operator must create it manually."
    return
  fi
  if [[ ! -r "$SIFT_CASES_ROOT" ]]; then
    warn "Evidence root '$SIFT_CASES_ROOT' is not readable by the current user."
    return
  fi
  local case_count
  case_count=$(find "$SIFT_CASES_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l || echo 0)
  log "Evidence root OK: $SIFT_CASES_ROOT ($case_count existing case directories)."
}

