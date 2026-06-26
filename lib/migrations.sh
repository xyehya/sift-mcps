# shellcheck shell=bash
# =============================================================================
# lib/migrations.sh — extracted VERBATIM from install.sh (#18 modularization).
# Side-effect-free on source: defines functions/vars only, runs no install
# step. install.sh sources it before main(); scripts/setup-addon.sh sources
# install.sh (which sources this) to reuse the functions as a library.
# =============================================================================
[[ -n "${_SIFT_LIB_MIGRATIONS_SOURCED:-}" ]] && return 0
_SIFT_LIB_MIGRATIONS_SOURCED=1

apply_db_migrations() {
  if [[ "${SIFT_CORE_ONLY:-0}" == "1" ]]; then
    log "apply_db_migrations: core-only — skipping."
    return 0
  fi

  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"
  if [[ -z "$cp_dsn" ]]; then
    log "apply_db_migrations: SIFT_CONTROL_PLANE_DSN not set — skipping."
    return 0
  fi

  local migrations_dir="$REPO_DIR/supabase/migrations"
  if [[ ! -d "$migrations_dir" ]]; then
    log "apply_db_migrations: no migrations directory at $migrations_dir — skipping."
    return 0
  fi

  # Collect and sort migration files by filename (lexicographic = timestamp order).
  local migration_files=()
  while IFS= read -r -d '' f; do
    migration_files+=("$f")
  done < <(find "$migrations_dir" -maxdepth 1 -name '*.sql' -print0 | sort -z)

  if [[ "${#migration_files[@]}" -eq 0 ]]; then
    log "apply_db_migrations: no .sql files found in $migrations_dir."
    return 0
  fi

  log "apply_db_migrations: applying ${#migration_files[@]} migration(s) via psycopg3."
  export SIFT_CONTROL_PLANE_DSN="$cp_dsn"
  export MIGRATIONS_DIR="$migrations_dir"

  # Pass filenames via a NUL-delimited env string.
  local files_joined
  files_joined="$(printf '%s\n' "${migration_files[@]}")"
  export MIGRATION_FILES_LIST="$files_joined"

  local result
  result=$("$VENV_DIR/bin/python" - 2>&1 <<'PY'
import os, sys
from pathlib import Path

dsn = os.environ["SIFT_CONTROL_PLANE_DSN"]
files_raw = os.environ.get("MIGRATION_FILES_LIST", "")
files = [f for f in files_raw.splitlines() if f.strip()]

try:
    import psycopg
except ImportError as exc:
    print(f"skip:psycopg_unavailable:{exc}", file=sys.stderr)
    sys.exit(1)


def _migration_version(name):
    # The Supabase CLI records each migration under the leading timestamp prefix
    # of the filename (the digits before the first underscore). We mirror that so
    # we can recognise migrations that `supabase start` already applied.
    stem = name[:-4] if name.endswith(".sql") else name
    head = stem.split("_", 1)[0]
    return head if head.isdigit() else stem


# B-MVP-043: `supabase start` already applies supabase/migrations/* and records
# each in supabase_migrations.schema_migrations. Re-running the same files here
# via psycopg produces noisy "already exists" / "cannot drop columns from view"
# warnings. Read the recorded versions up front and SKIP any migration that the
# CLI already applied. On a fresh DB (no Supabase CLI, table absent) this set is
# empty, so every migration still runs — fresh-install behaviour is unchanged.
applied_versions = set()
try:
    with psycopg.connect(dsn, autocommit=True) as conn:
        cur = conn.execute(
            "select version from supabase_migrations.schema_migrations"
        )
        applied_versions = {str(row[0]) for row in cur.fetchall()}
except Exception as exc:
    # Table/schema absent (non-Supabase DB or pre-CLI) — treat as nothing applied.
    print(f"info:migration_ledger_unavailable:{str(exc).split(chr(10))[0][:80]}",
          file=sys.stderr)

first_file = True
for fpath in files:
    p = Path(fpath)
    version = _migration_version(p.name)
    if version in applied_versions:
        print(f"skip:{p.name}:already recorded by supabase start")
        first_file = False
        continue
    sql_text = p.read_text(encoding="utf-8")
    try:
        # autocommit + no params = simple-query protocol; handles multi-statement DDL.
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(sql_text)
        print(f"ok:{p.name}")
    except Exception as exc:
        short = str(exc).split('\n')[0][:120]
        duplicate_ok = "already exists" in short or "Duplicate" in type(exc).__name__
        if first_file and not duplicate_ok:
            # First/foundational migration failing likely means DB is unreachable.
            print(f"fatal:{p.name}:{short}", file=sys.stderr)
            sys.exit(1)
        print(f"warn:{p.name}:{short}", file=sys.stderr)
    first_file = False
PY
  ) || {
    warn "apply_db_migrations: foundational migration failed (DB unreachable?)."
    warn "  $result"
    die "Cannot continue — DB migrations required.  Fix SIFT_CONTROL_PLANE_DSN and re-run."
  }

  # Parse results and emit per-file log/warn.
  local had_warn=0
  while IFS= read -r line; do
    case "$line" in
      ok:*)   log "  migration applied: ${line#ok:}" ;;
      warn:*) warn "  migration skipped/warned: ${line#warn:}"; had_warn=1 ;;
      skip:*) log "  $line" ;;
      *)      [[ -n "$line" ]] && log "  $line" ;;
    esac
  done <<< "$result"

  if [[ "$had_warn" -eq 1 ]]; then
    warn "apply_db_migrations: some migrations warned — schema may be partially applied."
    warn "  This is often safe (IF NOT EXISTS clauses). Verify manually if needed."
  else
    log "apply_db_migrations: all migrations applied successfully."
  fi
}

# =============================================================================
# G1 — provision the least-privilege audit-write role (sift_audit_writer).
# =============================================================================
# Migration 202606242100_audit_writer_role.sql CREATEs the scoped role WITH LOGIN
# but deliberately NO password (never hardcode a credential in a migration). The
# gateway reads SIFT_AUDIT_WRITER_DSN and FALLS BACK to the full control-plane
# (service_role / BYPASSRLS) DSN when it is unset — so without this step the
# least-privilege role ships INERT and forward-writes keep using the broad DSN.
#
# This function mints a password for the role and writes the scoped DSN into the
# 0600 sift-service control-plane.env. It runs AFTER apply_db_migrations so the
# role already exists. It is an ENHANCEMENT, not a hard dependency: on any
# failure (role absent, DB unreachable, parse error) it WARNS and continues — the
# code-side fallback keeps provenance working.
#
# Secret handling (security-reviewed):
#   - The password is generated with random_hex (CSPRNG via openssl) and passed
#     to Python ONLY through an environment variable (AUDIT_WRITER_PW), never on
#     argv (avoids /proc/<pid>/cmdline + `ps` leakage).
#   - The ALTER ROLE ... PASSWORD statement is composed with psycopg.sql
#     (Identifier for the role, Literal for the password) — the raw password is
#     NEVER f-string-interpolated into DDL.
#   - The scoped DSN is derived with urllib.parse (urlsplit/urlunsplit), the
#     password URL-encoded with quote(safe=''); host/port/path(db)/query are
#     preserved verbatim (sslmode etc. survive).
#   - Python emits ONLY a single `dsn:<value>` marker line on stdout; status
#     markers go to stderr. Bash captures the DSN but NEVER passes it (or the
#     password) to log/warn/echo. The DSN lands only in the 0600 env file.
provision_audit_writer() {
  if [[ "${SIFT_CORE_ONLY:-0}" == "1" ]]; then
    log "provision_audit_writer: core-only — skipping."
    return 0
  fi

  local cp_dsn
  cp_dsn="$(_resolved_control_plane_dsn)"
  if [[ -z "$cp_dsn" ]]; then
    log "provision_audit_writer: no control-plane DSN — skipping (least-privilege role stays inert)."
    return 0
  fi

  local control_env_file="$SIFT_HOME/control-plane.env"

  # Preserve-on-rerun: if the scoped DSN is already present, reuse it. Re-minting
  # the password would invalidate the live role's existing credential.
  local existing_writer_dsn
  existing_writer_dsn="$(_env_file_value "$control_env_file" "SIFT_AUDIT_WRITER_DSN")"
  if [[ -n "$existing_writer_dsn" ]]; then
    log "provision_audit_writer: SIFT_AUDIT_WRITER_DSN already set — preserving (no password churn)."
    export SIFT_AUDIT_WRITER_DSN="$existing_writer_dsn"
    return 0
  fi

  log "provision_audit_writer: minting sift_audit_writer credential + scoped DSN."

  # CSPRNG password — passed to Python via env (AUDIT_WRITER_PW), never argv.
  local audit_pw
  audit_pw="$(random_hex 32)"

  local scoped_dsn
  scoped_dsn="$(
    SIFT_CONTROL_PLANE_DSN="$cp_dsn" AUDIT_WRITER_PW="$audit_pw" \
      "$VENV_DIR/bin/python" - <<'PY'
import os, sys
from urllib.parse import urlsplit, urlunsplit, quote

dsn = os.environ["SIFT_CONTROL_PLANE_DSN"]
pw = os.environ["AUDIT_WRITER_PW"]
ROLE = "sift_audit_writer"

try:
    import psycopg
    from psycopg import sql
except ImportError as exc:
    print(f"skip:psycopg_unavailable:{exc}", file=sys.stderr)
    sys.exit(0)

# 1. Confirm the role exists (migration may have been skipped / DB partial).
try:
    with psycopg.connect(dsn, autocommit=True) as conn:
        cur = conn.execute(
            "select 1 from pg_roles where rolname = %s", (ROLE,)
        )
        if cur.fetchone() is None:
            print("skip:role_absent", file=sys.stderr)
            sys.exit(0)
        # 2. Set the password. Composed via psycopg.sql — the raw password is
        #    NEVER string-formatted into the DDL text.
        conn.execute(
            sql.SQL("alter role {} with password {}").format(
                sql.Identifier(ROLE),
                sql.Literal(pw),
            )
        )
except Exception as exc:  # noqa: BLE001 — best-effort enhancement, fail-soft
    short = str(exc).split("\n")[0][:120]
    print(f"error:alter_failed:{short}", file=sys.stderr)
    sys.exit(1)

# 3. Derive the scoped DSN: swap username -> sift_audit_writer and password ->
#    the minted (URL-encoded) password; keep host/port/path(db)/query verbatim.
parts = urlsplit(dsn)
host = parts.hostname or ""
userinfo = ROLE + ":" + quote(pw, safe="")
netloc = userinfo + "@" + host
if parts.port is not None:
    netloc += ":" + str(parts.port)
scoped = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))

# 4. Emit ONLY the DSN marker on stdout (status markers go to stderr).
sys.stdout.write("dsn:" + scoped + "\n")
PY
  )" || {
    warn "provision_audit_writer: credential provisioning failed — least-privilege role stays inert."
    warn "  Forward-writes fall back to the full control-plane DSN (provenance still works)."
    unset audit_pw
    return 0
  }

  # Extract the dsn: marker (do NOT echo/log the value).
  local writer_dsn=""
  while IFS= read -r line; do
    case "$line" in
      dsn:*) writer_dsn="${line#dsn:}" ;;
    esac
  done <<< "$scoped_dsn"

  # Scrub the plaintext password from this shell's memory ASAP.
  unset audit_pw scoped_dsn

  if [[ -z "$writer_dsn" ]]; then
    warn "provision_audit_writer: role absent or no DSN returned — skipping (least-privilege inactive)."
    return 0
  fi

  # UPSERT SIFT_AUDIT_WRITER_DSN into control-plane.env, preserving every other
  # key. Re-install 0600 sift-service via svc_install_file. The DSN value never
  # touches a log/echo line — it lives only in the operator-temp -> 0600 file.
  if ! svc_test_f "$control_env_file"; then
    warn "provision_audit_writer: $control_env_file missing — skipping DSN write."
    unset writer_dsn
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  # The temp file transiently holds the scoped DSN. EXIT cleanup covers `set -e`
  # aborts; normal and fail-soft paths clear the trap immediately after cleanup.
  trap 'rm -f "${tmp:-}"; trap - EXIT' EXIT
  # Copy existing keys EXCEPT any prior SIFT_AUDIT_WRITER_DSN line, then append
  # the fresh one. svc_read uses sudo to read the sift-service-owned 0600 file.
  svc_read "$control_env_file" | grep -v '^SIFT_AUDIT_WRITER_DSN=' > "$tmp" || true
  printf 'SIFT_AUDIT_WRITER_DSN=%s\n' "$writer_dsn" >> "$tmp"
  # Fail-soft: per this function's contract least-privilege is an enhancement, not
  # a hard dependency — a write failure must NOT abort the whole install. Warn
  # (no secret) and continue; forward-writes fall back to the full control-plane DSN.
  if ! svc_install_file "$tmp" "$control_env_file" 600; then
    warn "provision_audit_writer: audit-writer DSN write failed — least-privilege role inactive (forward-writes use the full control-plane DSN); continuing."
    rm -f "$tmp"
    trap - EXIT
    return 0
  fi

  export SIFT_AUDIT_WRITER_DSN="$writer_dsn"
  unset writer_dsn
  log "provision_audit_writer: scoped DSN written to control-plane.env (least-privilege active)."
  rm -f "$tmp"
  trap - EXIT
}
