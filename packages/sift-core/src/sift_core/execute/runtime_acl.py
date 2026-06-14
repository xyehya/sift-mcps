"""Runtime environment + authority-file isolation for ``run_command`` (BATCH-K5).

This module is the single source of truth for two run_command authority-isolation
guarantees that the rest of the execute pipeline relies on:

1. **Environment scrubbing.** The Gateway/worker process holds the control-plane
   DSN, Supabase keys, service-role secrets, OpenSearch credentials, and other
   VM secrets in its environment (the durable job worker, for example, loads
   ``~/.sift/supabase.env``). A sandboxed forensic command must never inherit
   those. :func:`build_sandbox_env` returns a minimal, scrubbed environment that
   keeps only an explicit safe allowlist (PATH, locale, HOME/TMPDIR, and the
   ``SIFT_EXECUTE_*`` runtime knobs the worker and tools legitimately need) and
   drops everything else, with a deny check that wins even if a future
   allowlist entry would otherwise match a secret name.

2. **Authority-file write protection.** In the final DB-active model the
   critical authority files (audit, approvals, evidence manifest/ledger, anchor,
   active-case pointers) do not live in the case dir at all, and host ACLs from
   ``scripts/setup-agent-runtime.sh`` are the backstop. :func:`is_authority_path`
   / :func:`assert_no_authority_write_target` add a defense-in-depth guard so a
   command can never be pointed at one of those legacy authority artifacts as a
   write/redirect target even if one is still present during the bridge.

Both guards are pure functions so they are unit-testable without spawning a
subprocess and without a real DB.
"""

from __future__ import annotations

import os
import re

from sift_core.execute.security_policy import SECURITY_POLICY_ENV

# --- environment isolation ---------------------------------------------------

# Exact env var names that are always safe to pass through to a forensic tool.
# Intentionally tiny: a locale, a search path, a writable temp/home, and a
# non-interactive terminal hint. Nothing here carries authority or secrets.
_SAFE_ENV_NAMES: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",  # informational only; we never invoke a shell (shell=False)
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "LC_NUMERIC",
        "LC_TIME",
        "LC_COLLATE",
        "LC_MESSAGES",
        "TZ",
        "PWD",
    }
)

# SIFT_* runtime knobs the worker/executor and a handful of tools genuinely
# need. These are operational configuration, not secrets. The security policy
# is shipped to the (in-process) policy layer via SECURITY_POLICY_ENV; it
# contains only allow/deny rules, no credentials, so it is safe to keep.
_SAFE_SIFT_ENV_NAMES: frozenset[str] = frozenset(
    {
        "SIFT_CASE_DIR",
        "SIFT_EXAMINER",
        "SIFT_TOOL_PATHS",
        "SIFT_TIMEOUT",
        "SIFT_HAYABUSA_DIR",
        "SIFT_RESPONSE_BUDGET",
        "SIFT_MAX_OUTPUT",
        "SIFT_EXECUTE_MEMORY_LIMIT",
        "SIFT_EXECUTE_AS_USER",
        "SIFT_SHARE_ROOT",
        "SIFT_STATE_DIR",
        SECURITY_POLICY_ENV,
    }
)

# Substring patterns (case-insensitive) that mark an env var as secret-bearing
# or authority-bearing. This is the deny floor for env: it is checked *after*
# the allowlist so it can never be re-enabled by an allowlist mistake, and it
# also covers names we never anticipated. Mirrors the run-command security
# invariant: no DB DSNs, Supabase keys, service-role secrets, OpenSearch
# credentials, or VM secrets.
_SECRET_ENV_PATTERNS: tuple[str, ...] = (
    "secret",
    "password",
    "passwd",
    "token",
    "apikey",
    "api_key",
    "service_role",
    "service-role",
    "private",
    "credential",
    "dsn",
    "database_url",
    "supabase",
    "postgres",
    "pg_",
    "pghost",
    "pgport",
    "pguser",
    "pgpassword",
    "pgdatabase",
    "opensearch",
    "elastic",
    "aws_",
    "gcp_",
    "azure_",
    "jwt",
    "hmac",
    "signing",
    "anchor",
    "solana",
    "session",
    "cookie",
    "auth",
    "bearer",
    "ssh",
    # Runtime code-injection vectors. These are not credentials, but they can
    # make allowed forensic runtimes load attacker-controlled code.
    "dotnet_",
    "coreclr_",
    "ld_",
    "ld_preload",
    "ld_library_path",
    "ld_audit",
    "python",
    "perl5",
    "rubyopt",
    "gem_",
    "node_options",
    "node_path",
    "lua_",
    "bash_env",
    "gconv_path",
    "nlspath",
    "ifs",
)


def _is_secret_env_name(name: str) -> bool:
    lowered = name.lower()
    return any(pattern in lowered for pattern in _SECRET_ENV_PATTERNS)


def build_sandbox_env(
    base_env: dict[str, str] | None = None,
    *,
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return a scrubbed environment for a sandboxed run_command subprocess.

    Only names in the explicit safe allowlist survive, and any name matching a
    secret pattern is dropped even if it was allowlisted. ``overrides`` are
    applied last and are themselves subject to the secret deny check, so a
    caller cannot accidentally smuggle a secret back in.

    Args:
        base_env: Source environment (defaults to ``os.environ``).
        overrides: Extra safe values to set (e.g. ``PATH`` for tool discovery,
            ``TERM`` to keep tools non-interactive). Secret-named overrides are
            ignored.
    """
    source = dict(os.environ if base_env is None else base_env)
    allow = _SAFE_ENV_NAMES | _SAFE_SIFT_ENV_NAMES
    scrubbed: dict[str, str] = {}
    for name, value in source.items():
        if name not in allow:
            continue
        if _is_secret_env_name(name):
            continue
        scrubbed[name] = value

    # Force non-interactive, predictable tool behavior. TERM=dumb stops pagers
    # and tools that probe for a TTY; explicit locale avoids parser surprises.
    scrubbed.setdefault("TERM", "dumb")
    scrubbed.setdefault("LC_ALL", scrubbed.get("LANG", "C.UTF-8"))

    if overrides:
        for name, value in overrides.items():
            if _is_secret_env_name(name):
                continue
            scrubbed[name] = value
    return scrubbed


def env_leak_report(env: dict[str, str]) -> list[str]:
    """Return any secret-named keys present in ``env`` (empty == clean).

    Used by tests and as a defensive assertion point before spawning.
    """
    return sorted(name for name in env if _is_secret_env_name(name))


# --- authority-file write protection -----------------------------------------

# Basenames of legacy authority/proof artifacts. In DB-active mode these are not
# authority (Postgres is), but a sandboxed command must still never be allowed
# to write/overwrite one if it is materialized during the bridge.
AUTHORITY_FILE_BASENAMES: frozenset[str] = frozenset(
    {
        "case.yaml",
        "active_case",
        "findings.json",
        "timeline.json",
        "todos.json",
        "iocs.json",
        "approvals.jsonl",
        "evidence-manifest.json",
        "evidence-ledger.jsonl",
        "evidence-verify-state.json",
        "host-dictionary.yaml",
    }
)

# Substring markers for authority directories/files (audit logs, anchors).
_AUTHORITY_PATH_MARKERS: tuple[str, ...] = (
    "/audit/",
    "evidence-anchor",
    "/.sift/",
    "/var/lib/sift",
)


def is_authority_path(path: str) -> bool:
    """True if ``path`` looks like a legacy authority/proof artifact."""
    if not path:
        return False
    normalized = path.replace("\\", "/")
    base = normalized.rsplit("/", 1)[-1].lower()
    if base in AUTHORITY_FILE_BASENAMES:
        return True
    lowered = normalized.lower()
    return any(marker in lowered for marker in _AUTHORITY_PATH_MARKERS)


def assert_no_authority_write_target(targets: list[str]) -> None:
    """Raise ``PermissionError`` if any write/redirect target is an authority file.

    Defense in depth on top of host ACLs and the case write-jail: even inside
    the allowed agent/extractions/tmp jail, refuse a path that resolves onto a
    known authority artifact name.
    """
    for target in targets:
        if is_authority_path(str(target)):
            raise PermissionError(
                "run_command may not write to an authority/proof artifact: "
                f"{os.path.basename(str(target)) or str(target)}"
            )
