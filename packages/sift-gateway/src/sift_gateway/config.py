"""YAML config loading with environment variable interpolation."""

import logging
import os
import re
from pathlib import Path

import yaml
from sift_core.execute.catalog import clear_catalog_cache
from sift_core.execute.security_policy import (
    SECURITY_POLICY_ENV,
    build_security_policy,
    policy_to_env_json,
)
from sift_gateway.response_guard import OUTPUT_CAP_ENV

logger = logging.getLogger(__name__)


_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
EXECUTE_AS_USER_ENV = "SIFT_EXECUTE_AS_USER"


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} patterns with environment variable values.

    If a referenced variable is not set, the placeholder is replaced with
    an empty string to prevent literal '${VAR}' from leaking into configs.
    """

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return os.environ.get(var_name, "")

    return _ENV_VAR_PATTERN.sub(_replace, value)


def _walk_and_interpolate(obj):
    """Recursively walk a parsed YAML structure and interpolate strings."""
    if isinstance(obj, str):
        return _interpolate_env(obj)
    if isinstance(obj, dict):
        return {k: _walk_and_interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_interpolate(item) for item in obj]
    return obj


def apply_case_env(config: dict) -> None:
    """Apply non-authoritative case-root config to process env.

    PR03B/D32: ``case.dir`` is no longer active-case authority and is never
    published as ``SIFT_CASE_DIR`` by the Gateway. ``case.root`` may still seed
    artifact-root behavior for legacy CLI surfaces.
    """
    case_config = config.get("case", {})
    if not isinstance(case_config, dict):
        case_config = {}

    cases_root = str(case_config.get("root") or "").strip()
    if not cases_root:
        cases_root = (
            os.environ.get("SIFT_CASES_ROOT")
            or os.environ.get("SIFT_CASE_ROOT")
            or ""
        )

    if cases_root:
        os.environ["SIFT_CASES_ROOT"] = cases_root
        logger.debug("SIFT_CASES_ROOT set to %s from gateway config", cases_root)

    # Do not publish or clear SIFT_CASE_DIR here. PR03B Gateway request paths
    # use DB active-case context when configured; legacy CLI/test surfaces may
    # still carry their own env value outside Gateway authority.


def apply_execute_security_env(config: dict) -> None:
    """Apply gateway executor policy to process env for in-process core tools."""
    execute_config = config.get("execute", {})
    if not isinstance(execute_config, dict):
        raise ValueError("execute must be a mapping")
    policy_config = execute_config.get("security")
    policy = build_security_policy(policy_config, require_operator_policy=True)
    os.environ[SECURITY_POLICY_ENV] = policy_to_env_json(policy)

    runtime_user = execute_config.get("runtime_user", "agent_runtime")
    if runtime_user is None:
        runtime_user = ""
    if not isinstance(runtime_user, str):
        raise ValueError("execute.runtime_user must be a string")
    runtime_user = runtime_user.strip()
    if runtime_user:
        os.environ[EXECUTE_AS_USER_ENV] = runtime_user
    else:
        os.environ[EXECUTE_AS_USER_ENV] = "__current__"
    clear_catalog_cache()


def apply_trust_env(config: dict) -> None:
    """Apply the trust-layer central output cap to process env.

    Translates ``trust.output_cap_bytes`` in ``gateway.yaml`` into the single
    ``SIFT_OUTPUT_CAP`` env read by ``response_guard.output_cap_bytes()``.
    Absent ⇒ leave the env untouched (the resolver falls back to its default).
    """
    trust_config = config.get("trust", {})
    if not isinstance(trust_config, dict):
        raise ValueError("trust must be a mapping")
    cap = trust_config.get("output_cap_bytes")
    if cap is None:
        return
    try:
        cap_int = int(cap)
    except (TypeError, ValueError):
        raise ValueError("trust.output_cap_bytes must be a positive integer") from None
    if cap_int <= 0:
        raise ValueError("trust.output_cap_bytes must be a positive integer")
    os.environ[OUTPUT_CAP_ENV] = str(cap_int)


def load_auth_config(config: dict):
    """Parse the ``auth.supabase`` / ``auth.legacy`` block into a SupabaseAuthConfig.

    Env secrets (SUPABASE_URL / SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY)
    are read from the process environment only — never from repo files.
    """
    from sift_gateway.supabase_auth import load_supabase_auth_config

    return load_supabase_auth_config(config)


def load_config(path: str) -> dict:
    """Load a YAML config file with env var interpolation.

    Args:
        path: Path to the YAML config file.

    Returns:
        Parsed and interpolated config dict.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    try:
        with open(config_path) as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error("Invalid YAML in config file %s: %s", path, e)
        raise
    except OSError as e:
        logger.error("Cannot read config file %s: %s", path, e)
        raise

    if raw is None:
        return {}

    if not isinstance(raw, dict):
        raise ValueError(
            f"Config file must contain a YAML mapping, got {type(raw).__name__}: {path}"
        )

    config = _walk_and_interpolate(raw)

    apply_case_env(config)
    apply_execute_security_env(config)
    apply_trust_env(config)
    resolve_portal_session_secret(config)

    # Warn early if portal session secret is absent — portal auth will fail at runtime.
    portal_secret = config.get("portal", {}).get("session_secret", "")
    if not portal_secret:
        logger.warning(
            "portal.session_secret is not set in %s — portal login will not function", path
        )

    return config


def resolve_portal_session_secret(config: dict) -> None:
    """Resolve the portal session secret from env-indirection (B-MVP-010).

    The installer no longer writes the literal session secret into
    ``gateway.yaml``; it writes a ``portal.session_secret_env`` name reference
    (like ``control_plane.postgres_dsn_env`` and ``token_registry.pepper_env``)
    and stores the value in the ``0600`` env file the unit loads. Here we read
    the named env var and populate ``portal.session_secret`` in-memory so the
    rest of the gateway (``server.py``) reads it unchanged.

    Back-compat: if ``session_secret_env`` is absent but a literal
    ``session_secret`` is present (older configs), that literal is kept as-is.
    """
    portal_config = config.get("portal")
    if not isinstance(portal_config, dict):
        return
    secret_env = portal_config.get("session_secret_env")
    if not secret_env:
        return
    resolved = os.environ.get(secret_env, "").strip()
    if resolved:
        portal_config["session_secret"] = resolved
    elif not portal_config.get("session_secret"):
        logger.warning(
            "portal.session_secret_env=%s is set but the environment variable is "
            "empty — portal login will not function",
            secret_env,
        )
