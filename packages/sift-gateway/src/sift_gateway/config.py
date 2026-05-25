"""YAML config loading with environment variable interpolation."""

import logging
import os
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


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
    """Apply gateway case config to process env for backend inheritance."""
    case_config = config.get("case", {})
    if not isinstance(case_config, dict):
        case_config = {}

    case_dir = str(case_config.get("dir") or "").strip()
    cases_root = str(case_config.get("root") or "").strip()
    if not cases_root and case_dir:
        cases_root = str(Path(case_dir).parent)
    if not cases_root:
        cases_root = (
            os.environ.get("AGENTIR_CASES_ROOT")
            or os.environ.get("AGENTIR_CASE_ROOT")
            or ""
        )

    if cases_root:
        os.environ["AGENTIR_CASES_ROOT"] = cases_root
        logger.debug("AGENTIR_CASES_ROOT set to %s from gateway config", cases_root)

    if case_dir:
        os.environ["AGENTIR_CASE_DIR"] = case_dir
        logger.debug("AGENTIR_CASE_DIR set to %s from gateway config", case_dir)
    else:
        os.environ.pop("AGENTIR_CASE_DIR", None)


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

    # Warn early if portal session secret is absent — portal auth will fail at runtime.
    portal_secret = config.get("portal", {}).get("session_secret", "")
    if not portal_secret:
        logger.warning(
            "portal.session_secret is not set in %s — portal login will not function", path
        )

    return config
