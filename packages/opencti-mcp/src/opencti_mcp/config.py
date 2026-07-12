"""Configuration management for OpenCTI MCP.

Security design:
- Tokens stored as SecretStr (never logged)
- Token file permissions enforced (600)
- Config objects cannot be pickled
- URL validation prevents SSRF
"""

from __future__ import annotations

import logging
import os
import stat
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

from sift_common.env import (
    SecretStr,
)
from sift_common.env import (
    parse_float_env as _parse_float_env,
)
from sift_common.env import (
    parse_int_env as _parse_int_env,
)
from sift_common.env import (
    parse_set_env as _parse_set_env,
)

from .errors import ConfigurationError

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration Class
# =============================================================================


@dataclass(frozen=True)
class Config:
    """Immutable server configuration.

    Security:
    - opencti_token is SecretStr (never logged)
    - Cannot be pickled (prevents serialization of secrets)
    - URL validated to prevent SSRF
    - frozen=True prevents accidental mutation

    Production considerations:
    - timeout_seconds: Increase for remote instances (60-120s recommended)
    - max_retries: Number of retry attempts for transient failures
    - retry_backoff: Exponential backoff multiplier
    - ssl_verify: Enable for production (disable only for local dev)
    - circuit_breaker_threshold: Failures before circuit opens
    """

    opencti_url: str
    opencti_token: SecretStr
    timeout_seconds: int = 60
    max_results: int = 100
    # Rate limits are PER MINUTE for both limiters. Previously the
    # enrichment limiter used a 1-hour window with a cap of 10, which
    # was arbitrarily conservative and blocked bulk operations (UAT
    # 2026-04-23: 5,426-IOC enrichment runs were bottlenecked by the
    # query limiter at 60/min → 90 min). Both defaults are sized for
    # a dedicated OpenCTI instance; shared/SaaS operators should
    # override via env. Override: `OPENCTI_RATE_LIMIT_QUERIES` and
    # `OPENCTI_RATE_LIMIT_ENRICHMENT` (both integers, requests/min).
    rate_limit_queries: int = 600  # queries per minute
    rate_limit_enrichment: int = 100  # enrichment/write ops per minute

    # Production network resilience
    max_retries: int = 3  # retry attempts for transient failures
    retry_base_delay: float = 1.0  # base delay in seconds (exponential backoff)
    retry_max_delay: float = 30.0  # max delay between retries
    ssl_verify: bool = True  # verify SSL certs (disable only for local dev)
    circuit_breaker_threshold: int = 5  # failures before circuit opens
    circuit_breaker_timeout: int = 60  # seconds before circuit half-opens

    # Extensibility - allow custom types for customized OpenCTI instances
    extra_observable_types: frozenset[str] = field(default_factory=frozenset)
    extra_pattern_types: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate configuration after initialization.

        Note: Uses object.__setattr__ because dataclass is frozen.
        """
        # Validate and normalize URL (can't reassign due to frozen, so validate first)
        validated_url = _validate_url(self.opencti_url)
        # Use object.__setattr__ to bypass frozen for initialization
        object.__setattr__(self, "opencti_url", validated_url)
        self._validate_values()

    def _validate_values(self) -> None:
        """Validate configuration values (called from __post_init__)."""
        # Validate token
        if not self.opencti_token:
            raise ConfigurationError("OpenCTI token is required")

        # Validate numeric values
        if self.timeout_seconds < 1 or self.timeout_seconds > 300:
            raise ConfigurationError("timeout_seconds must be between 1 and 300")

        if self.max_results < 1 or self.max_results > 1000:
            raise ConfigurationError("max_results must be between 1 and 1000")

    def __repr__(self) -> str:
        """Safe repr that never includes a credential or endpoint location."""
        return (
            f"Config(transport={urlparse(self.opencti_url).scheme!r}, "
            f"token=***, timeout={self.timeout_seconds}s)"
        )

    def __str__(self) -> str:
        return self.__repr__()

    def __getstate__(self) -> None:
        """Prevent pickling to avoid credential serialization."""
        raise TypeError("Config cannot be pickled (contains secrets)")

    def __reduce__(self) -> None:  # type: ignore[override]
        """Prevent pickling via reduce."""
        raise TypeError("Config cannot be pickled (contains secrets)")

    @classmethod
    def load(cls) -> Config:
        """Load configuration from environment and files.

        Credential sources (precedence order):
        1. OPENCTI_TOKEN environment variable
        2. ~/.config/opencti-mcp/token file
        3. .env file in working directory

        Returns:
            Config: Validated configuration

        Raises:
            ConfigurationError: If token not found or invalid
        """
        # Load URL
        url = os.getenv("OPENCTI_URL", "http://localhost:8080")

        # Load token
        token = _load_token()
        if not token:
            raise ConfigurationError(
                "OpenCTI API token not found. Set OPENCTI_TOKEN environment variable "
                "or create ~/.config/opencti-mcp/token file."
            )

        # Load optional settings with safe parsing
        timeout = _parse_int_env("OPENCTI_TIMEOUT", 60)
        max_results = _parse_int_env("OPENCTI_MAX_RESULTS", 100)

        # Rate limits — operator-tunable for varying OpenCTI capacities.
        # Defaults sized for a dedicated instance; shared/SaaS operators
        # should tune down.
        rate_limit_queries = _parse_int_env("OPENCTI_RATE_LIMIT_QUERIES", 600)
        rate_limit_enrichment = _parse_int_env("OPENCTI_RATE_LIMIT_ENRICHMENT", 100)

        # Production resilience settings
        max_retries = _parse_int_env("OPENCTI_MAX_RETRIES", 3)
        retry_base_delay = _parse_float_env("OPENCTI_RETRY_DELAY", 1.0)
        retry_max_delay = _parse_float_env("OPENCTI_RETRY_MAX_DELAY", 30.0)
        ssl_verify = os.getenv("OPENCTI_SSL_VERIFY", "true").lower() in (
            "true",
            "1",
            "yes",
        )
        circuit_threshold = _parse_int_env("OPENCTI_CIRCUIT_THRESHOLD", 5)
        circuit_timeout = _parse_int_env("OPENCTI_CIRCUIT_TIMEOUT", 60)

        # Extensibility settings for custom OpenCTI instances
        extra_observable_types = _parse_set_env("OPENCTI_EXTRA_OBSERVABLE_TYPES")
        extra_pattern_types = _parse_set_env("OPENCTI_EXTRA_PATTERN_TYPES")

        return cls(
            opencti_url=url,
            opencti_token=SecretStr(token),
            timeout_seconds=timeout,
            max_results=max_results,
            rate_limit_queries=rate_limit_queries,
            rate_limit_enrichment=rate_limit_enrichment,
            max_retries=max_retries,
            retry_base_delay=retry_base_delay,
            retry_max_delay=retry_max_delay,
            ssl_verify=ssl_verify,
            circuit_breaker_threshold=circuit_threshold,
            circuit_breaker_timeout=circuit_timeout,
            extra_observable_types=extra_observable_types,
            extra_pattern_types=extra_pattern_types,
        )


# =============================================================================
# Token Loading
# =============================================================================


def _load_token() -> str | None:
    """Load OpenCTI token from available sources.

    Security: Token file permissions are enforced.
    """
    # 1. Environment variable (highest priority)
    token = os.getenv("OPENCTI_TOKEN")
    if token is not None:
        stripped = token.strip()
        if stripped:
            logger.debug("Loaded token from OPENCTI_TOKEN environment variable")
            return stripped
        # Non-empty but whitespace-only — treat as explicitly invalid, don't fall through
        if token:
            return None

    # 2. Config file (primary location)
    config_file = Path.home() / ".config" / "opencti-mcp" / "token"
    token = _load_token_file(config_file)
    if token:
        logger.debug("Loaded token from config file")
        return token

    # 3. Legacy config file (for compatibility with opencti_query.py)
    legacy_config = Path.home() / ".config" / "rag" / "opencti_token"
    token = _load_token_file(legacy_config)
    if token:
        logger.debug(
            "Loaded token from legacy config file (~/.config/rag/opencti_token)"
        )
        return token

    # 4. .env file in current directory
    env_file = Path.cwd() / ".env"
    token = _load_token_from_env_file(env_file)
    if token:
        logger.debug("Loaded token from .env file")
        return token

    return None


def _load_token_file(path: Path) -> str | None:
    """Load token from file with permission check.

    Security: Refuses to load token if file permissions are too open.
    """
    if not path.exists():
        return None

    # Check file permissions on POSIX systems
    if hasattr(os, "stat"):
        mode = path.stat().st_mode
        # Check if group or other can read/write (requires 600 or 400)
        if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
            logger.warning(
                "Token file has insecure permissions",
                extra={"path": str(path), "mode": oct(mode)},
            )
            raise ConfigurationError(
                f"Token file {path} has insecure permissions. Run: chmod 600 {path}"
            )

    try:
        token = path.read_text().strip()
        if not token:
            return None
        return token
    except OSError as e:
        logger.warning(f"Failed to read token file: {e}")
        return None


def _load_token_from_env_file(path: Path) -> str | None:
    """Load token from .env file.

    Security: Enforces file permissions to prevent credential exposure.
    """
    if not path.exists():
        return None

    # Check file permissions on POSIX systems
    if hasattr(os, "stat"):
        mode = path.stat().st_mode
        # Warn if world (other) can read/write (group access OK for dev, 640)
        if mode & (stat.S_IROTH | stat.S_IWOTH):
            logger.warning(
                ".env file has insecure permissions (world-readable)",
                extra={"path": str(path), "mode": oct(mode)},
            )
            # Don't fail, but warn - .env files are often shared in dev

    try:
        content = path.read_text()
        for line in content.splitlines():
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            if line.startswith("OPENCTI_TOKEN=") or line.startswith(
                "OPENCTI_ADMIN_TOKEN="
            ):
                value = line.split("=", 1)[1].strip()
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                return value

        return None
    except OSError as e:
        logger.warning(f"Failed to read .env file: {e}")
        return None


# =============================================================================
# URL Validation
# =============================================================================


def _validate_url(url: str) -> str:
    """Validate and normalize OpenCTI URL.

    Security: prevents accidental plaintext transmission of the OpenCTI token.
    HTTP is allowed only for a true loopback endpoint. The production add-on
    sandbox also keeps egress loopback-only; remote connectivity needs a
    separately designed, exact-destination policy.
    """
    url = url.strip().rstrip("/")

    if not url:
        raise ConfigurationError("OpenCTI URL cannot be empty")

    parsed = urlparse(url)

    # Only allow http/https
    if parsed.scheme not in ("http", "https"):
        raise ConfigurationError(
            f"Invalid URL scheme: {parsed.scheme}. Use http or https."
        )

    # Must have a host
    if not parsed.netloc:
        raise ConfigurationError("Invalid URL: missing host")

    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("OpenCTI URL must not include credentials")

    if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname or ""):
        raise ConfigurationError(
            "Remote OpenCTI HTTP is disabled. Use a loopback endpoint or HTTPS "
            "in a separately approved remote-egress deployment."
        )

    return url


def _is_loopback_host(host: str) -> bool:
    """Return whether *host* is a literal loopback address or ``localhost``.

    Do not DNS-resolve hostnames here: configuration validation must be
    deterministic and a DNS result must not turn a remote name into an implicit
    plaintext-transport exception.
    """
    normalized = host.strip().rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False
