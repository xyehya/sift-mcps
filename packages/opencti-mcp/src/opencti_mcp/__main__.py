"""Entry point for running OpenCTI MCP server.

Usage:
    python -m opencti_mcp

Environment Variables:
    OPENCTI_URL: OpenCTI server URL (default: http://localhost:8080)
    OPENCTI_TOKEN: API token for authentication
    OPENCTI_TIMEOUT: Request timeout in seconds (default: 60)
    OPENCTI_MAX_RESULTS: Maximum results per query (default: 100)
    SIFT_LOG_FORMAT: Log format - "json" (default) or "text"
    SIFT_LOG_FILE: Write to ~/.sift/logs/ - "true" (default) or "false"

Feature Flags (FF_ prefix):
    FF_STARTUP_VALIDATION: Enable startup connectivity test (default: true)
    FF_RESPONSE_CACHING: Cache search responses (default: false)
    FF_GRACEFUL_DEGRADATION: Return cached results on failure (default: true)
    FF_NEGATIVE_CACHING: Cache "not found" results (default: true)

Token can also be provided via:
    ~/.config/opencti-mcp/token (with 600 permissions)
    .env file (OPENCTI_TOKEN=...)
"""

from __future__ import annotations

import argparse
import logging
import sys

from .client import OpenCTIClient
from .config import Config
from .errors import ConfigurationError
from .feature_flags import get_feature_flags
from .oplog import setup_logging
from .registry import create_server


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run the OpenCTI FastMCP backend.")
    parser.add_argument("--http", action="store_true", help="Run streamable HTTP instead of stdio.")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host.")
    parser.add_argument("--port", type=int, default=4626, help="HTTP bind port.")
    args = parser.parse_args()

    # Configure logging (JSON by default, text for development)
    setup_logging("opencti-mcp")
    logger = logging.getLogger("opencti_mcp")

    try:
        # Load configuration
        config = Config.load()
        logger.info(f"Starting OpenCTI MCP server: {config}")

        # Load feature flags
        flags = get_feature_flags()
        logger.debug(f"Feature flags: {flags.to_dict()}")

        # Startup validation (if enabled) — build ONE OpenCTIClient,
        # run validate_startup on it, then hand the SAME instance to
        # the server below. Pre-fix __main__.py built a separate
        # client here and OpenCTIMCPServer built another; the
        # `_degraded` flag set by validate_startup never propagated to
        # the tool-call path (live BLOCKER caught 2026-05-11).
        client: OpenCTIClient | None = None
        if flags.startup_validation:
            logger.info("Running startup validation...")
            client = OpenCTIClient(config)
            validation = client.validate_startup()

            # Log warnings
            for warning in validation.get("warnings", []):
                logger.warning(f"Startup warning: {warning}")

            # Log version info
            if validation.get("opencti_version"):
                logger.info(
                    f"Connected to OpenCTI {validation['opencti_version']}",
                    extra={"opencti_version": validation["opencti_version"]},
                )

            # Check for critical errors
            if not validation.get("valid", True):
                for error in validation.get("errors", []):
                    logger.error(f"Startup error: {error}")
                # Don't fail hard - allow server to start, it will report errors on queries
                logger.warning(
                    "Startup validation had errors - server will start but may have issues"
                )

        # Create and run the standalone FastMCP 3 server. Pass the validated client
        # through when startup validation built one so degraded state is preserved.
        server = create_server(config=config, client=client)
        if args.http:
            server.run(
                transport="streamable-http",
                host=args.host,
                port=args.port,
            )
        else:
            server.run(transport="stdio")

    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        print(f"Error: {e}", file=sys.stderr)
        print("\nTo configure, set OPENCTI_TOKEN environment variable", file=sys.stderr)
        print("or create ~/.config/opencti-mcp/token file", file=sys.stderr)
        sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Shutting down")

    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    main()
