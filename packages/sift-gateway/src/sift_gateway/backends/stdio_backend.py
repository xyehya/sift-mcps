"""Stdio-based MCP backend — launches a subprocess and communicates via MCP stdio transport."""

import asyncio
import logging
import os
from contextlib import AsyncExitStack

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import Tool

from sift_gateway.backends.base import MCPBackend

logger = logging.getLogger(__name__)

# Timeout (seconds) for backend operations
_TOOL_LIST_TIMEOUT = 30
_TOOL_CALL_TIMEOUT = 300
_STOP_TIMEOUT = 15
# Bound on session.initialize() so a hung backend doesn't block the
# gateway's own startup loop indefinitely. Pre-fix, an unreachable
# remote (e.g., OpenCTI off-network) caused initialize() to wait on
# the underlying backend's blocking I/O for 300s+ before the gateway
# noticed. 30s is generous for healthy backends, fail-fast for hung.
_INITIALIZE_TIMEOUT = 30


# SEC-4 (DSS-CAN-020): a registered stdio backend launches as the gateway
# account. Starting it from ``dict(os.environ)`` leaked every gateway secret
# (SIFT_CONTROL_PLANE_DSN, SIFT_AUDIT_WRITER_DSN, Supabase service keys, other
# backends' bearer tokens) into the add-on subprocess — a direct violation of
# the "add-on backend has NO DB creds by design" invariant. The child env is
# now built DENY-BY-DEFAULT from a minimal allowlist + the explicitly approved
# ``env_refs`` overlay. Never copy the whole process environment (a denylist of
# known-secret vars would fail open for any newly-added secret — the exact bug
# class we are closing).
#
# OS/runtime basics every subprocess legitimately needs.
_BASE_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "PWD",
        "LANG",
        "LANGUAGE",
        "TZ",
        "TMPDIR",
        "TEMP",
        "TMP",
        "TERM",
    }
)
# Non-secret SIFT case/runtime context the Backend Contract promises the add-on
# (the gateway sets these on case activation). NO *_DSN / token / key / secret
# var appears here — those reach an add-on ONLY via an explicitly-approved
# env_ref overlay, never by inheritance.
_SIFT_CASE_CONTEXT_ALLOWLIST = frozenset(
    {
        "SIFT_CASE_DIR",
        "SIFT_CASE_ROOT",
        "SIFT_CASES_ROOT",
        "SIFT_CASE_UUID",
        "SIFT_DB_ACTIVE",
        "SIFT_EXAMINER",
        "SIFT_MCPS_ROOT",
        "SIFT_STATE_DIR",
    }
)


def _build_minimal_backend_env(
    base_environ: dict, configured_env: dict
) -> dict[str, str]:
    """Build a stdio child env deny-by-default: minimal allowlist + approved overlay.

    Copies only the OS basics and non-secret SIFT case context from
    ``base_environ`` (the gateway process env), then overlays the explicitly
    approved ``configured_env`` (the resolved ``env_refs`` — the sole channel
    through which an add-on legitimately receives anything beyond the minimal
    base, e.g. a knowledge add-on's approved ``SIFT_CONTROL_PLANE_DSN`` ref for
    its read-only corpus). Secrets in the gateway env that are NOT in an env_ref
    (DSNs, service keys, other backends' tokens) are absent by construction.
    """
    env: dict[str, str] = {}
    for key in _BASE_ENV_ALLOWLIST:
        value = base_environ.get(key)
        if value:
            env[key] = value
    for key in _SIFT_CASE_CONTEXT_ALLOWLIST:
        value = base_environ.get(key)
        if value:
            env[key] = value
    # Locale LC_* family (non-secret).
    for key, value in base_environ.items():
        if key.startswith("LC_") and value:
            env[key] = value
    # Explicitly-approved per-backend overlay (resolved env_refs / configured
    # env). This is the ONLY path beyond the minimal base.
    if configured_env:
        for key, value in configured_env.items():
            env[key] = value
    return env


class StdioMCPBackend(MCPBackend):
    """Backend that manages a subprocess MCP server via stdio transport."""

    def __init__(self, name: str, config: dict, manifest: dict | None = None):
        super().__init__(name, config, manifest)
        self._session: ClientSession | None = None
        self._exit_stack: AsyncExitStack | None = None
        self._tools_cache: list[Tool] | None = None

    async def _safe_cleanup(self, *, context: str) -> None:
        """Cleanup that handles None _exit_stack and downgrades cancel-scope noise.

        Single helper used by start() failed-cleanup, stop(), and the
        list_tools / call_tool error paths — all four sites previously
        had near-identical patterns with subtly different bugs:
          - start() logged at WARNING for unavoidable cancel-scope errors
          - list_tools / call_tool used silent `pass`, swallowing real errors
          - stop() had the right pattern (downgrade on "cancel scope")
        One canonical helper makes the cleanup contract uniform.

        Cancel-scope errors during cleanup are structurally inevitable
        when a hung backend is cancelled mid-startup or mid-call (anyio
        rule: cancel scope must exit in the same task it entered).
        Those are DEBUG-level. Other exceptions are real failures and
        log at WARNING.

        `context` describes which cleanup site is calling — interpolated
        into the log message so journalctl distinguishes start-cleanup
        from list_tools-cleanup from stop-cleanup.
        """
        if self._exit_stack is None:
            self._session = None
            self._tools_cache = None
            self._started = False
            return
        try:
            await self._exit_stack.aclose()
        except BaseException as exc:
            level = logging.DEBUG if "cancel scope" in str(exc) else logging.WARNING
            logger.log(
                level,
                "Backend %s %s: %s: %s",
                self.name,
                context,
                type(exc).__name__,
                exc,
            )
        finally:
            self._exit_stack = None
            self._session = None
            self._tools_cache = None
            self._started = False

    async def start(self) -> None:
        if self._started:
            return

        command = self.config.get("command", "python")
        args = self.config.get("args", [])
        configured_env = self.config.get("env") or {}
        # SEC-4: deny-by-default minimal base env + approved env_refs overlay.
        # Do NOT inherit the full gateway environment (it holds the control-plane
        # / audit DSNs, Supabase service keys, and other backends' tokens).
        env = _build_minimal_backend_env(os.environ, configured_env)
        # Remove empty values from unset ${VAR} interpolation.
        env = {k: v for k, v in env.items() if v}
        if "SIFT_CASE_DIR" not in env:
            # No active case yet (portal reset or fresh install).
            # Backends start in no-case mode; individual tools return
            # "No active case" errors when called. Portal remains accessible
            # so the examiner can create and activate a case.
            import logging as _log
            _log.getLogger(__name__).warning(
                "Backend %s starting without SIFT_CASE_DIR — "
                "no active case set. Use the portal to create a case.",
                self.name,
            )
        if "SIFT_CASES_ROOT" not in env:
            import logging as _log
            _log.getLogger(__name__).warning(
                "Backend %s starting without SIFT_CASES_ROOT.",
                self.name,
            )

        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=env,
        )

        self._exit_stack = AsyncExitStack()
        try:
            transport = await self._exit_stack.enter_async_context(
                stdio_client(server_params)
            )
            read_stream, write_stream = transport
            self._session = await self._exit_stack.enter_async_context(
                ClientSession(read_stream, write_stream)
            )
            # Bound session.initialize() so a hung remote backend can't
            # block the gateway's startup loop indefinitely (UAT 2026-04-25
            # repro: unreachable OpenCTI caused initialize() to wait for
            # the underlying socket timeout before the gateway noticed).
            result = await asyncio.wait_for(
                self._session.initialize(), timeout=_INITIALIZE_TIMEOUT
            )
            self._instructions = result.instructions
            self._started = True
            logger.info("Backend %s started (stdio)", self.name)
        except asyncio.TimeoutError:
            logger.error(
                "Backend %s session.initialize() timed out after %ds",
                self.name,
                _INITIALIZE_TIMEOUT,
            )
            await self._safe_cleanup(context="cleanup after initialize timeout")
            raise
        except BaseException as exc:
            logger.error(
                "Backend %s failed to start: %s: %s", self.name, type(exc).__name__, exc
            )
            await self._safe_cleanup(context="cleanup after failed start")
            raise

    async def stop(self) -> None:
        if not self._started:
            return
        if self._exit_stack is not None:
            try:
                await asyncio.wait_for(self._exit_stack.aclose(), timeout=_STOP_TIMEOUT)
                # Successful close: state-reset still runs in finally below
            except asyncio.TimeoutError:
                logger.warning(
                    "Backend %s stop timed out after %ds", self.name, _STOP_TIMEOUT
                )
            except BaseException as exc:
                level = logging.DEBUG if "cancel scope" in str(exc) else logging.ERROR
                logger.log(
                    level,
                    "Backend %s error during stop: %s: %s",
                    self.name,
                    type(exc).__name__,
                    exc,
                )
        self._exit_stack = None
        self._session = None
        self._tools_cache = None
        self._started = False
        logger.info("Backend %s stopped", self.name)

    async def list_tools(self) -> list[Tool]:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        if self._tools_cache is None:
            try:
                result = await asyncio.wait_for(
                    self._session.list_tools(), timeout=_TOOL_LIST_TIMEOUT
                )
                self._tools_cache = result.tools
            except (ConnectionError, OSError):
                await self._safe_cleanup(context="list_tools cleanup after error")
                raise
            except Exception as e:
                exc_name = type(e).__name__.lower()
                if any(t in exc_name for t in ("closed", "broken", "resource")):
                    await self._safe_cleanup(context="list_tools cleanup after transport error")
                    raise ConnectionError(str(e)) from e
                raise
        return self._tools_cache

    async def call_tool(self, name: str, arguments: dict) -> list:
        if not self._started or not self._session:
            raise RuntimeError(f"Backend {self.name} is not started")

        try:
            result = await asyncio.wait_for(
                self._session.call_tool(name, arguments), timeout=_TOOL_CALL_TIMEOUT
            )
            return result.content
        except (ConnectionError, OSError) as e:
            await self._safe_cleanup(context="call_tool cleanup after error")
            raise
        except Exception as e:
            # Anyio transport errors (ClosedResourceError, BrokenResourceError) are not
            # ConnectionError/OSError subclasses but also mean the subprocess is dead.
            exc_name = type(e).__name__.lower()
            if any(t in exc_name for t in ("closed", "broken", "resource")):
                await self._safe_cleanup(context="call_tool cleanup after transport error")
                raise ConnectionError(str(e)) from e
            raise

    async def health_check(self) -> dict:
        if not self._started or not self._session:
            return {"status": "stopped", "type": "stdio"}
        try:
            await self.list_tools()
            return {
                "status": "ok",
                "type": "stdio",
                "tools": len(self._tools_cache or []),
            }
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
            logger.warning(
                "Backend %s health check failed: %s: %s",
                self.name,
                type(exc).__name__,
                exc,
            )
            return {"status": "error", "type": "stdio", "error": type(exc).__name__}
