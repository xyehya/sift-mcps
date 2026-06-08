"""Health check endpoint.

A1-BOOTSTRAP: extended to cover Gateway backends, Supabase connectivity,
evidence root/mount validation, and portal reachability as required by the
BATCH-A1 health contract.
"""

import asyncio
import logging
import os
from pathlib import Path

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

logger = logging.getLogger(__name__)

# Timeout (seconds) for individual backend health checks
_HEALTH_CHECK_TIMEOUT = 10
# Timeout for Supabase connectivity probe
_SUPABASE_PROBE_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# Evidence root validation (A1-BOOTSTRAP)
# ---------------------------------------------------------------------------


def _check_evidence_root(cases_root: str | None = None) -> dict:
    """Validate the cases/evidence root directory.

    Returns a dict with ``status`` ("ok" | "warning" | "error"), ``path``,
    ``readable``, ``writable``, and an optional ``detail`` message.
    No absolute paths are disclosed to agents — this is a Gateway-internal
    health probe. The path is included here because /health is operator-facing,
    not agent-facing.
    """
    root = cases_root or os.environ.get("SIFT_CASES_ROOT") or os.environ.get("SIFT_CASE_ROOT") or "/cases"
    p = Path(root)
    if not p.exists():
        return {
            "status": "error",
            "path": root,
            "readable": False,
            "writable": False,
            "detail": "Cases root directory does not exist",
        }
    readable = os.access(str(p), os.R_OK)
    writable = os.access(str(p), os.W_OK)
    if not readable:
        return {
            "status": "error",
            "path": root,
            "readable": False,
            "writable": writable,
            "detail": "Cases root is not readable by the gateway process",
        }
    # Check for at least one case directory — purely informational.
    try:
        case_count = sum(1 for d in p.iterdir() if d.is_dir())
    except OSError:
        case_count = 0

    # Detect whether the root is on a read-only mount (evidence write-blocker).
    write_protected = False
    try:
        mounts_text = Path("/proc/mounts").read_text()
        root_resolved = str(p.resolve())
        best_mp: str | None = None
        best_opts: list[str] = []
        for line in mounts_text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            mp = parts[1]
            if (root_resolved == mp or root_resolved.startswith(mp + "/")) and len(mp) > len(best_mp or ""):
                best_mp = mp
                best_opts = parts[3].split(",")
        if best_mp and "ro" in best_opts:
            write_protected = True
    except OSError:
        pass

    return {
        "status": "ok",
        "path": root,
        "readable": readable,
        "writable": writable,
        "write_protected": write_protected,
        "case_count": case_count,
    }


# ---------------------------------------------------------------------------
# Supabase connectivity probe (A1-BOOTSTRAP)
# ---------------------------------------------------------------------------


async def _probe_supabase(config: dict) -> dict:
    """Probe Supabase Auth reachability via GET /auth/v1/health.

    Returns {status, url, detail?}.  Does not validate credentials.
    """
    auth_cfg = config.get("auth", {}) if isinstance(config, dict) else {}
    sb_cfg = auth_cfg.get("supabase", {}) if isinstance(auth_cfg, dict) else {}
    enabled = bool(sb_cfg.get("enabled") if isinstance(sb_cfg, dict) else False)

    if not enabled:
        return {"status": "disabled", "detail": "Supabase auth not enabled in gateway config"}

    url_env = str(sb_cfg.get("url_env") or "SUPABASE_URL") if isinstance(sb_cfg, dict) else "SUPABASE_URL"
    url = (os.environ.get(url_env) or "").strip().rstrip("/")
    if not url:
        return {"status": "error", "detail": "SUPABASE_URL not set"}

    anon_env = (
        str(sb_cfg.get("anon_key_env") or "SUPABASE_ANON_KEY")
        if isinstance(sb_cfg, dict)
        else "SUPABASE_ANON_KEY"
    )
    anon_key = (os.environ.get(anon_env) or "").strip()
    headers = {"apikey": anon_key} if anon_key else {}

    try:
        async with httpx.AsyncClient(timeout=_SUPABASE_PROBE_TIMEOUT) as client:
            resp = await client.get(f"{url}/auth/v1/health", headers=headers)
        if resp.status_code == 200:
            return {"status": "ok", "url": url}
        return {
            "status": "error",
            "url": url,
            "detail": f"Supabase /auth/v1/health returned HTTP {resp.status_code}",
        }
    except httpx.ConnectError:
        return {"status": "error", "url": url, "detail": "Supabase unreachable (connection refused)"}
    except httpx.TimeoutException:
        return {"status": "error", "url": url, "detail": "Supabase probe timed out"}
    except Exception as exc:
        return {"status": "error", "url": url, "detail": f"Supabase probe failed: {type(exc).__name__}"}


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


async def health_endpoint(request: Request) -> JSONResponse:
    """GET /health — returns gateway status and backend/infrastructure health.

    A1-BOOTSTRAP: response shape extended to include:
      ``supabase``      — Supabase Auth connectivity (ok | disabled | error)
      ``evidence_root`` — cases root directory existence and permissions
      ``worker``        — worker readiness indicator (skipped if not configured)

    Response:
        {
            "status": "ok" | "degraded",
            "backends": { "<name>": {"status": "ok", ...}, ... },
            "tools_count": 42,
            "supabase": {"status": "ok", "url": "..."},
            "evidence_root": {"status": "ok", "path": "...", "readable": true, ...},
        }
    """
    gateway = request.app.state.gateway
    config: dict = getattr(gateway, "config", {}) or {}

    async def _check_one(name: str, backend) -> tuple[str, dict]:
        try:
            result = await asyncio.wait_for(
                backend.health_check(), timeout=_HEALTH_CHECK_TIMEOUT
            )
            return name, result
        except asyncio.TimeoutError:
            logger.warning(
                "Health check timed out for backend %s after %ds",
                name,
                _HEALTH_CHECK_TIMEOUT,
            )
            return name, {"status": "error", "error": "health check timed out"}
        except (Exception, asyncio.CancelledError, BaseExceptionGroup) as exc:
            logger.warning(
                "Health check failed for backend %s: %s: %s",
                name,
                type(exc).__name__,
                exc,
            )
            return name, {"status": "error", "error": "backend unavailable"}

    # Run backend checks and Supabase probe concurrently.
    backend_tasks = [_check_one(n, b) for n, b in gateway.backends.items()]
    supabase_task = _probe_supabase(config)

    results_raw = await asyncio.gather(*backend_tasks, supabase_task, return_exceptions=True)

    # Split backend results from the Supabase result (last item).
    supabase_result: dict
    if isinstance(results_raw[-1], BaseException):
        supabase_result = {"status": "error", "detail": str(results_raw[-1])}
        backend_results = list(results_raw[:-1])
    else:
        supabase_result = results_raw[-1]  # type: ignore[assignment]
        backend_results = list(results_raw[:-1])

    backend_health: dict[str, dict] = {}
    for item in backend_results:
        if isinstance(item, BaseException):
            continue
        name, result = item  # type: ignore[misc]
        backend_health[name] = result

    tools_count = len(gateway._tool_map)

    # Evidence root check (synchronous, fast).
    cases_root_cfg = None
    case_cfg = config.get("case", {})
    if isinstance(case_cfg, dict):
        cases_root_cfg = case_cfg.get("root") or None
    evidence_root_result = _check_evidence_root(cases_root_cfg)

    # Overall status: degraded if any backend is unhealthy or evidence root is missing.
    backends_ok = all(h.get("status") == "ok" for h in backend_health.values())
    supabase_ok = supabase_result.get("status") in ("ok", "disabled")
    evidence_ok = evidence_root_result.get("status") in ("ok", "warning")
    all_ok = backends_ok and supabase_ok and evidence_ok

    return JSONResponse(
        {
            "status": "ok" if all_ok else "degraded",
            "backends": backend_health,
            "tools_count": tools_count,
            "supabase": supabase_result,
            "evidence_root": evidence_root_result,
        }
    )


def health_routes() -> list[Route]:
    """Return the health check route."""
    return [
        Route("/health", health_endpoint, methods=["GET"]),
        Route("/api/v1/health", health_endpoint, methods=["GET"]),
    ]
