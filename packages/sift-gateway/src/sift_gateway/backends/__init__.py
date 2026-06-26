"""MCP backend implementations."""

import json
import logging
import os
import shutil
from pathlib import Path
from urllib.parse import urlparse
import jsonschema

from sift_gateway.backends.base import MCPBackend
from sift_gateway.backends.egress import EgressTarget, validate_egress_url
from sift_gateway.backends.http_backend import HttpMCPBackend
from sift_gateway.backends.stdio_backend import StdioMCPBackend

logger = logging.getLogger(__name__)

# Load schema
SCHEMA_PATH = Path(__file__).parent.parent / "sift-backend.schema.json"
VALID_EVIDENCE_CLASSES = {"read_only", "analysis", "mutating"}
VALID_PHASES = {"SURVEY", "INGEST", "ANALYZE", "CORRELATE", "FINDING"}


def _validate_remote_fetch_url(url: str, *, label: str) -> EgressTarget:
    """Validate a manifest-fetch URL via the shared SEC-3 egress policy.

    Returns the pinned :class:`EgressTarget` so the caller fetches from the
    vetted IP (anti-rebinding) rather than a freshly re-resolved hostname.
    """
    return validate_egress_url(url, label=label)


def _validate_manifest_instructions(manifest: dict, manifest_path: Path | None) -> None:
    """Validate and resolve optional backend-level manifest instructions."""
    inline = manifest.get("instructions")
    path_value = manifest.get("instructions_path")

    if inline and path_value:
        raise ValueError("Manifest must use only one of instructions or instructions_path.")
    if inline is not None and not str(inline).strip():
        raise ValueError("Manifest instructions must not be empty when provided.")
    if not path_value:
        return
    if manifest_path is None:
        raise ValueError(
            "Manifest instructions_path is only supported for local manifests."
        )

    rel_path = Path(str(path_value))
    if rel_path.is_absolute():
        raise ValueError("Manifest instructions_path must be relative to the backend package.")

    package_root = manifest_path.resolve().parent
    resolved = (package_root / rel_path).resolve()
    try:
        resolved.relative_to(package_root)
    except ValueError as exc:
        raise ValueError(
            "Manifest instructions_path must stay inside the backend package."
        ) from exc

    if not resolved.is_file():
        raise ValueError(f"Manifest instructions_path is not readable: {path_value}")
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Manifest instructions_path is not readable: {path_value}") from exc
    if not text.strip():
        raise ValueError("Manifest instructions_path file must not be empty.")
    manifest["_resolved_instructions"] = text


def validate_manifest_contract(manifest: dict, manifest_path: Path | None = None) -> None:
    """Validate cross-field Backend Contract invariants."""
    _validate_manifest_instructions(manifest, manifest_path)

    namespace = manifest.get("namespace", "")
    # AD2 (B-MVP-016 sweep): the spec (§2.1/§10) declares a non-empty namespace
    # is mandatory — it is the only thing that ties every tool name to this
    # backend and prevents arbitrary tool-name shadowing. The JSON schema types
    # it as a plain string (no minLength), so enforce non-emptiness here in the
    # cross-field contract, fail-closed, before any prefix check is skipped.
    if not isinstance(namespace, str) or not namespace.strip():
        raise ValueError("Manifest namespace must be a non-empty string.")
    tools = manifest.get("tools", [])
    if not tools:
        raise ValueError("Manifest must declare at least one tool.")

    # B-MVP-053: a reference-plane backend (capabilities.provides includes
    # "reference") MUST explicitly declare a boolean top-level
    # ``default_case_scoped``. The gateway's case-scoping fallback heuristic
    # (server.is_case_scoped_tool) keys off the per-tool ``category`` string and
    # treats anything whose category lacks the substring "reference" as
    # case-scoped — so reference/baseline/threat-intel tools (categories like
    # "baseline-check"/"threat-intel") get mis-classified as case-scoped and,
    # exposing no case argument, are denied fail-closed by ProxyActiveCaseMiddleware
    # whenever a case is active. Requiring the explicit declaration kills that
    # silent footgun: a reference plane states its case-scoping intent outright
    # instead of relying on the brittle category-substring fallback.
    _provides = (manifest.get("capabilities") or {}).get("provides") or []
    if "reference" in _provides and not isinstance(
        manifest.get("default_case_scoped"), bool
    ):
        raise ValueError(
            "Reference-plane manifest (capabilities.provides includes "
            "'reference') must explicitly declare a boolean "
            "'default_case_scoped' (use false for offline/reference tools that "
            "carry no case context)."
        )

    declared_tools: dict[str, dict] = {}
    health_tools: list[str] = []
    for tool in tools:
        tool_name = tool.get("name", "")
        if tool_name in declared_tools:
            raise ValueError(f"Duplicate tool declaration: {tool_name}")
        declared_tools[tool_name] = tool

        if namespace and not tool_name.startswith(f"{namespace}_"):
            raise ValueError(
                f"Tool '{tool_name}' does not start with declared namespace "
                f"prefix '{namespace}_'"
            )

        read_only = tool.get("read_only")
        read_only_hint = tool.get("readOnlyHint")
        evidence_class = tool.get("evidence_class")
        if read_only != read_only_hint:
            raise ValueError(
                f"Tool '{tool_name}' has inconsistent read_only/readOnlyHint "
                f"values ({read_only!r} vs {read_only_hint!r})."
            )
        if evidence_class not in VALID_EVIDENCE_CLASSES:
            raise ValueError(
                f"Tool '{tool_name}' has invalid evidence_class: {evidence_class!r}"
            )
        if evidence_class == "read_only" and read_only is not True:
            raise ValueError(
                f"Tool '{tool_name}' evidence_class=read_only requires read_only=true."
            )
        if evidence_class == "mutating" and read_only is not False:
            raise ValueError(
                f"Tool '{tool_name}' evidence_class=mutating requires read_only=false."
            )
        if tool.get("recommended_phase") not in VALID_PHASES:
            raise ValueError(
                f"Tool '{tool_name}' has invalid recommended_phase: "
                f"{tool.get('recommended_phase')!r}"
            )
        if tool.get("health"):
            health_tools.append(tool_name)

    health_name = manifest.get("health")
    if not health_name:
        raise ValueError("Manifest must declare top-level health tool name.")
    if health_name not in declared_tools:
        raise ValueError(
            f"Top-level health tool '{health_name}' is not declared in tools[]."
        )
    if not declared_tools[health_name].get("health"):
        raise ValueError(
            f"Top-level health tool '{health_name}' must have tool-level "
            '"health": true.'
        )
    if len(health_tools) != 1:
        raise ValueError(
            "Manifest must declare exactly one tool with health=true; "
            f"found {len(health_tools)}."
        )

    # XYE-24: case-scope contradiction lint. A NON-reference backend may opt OUT
    # of active-case scope (top-level ``default_case_scoped: false`` or a per-tool
    # ``case_scoped: false``) only when it carries no evidence/data-plane signal.
    # Declaring evidence behaviour AND opting out is internally contradictory:
    # ``server.is_case_scoped_tool`` would return false for an evidence-touching
    # tool, so ``CaseContextMiddleware`` skips the active-case denial and
    # ``ProxyActiveCaseMiddleware`` skips DB case_id/case_key/case_dir injection —
    # the tool then runs against a caller-supplied/backend-default case instead of
    # the DB active case. Reject fail-closed at load so an honest author cannot
    # silently disable case protection (e.g. by copy-pasting a reference manifest).
    #
    # The reference plane (capabilities.provides includes "reference") is exempt:
    # B-MVP-053 deliberately lets it declare default_case_scoped=false, and a
    # reference/threat-intel backend may legitimately expose a mutating tool that
    # writes to its OWN external store (e.g. a CTI platform), not case evidence.
    #
    # This is a manifest-honesty correctness gate, not a boundary against a
    # malicious backend — behavioural verification of a registered backend is
    # tracked separately (XYE-25, register-time MCP scan).
    _evidence_planes = {"search", "ingest", "enrichment"}
    _provides_set = {str(p).lower() for p in _provides}
    _is_reference = "reference" in _provides_set
    _data_plane = manifest.get("data_plane") or {}
    _writes = bool(_data_plane.get("writes"))
    _plane_evidence = bool(_provides_set & _evidence_planes)

    if not _is_reference:
        _mutating = [
            name
            for name, tool in declared_tools.items()
            if tool.get("evidence_class") in {"analysis", "mutating"}
        ]
        if manifest.get("default_case_scoped") is False and (
            _writes or _plane_evidence or _mutating
        ):
            raise ValueError(
                "Manifest declares evidence/data-plane behaviour "
                f"(data_plane.writes={_writes}, evidence provides="
                f"{sorted(_provides_set & _evidence_planes)}, mutating/analysis "
                f"tools={_mutating}) but sets default_case_scoped=false. An "
                "evidence-touching backend must remain case-scoped so the gateway "
                "enforces the active case and injects the DB case context; remove "
                "default_case_scoped=false (or set it true), or drop the "
                "evidence/data-plane declaration."
            )

        for tool_name, tool in declared_tools.items():
            if tool.get("case_scoped") is False and (
                tool.get("evidence_class") in {"analysis", "mutating"}
                or _writes
                or _plane_evidence
            ):
                raise ValueError(
                    f"Tool '{tool_name}' sets case_scoped=false but the tool "
                    f"(evidence_class={tool.get('evidence_class')!r}) or its backend "
                    "(data-plane writes / search-ingest-enrichment plane) touches "
                    "case evidence. An evidence-touching tool must stay case-scoped "
                    "so the gateway enforces the active case and injects the DB case "
                    "context."
                )


def load_and_validate_manifest(name: str, config: dict) -> dict | None:
    backend_type = config.get("type", "stdio")
    manifest_data = None
    manifest_source = None

    explicit_path = config.get("manifest_path")

    if backend_type == "stdio":
        if explicit_path:
            manifest_path = Path(explicit_path)
            manifest_source = str(manifest_path)
        else:
            # well-known path: packages/<name>/sift-backend.json
            mcps_root = os.environ.get("SIFT_MCPS_ROOT")
            if mcps_root:
                manifest_path = Path(mcps_root) / "packages" / name / "sift-backend.json"
            else:
                manifest_path = Path(__file__).resolve().parents[5] / "packages" / name / "sift-backend.json"
            manifest_source = f"well-known path {manifest_path}"
        
        try:
            if manifest_path.exists():
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
            else:
                logger.warning("Manifest not found for stdio backend %s at %s", name, manifest_path)
        except Exception as e:
            logger.warning("Failed to load manifest for stdio backend %s from %s: %s", name, manifest_path, e)

    elif backend_type == "http":
        if explicit_path:
            # manifest_path could be a local file path or a URL
            if explicit_path.startswith(("http://", "https://")):
                from sift_gateway.backends.egress import build_pinned_sync_client
                try:
                    target = _validate_remote_fetch_url(explicit_path, label="manifest_path")
                    with build_pinned_sync_client(target) as client:
                        resp = client.get(explicit_path, timeout=5.0)
                    if resp.status_code == 200:
                        manifest_data = resp.json()
                        manifest_source = explicit_path
                    else:
                        logger.warning("Failed to fetch manifest for HTTP backend %s from URL %s: status %d", name, explicit_path, resp.status_code)
                except Exception as e:
                    logger.warning("Failed to fetch manifest for HTTP backend %s from URL %s: %s", name, explicit_path, e)
            else:
                manifest_path = Path(explicit_path)
                manifest_source = str(manifest_path)
                try:
                    if manifest_path.exists():
                        with open(manifest_path, "r", encoding="utf-8") as f:
                            manifest_data = json.load(f)
                except Exception as e:
                    logger.warning("Failed to load manifest for HTTP backend %s from file %s: %s", name, manifest_path, e)
        else:
            # Default /manifest fetch from the backend URL
            url = config.get("url")
            if url:
                manifest_url = url.rstrip("/") + "/manifest"
                from sift_gateway.backends.egress import build_pinned_sync_client
                try:
                    target = _validate_remote_fetch_url(manifest_url, label="backend manifest URL")
                    with build_pinned_sync_client(target) as client:
                        resp = client.get(manifest_url, timeout=5.0)
                    if resp.status_code == 200:
                        manifest_data = resp.json()
                        manifest_source = manifest_url
                    else:
                        logger.warning("Failed to fetch manifest for HTTP backend %s from /manifest: status %d", name, resp.status_code)
                except Exception as e:
                    logger.warning("Failed to fetch manifest for HTTP backend %s from /manifest: %s", name, e)

    if manifest_data is None:
        # Contract graduation (Phase 6.4): a missing manifest is always a hard
        # reject — every add-on must ship a conformant sift-backend.json.
        raise ValueError(
            f"Backend manifest is missing/invalid for {name} (looked in {manifest_source}). "
            "Every add-on backend must ship a conformant sift-backend.json."
        )

    # Library add-ons (e.g. forensic-knowledge) ship a sift-backend.json to declare
    # their authority contract, but are imported in-process — not routable MCP
    # backends. They use transport "library" / standalone_server=false and do not
    # carry the stdio/http backend schema (tools/health). Treat them as
    # non-routable: never register, never validate against the backend schema.
    _capabilities = manifest_data.get("capabilities")
    _standalone = (
        _capabilities.get("standalone_server", True)
        if isinstance(_capabilities, dict)
        else True
    )
    if manifest_data.get("transport") == "library" or _standalone is False:
        logger.info(
            "Manifest for %s declares a library add-on (transport=%s, standalone_server=%s); "
            "treating as non-routable and skipping backend registration.",
            name,
            manifest_data.get("transport"),
            _standalone,
        )
        return None

    # Validate against JSON schema
    try:
        if not SCHEMA_PATH.exists():
            logger.error("JSON schema file not found at %s", SCHEMA_PATH)
            return manifest_data

        with open(SCHEMA_PATH, "r", encoding="utf-8") as sf:
            schema = json.load(sf)

        # spec_version major-version compatibility: gateway accepts 1.x, rejects 2.x.
        spec_version = manifest_data.get("spec_version")
        if not isinstance(spec_version, str) or not spec_version.startswith("1."):
            raise jsonschema.ValidationError(f"Unsupported spec_version: {spec_version}. Gateway only supports version 1.x.")

        jsonschema.validate(instance=manifest_data, schema=schema)
        local_manifest_path = manifest_path if "manifest_path" in locals() else None
        validate_manifest_contract(manifest_data, local_manifest_path)
        logger.info("Successfully validated manifest for backend %s from %s", name, manifest_source)
        return manifest_data
    except Exception as e:
        # Contract graduation (Phase 6.4): an invalid manifest is always a hard reject.
        logger.warning("Manifest validation failed for backend %s from %s: %s", name, manifest_source, e)
        raise ValueError(f"Backend manifest validation failed for {name}: {e}") from e


def create_backend(name: str, config: dict, *, manifest: dict | None = None) -> MCPBackend:
    """Factory: create a backend from config.

    Args:
        name: Backend name (e.g. "forensic-mcp").
        config: Backend config dict with at minimum a "type" key.

    Returns:
        An MCPBackend instance.

    Raises:
        ValueError: If the backend type is unknown or config is invalid.
    """
    backend_type = config.get("type", "stdio")
    if manifest is None:
        manifest = load_and_validate_manifest(name, config)

    if backend_type == "stdio":
        # Validate required keys for stdio
        command = config.get("command")
        if not command:
            raise ValueError(f"Backend {name!r}: stdio type requires 'command' key")
        if not isinstance(command, str):
            raise ValueError(
                f"Backend {name!r}: 'command' must be a string, got {type(command).__name__}"
            )
        # Warn (don't fail) if command not found on PATH — it may exist at runtime
        if shutil.which(command) is None:
            logger.warning("Backend %s: command %r not found on PATH", name, command)
        return StdioMCPBackend(name, config, manifest=manifest)

    elif backend_type == "http":
        # Validate required keys for http
        url = config.get("url")
        if not url:
            raise ValueError(f"Backend {name!r}: http type requires 'url' key")
        if not isinstance(url, str):
            raise ValueError(
                f"Backend {name!r}: 'url' must be a string, got {type(url).__name__}"
            )
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"Backend {name!r}: URL must use http or https scheme, got {parsed.scheme!r}"
            )
        if not parsed.hostname:
            raise ValueError(f"Backend {name!r}: URL must include a hostname")
        # SEC-3: materialization gate — refuse to build an HTTP backend whose URL
        # resolves to a non-routable/internal address (defense-in-depth; the
        # authoritative gate is HttpMCPBackend.start(), which re-validates and
        # pins immediately before each connect).
        validate_egress_url(url, label=f"Backend {name!r}: URL")
        return HttpMCPBackend(name, config, manifest=manifest)

    else:
        raise ValueError(f"Unknown backend type: {backend_type!r} for backend {name!r}")


__all__ = ["MCPBackend", "StdioMCPBackend", "HttpMCPBackend", "create_backend"]
