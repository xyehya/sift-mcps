"""agentir case management MCP server.

Exposes tools wrapping agentir-core _data() functions for LLM-callable
case management. No new logic — thin wrappers around tested code.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from sift_common.audit import AuditWriter, resolve_examiner
from sift_common.instructions import CASE_MCP as _INSTRUCTIONS
from sift_common.oplog import setup_logging
from sift_core.case_io import (
    cases_root,
    export_bundle as _export_bundle,
    import_bundle as _import_bundle,
)
from sift_core.case_ops import (
    _case_status_data,
)
from sift_core.evidence_chain import (
    ChainStatus,
    chain_status,
    load_manifest,
)

logger = logging.getLogger(__name__)

_MAX_NAME = 200
_MAX_TEXT = 10_000
_MAX_SHORT = 200


def _build_platform_capabilities() -> dict:
    """Detect available backends for Layer 4 platform capabilities."""
    import importlib.util

    capabilities = {
        "opensearch": importlib.util.find_spec("opensearch_mcp") is not None,
        "remnux": False,
        "windows_triage": importlib.util.find_spec("windows_triage_mcp") is not None,
        "wintools": False,
        "forensic_rag": importlib.util.find_spec("rag_mcp") is not None,
        "opencti": importlib.util.find_spec("opencti_mcp") is not None,
        "sift_tools": True,
    }
    try:
        import yaml

        gw_path = Path.home() / ".sift" / "gateway.yaml"
        if gw_path.exists():
            gw_config = yaml.safe_load(gw_path.read_text()) or {}
            backends = gw_config.get("backends", {})
            capabilities["remnux"] = "remnux-mcp" in backends
    except Exception:
        pass
    # REMnux connects directly to client (not via gateway) — check .claude.json
    if not capabilities["remnux"]:
        try:
            import json

            claude_json = Path.home() / ".claude.json"
            if claude_json.exists():
                cj = json.loads(claude_json.read_text())
                mcp_servers = cj.get("mcpServers", {})
                capabilities["remnux"] = "remnux-mcp" in mcp_servers
        except Exception:
            pass

    guidance = ["Available investigation capabilities:"]
    guidance.append("- SIFT forensic tools via run_command (65+ tools)")
    if capabilities["opensearch"]:
        guidance.append(
            "- Evidence indexing: idx_ingest for structured querying at scale"
        )
    if capabilities["windows_triage"]:
        guidance.append(
            "- Windows baseline validation: check_file, check_service, and related offline triage tools"
        )
    if capabilities["remnux"]:
        guidance.append("- Malware analysis: upload_from_host + analyze_file on REMnux")
    if capabilities["wintools"]:
        guidance.append(
            "- Windows host execution: unsupported in this portable SIFT runtime"
        )
    if capabilities["forensic_rag"]:
        guidance.append(
            "- Knowledge search: search_knowledge (Sigma, MITRE ATT&CK, KAPE)"
        )
    if capabilities["opencti"]:
        guidance.append("- Threat intel: lookup_ioc, search_threat_intel on OpenCTI")
    guidance.append("")
    guidance.append(
        "Do not rely solely on OpenSearch queries. "
        "Call suggest_tools(artifact_type='...') for deep analysis recommendations."
    )

    return {
        "platform_capabilities": capabilities,
        "investigation_guidance": "\n".join(guidance),
    }


def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    """Reject strings exceeding max_len, containing null bytes, or path traversal."""
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")
        if ".." in value:
            raise ValueError(f"{field} contains invalid path traversal")


def _resolve_case_dir(case_id: str = "") -> Path:
    """Resolve case directory without sys.exit.

    Same priority as agentir CLI get_case_dir(), but raises ValueError
    instead of calling sys.exit().

    Side effect: sets SIFT_CASE_DIR env var so AuditWriter can find
    the audit directory.
    """
    if case_id:
        if ".." in case_id or "/" in case_id or "\\" in case_id:
            raise ValueError(f"Invalid case ID: {case_id}")
        case_dir = cases_root() / case_id
        if not case_dir.exists():
            raise ValueError(f"Case not found: {case_id}")
        return case_dir

    # Portal-created case activation is the runtime contract. Do not read the
    # legacy ~/.sift/active_case pointer here; it can drift from gateway.yaml.
    env_dir = os.environ.get("SIFT_CASE_DIR")
    if env_dir:
        p = Path(env_dir)
        if not p.is_dir():
            raise ValueError(f"SIFT_CASE_DIR does not exist: {env_dir}")
        return p

    raise ValueError("No active case. Use the Examiner Portal to create or select a case first.")


def create_server() -> FastMCP:
    """Create and configure the case management MCP server."""
    server = FastMCP("case-mcp", instructions=_INSTRUCTIONS)
    audit = AuditWriter(mcp_name="case-mcp")

    server._audit = audit

    # ------------------------------------------------------------------
    # Tool: case_status
    # ------------------------------------------------------------------
    @server.tool(annotations={"readOnlyHint": True})
    def case_status() -> dict:
        """Get the status of the active case: finding counts, timeline
        entries, TODO progress, evidence summary, and available platform
        capabilities.

        The active case is set by the Examiner Portal — only the portal
        can switch cases. Call this at the start of every session to
        confirm the case context and available investigation tools before
        proceeding.
        """
        try:
            case_dir = _resolve_case_dir()
            result = _case_status_data(case_dir)
            result.update(_build_platform_capabilities())
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool: case_file_structure (SAFE)
    # ------------------------------------------------------------------
    @server.tool(annotations={"readOnlyHint": True})
    def case_file_structure() -> dict:
        """Recursively list all files and directories in the active case directory.
        Provides a tree structure of the case workspace (excluding system files).
        """
        try:
            case_dir = _resolve_case_dir()
            case_resolved = case_dir.resolve()

            files_list = []
            dirs_list = []

            exclude_basenames = {"evidence-ledger.jsonl", "evidence-verify-state.json"}
            exclude_dirs = {"audit", ".git", "__pycache__"}

            for path in sorted(case_resolved.rglob("*")):
                try:
                    rel_parts = path.relative_to(case_resolved).parts
                except ValueError:
                    continue

                if any(part in exclude_dirs for part in rel_parts):
                    continue

                if path.name in exclude_basenames or path.name.endswith(".tmp"):
                    continue

                rel_path = str(path.relative_to(case_resolved))

                if path.is_dir():
                    dirs_list.append(rel_path)
                elif path.is_file():
                    files_list.append({
                        "path": rel_path,
                        "size_bytes": path.stat().st_size,
                    })

            return {
                "case_id": case_resolved.name,
                "case_dir": str(case_resolved),
                "directories": dirs_list,
                "files": files_list,
            }
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool: evidence_register (BLOCKED — examiner-only via portal)
    # ------------------------------------------------------------------
    @server.tool()
    def evidence_register(path: str, description: str = "") -> dict:
        """Register an evidence file with the active case.

        Evidence registration is an examiner action performed via the
        Examiner Portal — this tool always returns a portal-redirect.
        Do not retry. Notify the operator to seal the file via the
        Portal → Evidence tab, then call evidence_list to confirm.
        """
        audit.log(
            tool="evidence_register",
            params={"path": path, "description": description},
            result_summary={"blocked": True, "reason": "portal_required"},
        )
        return {
            "blocked": True,
            "reason": "Evidence registration is an examiner action.",
            "action": "portal_required",
            "portal_hint": (
                "Notify the operator to open the Examiner Portal and use the "
                "'Register Evidence' panel in the Evidence Chain tab. "
                "After sealing, call evidence_list to confirm registered status."
            ),
        }

    # ------------------------------------------------------------------
    # Tool: evidence_list (SAFE)
    # ------------------------------------------------------------------
    @server.tool(annotations={"readOnlyHint": True})
    def evidence_list() -> dict:
        """List all files in the active case evidence/ directory and their
        registration and integrity status.

        Returns two sections:
        - evidence: sealed files from the manifest with SHA-256 hashes,
          registration dates, and integrity status per file.
        - unregistered: files found on disk that have not been sealed via
          the portal — these cannot be used for analysis until registered.

        Also includes an inline chain integrity summary. If
        requires_examiner_action is true, notify the operator before
        proceeding: unregistered files need portal sealing, and chain
        issues need HMAC verification (call evidence_verify for a full
        integrity check before escalating).
        """
        try:
            case_dir = _resolve_case_dir()

            # Load manifest
            manifest = load_manifest(case_dir)
            if manifest is None:
                active_files = []
                manifest_version = 0
            else:
                active_files = [
                    f for f in manifest.get("files", []) if f.get("status") != "IGNORED"
                ]
                manifest_version = manifest.get("version", 0)

            # Inline chain status for tamper detection
            try:
                cs = chain_status(case_dir)
                chain = {
                    "status": cs["status"],
                    "ok_count": cs["ok_count"],
                    "issues": cs["issues"],
                }
            except Exception:
                chain = {
                    "status": "unknown",
                    "ok_count": 0,
                    "issues": ["Chain status check failed — call evidence_verify for details."],
                }

            # Recursive scan of evidence/ for all files (including subdirs)
            evidence_dir = case_dir / "evidence"
            registered_paths = {f.get("path", "") for f in active_files}
            unregistered = []
            if evidence_dir.is_dir():
                for f in sorted(evidence_dir.rglob("*")):
                    if not f.is_file():
                        continue
                    rel = str(f.relative_to(case_dir))
                    if rel not in registered_paths and str(f) not in registered_paths:
                        unregistered.append({
                            "path": rel,
                            "size_bytes": f.stat().st_size,
                            "registered": False,
                            "action_required": (
                                "Notify the operator to seal this file via "
                                "Examiner Portal → Evidence tab before analysis."
                            ),
                        })

            has_chain_issues = bool(
                chain.get("issues")
                and chain.get("status") not in (ChainStatus.OK, ChainStatus.UNSEALED)
            )
            requires_examiner_action = bool(unregistered or has_chain_issues)

            result = {
                "evidence": active_files,
                "unregistered": unregistered,
                "chain": chain,
                "requires_examiner_action": requires_examiner_action,
                "manifest_version": manifest_version,
                "source": "manifest_v2",
            }
            if requires_examiner_action:
                hints = []
                if unregistered:
                    hints.append(
                        f"{len(unregistered)} unregistered file(s) found — "
                        "operator must seal via portal before analysis."
                    )
                if has_chain_issues:
                    hints.append(
                        "Chain integrity issues detected — call evidence_verify "
                        "for a full check before escalating to the operator."
                    )
                result["examiner_action_hint"] = " ".join(hints)
            if manifest is None:
                result["note"] = "No evidence manifest — case not yet initialised via portal."
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool: evidence_verify (SAFE)
    # ------------------------------------------------------------------
    @server.tool(annotations={"readOnlyHint": True})
    def evidence_verify() -> dict:
        """Run a dedicated integrity check on all registered evidence files.

        Performs a stat-check against the authoritative manifest and reports
        chain status: ok, unsealed, modified, missing, unregistered, or
        ledger_error. Use this before escalating a chain-of-custody concern
        to the operator to confirm the finding with a fresh check.

        For full cryptographic HMAC verification, the operator must use the
        Examiner Portal → Evidence tab → 'Verify HMAC' button.
        """
        try:
            case_dir = _resolve_case_dir()
            status = chain_status(case_dir)
            result = {
                "status": status["status"],
                "issues": status["issues"],
                "manifest_version": status["manifest_version"],
                "ok_count": status["ok_count"],
                "source": "manifest_v2",
            }
            if status["status"] not in (ChainStatus.OK, ChainStatus.UNSEALED):
                result["operator_action_required"] = (
                    "Integrity issues detected. Notify the operator to open the "
                    "Examiner Portal and run 'Verify HMAC' for full cryptographic "
                    "verification."
                )
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 8: export_bundle (SAFE)
    # ------------------------------------------------------------------
    @server.tool()
    def export_bundle(since: str = "") -> dict:
        """Export case findings and timeline as a JSON bundle for
        collaboration. Optionally filter to items modified since a
        given ISO timestamp.

        WARNING: Returns full case data which may be large (30,000+ tokens).
        For investigation status, use case_status instead."""
        try:
            case_dir = _resolve_case_dir()
            result = _export_bundle(case_dir, since=since)
            logged_id = audit.log(
                tool="export_bundle",
                params={"since": since},
                result_summary={
                    "findings": len(result.get("findings", [])),
                    "timeline": len(result.get("timeline", [])),
                },
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool 9: import_bundle (CONFIRM)
    # ------------------------------------------------------------------
    @server.tool()
    def import_bundle(bundle_path: str) -> dict:
        """Import a case data bundle from a JSON file, merging findings
        and timeline with the active case using last-write-wins.

        Confirm with the examiner before importing — this modifies case
        findings and timeline data.
        """
        try:
            case_dir = _resolve_case_dir()
            bundle_file = Path(bundle_path).resolve()
            allowed_parents = [case_dir, Path("/tmp")]
            if not any(bundle_file.is_relative_to(p) for p in allowed_parents):
                return {"error": "Bundle path must be within case directory or /tmp"}
            if not bundle_file.exists():
                return {"error": f"Bundle file not found: {bundle_path}"}
            bundle_data = json.loads(bundle_file.read_text())
            result = _import_bundle(case_dir, bundle_data)
            logged_id = audit.log(
                tool="import_bundle",
                params={"bundle_path": bundle_path},
                result_summary=result,
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, FileNotFoundError, OSError, json.JSONDecodeError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool: record_action (SAFE — auto-committed, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def record_action(
        description: str,
        reasoning: str,
        tool: str = "",
        command: str = "",
        analyst_override: str = "",
    ) -> dict:
        """Log an investigative action and your reasoning to the case record.

        Call this when you take an action not automatically captured by the
        audit trail — a manual file inspection, a scope decision, a choice
        of what to examine next. MCP tool calls are already captured
        automatically; use this for supplemental decisions.

        The reasoning field is required: state why you took this action so
        the case record reflects your investigative logic, not just the
        mechanics. This is especially important before context compaction.

        Args:
            description: What action was taken (the action itself).
            reasoning: Why you took this action (your investigative rationale,
                hypothesis, or decision logic).
            tool: Tool name if applicable.
            command: Command string if applicable.
            analyst_override: Override examiner identity (leave empty normally).
        """
        try:
            _validate_str_length(description, "description", _MAX_TEXT)
            _validate_str_length(reasoning, "reasoning", _MAX_TEXT)
            _validate_str_length(tool, "tool", _MAX_SHORT)
            _validate_str_length(command, "command", _MAX_TEXT)
            _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
            case_dir = _resolve_case_dir()
            examiner = analyst_override or resolve_examiner()
            ts = datetime.now(timezone.utc).isoformat()

            entry: dict = {
                "ts": ts,
                "description": description,
                "reasoning": reasoning,
                "examiner": examiner,
                "source": "mcp",
            }
            if tool:
                entry["tool"] = tool
            if command:
                entry["command"] = command

            try:
                with open(case_dir / "actions.jsonl", "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
            except OSError as e:
                return {"status": "write_failed", "timestamp": ts, "error": str(e)}

            logged_id = audit.log(
                tool="record_action",
                params={"description": description, "reasoning": reasoning},
                result_summary={"status": "recorded", "timestamp": ts},
            )
            result = {"status": "recorded", "timestamp": ts}
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except (ValueError, OSError) as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Tool: log_reasoning (SAFE — audit-only, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def log_reasoning(text: str, analyst_override: str = "") -> dict:
        """Record analytical reasoning to the audit trail.

        Call at every meaningful decision point: when choosing what to
        examine next, forming or revising a hypothesis, ruling something
        out, or noting a contradiction. No approval needed — this is
        audit-only and never modifies case data.

        Unrecorded reasoning is lost during context compaction. Use this
        to preserve your analytical logic across long investigations.
        record_action is for actions; log_reasoning is for thinking.
        """
        _validate_str_length(text, "text", _MAX_TEXT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        result = {"status": "logged"}
        logged_id = audit.log(
            tool="log_reasoning",
            params={"text": text, "analyst_override": analyst_override},
            result_summary=result,
            source="orchestrator",
        )
        if logged_id is None:
            result["status"] = "write_failed"
            result["warning"] = "Audit write failed — reasoning not recorded"
        return result

    # ------------------------------------------------------------------
    # Tool: log_external_action (SAFE — audit-only, no approval)
    # ------------------------------------------------------------------
    @server.tool()
    def log_external_action(
        command: str,
        output_summary: str,
        purpose: str,
        analyst_override: str = "",
        hook_audit_id: str = "",
        input_files: list[str] | None = None,
        output_files: list[str] | None = None,
    ) -> dict:
        """Record a command executed outside this MCP server (e.g., via Bash).

        Returns an audit_id that you can pass into record_finding's audit_ids
        list to link a finding to the Bash command that produced the evidence.
        Without this call, Bash-executed commands have no audit entry and
        findings cannot reference them for provenance.

        If the PostToolUse hook captured this command, pass its audit_id as
        hook_audit_id — this upgrades provenance from voluntary (self-reported)
        to verified (cross-referenced with the hook entry).

        Args:
            command: The exact command that was executed.
            output_summary: What the command produced (key findings, not full output).
            purpose: Why this command was run (investigative rationale).
            analyst_override: Override examiner identity (leave empty normally).
            hook_audit_id: PostToolUse hook audit_id if available.
            input_files: Files the command read (enables provenance chain).
            output_files: Files the command produced.
        """
        _validate_str_length(command, "command", _MAX_TEXT)
        _validate_str_length(output_summary, "output_summary", _MAX_TEXT)
        _validate_str_length(purpose, "purpose", _MAX_TEXT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)

        provenance_warning = ""
        if output_files and not input_files:
            provenance_warning = (
                "output_files provided without input_files — provenance chain "
                "cannot trace to evidence. Add input_files to enable chain resolution."
            )

        # Determine source tier based on hook_audit_id
        source = "orchestrator_voluntary"
        if hook_audit_id:
            _validate_str_length(hook_audit_id, "hook_audit_id", _MAX_SHORT)
            # Verify hook_audit_id exists in audit trail
            case_dir = _resolve_case_dir()
            if case_dir:
                hook_found = False
                audit_dir = case_dir / "audit"
                for hook_file in (
                    sorted(audit_dir.glob("*.jsonl")) if audit_dir.is_dir() else []
                ):
                    if hook_found:
                        break
                    try:
                        with open(hook_file, encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if not line or hook_audit_id not in line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    if entry.get("audit_id") == hook_audit_id:
                                        hook_found = True
                                        break
                                except (json.JSONDecodeError, ValueError):
                                    continue
                    except OSError:
                        pass
                if hook_found:
                    source = "orchestrator_verified"

        audit_id = audit.log(
            tool="log_external_action",
            params={
                "command": command,
                "output_summary": output_summary,
                "purpose": purpose,
                "analyst_override": analyst_override,
                "hook_audit_id": hook_audit_id,
            },
            result_summary={
                "status": "logged",
                "source": source,
                "output_files": output_files or [],
            },
            source=source,
            input_files=input_files or None,
        )
        result = {
            "status": "logged",
            "audit_id": audit_id,
            "source": source,
            "note": (
                "orchestrator_verified -- cross-referenced with hook entry"
                if source == "orchestrator_verified"
                else "orchestrator_voluntary -- not independently verified"
            ),
        }
        if audit_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        if provenance_warning:
            result["provenance_warning"] = provenance_warning
        return result

    return server


def main() -> None:
    """Run the case-mcp server."""
    setup_logging("case-mcp")
    logger.info("Starting case-mcp server")
    server = create_server()
    server.run()
