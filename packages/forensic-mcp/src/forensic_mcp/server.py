"""MCP server for forensic investigation management."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from sift_common.instructions import FORENSIC_MCP as _INSTRUCTIONS

from forensic_mcp.audit import AuditWriter
from forensic_mcp.case.manager import CaseManager

logger = logging.getLogger(__name__)

_MAX_TITLE = 500
_MAX_TEXT = 10_000
_MAX_SHORT = 200


def _validate_str_length(value: str | None, field: str, max_len: int) -> None:
    """Reject strings exceeding max_len or containing null bytes."""
    if value is not None and isinstance(value, str):
        if len(value) > max_len:
            raise ValueError(f"{field} exceeds maximum length of {max_len} characters")
        if "\x00" in value:
            raise ValueError(f"{field} contains invalid null byte")


def _build_finding_considerations(finding: dict) -> list[str]:
    """Assemble pre-acceptance guidance for a staged finding."""
    from forensic_knowledge import loader

    considerations: list[str] = []

    # Self-check items from investigation framework (always included)
    # New format has {question, how} dicts; old format has plain strings
    framework = loader.get_investigation_framework()
    if framework:
        for item in framework.get("self_check", [])[:5]:
            if isinstance(item, dict):
                text = item.get("question", "")
                how = item.get("how", "")
                considerations.append(f"{text} → {how}" if how else text)
            else:
                considerations.append(item)

    # Anti-patterns relevant to the finding type
    finding_type = finding.get("type", "")
    anti_patterns = loader.get_anti_patterns()
    if finding_type == "attribution":
        for ap in anti_patterns:
            if ap["name"] == "premature_attribution":
                how = ap.get("how_to_avoid", "")
                msg = f"Anti-pattern: {ap['description']}"
                if how:
                    msg += f" How to avoid: {how}"
                considerations.append(msg)
    if finding_type == "exclusion":
        for ap in anti_patterns:
            if ap["name"] == "confirmation_bias":
                how = ap.get("how_to_avoid", "")
                msg = f"Anti-pattern: {ap['description']}"
                if how:
                    msg += f" How to avoid: {how}"
                considerations.append(msg)

    # Confidence-level requirements
    confidence = finding.get("confidence", "").upper()
    confidence_defs = loader.get_confidence_definitions()
    if confidence in confidence_defs:
        cd = confidence_defs[confidence]
        min_ev = cd.get("min_audit_ids", 0)
        if min_ev >= 2:
            considerations.append(
                f"{confidence} confidence requires {min_ev}+ independent corroborating sources "
                f"— are yours truly independent?"
            )

    # Checkpoint requirements if finding type matches
    if finding_type in ("attribution", "exclusion", "conclusion"):
        checkpoint = loader.get_checkpoint(finding_type)
        if checkpoint and isinstance(checkpoint, dict) and "guidance" in checkpoint:
            considerations.append(checkpoint["guidance"])

    return considerations


def _build_validation_guidance(errors: list[str]) -> list[str]:
    """Enrich validation errors with rule citations."""
    guidance: list[str] = []
    for err in errors:
        if "audit_id" in err.lower():
            guidance.append(
                "FD-001: Every claim must reference at least one audit_id from an actual tool call"
            )
        if "confidence_justification" in err.lower():
            guidance.append(
                "FD-005: Confidence must be justified — cite specific evidence for your confidence level"
            )
        if "attribution" in err.lower() and "3" in err:
            guidance.append(
                "FD-003: Attribution requires multiple corroborating TTPs, not just a single IOC match"
            )
    return guidance


def create_server(reference_mode: str = "resources") -> FastMCP:
    """Create and configure the forensic MCP server.

    Args:
        reference_mode: How to expose discipline reference data.
            "resources" (default) — MCP resources, not counted as tools.
            "tools" — MCP tools, for clients without resource support.
    """
    server = FastMCP("forensic-mcp", instructions=_INSTRUCTIONS)
    manager = CaseManager()
    audit = AuditWriter(mcp_name="forensic-mcp")

    # Expose for testing and CLI integration
    server._manager = manager
    server._audit = audit

    # --- Investigation Records ---

    @server.tool()
    def record_finding(
        finding: dict,
        analyst_override: str = "",
        supporting_commands: list[dict] | None = None,
        artifacts: list[dict] | None = None,
    ) -> dict:
        """Stage finding as DRAFT for human review.

        IMPORTANT: Every artifact MUST include audit_id from the tool response
        that produced the data. Artifacts without audit_id are REJECTED.

        Required fields in finding dict:
        - title (str): brief summary
        - observation (str): factual evidence — what was seen
        - interpretation (str): analytical meaning — what it implies
        - confidence: SPECULATIVE, LOW, MEDIUM, or HIGH
        - confidence_justification (str): why this confidence level
        - type: finding, conclusion, attribution (requires 3+ audit_ids), or exclusion
        - audit_ids (list[str]): IDs from MCP tool responses.
          Use [] if providing supporting_commands only.
        - event_timestamp (str, ISO 8601): when the incident event occurred
          (e.g., "2026-01-24T15:00:41Z"). NOT the current time — the time
          from the evidence. Date-only accepted (e.g., "2026-01-24").
          Required for type=finding. Optional for other types.

        Context (recommended):
        - host (str): which system, e.g., "wkstn05" or "dc01"
        - affected_account (str): which account, e.g., "shieldbase\\wacsvc"

        Optional: mitre_ids, iocs, event_type, artifact_ref, related_findings

        iocs (list): indicators of compromise found in this evidence.
          Pass ALL suspicious IPs, hashes, domains, registry keys, file paths,
          and accounts. Types auto-detected, deduplication automatic.
          For ambiguous values (bare usernames), pass as dict with explicit type:
          {"value": "rsydow-a", "type": "user-account"}

        supporting_commands (separate parameter, list of dicts): for shell-based
        evidence only. Each dict: {command, purpose, output_excerpt}.

        artifacts (separate parameter, list of dicts): raw evidence reviewed.
        Each dict:
          Required: source, extraction, content, audit_id
          Optional: content_type, purpose, output_ref
          audit_id: REQUIRED — copy from the tool response envelope.

        Tip: stage findings soon after analysis — audit_ids from earlier tool
        calls may be lost to context compaction.

        Requires human approval via 'agentir approve'."""
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        if isinstance(finding, dict):
            _validate_str_length(finding.get("title"), "title", _MAX_TITLE)
            _validate_str_length(finding.get("observation"), "observation", _MAX_TEXT)
            _validate_str_length(
                finding.get("interpretation"), "interpretation", _MAX_TEXT
            )
            _validate_str_length(
                finding.get("confidence_justification"),
                "confidence_justification",
                _MAX_TEXT,
            )
        # Coerce JSON string to list (LLMs often serialize list[dict] as a string)
        if isinstance(supporting_commands, str):
            try:
                supporting_commands = json.loads(supporting_commands)
            except (json.JSONDecodeError, TypeError):
                supporting_commands = None
        if not isinstance(supporting_commands, list):
            supporting_commands = None
        if supporting_commands:
            for cmd in supporting_commands[:5]:
                if isinstance(cmd, dict):
                    _validate_str_length(
                        cmd.get("command"), "supporting_commands.command", _MAX_TEXT
                    )
                    _validate_str_length(
                        cmd.get("purpose"), "supporting_commands.purpose", _MAX_TEXT
                    )
        # Coerce artifacts JSON string to list
        if isinstance(artifacts, str):
            try:
                artifacts = json.loads(artifacts)
            except (json.JSONDecodeError, TypeError):
                artifacts = None
        if not isinstance(artifacts, list):
            artifacts = None
        try:
            result = manager.record_finding(
                finding,
                examiner_override=analyst_override,
                supporting_commands=supporting_commands,
                artifacts=artifacts,
                audit=audit,
            )
        except Exception as e:
            logger.error("record_finding failed: %s", e)
            return {"error": str(e)}
        logged_id = audit.log(
            tool="record_finding", params={"finding": finding}, result_summary=result
        )
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"

        # Enrich with considerations when staging succeeds
        if result.get("status") == "STAGED":
            result["finding_status"] = (
                "DRAFT — requires human approval via the examiner portal"
            )
            result["considerations"] = _build_finding_considerations(finding)
            grounding = manager._score_grounding(finding)
            if grounding:
                result["grounding"] = grounding

            # Add provenance classification to response
            provenance = result.pop("provenance_detail", None)
            if provenance:
                result["provenance"] = provenance
                if provenance["summary"] == "SHELL":
                    result["provenance_guidance"] = (
                        "For stronger provenance, re-run analysis through MCP tools."
                    )

        # Enrich validation failures with rule citations
        if result.get("status") == "VALIDATION_FAILED":
            result["guidance"] = _build_validation_guidance(result.get("errors", []))

        return result

    @server.tool()
    def record_timeline_event(event: dict, analyst_override: str = "") -> dict:
        """Stage timeline event as DRAFT. Requires human approval via 'agentir approve'.

        Required fields in event dict:
        - timestamp (str): ISO 8601 datetime (e.g. "2026-03-01T14:32:00Z")
        - description (str): what happened at this time

        Recommended fields:
        - source (str): origin artifact or tool (e.g. "Security.evtx", "Prefetch")

        Optional fields (pass through automatically):
        - related_findings: list of finding IDs this event supports (e.g. ["F-001", "F-003"])
        - event_type: process, network, file, registry, auth, persistence, lateral, execution, or other
        - artifact_ref: deduplication hint (e.g. "prefetch:EVIL.EXE-{hash}", "evtx:Security:4624:12345")
        """
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        if isinstance(event, dict):
            _validate_str_length(event.get("description"), "description", _MAX_TEXT)
            _validate_str_length(event.get("source"), "source", _MAX_TITLE)
        try:
            result = manager.record_timeline_event(
                event, examiner_override=analyst_override
            )
        except Exception as e:
            logger.error("record_timeline_event failed: %s", e)
            return {"error": str(e)}
        logged_id = audit.log(
            tool="record_timeline_event", params={"event": event}, result_summary=result
        )
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    @server.tool(annotations={"readOnlyHint": True})
    def list_existing_findings(status: str = "", limit: int = 20, offset: int = 0):
        """List staged findings already recorded in this case.

        Call this when you need to review DRAFT findings before adding new
        evidence, check what the examiner has APPROVED/REJECTED, or prepare
        report context. Do not use it to create findings; use record_finding.

        Args:
            status: Filter by DRAFT, APPROVED, or REJECTED. Empty = all.
            limit: Max findings to return (default 20, 0 = all).
            offset: Skip first N findings (for pagination).

        Response includes total count so the LLM knows if results were
        truncated. Use offset to paginate through large result sets.

        Each finding dict contains:
        - id, title, observation, interpretation, confidence, confidence_justification, type
        - audit_ids: list of evidence trail IDs
        - status: DRAFT, APPROVED, or REJECTED
        - provenance: MCP, HOOK, SHELL, or NONE (string — how evidence was obtained)
        - content_hash: SHA-256 for integrity verification
        - artifacts: list of {source, extraction, content, content_type, purpose} (if provided)
        - supporting_commands: list of {command, output_excerpt, purpose} (if provided)
        - Optional: mitre_ids, iocs, event_type, artifact_ref, related_findings
        - Metadata: staged, modified_at, created_by, examiner
        """
        try:
            all_findings = manager.get_findings(status or None)
            total = len(all_findings)
            paginated = (
                all_findings[offset : offset + limit] if limit > 0 else all_findings
            )
            return {
                "findings": paginated,
                "total": total,
                "limit": limit,
                "offset": offset,
            }
        except Exception as e:
            logger.error("list_existing_findings failed: %s", e)
            return {
                "findings": [{"error": str(e)}],
                "total": 0,
                "limit": limit,
                "offset": offset,
            }

    def get_timeline(
        status: str = "",
        source: str = "",
        examiner: str = "",
        start_date: str = "",
        end_date: str = "",
        event_type: str = "",
        limit: int = 50,
        offset: int = 0,
    ):
        """Return timeline events with optional filtering.

        Filters (all optional):
        - status: DRAFT, APPROVED, or REJECTED
        - source: substring match against event source
        - examiner: exact examiner slug
        - start_date: ISO date/datetime lower bound on timestamp
        - end_date: ISO date/datetime upper bound on timestamp
        - event_type: process, network, file, registry, auth, persistence, lateral, execution, other

        Pagination:
        - limit: Max events to return (default 50, 0 = all).
        - offset: Skip first N events (for pagination).

        Response includes total count so the LLM knows if results were truncated.
        """
        try:
            all_events = manager.get_timeline(
                status=status or None,
                source=source or None,
                examiner=examiner or None,
                start_date=start_date or None,
                end_date=end_date or None,
                event_type=event_type or None,
            )
            total = len(all_events)
            paginated = all_events[offset : offset + limit] if limit > 0 else all_events
            return {
                "events": paginated,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": total > offset + limit,
            }
        except Exception as e:
            logger.error("get_timeline failed: %s", e)
            return {
                "events": [{"error": str(e)}],
                "total": 0,
                "limit": limit,
                "offset": offset,
            }

    def get_actions(limit: int = 50):
        """Return recent actions from the case actions log."""
        try:
            return manager.get_actions(limit)
        except Exception as e:
            logger.error("get_actions failed: %s", e)
            return [{"error": str(e)}]

    @server.tool(annotations={"readOnlyHint": True})
    def query_case(
        record_type: str,
        status: str = "",
        source: str = "",
        examiner: str = "",
        start_date: str = "",
        end_date: str = "",
        event_type: str = "",
        limit: int = 50,
        offset: int = 0,
    ):
        """Read case timeline or action records without changing evidence.

        Use record_type='timeline' for staged timeline events and
        record_type='actions' for the case action log. Findings intentionally
        stay separate as list_existing_findings because they are the main
        human-review/reporting object.

        Examples:
        - query_case(record_type='timeline', status='DRAFT', event_type='auth')
        - query_case(record_type='actions', limit=25)
        """
        rt = record_type.strip().lower()
        if rt == "timeline":
            return get_timeline(
                status=status,
                source=source,
                examiner=examiner,
                start_date=start_date,
                end_date=end_date,
                event_type=event_type,
                limit=limit,
                offset=offset,
            )
        if rt == "actions":
            return {
                "actions": get_actions(limit=limit),
                "record_type": "actions",
                "limit": limit,
            }
        return {
            "error": "unsupported_record_type",
            "message": "record_type must be 'timeline' or 'actions'. Use list_existing_findings for findings.",
            "supported_record_types": ["timeline", "actions"],
            "next_step": "Call query_case(record_type='timeline') or query_case(record_type='actions').",
        }

    # --- Workflow Status ---

    @server.tool(annotations={"readOnlyHint": True})
    def workflow_status() -> dict:
        """Single entry point — detect current investigation phase and recommend next steps.

        Call this FIRST every session. Replaces 7+ discovery calls (case_status,
        evidence_list, idx_case_summary, idx_ingest_status,
        list_existing_findings, query_case, manage_todo) with one call.

        Returns: {phase, case_id, evidence_summary, indexing_status,
                  findings_summary, timeline_events, available_capabilities, next_steps[]}

        Phases: ORIENT (fresh case), SEALED (evidence ready, not ingested),
                INGESTING (ingestion running), INGESTED (data in OpenSearch),
                TRIAGE (ready for analysis), FINDINGS (draft findings exist),
                REPORTING (approved findings ready for report)
        """
        try:
            case_dir = manager._require_active_case()
        except ValueError as e:
            return {
                "phase": "NO_CASE",
                "case_id": "",
                "error": str(e),
                "next_steps": [
                    "Create a case in the Examiner Portal at /portal/",
                    "Or select an existing case",
                ],
            }

        meta = manager._load_case_meta(case_dir)
        case_id = meta.get("case_id", case_dir.name)

        # ── Evidence chain integrity (MUST check first — tampering blocks all) ─
        evidence_chain_status = "unsealed"
        evidence_chain_issues: list[str] = []
        evidence_chain_version = 0
        try:
            from agentir_core.evidence_chain import chain_status

            chain = chain_status(case_dir)
            evidence_chain_status = chain.get("status", "unsealed")
            evidence_chain_issues = chain.get("issues", [])
            evidence_chain_version = chain.get("manifest_version", 0)
        except ImportError:
            pass

        # VIOLATION: modified, missing, unregistered, or ledger_error
        _VIOLATION_STATES = frozenset({"modified", "missing", "unregistered", "ledger_error"})
        if evidence_chain_status in _VIOLATION_STATES:
            return {
                "phase": "EVIDENCE_VIOLATION",
                "case_id": case_id,
                "evidence_chain": {
                    "status": evidence_chain_status,
                    "issues": evidence_chain_issues,
                    "manifest_version": evidence_chain_version,
                },
                "evidence_summary": {"sealed_files": 0, "ingested": False},
                "indexing_status": {"complete": False, "running": False, "failed": False, "docs_indexed": 0, "indices": 0},
                "findings_summary": {"total": 0, "draft": 0, "approved": 0, "rejected": 0},
                "timeline_events": 0,
                "available_capabilities": {},
                "next_steps": [
                    "EVIDENCE CHAIN VIOLATION DETECTED — Human-in-the-loop required.",
                    f"Status: {evidence_chain_status.upper()}",
                    *(f"  Issue: {issue}" for issue in evidence_chain_issues[:10]),
                    "",
                    "ALL tool calls are BLOCKED by the evidence gate until this is resolved.",
                    "The examiner must resolve this from the Examiner Portal:",
                    "  1. Review the evidence chain status in the Portal Evidence tab",
                    "  2. If files were added/deleted: re-seal the evidence manifest",
                    "  3. Run HMAC verification to confirm chain integrity",
                    "  4. Once the chain returns to OK, the agent can resume",
                    "",
                    "Do NOT attempt further tool calls — they will all fail with",
                    "'evidence_chain_violation' blocks until the examiner resolves this.",
                ],
            }

        # ── Evidence detection ──────────────────────────────────────────
        evidence_manifest_file = case_dir / "evidence-manifest.json"
        evidence_json_file = case_dir / "evidence.json"
        evidence_data: dict = {}
        if evidence_manifest_file.exists():
            try:
                evidence_data = json.loads(evidence_manifest_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        if not evidence_data and evidence_json_file.exists():
            try:
                evidence_data = json.loads(evidence_json_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        evidence_files = evidence_data.get("files", []) if isinstance(evidence_data, dict) else []
        sealed_count = len(evidence_files)

        # ── Ingest status detection ─────────────────────────────────────
        ingest_status_dir = Path.home() / ".agentir" / "ingest-status"
        ingest_complete = False
        ingest_running = False
        ingest_failed = False
        ingest_error = ""
        ingest_docs = 0
        ingest_indices = 0
        if ingest_status_dir.exists():
            safe_case = case_id.replace("/", "_").replace("\\", "_").replace("..", "_")
            for sf in sorted(ingest_status_dir.glob(f"{safe_case}-*.json")):
                try:
                    sdata = json.loads(sf.read_text())
                except (json.JSONDecodeError, OSError):
                    continue
                if sdata.get("pid") == 0:
                    continue
                status_val = sdata.get("status", "")
                if status_val == "complete":
                    ingest_complete = True
                    totals = sdata.get("totals", {})
                    if isinstance(totals, dict):
                        # Status files use "indexed" key; "docs_indexed" kept for compat
                        ingest_docs = max(
                            ingest_docs,
                            totals.get("docs_indexed") or totals.get("indexed", 0),
                        )
                    hosts = sdata.get("hosts", [])
                    ingest_indices = max(ingest_indices, len(hosts) if isinstance(hosts, list) else 0)
                elif status_val in ("running", "starting"):
                    ingest_running = True
                elif status_val == "failed":
                    ingest_failed = True
                    ingest_error = sdata.get("error", "")

        # ── Findings ─────────────────────────────────────────────────────
        findings = manager._load_findings(case_dir)
        draft_count = sum(1 for f in findings if f.get("status") == "DRAFT")
        approved_count = sum(1 for f in findings if f.get("status") == "APPROVED")
        rejected_count = sum(1 for f in findings if f.get("status") == "REJECTED")

        # ── Timeline ─────────────────────────────────────────────────────
        timeline = manager._load_timeline(case_dir)
        timeline_count = len(timeline)

        # ── Capabilities ─────────────────────────────────────────────────
        import importlib.util

        capabilities = {
            "opensearch": importlib.util.find_spec("opensearch_mcp") is not None,
            "forensic_rag": importlib.util.find_spec("rag_mcp") is not None,
            "opencti": importlib.util.find_spec("opencti_mcp") is not None,
            "sift_tools": True,
        }

        # ── Phase detection ──────────────────────────────────────────────
        if not sealed_count and not ingest_complete and not ingest_running:
            phase = "ORIENT"
            if evidence_chain_status == "unsealed":
                next_steps = [
                    "Copy evidence to the case directory (e.g., /cases/{case}/evidence/)",
                    "Seal evidence via the Examiner Portal (Evidence tab → Seal Manifest)",
                    "NOTE: Write tools are BLOCKED until evidence is sealed. Read-only tools (case_status, evidence_list, evidence_verify, search_knowledge) still work.",
                    "Then run idx_ingest() to index evidence into OpenSearch for structured analysis",
                ]
            else:
                next_steps = [
                    "Copy evidence to the case directory (e.g., /cases/{case}/evidence/)",
                    "Seal evidence via the Examiner Portal (Evidence tab → Seal Manifest)",
                    "Then run idx_ingest() to index evidence into OpenSearch for structured analysis",
                ]
        elif sealed_count > 0 and not ingest_complete and not ingest_running and not ingest_failed:
            phase = "SEALED"
            evidence_names = []
            for ef in evidence_files[:5]:
                if isinstance(ef, dict):
                    evidence_names.append(ef.get("name", ef.get("path", "unknown")))
                elif isinstance(ef, str):
                    evidence_names.append(ef)
            hint = ""
            if evidence_names:
                hint = f" (e.g., {evidence_names[0]})"
            next_steps = [
                f"Run idx_ingest(path='evidence/<file>', hostname='<HOST>') to index {sealed_count} sealed evidence file(s){hint}",
                "After ingestion, use idx_case_summary() for a full overview of indexed artifacts",
            ]
        elif ingest_running:
            phase = "INGESTING"
            next_steps = [
                "Ingestion is currently running. Wait for it to complete.",
                "Call idx_ingest_status() to check progress.",
                "Once complete, use idx_case_summary() to review indexed artifacts.",
            ]
        elif ingest_failed and not ingest_complete:
            phase = "SEALED"
            next_steps = [
                f"Ingestion failed: {ingest_error or 'unknown error'}",
                "Check ingest logs in ~/.agentir/ingest-logs/ for details.",
                "Fix the issue and re-run idx_ingest().",
            ]
        elif ingest_complete and draft_count == 0 and approved_count == 0:
            phase = "TRIAGE"
            next_steps = [
                "Evidence is indexed — start your analysis:",
                "1. Run idx_case_summary() for a complete overview of all indexed artifacts",
                "2. Search for IOCs with idx_search() across all artifact types",
                "3. Use idx_aggregate() to spot patterns (top commands, accounts, etc.)",
                "4. Query specific hosts with idx_artifact_browse()",
                "5. Check the RAG knowledge base with search_knowledge() for relevant detection guidance",
                "6. Run timeline analysis on EVTX files if available",
                "Stage findings as you go with record_finding() — they'll be DRAFT until examiner approval",
            ]
        elif draft_count > 0 and approved_count == 0:
            phase = "FINDINGS"
            next_steps = [
                f"You have {draft_count} draft finding(s) waiting for examiner review.",
                "Continue investigation: look for corroborating evidence, expand timeline coverage,",
                "and cross-reference with threat intelligence via OpenCTI.",
                "When findings are solid, the examiner can approve them in the portal.",
                "Run list_existing_findings(status='DRAFT') to review your staged findings.",
            ]
        elif approved_count > 0:
            phase = "REPORTING"
            next_steps = [
                f"{approved_count} finding(s) approved — ready for report generation.",
                "Run generate_report() to produce the final forensic report.",
                "Pending findings can still be investigated and added.",
                f"You also have {draft_count} draft finding(s) still pending.",
            ]
        else:
            phase = "ORIENT"
            next_steps = ["Investigate the case using available tools."]

        return {
            "phase": phase,
            "case_id": case_id,
            "evidence_chain": {
                "status": evidence_chain_status,
                "issues": evidence_chain_issues,
                "manifest_version": evidence_chain_version,
            },
            "evidence_summary": {
                "sealed_files": sealed_count,
                "ingested": ingest_complete,
            },
            "indexing_status": {
                "complete": ingest_complete,
                "running": ingest_running,
                "failed": ingest_failed,
                "docs_indexed": ingest_docs,
                "indices": ingest_indices,
                "note": "docs_indexed reflects ingest status files only. Call idx_case_summary for authoritative OpenSearch counts.",
            },
            "findings_summary": {
                "total": len(findings),
                "draft": draft_count,
                "approved": approved_count,
                "rejected": rejected_count,
            },
            "timeline_events": timeline_count,
            "available_capabilities": capabilities,
            "next_steps": next_steps,
        }

    # --- TODOs ---

    def add_todo(
        description: str,
        assignee: str = "",
        priority: str = "medium",
        related_findings: list[str] | None = None,
        analyst_override: str = "",
    ) -> dict:
        """Create a TODO item for the investigation. Priority: high/medium/low."""
        _validate_str_length(description, "description", _MAX_TEXT)
        _validate_str_length(assignee, "assignee", _MAX_SHORT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        try:
            result = manager.add_todo(
                description,
                assignee,
                priority,
                related_findings,
                examiner_override=analyst_override,
            )
        except Exception as e:
            logger.error("add_todo failed: %s", e)
            return {"error": str(e)}
        logged_id = audit.log(
            tool="add_todo",
            params={"description": description, "assignee": assignee},
            result_summary=result,
        )
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    def list_todos(status: str = "open", assignee: str = ""):
        """List TODO items. Status: open/completed/all."""
        try:
            return manager.list_todos(status, assignee)
        except Exception as e:
            logger.error("list_todos failed: %s", e)
            return [{"error": str(e)}]

    def update_todo(
        todo_id: str,
        status: str = "",
        note: str = "",
        assignee: str = "",
        priority: str = "",
        analyst_override: str = "",
    ) -> dict:
        """Update a TODO: change status, add note, reassign, reprioritize."""
        _validate_str_length(note, "note", _MAX_TEXT)
        _validate_str_length(assignee, "assignee", _MAX_SHORT)
        _validate_str_length(analyst_override, "analyst_override", _MAX_SHORT)
        try:
            result = manager.update_todo(
                todo_id,
                status,
                note,
                assignee,
                priority,
                examiner_override=analyst_override,
            )
        except Exception as e:
            logger.error("update_todo failed: %s", e)
            return {"error": str(e)}
        logged_id = audit.log(
            tool="update_todo", params={"todo_id": todo_id}, result_summary=result
        )
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    def complete_todo(todo_id: str, analyst_override: str = "") -> dict:
        """Mark a TODO as completed."""
        try:
            result = manager.complete_todo(todo_id, examiner_override=analyst_override)
        except Exception as e:
            logger.error("complete_todo failed: %s", e)
            return {"error": str(e)}
        logged_id = audit.log(
            tool="complete_todo", params={"todo_id": todo_id}, result_summary=result
        )
        if logged_id is None:
            result["warning"] = "Audit write failed — action not recorded"
        return result

    @server.tool()
    def manage_todo(
        action: str,
        todo_id: str = "",
        description: str = "",
        assignee: str = "",
        priority: str = "medium",
        status: str = "",
        note: str = "",
        related_findings: list[str] | None = None,
        analyst_override: str = "",
    ):
        """Create, list, update, or complete investigation TODOs.

        Use this for investigation task tracking, not for findings. Actions:
        - action='add': requires description; optional assignee, priority,
          related_findings.
        - action='list': optional status='open|completed|all' and assignee.
        - action='update': requires todo_id; optional status, note, assignee,
          priority.
        - action='complete': requires todo_id.

        Examples:
        - manage_todo(action='add', description='Correlate 4624 logons for SRL-FORGE', priority='high')
        - manage_todo(action='list', status='open')
        - manage_todo(action='complete', todo_id='T-001')
        """
        normalized = action.strip().lower()
        if normalized == "add":
            if not description:
                return {
                    "error": "missing_description",
                    "message": "description is required when action='add'.",
                    "next_step": "Call manage_todo(action='add', description='...').",
                }
            return add_todo(
                description=description,
                assignee=assignee,
                priority=priority,
                related_findings=related_findings,
                analyst_override=analyst_override,
            )
        if normalized == "list":
            return {
                "todos": list_todos(status=status or "open", assignee=assignee),
                "action": "list",
                "status": status or "open",
                "assignee": assignee,
            }
        if normalized == "update":
            if not todo_id:
                return {
                    "error": "missing_todo_id",
                    "message": "todo_id is required when action='update'.",
                    "next_step": "Call manage_todo(action='update', todo_id='...', status='...', note='...').",
                }
            return update_todo(
                todo_id=todo_id,
                status=status,
                note=note,
                assignee=assignee,
                priority=priority,
                analyst_override=analyst_override,
            )
        if normalized == "complete":
            if not todo_id:
                return {
                    "error": "missing_todo_id",
                    "message": "todo_id is required when action='complete'.",
                    "next_step": "Call manage_todo(action='complete', todo_id='...').",
                }
            return complete_todo(todo_id=todo_id, analyst_override=analyst_override)
        return {
            "error": "unsupported_todo_action",
            "message": "action must be one of: add, list, update, complete",
            "supported_actions": ["add", "list", "update", "complete"],
            "next_step": "Call manage_todo with action='add', 'list', 'update', or 'complete'.",
        }

    # --- Discipline Reference Data ---

    if reference_mode == "resources":
        _register_discipline_resources(server)
    elif reference_mode == "tools":
        _register_discipline_tools(server, audit)
    else:
        raise ValueError(
            f"Invalid reference_mode: {reference_mode!r} (expected 'resources' or 'tools')"
        )

    return server


def _register_discipline_resources(server: FastMCP) -> None:
    """Register discipline reference data as MCP resources.

    Resources are static reference content accessed by URI. They don't count
    as tools in the tool list, reducing cognitive load for the LLM client.
    """

    @server.resource("forensic-mcp://investigation-framework")
    def investigation_framework_resource() -> str:
        """Full investigation framework: principles, HITL checkpoints, workflow, golden rules, self-check."""
        from forensic_mcp.discipline.rules import get_investigation_framework

        return json.dumps(get_investigation_framework())

    @server.resource("forensic-mcp://rules")
    def rules_resource() -> str:
        """All forensic discipline rules as structured data."""
        from forensic_mcp.discipline.rules import get_all_rules

        return json.dumps(get_all_rules())

    @server.resource("forensic-mcp://checkpoint/{action_type}")
    def checkpoint_resource(action_type: str) -> str:
        """Requirements before a specific action (attribution, root_cause, exclusion, clean_declaration)."""
        from forensic_mcp.discipline.rules import get_checkpoint

        return json.dumps(get_checkpoint(action_type))

    @server.resource("forensic-mcp://validation-schema")
    def validation_schema_resource() -> str:
        """Finding validation rules: required fields, confidence levels, evidence count requirements."""
        from forensic_knowledge import loader

        from forensic_mcp.discipline.validation import VALID_TYPES

        confidence_defs = loader.get_confidence_definitions()
        schema = {
            "required_fields": [
                "title",
                "observation",
                "interpretation",
                "confidence",
                "type",
                "audit_ids",
                "confidence_justification",
            ],
            "valid_types": sorted(VALID_TYPES),
            "confidence_levels": {
                level: {"min_audit_ids": defs.get("min_audit_ids", 1)}
                for level, defs in confidence_defs.items()
            },
            "rules": [
                "FD-001: Every claim must reference at least one audit_id from an actual tool call",
                "FD-003: Attribution requires at least 3 audit_ids from multiple corroborating TTPs",
                "FD-005: Confidence must be justified with specific evidence citations",
            ],
        }
        return json.dumps(schema)

    @server.resource("forensic-mcp://evidence-standards")
    def evidence_standards_resource() -> str:
        """Evidence classification levels with definitions."""
        from forensic_mcp.discipline.rules import get_evidence_standards_data

        return json.dumps(get_evidence_standards_data())

    @server.resource("forensic-mcp://confidence-definitions")
    def confidence_definitions_resource() -> str:
        """Confidence levels (HIGH/MEDIUM/LOW/SPECULATIVE) with criteria."""
        from forensic_mcp.discipline.rules import get_confidence_definitions_data

        return json.dumps(get_confidence_definitions_data())

    @server.resource("forensic-mcp://anti-patterns")
    def anti_patterns_resource() -> str:
        """Common forensic mistakes to avoid."""
        from forensic_mcp.discipline.rules import get_anti_patterns_data

        return json.dumps(get_anti_patterns_data())

    @server.resource("forensic-mcp://evidence-template")
    def evidence_template_resource() -> str:
        """Required evidence presentation format."""
        from forensic_mcp.discipline.rules import get_evidence_template_data

        return json.dumps(get_evidence_template_data())

    @server.resource("forensic-mcp://tool-guidance/{tool_name}")
    def tool_guidance_resource(tool_name: str) -> str:
        """How to interpret results from a specific forensic tool."""
        from forensic_mcp.discipline.guidance import get_guidance

        return json.dumps(get_guidance(tool_name))

    @server.resource("forensic-mcp://false-positive-context/{tool_name}/{finding_type}")
    def false_positive_context_resource(tool_name: str, finding_type: str) -> str:
        """Common false positives for a tool/finding combination."""
        from forensic_mcp.discipline.guidance import get_false_positives

        return json.dumps(get_false_positives(tool_name, finding_type))

    @server.resource("forensic-mcp://corroboration/{finding_type}")
    def corroboration_resource(finding_type: str) -> str:
        """Cross-reference suggestions based on finding type."""
        from forensic_mcp.discipline.guidance import get_corroboration

        return json.dumps(get_corroboration(finding_type))

    @server.resource("forensic-mcp://playbooks")
    def playbooks_resource() -> str:
        """Available investigation playbooks."""
        from forensic_mcp.discipline.playbooks import list_all

        return json.dumps(list_all())

    @server.resource("forensic-mcp://playbook/{name}")
    def playbook_resource(name: str) -> str:
        """Step-by-step procedure for a specific investigation type."""
        from forensic_mcp.discipline.playbooks import get_by_name

        return json.dumps(get_by_name(name))

    @server.resource("forensic-mcp://collection-checklist/{artifact_type}")
    def collection_checklist_resource(artifact_type: str) -> str:
        """Evidence collection checklist per artifact type."""
        from forensic_mcp.discipline.playbooks import get_checklist

        return json.dumps(get_checklist(artifact_type))


def _register_discipline_tools(server: FastMCP, audit: AuditWriter) -> None:
    """Register discipline reference data as MCP tools.

    Used when the client doesn't support MCP resources. All 14 functions
    appear in the tool list alongside the 12 active tools.
    """

    @server.tool()
    def get_investigation_framework() -> dict:
        """Return the full investigation framework: principles, HITL checkpoints, workflow, golden rules, self-check."""
        try:
            from forensic_mcp.discipline.rules import (
                get_investigation_framework as _get_fw,
            )

            result = _get_fw()
            logged_id = audit.log(
                tool="get_investigation_framework",
                params={},
                result_summary={"keys": list(result.keys())},
            )
            if logged_id is None:
                result["warning"] = "Audit write failed — action not recorded"
            return result
        except Exception as e:
            logger.error("get_investigation_framework failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_rules():
        """Return all forensic discipline rules as structured data."""
        try:
            from forensic_mcp.discipline.rules import get_all_rules

            return get_all_rules()
        except Exception as e:
            logger.error("get_rules failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def get_checkpoint_requirements(action_type: str) -> dict:
        """What's required before a specific action (attribution, root cause, exclusion, etc.)."""
        try:
            from forensic_mcp.discipline.rules import get_checkpoint

            return get_checkpoint(action_type)
        except Exception as e:
            logger.error("get_checkpoint_requirements failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def validate_finding(finding_json: dict) -> dict:
        """Check a proposed finding against format and methodology standards."""
        try:
            from forensic_mcp.discipline.validation import validate

            return validate(finding_json)
        except Exception as e:
            logger.error("validate_finding failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_evidence_standards() -> dict:
        """Evidence classification levels with definitions."""
        try:
            from forensic_mcp.discipline.rules import get_evidence_standards_data

            return get_evidence_standards_data()
        except Exception as e:
            logger.error("get_evidence_standards failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_confidence_definitions() -> dict:
        """Confidence levels (HIGH/MEDIUM/LOW/SPECULATIVE) with criteria."""
        try:
            from forensic_mcp.discipline.rules import get_confidence_definitions_data

            return get_confidence_definitions_data()
        except Exception as e:
            logger.error("get_confidence_definitions failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_anti_patterns():
        """Common forensic mistakes to avoid."""
        try:
            from forensic_mcp.discipline.rules import get_anti_patterns_data

            return get_anti_patterns_data()
        except Exception as e:
            logger.error("get_anti_patterns failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def get_evidence_template() -> dict:
        """Required evidence presentation format."""
        try:
            from forensic_mcp.discipline.rules import get_evidence_template_data

            return get_evidence_template_data()
        except Exception as e:
            logger.error("get_evidence_template failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_tool_guidance(tool_name: str) -> dict:
        """How to interpret results from a specific forensic tool."""
        try:
            from forensic_mcp.discipline.guidance import get_guidance

            return get_guidance(tool_name)
        except Exception as e:
            logger.error("get_tool_guidance failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_false_positive_context(tool_name: str, finding_type: str) -> dict:
        """Common false positives for a tool/finding combination."""
        try:
            from forensic_mcp.discipline.guidance import get_false_positives

            return get_false_positives(tool_name, finding_type)
        except Exception as e:
            logger.error("get_false_positive_context failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_corroboration_suggestions(finding_type: str):
        """Cross-reference suggestions based on finding type."""
        try:
            from forensic_mcp.discipline.guidance import get_corroboration

            return get_corroboration(finding_type)
        except Exception as e:
            logger.error("get_corroboration_suggestions failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def list_playbooks():
        """Available investigation playbooks."""
        try:
            from forensic_mcp.discipline.playbooks import list_all

            return list_all()
        except Exception as e:
            logger.error("list_playbooks failed: %s", e)
            return [{"error": str(e)}]

    @server.tool()
    def get_playbook(name: str) -> dict:
        """Step-by-step procedure for a specific investigation type."""
        try:
            from forensic_mcp.discipline.playbooks import get_by_name

            return get_by_name(name)
        except Exception as e:
            logger.error("get_playbook failed: %s", e)
            return {"error": str(e)}

    @server.tool()
    def get_collection_checklist(artifact_type: str) -> dict:
        """Evidence collection checklist per artifact type."""
        try:
            from forensic_mcp.discipline.playbooks import get_checklist

            return get_checklist(artifact_type)
        except Exception as e:
            logger.error("get_collection_checklist failed: %s", e)
            return {"error": str(e)}
