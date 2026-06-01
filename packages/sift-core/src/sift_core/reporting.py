"""Core report generation.

Owned by sift-core (Phase 2): assembling a structured report from approved
case data — findings, timeline, IOCs, MITRE mapping, evidence chain provenance
and verification reconciliation — is a core capability, not an add-on concern.

Report generation is *triggered* by the examiner in the portal (F-E); the agent
MCP surface no longer exposes a report tool. This module holds the pure
generation logic the portal calls into.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from sift_core.case_io import (
    load_case_meta,
    load_findings,
    load_timeline,
    load_todos,
)
from sift_core.evidence_chain import (
    ChainStatus,
    chain_status as _ev_chain_status,
    load_manifest,
)
from sift_core.evidence_ops import list_evidence_data
from sift_core.report_profiles import PROFILES, STRIPPED_FINDING_FIELDS
from sift_core.verification import VERIFICATION_DIR

# Substantive-field exclusion used when reconciling an approved item against
# its verification ledger snapshot. Mirrors sift_core.case_io.hmac_text intent.
_HASH_EXCLUDE_KEYS = {
    "status",
    "approved_at",
    "approved_by",
    "rejected_at",
    "rejected_by",
    "rejection_reason",
    "examiner_notes",
    "examiner_modifications",
    "content_hash",
    "verification",
    "modified_at",
    "provenance",
    "provenance_warnings",
    "timeline_event_id",
    "source_evidence",
}


WRITING_GUIDANCE = """Report Writing Guidance (forensic-specific):

1. DRAFT STATUS: This is a draft for human curation. Sections marked in
   human_review_required need placeholder guidance, not fabrication. Write
   "[HUMAN INPUT NEEDED: ...]" with specific prompts for what to add.

2. FINDING SYNTHESIS: Group findings by MITRE ATT&CK technique or kill
   chain phase. Tell a coherent attack narrative, not a disconnected list.
   Cross-reference related findings by ID.

3. CONFIDENCE COMMUNICATION:
   - HIGH: State as established fact ("The attacker exfiltrated...")
   - MEDIUM: Use evidential language ("Evidence suggests...",
     "Analysis indicates...")
   - LOW: Use preliminary framing ("Preliminary indicators suggest...",
     "Initial analysis points to...")

4. MITRE ATT&CK IN PROSE: Weave technique references into the narrative
   ("The attacker used credential dumping (T1003) to harvest..."). Do not
   just table-dump technique IDs.

5. IOC PRESENTATION: For executive profile, summarize IOC categories and
   counts. For full/IOC profiles, present structured tables with
   cross-references to source findings.

6. INTEGRITY: If an integrity_warning key is present in this response,
   include a conspicuous integrity statement in the report. Do not bury it.

7. AUDIENCE: Executive summary uses business impact language, no technical
   jargon. Technical sections use forensic precision. Adjust vocabulary
   per section, not per report.

8. CONTEXT FIELD: When a finding includes a 'context' field with examiner
   notes, incorporate that context into the narrative. These are
   examiner-verified observations about data exposure, business impact,
   or third-party relevance. Cite them authoritatively.

9. EVIDENCE: Reference evidence in general terms ("forensic analysis of
   the Exchange server logs revealed..."). Do not fabricate specific
   evidence file names or paths not present in the data."""

HUMAN_REVIEW_REQUIRED = [
    {
        "section": "Business Impact",
        "reason": "Requires organizational knowledge of affected business processes, revenue impact, and regulatory exposure.",
        "prompt": "Describe the business impact: affected operations, estimated financial impact, regulatory implications, customer/partner exposure.",
    },
    {
        "section": "Third-Party Involvement",
        "reason": "Requires knowledge of vendor relationships, shared infrastructure, and contractual obligations.",
        "prompt": "List involved third parties, their role in the incident, notification status, and any contractual obligations triggered.",
    },
    {
        "section": "What Went Well",
        "reason": "Requires organizational context about response effectiveness.",
        "prompt": "Describe what worked well in detection, containment, and response. Include team coordination and tool effectiveness.",
    },
    {
        "section": "Action Items",
        "reason": "Requires management input for owners, deadlines, and budget.",
        "prompt": "Assign owners and deadlines to each recommendation. Include budget estimates where applicable.",
    },
    {
        "section": "Report Changelog",
        "reason": "Human revision tracking — not applicable to initial draft.",
        "prompt": "Track revisions: date, author, sections changed, reason for change.",
    },
]

GENERATION_CONSTRAINTS = (
    "This report data contains ONLY approved findings and timeline "
    "events. Never reference, count, or speculate about unapproved, "
    "draft, or rejected items in report output. The summary.findings_total "
    "count is for internal tracking only — use summary.findings_approved "
    "as the authoritative count in all report text."
)


def _strip_finding(finding: dict) -> dict:
    """Remove internal fields from a finding for report output."""
    return {k: v for k, v in finding.items() if k not in STRIPPED_FINDING_FIELDS}


def extract_all_iocs(findings: list[dict]) -> dict[str, list[dict]]:
    """Extract IOCs from findings with cross-references to source finding IDs.

    Returns {type: [{value, source_findings: [ids]}]}.
    """
    # Collect: (type, value) -> set of finding IDs
    collected: dict[tuple[str, str], set[str]] = {}

    for f in findings:
        fid = f.get("id", "")

        # Structured IOC field
        iocs_field = f.get("iocs")
        if isinstance(iocs_field, dict):
            for ioc_type, values in iocs_field.items():
                if isinstance(values, list):
                    for v in values:
                        key = (ioc_type, str(v))
                        collected.setdefault(key, set()).add(fid)
                else:
                    key = (ioc_type, str(values))
                    collected.setdefault(key, set()).add(fid)
        elif isinstance(iocs_field, list):
            for ioc in iocs_field:
                if isinstance(ioc, dict):
                    ioc_type = ioc.get("type", "Unknown")
                    ioc_value = str(ioc.get("value", ""))
                    collected.setdefault((ioc_type, ioc_value), set()).add(fid)
                elif isinstance(ioc, str) and ioc.strip():
                    collected.setdefault(("Unknown", ioc.strip()), set()).add(fid)

        # Text extraction from observation + interpretation (findings use these, not description)
        text = f"{f.get('observation', '')} {f.get('interpretation', '')} {f.get('description', '')}"
        ipv4_pattern = (
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        )
        for ip in re.findall(ipv4_pattern, text):
            if not ip.startswith(("0.", "127.", "255.")):
                collected.setdefault(("IPv4", ip), set()).add(fid)
        for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
            collected.setdefault(("SHA256", h.lower()), set()).add(fid)
        for h in re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])", text):
            collected.setdefault(("SHA1", h.lower()), set()).add(fid)
        for h in re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])", text):
            collected.setdefault(("MD5", h.lower()), set()).add(fid)
        for fp in re.findall(r"[A-Z]:\\(?:[^\s,;]+)", text):
            collected.setdefault(("File", fp), set()).add(fid)
        for d in re.findall(
            r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|cc|tk)\b",
            text,
        ):
            collected.setdefault(("Domain", d.lower()), set()).add(fid)

    # Group by type
    by_type: dict[str, list[dict]] = {}
    for (ioc_type, value), fids in sorted(collected.items()):
        by_type.setdefault(ioc_type, []).append(
            {"value": value, "source_findings": sorted(fids)}
        )

    return by_type


def build_mitre_mapping(findings: list[dict]) -> dict[str, dict]:
    """Build MITRE ATT&CK mapping from findings.

    Returns {technique_id: {name, findings: [ids]}}.
    """
    mapping: dict[str, dict] = {}

    for f in findings:
        fid = f.get("id", "")
        techniques = f.get("mitre_techniques") or f.get("mitre_ids")
        if not techniques:
            continue
        if isinstance(techniques, list):
            for t in techniques:
                if isinstance(t, dict):
                    tid = t.get("id", t.get("technique_id", ""))
                    name = t.get("name", "")
                elif isinstance(t, str):
                    tid = t
                    name = ""
                else:
                    continue
                if tid:
                    if tid not in mapping:
                        mapping[tid] = {"name": name, "findings": []}
                    if fid and fid not in mapping[tid]["findings"]:
                        mapping[tid]["findings"].append(fid)
                    if name and not mapping[tid]["name"]:
                        mapping[tid]["name"] = name

    return mapping


def build_summary(
    findings: list[dict],
    timeline: list[dict],
    todos: list[dict],
    evidence_count: int,
    iocs: dict,
) -> dict:
    """Build summary counts."""
    all_findings = findings  # Already loaded (may include non-approved for total count)
    approved_findings = [f for f in findings if f.get("status") == "APPROVED"]
    approved_timeline = [t for t in timeline if t.get("status") == "APPROVED"]
    ioc_count = sum(len(v) for v in iocs.values())
    open_todos = sum(1 for t in todos if t.get("status") == "open")

    return {
        "findings_total": len(all_findings),
        "findings_approved": len(approved_findings),
        "timeline_events": len(approved_timeline),
        "evidence_files": evidence_count,
        "ioc_count": ioc_count,
        "todos_open": open_todos,
    }


def build_zeltser_guidance(profile_name: str, profile: dict, metadata: dict) -> dict:
    """Construct Zeltser IR Writing MCP guidance for a profile."""
    tools = profile.get("zeltser_tools", [])
    if not tools:
        return {}

    guidance: dict = {
        "tools": tools,
        "workflow": [
            "1. Call ir_get_template() to get the IR report structure",
            "2. Call ir_load_context(incident_type=...) for case-specific guidance",
            "3. Call ir_get_guidelines() for writing best practices",
            "4. Write each narrative section using report_data and Zeltser guidance",
            "5. Call ir_review_report(sections=[...]) to review draft quality",
            "6. Call save_report(filename, content) to persist the final report",
        ],
        "parameters": {},
    }

    # Derive parameters from metadata
    incident_type = metadata.get("incident_type", "")
    if incident_type:
        guidance["parameters"]["ir_load_context"] = {"incident_type": incident_type}

    # Map profile to guidelines topic
    topic_map = {
        "full": "full_report",
        "executive": "executive_summary",
        "timeline": "timeline",
        "findings": "findings",
        "status": "status_brief",
    }
    topic = topic_map.get(profile_name)
    if topic:
        guidance["parameters"]["ir_get_guidelines"] = {"topic": topic}

    return guidance


def generate_report_data(
    profile_name: str,
    case_dir: Path,
    finding_ids: list[str] | None = None,
    start_date: str = "",
    end_date: str = "",
) -> dict:
    """Core report generation logic.

    Assembles a structured report dict from approved case data, with evidence
    chain provenance and verification reconciliation. Raises KeyError if the
    profile is unknown (callers validate the profile name first).
    """
    profile = PROFILES[profile_name]

    # Load all data
    metadata = load_case_meta(case_dir)
    all_findings = load_findings(case_dir)
    all_timeline = load_timeline(case_dir)
    todos = load_todos(case_dir)

    # Evidence
    evidence_list: list[dict] = []
    try:
        ev_data = list_evidence_data(case_dir)
        evidence_list = ev_data.get("evidence", [])
    except (ValueError, OSError):
        pass
    evidence_count = len(evidence_list)

    # Evidence chain status — included in every report for chain-of-custody
    ev_chain: dict = {}
    try:
        ev_status = _ev_chain_status(case_dir)
        ev_chain = {
            "status": str(ev_status["status"]),
            "manifest_version": ev_status.get("manifest_version", 0),
            "ok_count": ev_status.get("ok_count", 0),
            "issues": ev_status.get("issues", []),
            "manifest_hash": None,
        }
        try:
            manifest = load_manifest(case_dir)
            if manifest:
                ev_chain["manifest_hash"] = manifest.get("manifest_hash")
        except Exception:
            pass
    except Exception as exc:
        ev_chain = {
            "status": str(ChainStatus.LEDGER_ERROR),
            "issues": [f"Chain status check failed: {exc}"],
            "manifest_version": 0,
            "ok_count": 0,
            "manifest_hash": None,
        }

    # Filter approved only
    approved_findings = [f for f in all_findings if f.get("status") == "APPROVED"]
    approved_timeline = [t for t in all_timeline if t.get("status") == "APPROVED"]

    # Apply findings_mode
    findings_mode = profile.get("findings_mode", "all")
    if findings_mode == "all":
        report_findings = approved_findings
    elif findings_mode == "top_5":
        report_findings = approved_findings[:5]
    elif findings_mode == "count":
        report_findings = []
    elif findings_mode == "referenced":
        # Include findings referenced by other primary data
        report_findings = approved_findings
    else:
        report_findings = approved_findings

    # Apply finding_ids filter (findings profile)
    if finding_ids and profile.get("filterable", {}).get("finding_ids"):
        id_set = set(finding_ids)
        report_findings = [f for f in report_findings if f.get("id") in id_set]

    # Apply timeline_mode
    timeline_mode = profile.get("timeline_mode", "all")
    if timeline_mode == "all":
        report_timeline = approved_timeline
    elif timeline_mode == "count":
        report_timeline = []
    elif timeline_mode == "referenced":
        report_timeline = approved_timeline
    elif timeline_mode == "none":
        report_timeline = []
    else:
        report_timeline = approved_timeline

    # Apply date filters (timeline profile)
    if start_date and profile.get("filterable", {}).get("start_date"):
        report_timeline = [
            t for t in report_timeline if t.get("timestamp", "") >= start_date
        ]
    if end_date and profile.get("filterable", {}).get("end_date"):
        report_timeline = [
            t for t in report_timeline if t.get("timestamp", "") <= end_date
        ]

    # Strip internal fields from findings
    stripped_findings = [_strip_finding(f) for f in report_findings]

    # IOC aggregation
    iocs = extract_all_iocs(approved_findings)

    # MITRE mapping
    mitre = build_mitre_mapping(approved_findings)

    # Open TODOs
    open_todos = [t for t in todos if t.get("status") == "open"]

    # Build summary with all findings (not just report-filtered)
    summary = build_summary(all_findings, all_timeline, todos, evidence_count, iocs)

    # Assemble report_data based on profile's data_keys
    data_keys = profile.get("data_keys", [])
    report_data: dict = {}
    if "metadata" in data_keys:
        report_data["metadata"] = metadata
    if "findings" in data_keys:
        if findings_mode == "count":
            report_data["findings_count"] = len(approved_findings)
        else:
            report_data["findings"] = stripped_findings
    elif findings_mode == "count":
        # Count-only mode: emit count even if "findings" not in data_keys
        report_data["findings_count"] = len(approved_findings)
    if "timeline" in data_keys:
        if timeline_mode == "count":
            report_data["timeline_count"] = len(approved_timeline)
        else:
            report_data["timeline"] = report_timeline
    elif timeline_mode == "count":
        # Count-only mode: emit count even if "timeline" not in data_keys
        report_data["timeline_count"] = len(approved_timeline)
    if "iocs" in data_keys:
        report_data["iocs"] = iocs
    if "mitre_mapping" in data_keys:
        report_data["mitre_mapping"] = mitre
    if "evidence" in data_keys:
        report_data["evidence"] = evidence_list
    if "todos" in data_keys:
        report_data["todos"] = open_todos
    if "summary" in data_keys:
        report_data["summary"] = summary

    # Build sections
    sections = profile.get("sections", [])

    # Build Zeltser guidance
    zeltser_guidance = build_zeltser_guidance(profile_name, profile, metadata)

    result: dict = {
        "profile": profile_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_data": report_data,
        "sections": sections,
    }
    if zeltser_guidance:
        result["zeltser_guidance"] = zeltser_guidance

    result["writing_guidance"] = WRITING_GUIDANCE
    result["human_review_required"] = HUMAN_REVIEW_REQUIRED
    result["generation_constraints"] = GENERATION_CONSTRAINTS

    # Evidence chain provenance
    result["evidence_chain"] = ev_chain
    _ev_status_val = ev_chain.get("status", "")
    _VIOLATION_STATUSES = {
        str(ChainStatus.MODIFIED),
        str(ChainStatus.MISSING),
        str(ChainStatus.UNREGISTERED),
        str(ChainStatus.LEDGER_ERROR),
    }
    if _ev_status_val in _VIOLATION_STATUSES:
        _chain_warning = (
            f"EVIDENCE INTEGRITY VIOLATION ({_ev_status_val}): "
            "The evidence chain has detected integrity violations. "
            "This report may be based on compromised or tampered evidence. "
            "Do NOT distribute this report until an examiner resolves the issues in evidence_chain.issues."
        )
        existing = result.get("integrity_warning", "")
        result["integrity_warning"] = (
            _chain_warning + " | " + existing if existing else _chain_warning
        )
    elif _ev_status_val and _ev_status_val != str(ChainStatus.OK):
        # UNSEALED — evidence not yet registered
        result["evidence_chain_warning"] = (
            "No sealed evidence manifest. Evidence integrity is unverified. "
            "Register and seal evidence in the Examiner Portal before finalizing this report."
        )

    # Verification ledger reconciliation
    case_id = metadata.get("case_id", "")
    if case_id:
        try:
            alerts = reconcile_verification(
                case_id, approved_findings, approved_timeline
            )
            if alerts:
                result["verification_alerts"] = alerts
                has_mismatch = any(
                    a.get("status") == "DESCRIPTION_MISMATCH" for a in alerts
                )
                if has_mismatch:
                    result["integrity_warning"] = (
                        "One or more approved findings have been modified since "
                        "approval. Verify integrity before including in report. "
                        "Mismatched findings may contain unauthorized changes."
                    )
        except Exception as e:
            result["verification_alerts"] = [
                {"alert": "RECONCILIATION_ERROR", "detail": str(e)}
            ]

    return result


def reconcile_verification(
    case_id: str,
    approved_findings: list[dict],
    approved_timeline: list[dict],
) -> list[dict]:
    """Bidirectional check: approved items vs verification ledger.

    No password needed — this checks structural consistency (item counts,
    description text matches) not cryptographic HMAC validity.
    """
    ledger_path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not ledger_path.exists():
        return [{"alert": "NO_VERIFICATION_LEDGER", "detail": "No ledger found"}]

    ledger_entries: list[dict] = []
    try:
        for line in ledger_path.read_text().splitlines():
            if line.strip():
                ledger_entries.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return [{"alert": "LEDGER_READ_ERROR", "detail": "Could not read ledger"}]

    ledger_by_id = {e["finding_id"]: e for e in ledger_entries}
    all_approved = approved_findings + approved_timeline
    items_by_id = {i["id"]: i for i in all_approved}
    all_ids = set(items_by_id) | set(ledger_by_id)

    results: list[dict] = []
    for item_id in sorted(all_ids):
        item = items_by_id.get(item_id)
        entry = ledger_by_id.get(item_id)
        if item and not entry:
            results.append({"id": item_id, "status": "APPROVED_NO_VERIFICATION"})
        elif entry and not item:
            # IOCs and auto-extracted items have ledger entries but no standalone finding
            status = (
                "EXTRACTED_FROM_FINDING"
                if item_id.startswith("IOC-")
                else "VERIFICATION_NO_FINDING"
            )
            results.append({"id": item_id, "status": status})
        elif item and entry:
            # Reconstruct hmac_text: canonical JSON of all substantive fields
            hashable = {k: v for k, v in item.items() if k not in _HASH_EXCLUDE_KEYS}
            live_text = json.dumps(hashable, sort_keys=True, default=str)
            if live_text != entry.get("content_snapshot", ""):
                results.append({"id": item_id, "status": "DESCRIPTION_MISMATCH"})
            else:
                results.append({"id": item_id, "status": "VERIFIED"})

    # Compare counts excluding auto-extracted IOCs (they don't go through approval)
    non_ioc_ledger = [
        e for e in ledger_entries if not e.get("id", "").startswith("IOC-")
    ]
    if len(all_approved) != len(non_ioc_ledger):
        ioc_count = len(ledger_entries) - len(non_ioc_ledger)
        results.append(
            {
                "id": "_summary",
                "status": "COUNT_MISMATCH",
                "detail": (
                    f"approved={len(all_approved)}, "
                    f"ledger={len(non_ioc_ledger)} "
                    f"(+{ioc_count} auto-extracted IOCs excluded)"
                ),
            }
        )
    return results
