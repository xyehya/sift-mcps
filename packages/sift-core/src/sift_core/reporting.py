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
from sift_core.active_case_context import db_authority_active
from sift_core.investigation_store import HASH_EXCLUDE_KEYS, compute_content_hash

# BATCH-NW1: the old narrow _HASH_EXCLUDE_KEYS (15 keys) has been removed.
# HASH_EXCLUDE_KEYS imported from investigation_store is the single authoritative
# 19-key exclude set, shared with compute_content_hash so DB content-hash
# verification (the sole authority after B-MVP-011) covers a stable field set.


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


def _provenance_refs(item: dict) -> list[str]:
    """Extract sanitized provenance identifiers from a finding/timeline item.

    Provenance is a list/dict of source references stamped by ingest/agent
    pipelines. We surface only opaque identifiers (provenance ids, audit ids,
    source-evidence display paths) — never absolute mount/case paths. The caller
    is responsible for keeping any absolute path out of the appendix.
    """
    refs: list[str] = []

    prov = item.get("provenance")
    if isinstance(prov, list):
        for p in prov:
            if isinstance(p, dict):
                pid = p.get("id") or p.get("provenance_id") or p.get("source_id")
                if pid:
                    refs.append(str(pid))
            elif isinstance(p, str) and p.strip():
                refs.append(p.strip())
    elif isinstance(prov, dict):
        pid = prov.get("id") or prov.get("provenance_id") or prov.get("source_id")
        if pid:
            refs.append(str(pid))

    for aid in item.get("audit_ids") or []:
        if aid:
            refs.append(str(aid))

    # source_evidence carries relative display paths/labels only (the broker
    # never writes absolutes here); de-dup against accidental absolute leakage.
    src = item.get("source_evidence")
    if isinstance(src, list):
        for s in src:
            s = str(s)
            if s and not s.startswith("/") and not re.match(r"^[A-Za-z]:[\\/]", s):
                refs.append(s)
    elif isinstance(src, str) and src.strip():
        if not src.startswith("/") and not re.match(r"^[A-Za-z]:[\\/]", src):
            refs.append(src.strip())

    # Stable, de-duplicated order.
    seen: set[str] = set()
    out: list[str] = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def build_custody_appendix(
    approved_findings: list[dict],
    ev_chain: dict,
    custody: dict | None = None,
) -> dict:
    """Assemble the custody / provenance appendix (F-MVP-4).

    Provides the verification material a finalized report must carry:
      - per-finding provenance: finding id, approval content_hash, provenance
        ids, audit ids, and relative source-evidence references;
      - evidence seal/custody status and the per-case hash-chain proof refs
        (manifest version + hash, chain head hash, ledger tip);
      - the operator re-auth event id that authorized inclusion/export (stamped
        in by the portal, not here).

    All values are opaque identifiers, hashes, or relative display labels. No
    absolute case/evidence/mount path is ever emitted here.
    """
    finding_provenance: list[dict] = []
    for f in approved_findings:
        entry: dict = {
            "id": f.get("id", ""),
            "content_hash": f.get("content_hash", ""),
            "approved_by": f.get("approved_by", ""),
            "approved_at": f.get("approved_at", ""),
            "provenance_refs": _provenance_refs(f),
        }
        finding_provenance.append(entry)

    seal = ev_chain.get("status", "")
    proof: dict = {
        "seal_status": seal,
        "manifest_version": ev_chain.get("manifest_version", 0),
        "manifest_hash": ev_chain.get("manifest_hash"),
        "chain_head_hash": ev_chain.get("head_hash"),
        "ledger_tip_hash": ev_chain.get("ledger_tip_hash"),
        "active_count": ev_chain.get("ok_count", ev_chain.get("active_count", 0)),
    }

    appendix: dict = {
        "evidence_seal": proof,
        "finding_provenance": finding_provenance,
        "verification_note": (
            "This appendix lists the approval content hash and provenance/audit "
            "references for each included finding and the evidence seal status at "
            "report generation time. Reconcile these against the case custody "
            "ledger to verify report integrity."
        ),
    }
    if custody is not None:
        # custody is a sanitized summary (event counts / last events) from the
        # DB authority; the portal supplies it. Never contains absolute paths.
        appendix["custody"] = custody
    return appendix


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
    custody: dict | None = None,
    reauth_audit_event_id: str | None = None,
    investigation_inputs: dict | None = None,
) -> dict:
    """Core report generation logic.

    Assembles a structured report dict from approved case data, with evidence
    chain provenance and verification reconciliation. Raises KeyError if the
    profile is unknown (callers validate the profile name first).

    custody / reauth_audit_event_id are supplied by the portal (F-MVP-4): the
    custody summary is folded into the provenance appendix, and the re-auth
    event id is recorded as the authorization that gated report inclusion.

    BATCH-K2: in DB-active mode the portal passes ``investigation_inputs`` =
    ``{"findings": [...], "timeline": [...], "iocs": [...]}`` already filtered to
    APPROVED DB rows. When supplied, findings/timeline come from Postgres
    authority and the case JSON is never consulted for report inclusion, so file
    tampering cannot inject or alter report content.
    """
    profile = PROFILES[profile_name]

    # Load all data. In DB-active mode the approved findings/timeline come from
    # the DB authority inputs, not the (mirror/export) case JSON.
    metadata = load_case_meta(case_dir)
    if investigation_inputs is not None:
        all_findings = list(investigation_inputs.get("findings") or [])
        all_timeline = list(investigation_inputs.get("timeline") or [])
    else:
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

    # Evidence chain status — included in every report for chain-of-custody. In
    # DB-active portal generation, the caller supplies the DB custody summary;
    # prefer that authority over the legacy local manifest mirror.
    ev_chain: dict = {}
    if custody and custody.get("seal_status"):
        active_count = custody.get("active_count", 0)
        ev_chain = {
            "status": str(custody.get("seal_status")),
            "manifest_version": custody.get("manifest_version", 0),
            "ok_count": active_count,
            "active_count": active_count,
            "issues": custody.get("issues", []),
            "manifest_hash": custody.get("manifest_hash"),
            "head_hash": custody.get("head_hash"),
            "ledger_tip_hash": custody.get("ledger_tip_hash"),
        }
    else:
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

    # Filter approved only. This is the single authoritative gate: only items
    # whose status is exactly "APPROVED" reach the report. Unapproved, draft,
    # proposed, or rejected items are dropped here and never re-introduced
    # downstream (F-MVP-4 / AGENTS.md security invariant: reports include
    # approved findings and approved supporting data only).
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
    _ev_status_val = str(ev_chain.get("status", ""))
    _VIOLATION_STATUSES = {
        str(ChainStatus.MODIFIED),
        ChainStatus.MODIFIED.value,
        str(ChainStatus.MISSING),
        ChainStatus.MISSING.value,
        str(ChainStatus.UNREGISTERED),
        ChainStatus.UNREGISTERED.value,
        str(ChainStatus.LEDGER_ERROR),
        ChainStatus.LEDGER_ERROR.value,
    }
    _OK_STATUSES = {str(ChainStatus.OK), ChainStatus.OK.value, "sealed"}
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
    elif _ev_status_val and _ev_status_val not in _OK_STATUSES:
        # UNSEALED — evidence not yet registered
        result["evidence_chain_warning"] = (
            "No sealed evidence manifest. Evidence integrity is unverified. "
            "Register and seal evidence in the Examiner Portal before finalizing this report."
        )

    # Verification reconciliation. B-MVP-011: the per-row DB ``content_hash``
    # recorded at approval (BATCH-K2) is now the ONLY verification authority — so
    # report integrity cannot be spoofed by tampering, deleting, or staling a
    # local file. The legacy file-mode HMAC ledger path has been retired; when the
    # DB control plane is unavailable, reconciliation reports that cleanly rather
    # than falling back to a file ledger.
    _db_mode = investigation_inputs is not None or db_authority_active()
    if _db_mode:
        result["verification_authority"] = "db-content-hash"
        try:
            alerts = reconcile_verification_db(approved_findings, approved_timeline)
        except Exception as e:
            alerts = [{"alert": "RECONCILIATION_ERROR", "detail": str(e)}]
        if alerts:
            result["verification_alerts"] = alerts
            has_mismatch = any(
                a.get("status") == "DESCRIPTION_MISMATCH" for a in alerts
            )
            if has_mismatch:
                result["integrity_warning"] = (
                    "One or more approved findings no longer match the content hash "
                    "recorded in the database at approval. Verify integrity before "
                    "including in report. Mismatched findings may contain "
                    "unauthorized changes."
                )
    else:
        # No DB control plane: verification authority is unavailable. The retired
        # file ledger is no longer consulted.
        result["verification_authority"] = "unavailable"
        result["verification_alerts"] = [
            {
                "alert": "VERIFICATION_UNAVAILABLE",
                "detail": (
                    "DB content-hash verification authority is not active and the "
                    "legacy file-ledger plane has been retired (B-MVP-011). "
                    "Finalize reports with the Supabase control plane configured."
                ),
            }
        ]

    # Custody / provenance appendix (F-MVP-4). Built from the full approved
    # findings (with provenance/content_hash/audit ids intact) BEFORE they were
    # stripped for the body, so each included finding carries verification
    # material. Bodies stay clean; the appendix carries the proof references.
    result["custody_appendix"] = build_custody_appendix(
        approved_findings, ev_chain, custody=custody
    )

    # Record the operator re-auth that authorized report inclusion/export, so the
    # generated artifact carries its own authorization provenance (F-MVP-4).
    if reauth_audit_event_id:
        result["reauth_audit_event_id"] = str(reauth_audit_event_id)
        result["custody_appendix"]["authorized_by_reauth_event"] = str(
            reauth_audit_event_id
        )

    return result


def reconcile_verification_db(
    approved_findings: list[dict],
    approved_timeline: list[dict],
) -> list[dict]:
    """DB-authority verification: compare each approved item's live content
    against the ``content_hash`` recorded in Postgres at approval (BATCH-K2/K6).

    Unlike :func:`reconcile_verification`, this reads no local file: the items
    carry their authoritative DB ``content_hash`` (the portal sources them from
    ``PostgresInvestigationStore.report_inputs``). Recomputing the hash with the
    same canonicalisation the store uses (:func:`compute_content_hash`) detects
    any post-approval mutation of the row's substantive content. Tampering with,
    deleting, or staling the legacy verification JSONL ledger has no effect on
    this result.
    """
    results: list[dict] = []
    for item in approved_findings + approved_timeline:
        item_id = item.get("id", "")
        stored = item.get("content_hash") or ""
        if not stored:
            results.append({"id": item_id, "status": "APPROVED_NO_DB_HASH"})
            continue
        live = compute_content_hash(item)
        if live != stored:
            results.append({"id": item_id, "status": "DESCRIPTION_MISMATCH"})
        else:
            results.append({"id": item_id, "status": "VERIFIED"})
    return results


# B-MVP-011: ``reconcile_verification`` (the file-mode HMAC ledger reconciliation)
# has been retired. DB ``content_hash`` (``reconcile_verification_db`` above) is now
# the sole verification authority. The verification JSONL ledger is no longer read
# for report integrity.
