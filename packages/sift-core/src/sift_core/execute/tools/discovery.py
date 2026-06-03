"""Tool discovery: list tools, suggest tools, check availability."""

from __future__ import annotations

import itertools
import logging

logger = logging.getLogger(__name__)
from forensic_knowledge import loader

from sift_core.execute.catalog import get_tool_def, list_tools_in_catalog
from sift_core.execute.environment import find_binary
from sift_core.execute.response import DISCIPLINE_REMINDERS

# Alias mapping — common artifact names to FK artifact YAML names
ARTIFACT_ALIASES: dict[str, list[str]] = {
    "evtx": [
        "event_logs_security",
        "event_logs_system",
        "event_logs_sysmon",
        "event_logs_powershell",
    ],
    "evt": ["event_logs_security", "event_logs_system"],
    "event_log": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "event_logs": ["event_logs_security", "event_logs_system", "event_logs_sysmon"],
    "registry": ["registry_run_keys", "registry_services", "shellbags", "shimcache"],
    "mft": ["mft"],
    "prefetch": ["prefetch"],
    "usn": ["usn_journal"],
    "userassist": ["userassist"],
    "amcache": ["amcache"],
}

_suggest_counter = itertools.count(1)


def _normalize_artifact_key(value: str) -> str:
    """Lowercase and collapse non-alphanumeric runs to single spaces.

    Makes 'Security Event Log', 'security_event_log', and 'Security  Event-Log'
    all comparable. Used to match user input against artifact ids and names.
    """
    out: list[str] = []
    prev_sep = False
    for ch in value.strip().lower():
        if ch.isalnum():
            out.append(ch)
            prev_sep = False
        elif not prev_sep:
            out.append(" ")
            prev_sep = True
    return "".join(out).strip()


_ARTIFACT_INDEX: dict[str, str] | None = None


def _artifact_index() -> dict[str, str]:
    """Build (and cache) a normalized-key -> artifact id lookup.

    Indexes each artifact by its canonical id (file stem), its display name,
    and any declared aliases, so that whatever identifier suggest_tools
    advertises in available_artifacts can be passed straight back in.
    """
    global _ARTIFACT_INDEX
    if _ARTIFACT_INDEX is not None:
        return _ARTIFACT_INDEX
    index: dict[str, str] = {}
    try:
        catalog = loader.artifact_catalog()
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("artifact_catalog failed: %s", e)
        catalog = []
    for entry in catalog:
        art_id = entry.get("id", "")
        if not art_id:
            continue
        keys = [art_id, entry.get("name", ""), *entry.get("aliases", [])]
        for key in keys:
            norm = _normalize_artifact_key(str(key))
            if norm:
                index.setdefault(norm, art_id)
    _ARTIFACT_INDEX = index
    return index


def _resolve_artifact_ids(artifact_type: str) -> list[str]:
    """Resolve a user-supplied artifact_type to FK artifact ids.

    Resolution order: multi-target alias map -> exact normalized match against
    id/name/alias -> token-subset match. Returns [] when nothing matches.
    """
    raw = (artifact_type or "").strip()
    if not raw:
        return []
    # 1. Multi-target alias map (e.g. "evtx" -> several event-log artifacts).
    alias_hit = ARTIFACT_ALIASES.get(raw.lower())
    if alias_hit:
        return list(alias_hit)
    index = _artifact_index()
    norm = _normalize_artifact_key(raw)
    if not norm:
        return []
    # 2. Exact normalized match.
    if norm in index:
        return [index[norm]]
    # 3. Token-subset: every input token appears in a candidate key (and the
    #    candidate is not absurdly broader). Conservative, deterministic.
    input_tokens = set(norm.split())
    matches: list[str] = []
    for key, art_id in index.items():
        key_tokens = set(key.split())
        if input_tokens and input_tokens.issubset(key_tokens):
            if art_id not in matches:
                matches.append(art_id)
    return matches

# Layer 7b: SIFT limitations where wintools-mcp produces better results
_SIFT_LIMITATIONS: dict[str, str] = {
    "srum": (
        "SRUM parsing on SIFT uses Plaso (limited dirty-database handling). "
        "For reliable SRUM analysis, provision wintools-mcp with SrumECmd."
    ),
    "prefetch": (
        "Prefetch parsing on SIFT uses Plaso (misses execution counts, loaded DLLs). "
        "For complete prefetch analysis, provision wintools-mcp with PECmd."
    ),
    "registry": (
        "Registry parsing on SIFT has limited transaction log recovery. "
        "For dirty hives from KAPE live collection, provision wintools-mcp with RECmd."
    ),
    "digital_signatures": (
        "SIFT cannot verify Authenticode signatures. "
        "For signature verification, provision wintools-mcp with sigcheck."
    ),
}


def _wintools_available() -> bool:
    """Check if wintools-mcp is configured in gateway.yaml."""
    try:
        from pathlib import Path

        import yaml

        gw = yaml.safe_load((Path.home() / ".sift" / "gateway.yaml").read_text()) or {}
        return "wintools-mcp" in gw.get("backends", {})
    except Exception:
        return False


def list_available_tools(category: str | None = None) -> list[dict]:
    """List cataloged tools with availability and FK enrichment status.

    Note: tools not in the catalog can also be executed via run_command.
    Cataloged tools get enriched responses (caveats, corroboration, field meanings).
    """
    tools = list_tools_in_catalog(category=category)
    results = []
    for t in tools:
        td = get_tool_def(t["name"])
        available = find_binary(td.binary) is not None if td else False
        entry = {**t, "available": available, "enriched": True}
        if td and available:
            entry["binary_path"] = find_binary(td.binary)
        results.append(entry)
    return results


def get_tool_help(tool_name: str) -> dict:
    """Get usage information for a specific tool."""
    if tool_name == "run_command":
        return {
            "name": "run_command",
            "description": "Execute a validated command plan as the low-privilege native runtime user. No shell wrapper is used; parsed argv stages are launched with shell=False.",
            "policy": {
                "blocked_constructs": [
                    "agent-supplied sudo",
                    "nested shells/interpreters such as sh, bash, python, perl, ruby, node",
                    "background operator '&'",
                    "heredocs and exotic file-descriptor duplication",
                    "writes, deletes, or metadata changes under evidence/ or integrity-record directories",
                    "awk system(), getline, and pipe constructs",
                ],
                "safe_alternatives": [
                    "Use a single command string for pipelines: fls evidence/disk.E01 | grep Users",
                    "Write analysis outputs under agent/, extractions/, or tmp/",
                    "Use '< input-file' instead of heredocs",
                    "Use '2>&1', '2> agent/file.err', or '>/dev/null' for stderr control",
                ],
                "path_restrictions": "Outputs must be under the active case agent/, extractions/, or tmp/ directories. Evidence and integrity records are read-only to the runtime user and write-blocked by policy."
            }
        }
    td = get_tool_def(tool_name)
    if not td:
        return {"error": f"Tool '{tool_name}' not in catalog. You can still run it, but run_command security policies apply."}

    available = find_binary(td.binary) is not None
    result = {
        "name": td.name,
        "binary": td.binary,
        "category": td.category,
        "description": td.description,
        "input_style": td.input_style,
        "input_flag": td.input_flag,
        "output_format": td.output_format,
        "timeout_seconds": td.timeout_seconds,
        "common_flags": td.common_flags,
        "available": available,
    }
    # This help reflects the catalog + curated forensic-knowledge entry, which
    # may not cover every flag. For the tool's own complete CLI reference, run it
    # with its help flag via run_command (e.g. run_command(['EvtxECmd','--help'])).
    if available:
        result["usage_hint"] = (
            f"For the full CLI reference run: run_command(['{td.binary}', '--help']) "
            f"(or '-h'). This card shows curated catalog + forensic-knowledge notes."
        )

    # Add FK knowledge
    try:
        fk = loader.get_tool(td.knowledge_name)
    except Exception as e:
        logger.debug("FK lookup failed for %s: %s", td.knowledge_name, e)
        fk = None
    if fk:
        result["caveats"] = fk.get("caveats", [])
        result["advisories"] = fk.get("advisories", [])
        result["artifacts_parsed"] = fk.get("artifacts_parsed", [])
        if fk.get("quick_start"):
            result["quick_start"] = fk["quick_start"]
        if fk.get("investigation_sequence"):
            result["investigation_sequence"] = fk["investigation_sequence"]
        if fk.get("field_meanings"):
            result["field_meanings"] = fk["field_meanings"]

    return result


def check_tools(tool_names: list[str] | None = None) -> dict:
    """Check availability of tools on the system."""
    if tool_names:
        results = {}
        for name in tool_names:
            td = get_tool_def(name)
            if td:
                path = find_binary(td.binary)
                results[name] = {"available": path is not None, "binary_path": path}
            else:
                results[name] = {
                    "available": False,
                    "note": "not in catalog — can execute but without FK enrichment",
                }
        return results

    # Check all
    tools = list_tools_in_catalog()
    results = {}
    for t in tools:
        td = get_tool_def(t["name"])
        if td:
            path = find_binary(td.binary)
            results[t["name"]] = {"available": path is not None, "binary_path": path}
    return results


def suggest_tools(artifact_type: str, question: str = "") -> dict:
    """Suggest tools based on artifact type, using FK knowledge.

    Returns an enriched envelope with suggestions, advisories, corroboration,
    cross-MCP checks, and discipline reminders.
    """
    # Resolve the requested artifact (display name, file-stem id, or alias) to
    # one or more canonical FK artifact ids that get_artifact() accepts.
    artifact_names = _resolve_artifact_ids(artifact_type)

    suggestions: list[dict] = []
    all_advisories: list[str] = []
    all_corroboration: dict[str, list[str]] = {}
    all_cross_mcp: list[dict] = []

    # Layer 7b: add SIFT limitation advisories when wintools unavailable
    if not _wintools_available():
        for art_name in artifact_names:
            if art_name in _SIFT_LIMITATIONS:
                all_advisories.append(_SIFT_LIMITATIONS[art_name])

    for art_name in artifact_names:
        try:
            artifact = loader.get_artifact(art_name)
        except Exception as e:
            logger.debug("FK artifact lookup failed for %s: %s", art_name, e)
            continue
        if not artifact:
            continue

        for tool_name in artifact.get("related_tools", []):
            # Avoid duplicates across aliases
            if any(s.get("tool") == tool_name for s in suggestions):
                continue
            td = get_tool_def(tool_name)
            try:
                fk = loader.get_tool(tool_name)
            except Exception as e:
                logger.debug("FK tool lookup failed for %s: %s", tool_name, e)
                fk = None
            entry = {
                "tool": tool_name,
                "artifact": art_name,
                "available": find_binary(td.binary) is not None if td else False,
                "description": fk.get("description", "") if fk else "",
                "what_it_reveals": artifact.get("proves", []),
                "what_it_does_not_reveal": artifact.get("does_not_prove", []),
            }
            suggestions.append(entry)

        # Advisories from does_not_prove
        for item in artifact.get("does_not_prove", []):
            advisory = f"This artifact does NOT prove: {item}"
            if advisory not in all_advisories:
                all_advisories.append(advisory)

        # Corroboration map
        for key, val in artifact.get("corroborate_with", {}).items():
            if key not in all_corroboration:
                all_corroboration[key] = []
            for ref in val:
                if ref not in all_corroboration[key]:
                    all_corroboration[key].append(ref)

        # Cross-MCP checks
        for check in artifact.get("cross_mcp_checks", []):
            if check not in all_cross_mcp:
                all_cross_mcp.append(check)

    if not suggestions:
        try:
            available = [
                {"id": a["id"], "name": a["name"]}
                for a in loader.artifact_catalog()
            ]
        except Exception as e:
            logger.debug("FK artifact_catalog failed: %s", e)
            available = []
        return {
            "suggestions": [],
            "info": (
                f"No artifact matched '{artifact_type}'. Pass either the 'id' or "
                "'name' of an entry in available_artifacts."
            ),
            "available_artifacts": available,
        }

    call_num = next(_suggest_counter)
    return {
        "suggestions": suggestions,
        "advisories": all_advisories,
        "corroboration": all_corroboration,
        "cross_mcp_checks": all_cross_mcp,
        "discipline_reminder": DISCIPLINE_REMINDERS[
            call_num % len(DISCIPLINE_REMINDERS)
        ],
    }
