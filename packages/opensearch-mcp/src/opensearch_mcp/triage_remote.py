"""Post-ingest triage enrichment — batch gateway calls + registry persistence rules.

Gateway-dependent: wintriage_check_artifact/wintriage_check_system via windows-triage-mcp.
Gateway-independent: registry persistence R1-R17 via update_by_query.
"""

from __future__ import annotations

import logging
import sys

from opensearchpy import OpenSearch

from opensearch_mcp.gateway import call_tool, gateway_available, wait_for_gateway
from opensearch_mcp.paths import sanitize_index_component

logger = logging.getLogger(__name__)


def _escape_wildcard(value: str) -> str:
    """Escape wildcard characters in OpenSearch query values."""
    return value.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


_MAX_CONSECUTIVE_FAILURES = 3


def _degraded_result(reason: str, checked: int = 0, enriched: int = 0) -> dict:
    return {
        "status": "degraded",
        "reason": reason,
        "checked": checked,
        "enriched": enriched,
    }


def _triage_degraded(verdict: dict) -> str | None:
    if verdict.get("status") == "degraded":
        reasons = verdict.get("reasons") or []
        if reasons:
            return "; ".join(str(reason) for reason in reasons)
        return "windows-triage backend returned degraded status"
    if verdict.get("db_available") is False:
        return "windows-triage baseline database is not installed"
    return None


def _check_file(path: str) -> dict:
    return call_tool("wintriage_check_artifact", {"type": "file", "value": path}, timeout=15)


def _check_service(service_name: str, binary_path: str | None = None) -> dict:
    args = {"type": "service", "name": service_name}
    if binary_path:
        args["binary_path"] = binary_path
    return call_tool("wintriage_check_system", args, timeout=15)


def enrich_remote(
    client: OpenSearch,
    case_id: str,
    on_progress=None,
) -> dict:
    """Run batch triage enrichment against indexed data.

    Returns dict with counts per artifact type.
    """
    if not wait_for_gateway(timeout=60):
        return {
            "_gateway": "Gateway not reachable after 60s — enrichment skipped. "
            "Run opensearch_enrich_triage() once gateway is ready.",
            "status": "degraded",
        }

    safe_case = sanitize_index_component(case_id)

    # Refresh indices so aggregations see all recently ingested docs
    try:
        client.indices.refresh(index=f"case-{safe_case}-*")
    except Exception:
        pass

    results: dict = {}

    # --- Gateway-independent: registry persistence R1-R14, R16 ---
    results["registry_persistence"] = _enrich_registry_persistence(client, safe_case, on_progress)

    # --- Gateway-independent: Hayabusa ↔ memory correlation ---
    results["hayabusa_memory"] = _enrich_hayabusa_memory_correlation(client, safe_case, on_progress)

    # --- Gateway-dependent: file + service enrichment ---
    if not gateway_available():
        results["_gateway"] = "not configured — file/service enrichment skipped"
        return results

    # No health pre-check — the first check_file call serves as the
    # availability test. Circuit breaker (3 failures) handles backend down.
    # Removed hardcoded windows-triage-mcp__get_health: the collision-prefixed
    # name only exists when BOTH windows-triage-mcp AND opencti-mcp are
    # registered. In single-backend configs, bare get_health is the name.

    # File enrichment (check_file)
    # Fields with .keyword: dynamically mapped text fields (no explicit template mapping).
    # Fields without: explicitly mapped as keyword in their template.
    # Vol3 pslist/pstree/psscan excluded: ImageFileName is a bare 14-char name
    # (no path) — check_file gives wrong is_system_path, all system procs → SUSPICIOUS.
    # Vol3 dlllist uses Path (full Windows path), not Name (bare DLL name).
    for name, suffix, field, query in [
        ("shimcache", "shimcache", "Path.keyword", "*"),
        ("amcache", "amcache", "FullPath.keyword", "*"),
        ("evtx_proc", "evtx", "process.name", "event.code:(4688 OR 1)"),
        ("tasks", "tasks", "task.command", "*"),
        ("vol_dlls", "vol-dlllist", "Path.keyword", "*"),
    ]:
        results[name] = _enrich_file_artifact(
            client,
            safe_case,
            index_pattern=f"case-{safe_case}-{suffix}-*",
            path_field=field,
            artifact_name=name,
            query=query,
            on_progress=on_progress,
        )

    # Service enrichment (check_service)
    results["evtx_svc"] = _enrich_evtx_services(client, safe_case, on_progress)
    results["vol_svcs"] = _enrich_service_artifact(
        client,
        safe_case,
        index_pattern=f"case-{safe_case}-vol-svcscan-*",
        name_field="Name.keyword",
        artifact_name="vol_svcs",
        on_progress=on_progress,
    )
    results["registry_svcs"] = _enrich_registry_services(client, safe_case, on_progress)

    # Registry Run keys (check_file on ValueData)
    results["registry_run"] = _enrich_registry_run_keys(client, safe_case, on_progress)

    # R15: Active Setup StubPath (check_file)
    results["registry_activestub"] = _enrich_registry_check_file(
        client,
        safe_case,
        query_body={"wildcard": {"KeyPath.keyword": "*Active Setup\\\\Installed Components*"}},
        value_field="StubPath",
        artifact_name="registry_activestub",
        on_progress=on_progress,
    )

    # R17: NetSh Helper DLLs (check_file)
    results["registry_netsh"] = _enrich_registry_check_file(
        client,
        safe_case,
        query_body={
            "bool": {
                "should": [
                    {"wildcard": {"KeyPath.keyword": "*\\\\NetSh*"}},
                    {"wildcard": {"KeyPath.keyword": "*\\\\NetSh\\\\*"}},
                ],
                "minimum_should_match": 1,
            }
        },
        value_field="ValueData",
        artifact_name="registry_netsh",
        on_progress=on_progress,
        dll_filter=True,
    )

    return results


# ---------------------------------------------------------------------------
# File enrichment (check_file)
# ---------------------------------------------------------------------------


def _enrich_file_artifact(
    client: OpenSearch,
    safe_case: str,
    index_pattern: str,
    path_field: str,
    artifact_name: str,
    query: str = "*",
    on_progress=None,
) -> dict:
    """Enrich file-based artifacts in batch via check_file."""
    try:
        agg_result = client.search(
            index=index_pattern,
            body={
                "query": {"query_string": {"query": query}},
                "aggs": {"paths": {"terms": {"field": path_field, "size": 5000}}},
                "size": 0,
            },
        )
    except Exception as e:
        from opensearchpy.exceptions import NotFoundError

        if isinstance(e, NotFoundError):
            return {"status": "skipped", "reason": "index not found"}
        print(
            f"  WARNING: {artifact_name} aggregation failed: {e}",
            file=sys.stderr,
        )
        return {"status": "skipped", "reason": str(e)}

    buckets = agg_result.get("aggregations", {}).get("paths", {}).get("buckets", [])
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(buckets))

    verdicts: dict = {}
    consecutive_failures = 0
    degraded_reason = ""
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            print(
                f"  WARNING: {consecutive_failures} consecutive gateway failures "
                f"— stopping {artifact_name}",
                file=sys.stderr,
            )
            break
        path = bucket["key"]
        # Skip non-path entries (AppX metadata, hex strings, empty)
        if not path or not (path[0] in ("\\", "/") or (len(path) > 1 and path[1] == ":")):
            continue
        try:
            result = _check_file(path)
            consecutive_failures = 0
            degraded_reason = _triage_degraded(result) or ""
            if degraded_reason:
                break
            if result.get("verdict"):
                verdicts[path] = result
        except Exception:
            consecutive_failures += 1
            continue

    if degraded_reason:
        return _degraded_result(degraded_reason, checked=len(buckets))
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES and not verdicts:
        return _degraded_result(
            "windows-triage backend unavailable after consecutive failures",
            checked=len(buckets),
        )
    if not verdicts:
        return {"status": "complete", "checked": len(buckets), "enriched": 0}

    enriched = _batch_stamp_verdicts(client, index_pattern, path_field, verdicts)

    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=len(buckets),
            enriched=enriched,
        )

    return {"status": "complete", "checked": len(buckets), "enriched": enriched}


def _batch_stamp_verdicts(
    client: OpenSearch,
    index_pattern: str,
    path_field: str,
    verdicts: dict,
) -> int:
    """Batch-stamp verdicts by grouping paths with identical verdicts.

    Groups paths by (verdict, confidence, is_lolbin) and issues
    update_by_query per group using terms queries. Chunks to 500 paths
    per batch to avoid timeouts on large cases.
    """
    from collections import defaultdict

    # Group paths by stamp key: (verdict, confidence, lolbin)
    groups: dict[tuple, dict] = defaultdict(lambda: {"paths": [], "reasons": []})
    for path, result in verdicts.items():
        verdict_str = result.get("verdict", "UNKNOWN")
        confidence = result.get("confidence", "low")
        is_lolbin = bool(result.get("is_lolbin"))
        key = (verdict_str, confidence, is_lolbin)
        groups[key]["paths"].append(path)
        reasons = result.get("reasons", [])
        if reasons:
            groups[key]["reasons"].append("; ".join(reasons))

    total_updated = 0
    for (verdict_str, confidence, is_lolbin), group in groups.items():
        script_lines = [
            "ctx._source['triage.verdict'] = params.verdict",
            "ctx._source['triage.checked'] = true",
            "ctx._source['triage.confidence'] = params.confidence",
        ]
        params: dict = {"verdict": verdict_str, "confidence": confidence}
        if is_lolbin:
            script_lines.append("ctx._source['triage.lolbin'] = true")

        # For batched paths, stamp a generic reason (individual reasons
        # vary per path but the verdict is the same for all in this group)
        unique_reasons = sorted(set(group["reasons"]))
        if len(unique_reasons) == 1:
            script_lines.append("ctx._source['triage.reason'] = params.reason")
            params["reason"] = unique_reasons[0]
        elif unique_reasons:
            # Multiple distinct reasons in same verdict group — use per-doc
            # reason from a lookup map in params
            script_lines.append(
                "String p = ctx._source.getOrDefault(params.path_field, ''); "
                "if (params.reason_map.containsKey(p)) { "
                "ctx._source['triage.reason'] = params.reason_map.get(p); }"
            )
            params["path_field"] = path_field.replace(".keyword", "")
            params["reason_map"] = {
                p: "; ".join(verdicts[p].get("reasons", []))
                for p in group["paths"]
                if verdicts[p].get("reasons")
            }

        # Chunk paths to avoid timeouts on large cases
        all_paths = group["paths"]
        for i in range(0, len(all_paths), 500):
            chunk = all_paths[i : i + 500]
            chunk_params = dict(params)
            if "reason_map" in chunk_params:
                chunk_params["reason_map"] = {
                    p: params["reason_map"][p] for p in chunk if p in params["reason_map"]
                }
            try:
                resp = client.update_by_query(
                    index=index_pattern,
                    body={
                        "query": {"terms": {path_field: chunk}},
                        "script": {
                            "source": "; ".join(script_lines),
                            "lang": "painless",
                            "params": chunk_params,
                        },
                    },
                    conflicts="proceed",
                    requests_per_second=1000,
                )
                total_updated += resp.get("updated", 0)
            except Exception as e:
                print(
                    f"  WARNING: batch update_by_query failed for {verdict_str}: {e}",
                    file=sys.stderr,
                )

    return total_updated


# ---------------------------------------------------------------------------
# Service enrichment (check_service)
# ---------------------------------------------------------------------------


def _enrich_evtx_services(client, safe_case, on_progress=None):
    """Enrich evtx 7045 service install events via check_service."""
    index = f"case-{safe_case}-evtx-*"
    try:
        # No _source filter — "winlog.event_data" is a literal dotted key
        # (normalize.py:128), not a nested path. _source filtering treats
        # dots as path separators and would miss it.
        result = client.search(
            index=index,
            body={"query": {"term": {"event.code": 7045}}, "size": 5000},
        )
    except Exception:
        return {"status": "skipped"}

    hits = result["hits"]["hits"]
    if not hits:
        return {"status": "empty", "checked": 0}

    service_names = set()
    for h in hits:
        ed = h["_source"].get("winlog.event_data", {})
        if isinstance(ed, dict) and ed.get("ServiceName"):
            service_names.add(ed["ServiceName"])

    if on_progress:
        on_progress("triage_start", artifact="evtx_svc", unique_values=len(service_names))

    enriched = 0
    consecutive_failures = 0
    degraded_reason = ""
    for name in service_names:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        try:
            verdict = _check_service(name)
            consecutive_failures = 0
            degraded_reason = _triage_degraded(verdict) or ""
            if degraded_reason:
                break
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = client.update_by_query(
                index=index,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"event.code": 7045}},
                                {"term": {"winlog.event_data.ServiceName": name}},
                            ]
                        }
                    },
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            enriched += resp.get("updated", 0)
        except Exception:
            consecutive_failures += 1

    if degraded_reason:
        return _degraded_result(degraded_reason, checked=len(service_names), enriched=enriched)
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES and enriched == 0:
        return _degraded_result(
            "windows-triage backend unavailable after consecutive failures",
            checked=len(service_names),
        )
    if on_progress:
        on_progress(
            "triage_done",
            artifact="evtx_svc",
            checked=len(service_names),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(service_names), "enriched": enriched}


def _enrich_service_artifact(
    client, safe_case, index_pattern, name_field, artifact_name, on_progress=None
):
    """Enrich service-based artifacts (vol3 svcscan, registry Services)."""
    try:
        agg_result = client.search(
            index=index_pattern,
            body={
                "query": {"match_all": {}},
                "aggs": {"names": {"terms": {"field": name_field, "size": 5000}}},
                "size": 0,
            },
        )
    except Exception:
        return {"status": "skipped"}

    buckets = agg_result.get("aggregations", {}).get("names", {}).get("buckets", [])
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(buckets))

    enriched = 0
    consecutive_failures = 0
    degraded_reason = ""
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        name = bucket["key"]
        try:
            verdict = _check_service(name)
            consecutive_failures = 0
            degraded_reason = _triage_degraded(verdict) or ""
            if degraded_reason:
                break
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = client.update_by_query(
                index=index_pattern,
                body={
                    "query": {"term": {name_field: name}},
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            enriched += resp.get("updated", 0)
        except Exception:
            consecutive_failures += 1

    if degraded_reason:
        return _degraded_result(degraded_reason, checked=len(buckets), enriched=enriched)
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES and enriched == 0:
        return _degraded_result(
            "windows-triage backend unavailable after consecutive failures",
            checked=len(buckets),
        )
    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=len(buckets),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(buckets), "enriched": enriched}


def _enrich_registry_services(client, safe_case, on_progress=None):
    """Enrich registry Services key entries via check_service."""
    index = f"case-{safe_case}-registry-*"
    # Services keys: KeyPath ends with \Services\{ServiceName},
    # need to extract service names from KeyPath, not ValueName.
    # Use a scroll/search instead to extract unique last path components.
    try:
        result = client.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*\\\\Services\\\\*"}},
                            {"term": {"ValueName.keyword": "ImagePath"}},
                        ]
                    }
                },
                "size": 5000,
            },
        )
    except Exception:
        return {"status": "skipped"}

    hits = result["hits"]["hits"]
    if not hits:
        return {"status": "empty", "checked": 0}

    # Extract unique service names from KeyPath
    services: dict = {}  # service_name -> image_path
    for h in hits:
        src = h["_source"]
        key_path = src.get("KeyPath", "")
        # KeyPath: ...\Services\ServiceName
        parts = key_path.replace("/", "\\").rsplit("\\", 1)
        if len(parts) > 1:
            svc_name = parts[-1]
            services[svc_name] = src.get("ValueData", "")

    if on_progress:
        on_progress("triage_start", artifact="registry_svcs", unique_values=len(services))

    enriched = 0
    consecutive_failures = 0
    degraded_reason = ""
    for svc_name in services:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        try:
            verdict = _check_service(svc_name)
            consecutive_failures = 0
            degraded_reason = _triage_degraded(verdict) or ""
            if degraded_reason:
                break
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = client.update_by_query(
                index=index,
                body={
                    "query": {
                        "wildcard": {
                            "KeyPath.keyword": f"*\\\\Services\\\\{_escape_wildcard(svc_name)}*"
                        }
                    },
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            enriched += resp.get("updated", 0)
        except Exception:
            consecutive_failures += 1

    if degraded_reason:
        return _degraded_result(degraded_reason, checked=len(services), enriched=enriched)
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES and enriched == 0:
        return _degraded_result(
            "windows-triage backend unavailable after consecutive failures",
            checked=len(services),
        )
    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_svcs",
            checked=len(services),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(services), "enriched": enriched}


# ---------------------------------------------------------------------------
# Registry Run keys (check_file on ValueData)
# ---------------------------------------------------------------------------


def _enrich_registry_run_keys(client, safe_case, on_progress=None):
    """Enrich registry Run key entries with check_file."""
    index = f"case-{safe_case}-registry-*"
    try:
        result = client.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"KeyPath.keyword": "*\\\\Run\\\\*"}},
                            {"wildcard": {"KeyPath.keyword": "*\\\\Run"}},
                        ],
                        "minimum_should_match": 1,
                        "filter": [{"exists": {"field": "ValueData"}}],
                    }
                },
                "size": 0,
                "aggs": {"values": {"terms": {"field": "ValueData.keyword", "size": 5000}}},
            },
        )
    except Exception:
        return {"status": "skipped"}

    buckets = result.get("aggregations", {}).get("values", {}).get("buckets", [])
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact="registry_run", unique_values=len(buckets))

    enriched = 0
    consecutive_failures = 0
    degraded_reason = ""
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        value_data = bucket["key"]
        if not value_data.strip():
            continue
        try:
            verdict = _check_file(value_data)
            consecutive_failures = 0
            degraded_reason = _triage_degraded(verdict) or ""
            if degraded_reason:
                break
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
                "ctx._source['triage.confidence'] = params.confidence",
            ]
            params: dict = {
                "verdict": verdict["verdict"],
                "confidence": verdict.get("confidence", "low"),
            }
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            if verdict.get("is_lolbin"):
                script_lines.append("ctx._source['triage.lolbin'] = true")
            try:
                resp = client.update_by_query(
                    index=index,
                    body={
                        "query": {"term": {"ValueData.keyword": value_data}},
                        "script": {
                            "source": "; ".join(script_lines),
                            "lang": "painless",
                            "params": params,
                        },
                    },
                    conflicts="proceed",
                    requests_per_second=1000,
                )
                enriched += resp.get("updated", 0)
            except Exception as e:
                print(
                    f"  WARNING: update_by_query failed for Run key: {e}",
                    file=sys.stderr,
                )
        except Exception:
            consecutive_failures += 1

    if degraded_reason:
        return _degraded_result(degraded_reason, checked=len(buckets), enriched=enriched)
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES and enriched == 0:
        return _degraded_result(
            "windows-triage backend unavailable after consecutive failures",
            checked=len(buckets),
        )
    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_run",
            checked=len(buckets),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(buckets), "enriched": enriched}


# ---------------------------------------------------------------------------
def _enrich_registry_check_file(
    client,
    safe_case,
    query_body,
    value_field,
    artifact_name,
    on_progress=None,
    dll_filter=False,
):
    """Enrich registry entries by calling check_file on a value field.

    Used for R15 (Active Setup StubPath) and R17 (NetSh helper DLLs).
    """
    index = f"case-{safe_case}-registry-*"
    try:
        result = client.search(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [query_body, {"exists": {"field": value_field}}],
                    }
                },
                "size": 0,
                "aggs": {"values": {"terms": {"field": f"{value_field}.keyword", "size": 5000}}},
            },
        )
    except Exception:
        return {"status": "skipped"}

    buckets = result.get("aggregations", {}).get("values", {}).get("buckets", [])
    if not buckets:
        return {"status": "empty", "checked": 0}

    if on_progress:
        on_progress("triage_start", artifact=artifact_name, unique_values=len(buckets))

    enriched = 0
    consecutive_failures = 0
    degraded_reason = ""
    for bucket in buckets:
        if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
            break
        value = bucket["key"]
        if not value.strip():
            continue
        if dll_filter and not value.lower().endswith(".dll"):
            continue
        try:
            verdict = _check_file(value)
            consecutive_failures = 0
            degraded_reason = _triage_degraded(verdict) or ""
            if degraded_reason:
                break
            if not verdict.get("verdict"):
                continue
            reasons = verdict.get("reasons", [])
            script_lines = [
                "ctx._source['triage.verdict'] = params.verdict",
                "ctx._source['triage.checked'] = true",
            ]
            params: dict = {"verdict": verdict["verdict"]}
            if reasons:
                script_lines.append("ctx._source['triage.reason'] = params.reason")
                params["reason"] = "; ".join(reasons)
            resp = client.update_by_query(
                index=index,
                body={
                    "query": {"term": {f"{value_field}.keyword": value}},
                    "script": {
                        "source": "; ".join(script_lines),
                        "lang": "painless",
                        "params": params,
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            enriched += resp.get("updated", 0)
        except Exception:
            consecutive_failures += 1

    if degraded_reason:
        return _degraded_result(degraded_reason, checked=len(buckets), enriched=enriched)
    if consecutive_failures >= _MAX_CONSECUTIVE_FAILURES and enriched == 0:
        return _degraded_result(
            "windows-triage backend unavailable after consecutive failures",
            checked=len(buckets),
        )
    if on_progress:
        on_progress(
            "triage_done",
            artifact=artifact_name,
            checked=len(buckets),
            enriched=enriched,
        )
    return {"status": "complete", "checked": len(buckets), "enriched": enriched}


# Registry persistence R1-R17 (no gateway — pure update_by_query)
# ---------------------------------------------------------------------------


def _enrich_registry_persistence(client, safe_case, on_progress=None):
    """Flag registry persistence mechanisms via update_by_query.

    Implements R1-R14, R16. R15 (Active Setup) and R17 (NetSh) use
    check_file gateway calls and are handled in enrich_remote().

    No gateway calls — queries OpenSearch directly. Runs even when
    gateway is unavailable.
    """
    index = f"case-{safe_case}-registry-*"
    total_updated = 0

    rules = [
        # R1: IFEO Debugger (T1546.012)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Image File Execution Options*"}},
                        {"term": {"ValueName.keyword": "Debugger"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "IFEO debugger: ",
        },
        # R2: Silent Process Exit Monitor (T1546.012)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*SilentProcessExit*"}},
                        {"term": {"ValueName.keyword": "MonitorProcess"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "SilentProcessExit monitor: ",
        },
        # R3: AppInit_DLLs (T1546.010)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*CurrentVersion\\\\Windows*"}},
                        {"term": {"ValueName.keyword": "AppInit_DLLs"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "AppInit_DLLs: ",
        },
        # R6: Winlogon mpnotify (T1547.004)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Winlogon*"}},
                        {"term": {"ValueName.keyword": "mpnotify"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "Winlogon mpnotify: ",
        },
        # R11: Print Monitors (T1547.010)
        # NOTE: R8-R10 (LSA packages) handled separately below (need Painless set logic)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Print\\\\Monitors*"}},
                        {"term": {"ValueName.keyword": "Driver"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "Print Monitor DLL: ",
        },
        # R12: Command Processor AutoRun (T1546)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Command Processor*"}},
                        {"term": {"ValueName.keyword": "AutoRun"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "cmd.exe AutoRun: ",
        },
        # R13: Explorer Load (T1547.001)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*CurrentVersion\\\\Windows*"}},
                        {"term": {"ValueName.keyword": "Load"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "Explorer Load: ",
        },
        # R16: Terminal Services InitialProgram (T1547.001)
        {
            "query": {
                "bool": {
                    "must": [
                        {"wildcard": {"KeyPath.keyword": "*Terminal Services*"}},
                        {"term": {"ValueName.keyword": "InitialProgram"}},
                        {"exists": {"field": "ValueData"}},
                    ]
                }
            },
            "reason_prefix": "TS InitialProgram: ",
        },
    ]

    # Simple rules: any match with ValueData → SUSPICIOUS
    for rule in rules:
        try:
            resp = client.update_by_query(
                index=index,
                body={
                    "query": rule["query"],
                    "script": {
                        "source": (
                            "ctx._source['triage.verdict'] = 'SUSPICIOUS'; "
                            "ctx._source['triage.reason'] = params.prefix + "
                            "ctx._source['ValueData']; "
                            "ctx._source['triage.checked'] = true"
                        ),
                        "lang": "painless",
                        "params": {"prefix": rule["reason_prefix"]},
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            total_updated += resp.get("updated", 0)
        except Exception:
            continue

    # R8-R10: LSA packages — flag non-default entries
    _LSA_DEFAULTS = (
        "msv1_0 kerberos schannel wdigest tspkg pku2u cloudap negoextender scecli rassfm"
    ).split()
    for lsa_value_name, lsa_label in [
        ("Authentication Packages", "Authentication Packages"),
        ("Security Packages", "Security Packages"),
        ("Notification Packages", "Notification Packages"),
    ]:
        try:
            resp = client.update_by_query(
                index=index,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"wildcard": {"KeyPath.keyword": "*Control\\\\Lsa*"}},
                                {"term": {"ValueName.keyword": lsa_value_name}},
                                {"exists": {"field": "ValueData"}},
                            ]
                        }
                    },
                    "script": {
                        "source": """
                            String val = ctx._source['ValueData'].toLowerCase().trim();
                            String[] entries = /[\\n| ]+/.split(val);
                            List unknown = new ArrayList();
                            for (String e : entries) {
                                String trimmed = e.trim();
                                if (trimmed.length() > 0 && !params.known.contains(trimmed)) {
                                    unknown.add(trimmed);
                                }
                            }
                            if (unknown.size() > 0) {
                                ctx._source['triage.verdict'] = 'SUSPICIOUS';
                                String r = params.label + ': ' + String.join(', ', unknown);
                                ctx._source['triage.reason'] = r;
                                ctx._source['triage.checked'] = true;
                            } else {
                                ctx.op = 'noop';
                            }
                        """,
                        "lang": "painless",
                        "params": {
                            "known": _LSA_DEFAULTS,
                            "label": f"Non-default {lsa_label}",
                        },
                    },
                },
                conflicts="proceed",
                requests_per_second=1000,
            )
            total_updated += resp.get("updated", 0)
        except Exception as exc:
            logger.debug("Registry rule failed: %s", exc)

    # R4: Winlogon Shell — conditional (not explorer.exe → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Winlogon*"}},
                            {"term": {"ValueName.keyword": "Shell"}},
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        if (val.length() == 0) { ctx.op = 'noop'; return; }
                        int idx = val.lastIndexOf('\\\\');
                        String filename = idx >= 0 ? val.substring(idx + 1) : val;
                        if (!filename.equals('explorer.exe')) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            String vd = ctx._source.getOrDefault('ValueData', '');
                            ctx._source['triage.reason'] = params.prefix + vd;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                    "params": {"prefix": "Winlogon Shell: "},
                },
            },
            conflicts="proceed",
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
    except Exception as exc:
        logger.debug("Registry rule failed: %s", exc)

    # R5: Winlogon Userinit — conditional (not userinit.exe → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Winlogon*"}},
                            {"term": {"ValueName.keyword": "Userinit"}},
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        if (val.length() == 0) { ctx.op = 'noop'; return; }
                        if (val.endsWith(',')) { val = val.substring(0, val.length() - 1).trim(); }
                        if (!val.endsWith('userinit.exe')) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            String vd = ctx._source.getOrDefault('ValueData', '');
                            ctx._source['triage.reason'] = params.prefix + vd;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                    "params": {"prefix": "Winlogon Userinit: "},
                },
            },
            conflicts="proceed",
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
    except Exception as exc:
        logger.debug("Registry rule failed: %s", exc)

    # R7: BootExecute — conditional (not "autocheck autochk *" → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Session Manager*"}},
                            {"term": {"ValueName.keyword": "BootExecute"}},
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].trim();
                        if (val.length() == 0) { ctx.op = 'noop'; return; }
                        if (!val.equals('autocheck autochk *')) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            ctx._source['triage.reason'] = params.prefix + val;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                    "params": {"prefix": "BootExecute: "},
                },
            },
            conflicts="proceed",
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
    except Exception as exc:
        logger.debug("Registry rule failed: %s", exc)

    # R14: Screensaver — conditional (non-.scr or outside System32 → SUSPICIOUS)
    try:
        resp = client.update_by_query(
            index=index,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"wildcard": {"KeyPath.keyword": "*Control Panel\\\\Desktop*"}},
                            {"term": {"ValueName.keyword": "SCRNSAVE.EXE"}},
                            {"exists": {"field": "ValueData"}},
                        ]
                    }
                },
                "script": {
                    "source": """
                        String val = ctx._source['ValueData'].toLowerCase().trim();
                        if (val.length() == 0) { ctx.op = 'noop'; return; }
                        boolean suspicious = false;
                        String reason = '';
                        if (!val.endsWith('.scr')) {
                            suspicious = true;
                            reason = 'Screensaver non-.scr: ' + ctx._source['ValueData'];
                        } else if (val.contains('\\\\') && !val.contains('system32')
                                   && !val.contains('winsxs')) {
                            suspicious = true;
                            reason = 'Screensaver outside System32: ' + ctx._source['ValueData'];
                        }
                        if (suspicious) {
                            ctx._source['triage.verdict'] = 'SUSPICIOUS';
                            ctx._source['triage.reason'] = reason;
                            ctx._source['triage.checked'] = true;
                        } else {
                            ctx.op = 'noop';
                        }
                    """,
                    "lang": "painless",
                },
            },
            conflicts="proceed",
            requests_per_second=1000,
        )
        total_updated += resp.get("updated", 0)
    except Exception as exc:
        logger.debug("Registry rule failed: %s", exc)

    if on_progress:
        on_progress(
            "triage_done",
            artifact="registry_persistence",
            checked=0,
            enriched=total_updated,
        )
    return {"status": "complete", "enriched": total_updated}


# ---------------------------------------------------------------------------
# Hayabusa ↔ memory correlation (gateway-independent)
# ---------------------------------------------------------------------------


def _enrich_hayabusa_memory_correlation(client, safe_case, on_progress=None):
    """Cross-reference Hayabusa high/critical detections against vol memory artifacts.

    Stamps vol-pslist, vol-psscan, and vol-netscan records where the process
    name (ImageFileName / Owner) matches a process flagged by Hayabusa.
    Gateway-independent — uses only OpenSearch update_by_query.

    Stamped fields:
        hayabusa_corroboration.flagged      bool  — always True on stamped docs
        hayabusa_corroboration.max_level    str   — highest Hayabusa level that
                                                    flagged this process name
        hayabusa_corroboration.rule_titles  list  — up to 5 distinct rule titles
    """
    import re

    hayabusa_index = f"case-{safe_case}-hayabusa-*"
    try:
        result = client.search(
            index=hayabusa_index,
            body={
                "query": {"terms": {"Level": ["critical", "high"]}},
                "size": 5000,
                "_source": ["Details", "RuleTitle", "Level"],
            },
        )
    except Exception:
        return {"status": "skipped", "reason": "hayabusa index not found"}

    hits = result["hits"]["hits"]
    if not hits:
        return {"status": "empty", "hayabusa_alerts_scanned": 0}

    # Extract bare process names from Hayabusa Details.
    # Hayabusa verbose profile format: "Alias: Value ¦ Alias: Value"
    # ¦ is U+00A6 (BROKEN BAR). Process-bearing aliases across rule types:
    #   EID 4688  → Proc (NewProcessName), PProc (ParentProcessName)
    #   Sysmon 1  → Img (Image full path), PImg (ParentImage full path)
    #   Sysmon 10 → TgtImg (TargetImage)
    # We only match the forward process (not parent) to avoid over-flagging.
    _PROC_RE = re.compile(
        r"(?:^|¦|\|)\s*(?:Proc|Img|TgtImg):\s*([^\s¦|,;]+)",
        re.IGNORECASE,
    )
    _LEVEL_RANK = {"critical": 0, "high": 1}

    # flagged: {bare_lower_name -> {"max_level": str, "rule_titles": set}}
    flagged: dict[str, dict] = {}
    for h in hits:
        src = h["_source"]
        details = src.get("Details", "")
        rule_title = src.get("RuleTitle", "unknown")
        level = src.get("Level", "high").lower()
        for m in _PROC_RE.finditer(details):
            raw = m.group(1).strip()
            bare = raw.replace("\\", "/").split("/")[-1].lower()
            # Must look like an executable filename
            if not bare or "." not in bare or len(bare) > 64:
                continue
            entry = flagged.setdefault(bare, {"max_level": "high", "rule_titles": set()})
            entry["rule_titles"].add(rule_title)
            if _LEVEL_RANK.get(level, 1) < _LEVEL_RANK.get(entry["max_level"], 1):
                entry["max_level"] = level

    if not flagged:
        return {
            "status": "empty",
            "hayabusa_alerts_scanned": len(hits),
            "flagged_process_names": 0,
        }

    if on_progress:
        on_progress("triage_start", artifact="hayabusa_memory", unique_values=len(flagged))

    total_stamped = 0

    # vol-pslist and vol-psscan use ImageFileName; vol-netscan uses Owner.
    # Both are dynamically mapped → need .keyword suffix.
    for vol_suffix, name_field in [
        ("vol-pslist", "ImageFileName.keyword"),
        ("vol-psscan", "ImageFileName.keyword"),
        ("vol-netscan", "Owner.keyword"),
    ]:
        vol_index = f"case-{safe_case}-{vol_suffix}-*"
        try:
            agg = client.search(
                index=vol_index,
                body={
                    "size": 0,
                    "aggs": {"names": {"terms": {"field": name_field, "size": 5000}}},
                },
            )
        except Exception:
            continue

        buckets = agg.get("aggregations", {}).get("names", {}).get("buckets", [])
        for bucket in buckets:
            exact_val = bucket["key"]
            entry = flagged.get(exact_val.lower())
            if not entry:
                continue
            rule_list = sorted(entry["rule_titles"])[:5]
            try:
                resp = client.update_by_query(
                    index=vol_index,
                    body={
                        "query": {"term": {name_field: exact_val}},
                        "script": {
                            "source": (
                                "ctx._source['hayabusa_corroboration.flagged'] = true; "
                                "ctx._source['hayabusa_corroboration.max_level'] = params.max_level; "
                                "ctx._source['hayabusa_corroboration.rule_titles'] = params.rule_titles;"
                            ),
                            "lang": "painless",
                            "params": {
                                "max_level": entry["max_level"],
                                "rule_titles": rule_list,
                            },
                        },
                    },
                    conflicts="proceed",
                    requests_per_second=1000,
                )
                total_stamped += resp.get("updated", 0)
            except Exception as e:
                print(
                    f"  WARNING: hayabusa_memory stamp failed for {vol_suffix}/{exact_val}: {e}",
                    file=sys.stderr,
                )

    if on_progress:
        on_progress(
            "triage_done",
            artifact="hayabusa_memory",
            checked=len(hits),
            enriched=total_stamped,
        )

    return {
        "status": "complete",
        "hayabusa_alerts_scanned": len(hits),
        "flagged_process_names": len(flagged),
        "vol_docs_stamped": total_stamped,
    }
