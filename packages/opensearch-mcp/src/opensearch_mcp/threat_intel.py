"""Post-ingest threat intel enrichment.

Extracts unique IOCs (IPs, hashes, domains) from indexed evidence and stamps
matching documents with ``threat_intel.*`` fields. There is no intel-lookup
backend wired in, so :func:`batch_lookup` produces no enrichments and
:func:`enrich_case` reports enrichment as unavailable.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from datetime import datetime, timezone
from typing import Any

from opensearchpy import OpenSearch

# Fields for aggregation and term queries.
# Explicitly-mapped keyword/ip fields use bare names.
# Dynamically-mapped text fields need .keyword suffix.
_IP_FIELDS = [
    "source.ip",  # explicit ip type in evtx/accesslog/w3c templates
    "ForeignAddr.keyword",  # dynamic in vol3_template
    "LocalAddr.keyword",  # dynamic in vol3_template
]

_HASH_FIELDS = [
    "SHA1.keyword",  # dynamic in csv_template
    "SHA256.keyword",  # dynamic in csv_template
    "MD5.keyword",  # dynamic in csv_template
]

_DOMAIN_FIELDS = [
    "dns.query.keyword",  # dynamic in json_template
    "query.keyword",  # dynamic in json/delimited
    "source_host.keyword",  # dynamic (B36 renamed field)
    "server_name.keyword",  # dynamic in delimited
]


def _is_external(ip_str: str) -> bool:
    """Filter out RFC1918, loopback, link-local, multicast."""
    try:
        return ipaddress.ip_address(ip_str).is_global
    except ValueError:
        return False


# Hash validation — covers every STIX file-hash type OpenCTI's
# stix_cyber_observable schema accepts (UAT 2026-04-23 follow-up to the
# rate-limit raise). Without this, the extractor used to ship any value
# from a SHA256/SHA1/MD5 field to OpenCTI, including text fragments
# that looked nothing like a hash — OpenCTI's fuzzy search would return
# real-looking label matches (malware-bazaar, rat, loader) and stamp
# clean docs MALICIOUS. Fast + noisy is worse than slow + noisy, so
# validator ships before any bulk run against the raised rate limit.
#
# Hex hash lengths (all length-ambiguous — we do NOT pre-classify by
# length; OpenCTI's stix_cyber_observable.list(search=...) multi-field
# matches across all hash fields. Pre-classification would misattribute
# IMPHASH as MD5, PESHA1 as SHA-1, etc.):
#   32  — MD5, IMPHASH, AUTHENTIHASH, GIMPHASH, MD6, JA3, JA3S
#   40  — SHA-1, RIPEMD-160, PESHA1  (NOTE: Ethereum wallets are 40-hex
#         but always carry a `0x` prefix → _HEX_RE rejects them here;
#         the 0x prefix makes the total length 42 and the `x` fails the
#         hex class. Wallets in hash fields are therefore correctly
#         dropped; a future crypto-wallet observable type would extract
#         them from a dedicated field.)
#   56  — SHA-224, SHA3-224
#   64  — SHA-256, SHA3-256, PESHA256, BLAKE2s, BLAKE3
#   96  — SHA-384, SHA3-384
#   128 — SHA-512, SHA3-512, WHIRLPOOL, BLAKE2b
#
# Fuzzy hashes (non-hex):
#   SSDEEP   — <n>:<base64ish>:<base64ish>
#   TLSH     — T1/T2 + 70 hex (first char is T)
#   TELFHASH — 70 lowercase alphanumeric
#
# Not supported (fall through to reject — rare enough in forensic
# corpora that the 2-line addition isn't worth the surface area):
#   JA4      — colon-segmented (e.g. t13d1516h2_8daaf6152771_...)
#   JARM     — 62 hex
# Add to _HEX_HASH_LENGTHS / a dedicated regex if they become needed.
_HEX_HASH_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_SSDEEP_RE = re.compile(r"^\d+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$")
_TLSH_RE = re.compile(r"^T[12][0-9A-Fa-f]{70}$")
_TELFHASH_RE = re.compile(r"^[a-z0-9]{70}$")


def _is_valid_hash(val: str) -> bool:
    """Validate a hash observable against STIX file-hash formats.

    Accepts any hex hash at a recognised cryptographic length, plus
    SSDEEP / TLSH / TELFHASH fuzzy hashes. Rejects everything else —
    including text fragments from mis-mapped amcache/evtx/mft fields
    that previously slipped through as `ioc_type=hash` and drove the
    observed false-positive MALICIOUS stamps.
    """
    if not val:
        return False
    length = len(val)
    if length in _HEX_HASH_LENGTHS and _HEX_RE.match(val):
        return True
    if length == 72 and _TLSH_RE.match(val):
        return True
    if length == 70 and _TELFHASH_RE.match(val):
        return True
    if _SSDEEP_RE.match(val):
        return True
    return False


# Domain validation — RFC 1035 label rules, with pragmatic concessions:
# single-label hostnames are rejected (netbios names aren't OpenCTI
# observables), IP-as-string is rejected here (gets routed to ip path),
# anything with whitespace, control chars, or path separators is
# rejected (source_host.keyword picks up a lot of these from evtx).
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _is_valid_domain(val: str) -> bool:
    """Validate a domain observable against RFC 1035 label rules.

    Rejects single-label hostnames (netbios), IP literals (routed via
    the ip path), and anything with whitespace / control chars /
    path separators. Accepts underscores ONLY in labels that are not
    the TLD — pure-DNS policies reject underscores but many real
    records (DMARC, DKIM TXT) include them, and OpenCTI stores them.
    """
    if not val or len(val) > 253:
        return False
    # Reject control chars, whitespace, slashes, and common garbage.
    if any(c.isspace() or c in "\\/:\x00" for c in val):
        return False
    # Reject IP literals — they belong on the ip path.
    try:
        ipaddress.ip_address(val)
        return False
    except ValueError:
        pass
    labels = val.split(".")
    if len(labels) < 2:
        return False  # Single-label hostnames aren't DNS observables
    for label in labels:
        # Allow underscores in non-TLD labels (DMARC / DKIM etc.).
        check = _DOMAIN_LABEL_RE
        if label is not labels[-1] and "_" in label:
            if not re.match(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$", label):
                return False
            continue
        if not check.match(label):
            return False
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False
    return True


def extract_unique_iocs(
    client: OpenSearch,
    index_pattern: str,
    force: bool = False,
) -> dict[str, set[str]]:
    """Extract unique IOCs from indexed data using aggregations.

    If force=False, skip docs already enriched (threat_intel.checked: true).
    """
    iocs: dict[str, set[str]] = {"ip": set(), "hash": set(), "domain": set()}
    warnings: list[str] = []
    # Per-field rejection counts. Without field attribution, operators
    # can't tell WHICH field is feeding garbage values into the
    # extractor — and can't tune the field list. Aggregate rejects
    # per field and surface them as warnings at the end.
    rejected_by_field: dict[str, int] = {}
    any_succeeded = False

    query: dict = {"match_all": {}}
    if not force:
        query = {
            "bool": {
                "must_not": [{"exists": {"field": "threat_intel.checked"}}],
            }
        }

    # Per-type validators (UAT 2026-04-23): without these, any value
    # aggregated from a *_HASH_FIELDS / *_DOMAIN_FIELDS field was passed
    # through to OpenCTI. OpenCTI's fuzzy-label match then produced
    # real-looking MALICIOUS stamps on doc fragments like
    # "astloggedonuser:[(-1,1)]..." — ~845K false positives in the
    # observed case. Validators reject malformed values at extraction
    # time so OpenCTI only ever sees something that parses as its
    # claimed type. IP already had _is_external (which requires a
    # parseable address).
    validators: dict[str, Any] = {
        "ip": _is_external,
        "hash": _is_valid_hash,
        "domain": _is_valid_domain,
    }

    for ioc_type, fields in [
        ("ip", _IP_FIELDS),
        ("hash", _HASH_FIELDS),
        ("domain", _DOMAIN_FIELDS),
    ]:
        validate = validators[ioc_type]
        for field in fields:
            try:
                result = client.search(
                    index=index_pattern,
                    body={
                        "query": query,
                        "size": 0,
                        "aggs": {"values": {"terms": {"field": field, "size": 10000}}},
                    },
                    request_timeout=60,
                )
                any_succeeded = True
                agg_vals = result["aggregations"]["values"]
                other_count = agg_vals.get("sum_other_doc_count", 0)
                if other_count > 0:
                    warnings.append(
                        f"{field}: {other_count} additional unique values "
                        "not included (limit 10000)"
                    )
                field_rejects = 0
                for bucket in agg_vals["buckets"]:
                    val = str(bucket["key"])
                    if validate(val):
                        iocs[ioc_type].add(val)
                    else:
                        field_rejects += 1
                if field_rejects:
                    rejected_by_field[field] = rejected_by_field.get(field, 0) + field_rejects
            except Exception as e:
                if "AuthorizationException" in type(e).__name__:
                    print(
                        f"WARNING: OpenSearch auth error during IOC extraction: {e}",
                        file=sys.stderr,
                    )
                continue

    if not any_succeeded:
        raise RuntimeError("IOC extraction failed -- all OpenSearch queries failed")

    for w in warnings:
        print(f"WARNING: {w}", file=sys.stderr)

    # Surface per-field rejection totals so operators can audit which
    # mapped field is producing non-IOC text (e.g. amcache
    # astloggedonuser bleeding into SHA256.keyword). Sorted high→low so
    # the top offender is obvious.
    if rejected_by_field:
        total = sum(rejected_by_field.values())
        print(
            f"INFO: dropped {total} malformed values at extraction "
            "(failed type validation; would otherwise produce OpenCTI "
            "false-positive stamps):",
            file=sys.stderr,
        )
        for field, count in sorted(rejected_by_field.items(), key=lambda kv: -kv[1])[:10]:
            print(f"  {field}: {count} rejected", file=sys.stderr)

    return iocs


def batch_lookup(
    iocs: dict[str, set[str]],
    on_progress=None,
) -> dict[str, dict]:
    """Look up IOCs against a threat-intel backend.

    No intel-lookup backend is wired into enrichment, so no IOC is ever looked
    up and no enrichment is produced. Returns an empty mapping; ``enrich_case``
    detects the empty result and reports enrichment as unavailable to the caller.
    """
    return {}


def stamp_documents(
    client: OpenSearch,
    index_pattern: str,
    ioc_results: dict[str, dict],
) -> int:
    """Stamp indexed documents with threat_intel.* fields via update-by-query."""
    now = datetime.now(timezone.utc).isoformat()
    total_updated = 0

    for ioc_value, intel in ioc_results.items():
        ioc_type = intel.get("threat_intel.ioc_type", "")

        if ioc_type == "ip":
            fields = _IP_FIELDS
        elif ioc_type == "hash":
            fields = _HASH_FIELDS
        elif ioc_type == "domain":
            fields = _DOMAIN_FIELDS
        else:
            continue

        should_clauses = [{"term": {field: ioc_value}} for field in fields]

        intel_with_ts = dict(intel)
        intel_with_ts["threat_intel.enriched_at"] = now
        intel_with_ts["threat_intel.checked"] = True

        set_clauses = []
        params = {}
        for k, v in intel_with_ts.items():
            safe_key = k.replace(".", "_")
            set_clauses.append(f"ctx._source['{k}'] = params.{safe_key}")
            params[safe_key] = v

        try:
            result = client.update_by_query(
                index=index_pattern,
                body={
                    "query": {
                        "bool": {
                            "should": should_clauses,
                            "minimum_should_match": 1,
                        }
                    },
                    "script": {
                        "source": "; ".join(set_clauses),
                        "lang": "painless",
                        "params": params,
                    },
                },
                request_timeout=120,
                conflicts="proceed",
                requests_per_second=1000,
            )
            total_updated += result.get("updated", 0)
        except Exception as e:
            print(
                f"WARNING: Update failed for {ioc_value}: {e}",
                file=sys.stderr,
            )

    return total_updated


def enrich_case(
    client: OpenSearch,
    case_id: str,
    force: bool = False,
    on_progress=None,
) -> dict:
    """Full enrichment pipeline for a case.

    Returns summary dict.
    """
    from opensearch_mcp.paths import build_index_pattern

    index_pattern = build_index_pattern(case_id)

    if on_progress:
        on_progress("extracting", message="Extracting unique IOCs from indexed data")
    iocs = extract_unique_iocs(client, index_pattern, force=force)

    total_iocs = sum(len(v) for v in iocs.values())
    if on_progress:
        on_progress(
            "extracted",
            ips=len(iocs["ip"]),
            hashes=len(iocs["hash"]),
            domains=len(iocs["domain"]),
        )

    if total_iocs == 0:
        return {
            "status": "no_iocs",
            "message": "No external IOCs found in indexed data",
        }

    if on_progress:
        on_progress("looking_up", total=total_iocs)
    results = batch_lookup(iocs, on_progress=on_progress)

    # batch_lookup returns {} when no intel backend processed the lookups. IOCs
    # were extracted but NOTHING was looked up ⇒ the intel backend is
    # unavailable. Surface that as a clear unavailable status through the worker
    # result_public instead of a misleading "complete" with documents_updated:0.
    if total_iocs > 0 and not results:
        if on_progress:
            on_progress("unavailable", iocs_extracted=total_iocs)
        return {
            "status": "unavailable",
            "message": (
                "intel enrichment unavailable — no OpenCTI/intel backend processed "
                "lookups; register OpenCTI via setup-addon"
            ),
            "iocs_extracted": total_iocs,
            "iocs_looked_up": 0,
        }

    malicious = sum(1 for r in results.values() if r.get("threat_intel.verdict") == "MALICIOUS")
    suspicious = sum(1 for r in results.values() if r.get("threat_intel.verdict") == "SUSPICIOUS")

    if on_progress:
        on_progress("stamping", matched=len(results))
    updated = stamp_documents(client, index_pattern, results)

    return {
        "status": "complete",
        "iocs_extracted": total_iocs,
        "iocs_looked_up": len(results),
        "malicious": malicious,
        "suspicious": suspicious,
        "documents_updated": updated,
    }
