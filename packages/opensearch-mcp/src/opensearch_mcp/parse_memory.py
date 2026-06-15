"""Automated Volatility 3 memory image parsing.

Runs vol3 plugins as subprocesses with JSON output, indexes structured
results into OpenSearch. Tiered execution: fast plugins always, slow
plugins opt-in.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from opensearchpy import OpenSearch

from opensearch_mcp.bulk import flush_bulk

# Plugin tiers — ordered within each tier for dependency resolution
TIER_1 = [
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.psscan",
    "windows.netscan",
    "windows.cmdline",
    "windows.netstat",
    "windows.svcscan",
    "windows.modules",
    "windows.registry.hivelist",
]

TIER_2 = TIER_1 + [
    "windows.dlllist",
    "windows.envars",
    "windows.getsids",
    "windows.ldrmodules",
    "windows.callbacks",
    "windows.ssdt",
    "windows.registry.userassist",
]

TIER_3 = TIER_2 + [
    "windows.handles",
    "windows.filescan",
    "windows.malfind",
    "windows.shimcachemem",
    "windows.driverscan",
    "windows.mutantscan",
    "timeliner",
]
# UAT 2026-04-23 BUG 4: removed from TIER_3:
# - windows.registry.hashdump — not in Vol3 2.26.2's argparse choice
#   list (errors with "invalid choice PLUGIN" on every invocation).
#   Credentials evidence is better surfaced via disk-side SAM/SECURITY
#   hives (already ingested as the "registry" artifact) + live-collected
#   creds from Kansa/Velociraptor.
# - windows.vadinfo — compute-heavy (>60s on 5GB memory images, times
#   out) and its forensic value overlaps malfind + dlllist + ldrmodules
#   + handles that are already in the tier. Operators can run it on-
#   demand via `vol -f <img> windows.vadinfo --pid <pid>`.

# Natural keys per plugin (content-intrinsic, version-independent)
_NATURAL_KEYS: dict[str, list[str]] = {
    "windows.pslist": ["PID", "CreateTime"],
    "windows.pstree": ["PID", "CreateTime"],
    "windows.netscan": ["LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "PID"],
    "windows.netstat": ["LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "PID"],
    "windows.svcscan": ["Name", "PID"],
    "windows.cmdline": ["PID"],
    "windows.dlllist": ["PID", "Base", "Name"],
    "windows.handles": ["PID", "Offset(V)"],
    "windows.modules": ["Base", "Name"],
    "windows.registry.hivelist": ["Offset(V)"],
}

# Primary timestamp field per plugin — mapped to @timestamp
_TIMESTAMP_FIELD: dict[str, str | None] = {
    "windows.info": None,
    "windows.pslist": "CreateTime",
    "windows.pstree": "CreateTime",
    "windows.psscan": "CreateTime",
    "windows.cmdline": None,
    "windows.netscan": "Created",
    "windows.netstat": "Created",
    "windows.svcscan": None,
    "windows.modules": None,
    "windows.registry.hivelist": None,
    "windows.dlllist": "LoadTime",
    "windows.envars": None,
    "windows.getsids": None,
    "windows.ldrmodules": None,
    "windows.callbacks": None,
    "windows.ssdt": None,
    # Vol3's registry.userassist TreeGrid column is "Last Write Time"
    # (with spaces), not "LastWriteTime" — see volatility3 source:
    # framework/plugins/windows/registry/userassist.py:380-390. The
    # JSON renderer preserves column names verbatim. Prior value
    # "LastWriteTime" never matched the emitted field, so @timestamp
    # was silently left unset on every userassist row (UAT 2026-04-23).
    "windows.registry.userassist": "Last Write Time",
    "windows.handles": None,
    "windows.filescan": None,
    "windows.malfind": None,
    "windows.shimcachemem": "LastModified",
    "windows.driverscan": None,
    "windows.mutantscan": None,
    "timeliner": None,
}

# Handle type filtering — only index forensically relevant handle types
_HANDLE_TYPES_KEEP = {
    "File",
    "Key",
    "Mutant",
    "Event",
    "Section",
    "ALPC Port",
    "Directory",
    "SymbolicLink",
    "Thread",
    "Process",
}

_MAX_JSON_BYTES = 200 * 1024 * 1024  # 200MB

_VOL3_CMD: str | None = None


def _find_vol3() -> str:
    """Find the vol3 command.

    Systemd user services run with a minimal PATH that excludes /usr/local/bin,
    so PATH-based lookup fails even when vol is installed there. Try known
    absolute install locations first, then fall back to PATH candidates.
    """
    global _VOL3_CMD
    if _VOL3_CMD:
        return _VOL3_CMD

    # Absolute paths first — bypasses PATH entirely, works under any environment.
    absolute_candidates = [
        "/usr/local/bin/vol",
        "/opt/volatility3/bin/vol",
        "/usr/local/bin/vol3",
        "/usr/bin/vol",
        "/usr/bin/vol3",
    ]
    path_candidates = ["vol3", "vol"]

    all_candidates: list[list[str]] = (
        [[p] for p in absolute_candidates if Path(p).exists()]
        + [c.split() for c in path_candidates]
        + [["python3", "-m", "volatility3"]]
    )

    for cmd in all_candidates:
        try:
            # vol has no --version flag; -h prints usage and exits 2.
            # Any non-127 exit with output means the binary is present and runnable.
            result = subprocess.run(cmd + ["-h"], capture_output=True, text=True, timeout=10)
            if (result.stdout + result.stderr).strip():
                _VOL3_CMD = cmd[0] if len(cmd) == 1 else " ".join(cmd)
                return _VOL3_CMD
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    raise RuntimeError(
        "Volatility 3 not found. Tried absolute paths and PATH candidates.\n"
        "Install: pip install volatility3  or  apt install volatility3"
    )


def _plugin_to_index_suffix(plugin: str) -> str:
    """windows.pslist → vol-pslist, windows.registry.hivelist → vol-hivelist."""
    parts = plugin.split(".")
    return f"vol-{parts[-1]}"


_DEFAULT_SHARED_SYMBOL_DIR = Path("/var/cache/sift/volatility-symbols")


def _user_symbol_dir() -> Path:
    """Return a writable Volatility 3 symbol cache directory.

    This is a SHARED, env-overridable symbol cache, consumed via ``-s`` so vol
    can cache generated/downloaded ISF symbols without needing write access to
    its read-only install dir. The same cache is written by both the
    ``sift-service`` service user and the ``agent_runtime`` sandbox user, which
    is why the on-VM default lives in a group-writable shared location rather
    than per-user.

    Resolution order:
      1. ``SIFT_VOL_SYMBOLS`` env var, if set, is used verbatim.
      2. otherwise the shared default ``/var/cache/sift/volatility-symbols``.
      3. if the chosen dir cannot be created or is not writable, fall back to
         ``~/.cache/volatility3/symbols`` so host dev/tests still work.

    The returned dir is always created (``mkdir(parents=True, exist_ok=True)``).
    """
    env_override = os.environ.get("SIFT_VOL_SYMBOLS", "").strip()
    chosen = Path(env_override) if env_override else _DEFAULT_SHARED_SYMBOL_DIR
    try:
        chosen.mkdir(parents=True, exist_ok=True)
        if os.access(chosen, os.W_OK):
            return chosen
    except OSError:
        pass

    fallback = Path.home() / ".cache" / "volatility3" / "symbols"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def run_vol3_plugin(
    image_path: Path,
    plugin: str,
    timeout: int = 3600,
    plugin_args: list[str] | None = None,
) -> list[dict]:
    """Run a single vol3 plugin with JSON output.

    Args:
        image_path: Path to the memory image.
        plugin: Vol3 plugin name (e.g. "windows.pslist").
        timeout: Per-plugin subprocess timeout in seconds.
        plugin_args: Optional extra args appended AFTER the plugin name
            (e.g. ``["--key", "ControlSet001\\Control\\ComputerName\\ActiveComputerName"]``).
            Backward-compatible: callers that omit this get the existing behaviour.
    """
    vol_cmd = _find_vol3()
    sym_dir = _user_symbol_dir()
    cmd = vol_cmd.split() + [
        "-s", str(sym_dir),
        "-f", str(image_path),
        "--renderer", "json",
        "-q",
        plugin,
    ]
    if plugin_args:
        cmd.extend(plugin_args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        stderr = result.stderr[:500] if result.stderr else ""
        raise RuntimeError(f"vol3 {plugin} failed (exit {result.returncode}): {stderr}")
    if not result.stdout.strip():
        return []

    if len(result.stdout) > _MAX_JSON_BYTES:
        print(
            f"WARNING: vol3 {plugin} produced {len(result.stdout) // (1024 * 1024)}MB "
            f"of JSON — memory spike during parsing",
            file=sys.stderr,
        )

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"vol3 {plugin} produced invalid JSON: {e}") from e

    if isinstance(raw, dict) and "columns" in raw:
        cols = [c["name"] for c in raw["columns"]]
        return [dict(zip(cols, row)) for row in raw.get("data", [])]
    elif isinstance(raw, list):
        return raw
    return []


def _derive_hostname_from_image(image_path: Path, timeout: int = 60) -> tuple[str | None, str]:
    """Auto-derive the hostname from a Windows memory image via Volatility 3.

    Implements the proven probe recipe from B-MVP-042:

    PRIMARY — ``windows.registry.printkey`` on the SYSTEM-hive ComputerName key.
    Fallback key order per the spec:
      1. ControlSet001\\Control\\ComputerName\\ActiveComputerName
      2. ControlSet001\\Control\\ComputerName\\ComputerName
      3. ControlSet002\\Control\\ComputerName\\ActiveComputerName
      4. ControlSet002\\Control\\ComputerName\\ComputerName

    SECONDARY (if all registry probes yield nothing) — ``windows.envars``.
    Filters ``Variable.upper() == "COMPUTERNAME"``; takes the majority/first Value.

    Returns:
        ``(hostname, source)`` where ``source`` is ``"registry"`` or ``"envars"``,
        or ``(None, "")`` if both probes fail / image is unsupported.

    Notes:
        - REG_SZ Data is rendered as ``"\"SRL-FORGE\""`` (literal surrounding
          double-quotes inside the JSON string) — they are stripped here.
        - printkey returns ~45 rows (all hives in memory); only the
          ``\\REGISTRY\\MACHINE\\SYSTEM\\`` row with ``Name=="ComputerName"``
          and ``Type=="REG_SZ"`` carries the machine name.
        - All probes use short timeouts; a first-ever run on an uncached Windows
          build pays ISF generation cost (~30–120 s). The caller's timeout is
          forwarded to each probe.
    """
    # Verbatim prefix as emitted by vol3 -r json (single backslashes).
    # Cannot use a raw string ending in a single backslash; use a regular
    # escaped string instead: "\\X" → the one-character '\X' at runtime.
    _SYSTEM_PREFIX = "\\REGISTRY\\MACHINE\\SYSTEM\\"
    # Registry key probe order (ControlSet001 preferred, ActiveComputerName preferred)
    _REG_KEYS = [
        r"ControlSet001\Control\ComputerName\ActiveComputerName",
        r"ControlSet001\Control\ComputerName\ComputerName",
        r"ControlSet002\Control\ComputerName\ActiveComputerName",
        r"ControlSet002\Control\ComputerName\ComputerName",
    ]

    # --- PRIMARY: registry ---
    for key in _REG_KEYS:
        try:
            rows = run_vol3_plugin(
                image_path,
                "windows.registry.printkey",
                timeout=timeout,
                plugin_args=["--key", key],
            )
        except (RuntimeError, Exception):
            # Plugin failed (exit != 0) — try next key
            continue

        for row in rows:
            # Filter: must be the SYSTEM hive row with the right name/type
            key_field = row.get("Key", "")
            name = row.get("Name", "")
            rtype = row.get("Type", "")
            data = row.get("Data", "")
            if (
                name == "ComputerName"
                and rtype == "REG_SZ"
                and _SYSTEM_PREFIX.lower() in key_field.lower()
                and data
                and data != "-"
            ):
                # Strip surrounding literal double-quotes (REG_SZ renders as
                # '"SRL-FORGE"' inside the JSON string value)
                hostname = data.strip('"')
                if hostname:
                    print(
                        f"[memory-hostname] derived from registry key {key!r}: {hostname!r}",
                        file=sys.stderr,
                    )
                    return hostname, "registry"

    # --- SECONDARY: envars COMPUTERNAME ---
    try:
        rows = run_vol3_plugin(image_path, "windows.envars", timeout=timeout)
    except (RuntimeError, Exception):
        rows = []

    values: list[str] = [
        row["Value"]
        for row in rows
        if row.get("Variable", "").upper() == "COMPUTERNAME" and row.get("Value")
    ]
    if values:
        # Majority vote: the most frequent value (all 181 rows were unanimous
        # on the test image, so first is fine; majority handles edge cases)
        from collections import Counter

        hostname = Counter(values).most_common(1)[0][0]
        print(
            f"[memory-hostname] derived from envars COMPUTERNAME ({len(values)} rows): {hostname!r}",
            file=sys.stderr,
        )
        return hostname, "envars"

    print(
        "[memory-hostname] auto-derivation failed: registry and envars probes returned nothing.",
        file=sys.stderr,
    )
    return None, ""


def _flatten_records(records: list[dict], _depth: int = 0) -> list[dict]:
    """Recursively flatten __children into a flat list."""
    flat = []
    for record in records:
        children = record.pop("__children", [])
        flat.append(record)
        if children and _depth < 50:
            flat.extend(_flatten_records(children, _depth + 1))
    return flat


def _vol3_doc_id(index_name: str, plugin: str, record: dict, source_file: str) -> str:
    """Deterministic ID — natural key or content hash."""
    source_name = Path(source_file).name

    nk_fields = _NATURAL_KEYS.get(plugin)
    if nk_fields:
        parts = [str(record.get(f, "")) for f in nk_fields]
        if all(parts):
            key = f"{index_name}:{source_name}:{plugin}:{':'.join(parts)}"
            return hashlib.sha256(key.encode()).hexdigest()[:20]

    stable = {
        k: v
        for k, v in record.items()
        if not k.startswith("vhir.")
        and k != "host.name"
        and k != "pipeline_version"
        and k != "@timestamp"
    }
    content = json.dumps(stable, sort_keys=True, default=str)
    return hashlib.sha256(f"{index_name}:{source_name}:{content}".encode()).hexdigest()[:20]


def _index_vol3_records(
    records: list[dict],
    client: OpenSearch,
    index_name: str,
    plugin: str,
    hostname: str,
    source_file: str,
    ingest_audit_id: str,
    pipeline_version: str,
    host_dict=None,
) -> tuple[int, int]:
    """Index vol3 JSON records into OpenSearch."""
    count = 0
    bulk_failed = 0
    actions: list[dict] = []

    flat = _flatten_records(records)

    if plugin == "windows.handles":
        flat = [r for r in flat if r.get("Type") in _HANDLE_TYPES_KEEP]

    for record in flat:
        ts_field = _TIMESTAMP_FIELD.get(plugin)
        if ts_field and record.get(ts_field):
            record["@timestamp"] = record[ts_field]

        doc_id = _vol3_doc_id(index_name, plugin, record, source_file)

        record["host.name"] = hostname
        if hostname:
            if host_dict is not None:
                _resolved = host_dict.resolve(hostname)
                record["host.id"] = _resolved if _resolved else hostname
            else:
                record["host.id"] = hostname
        record["vhir.source_file"] = source_file
        record["vhir.parse_method"] = f"vol3-{plugin}"
        if ingest_audit_id:
            record["vhir.ingest_audit_id"] = ingest_audit_id
        if pipeline_version:
            record["pipeline_version"] = pipeline_version

        actions.append({"_index": index_name, "_id": doc_id, "_source": record})

        if len(actions) >= 500:
            flushed, failed = flush_bulk(client, actions)
            count += flushed
            bulk_failed += failed
            actions = []

    if actions:
        flushed, failed = flush_bulk(client, actions)
        count += flushed
        bulk_failed += failed

    return count, bulk_failed


def _register_memory_evidence(image_path: Path, hostname: str) -> None:
    """Register memory image via the gateway evidence_register tool (best-effort)."""
    try:
        from opensearch_mcp.gateway import call_tool

        call_tool(
            "evidence_register",
            {
                "path": str(image_path),
                "description": f"Memory image from {hostname} (vol3 analysis)",
            },
        )
    except Exception:
        pass


def ingest_memory(
    image_path: Path,
    client: OpenSearch,
    case_id: str,
    hostname: str,
    tier: int = 1,
    plugins: list[str] | None = None,
    timeout: int = 3600,
    ingest_audit_id: str = "",
    run_id: str = "",
    pipeline_version: str = "",
    on_progress=None,
    audit_log=None,
    host_dict=None,
) -> dict:
    """Run vol3 plugins and index results.

    When ``hostname`` is empty/falsy, attempts to auto-derive it from the
    memory image itself via vol3 (registry ComputerName, then envars COMPUTERNAME).
    If derivation fails the function returns the same structured error as before
    (hostname is required) so callers get a clear last-resort message.

    Returns dict with per-plugin results (includes ``"hostname_source"`` key
    indicating ``"operator"``, ``"registry"``, or ``"envars"`` so the agent
    can see which source was used).
    """
    if plugins is not None and len(plugins) > 0:
        plugin_list = plugins
    elif tier >= 3:
        plugin_list = TIER_3
    elif tier >= 2:
        plugin_list = TIER_2
    else:
        plugin_list = TIER_1

    # --- B-MVP-042: auto-derive hostname when operator did not supply one ---
    hostname_source: str
    if not hostname:
        derived, hostname_source = _derive_hostname_from_image(image_path, timeout=min(timeout, 120))
        if not derived:
            return {
                "error": "hostname is required for format='memory'.",
                "detail": (
                    "Auto-derivation was attempted (windows.registry.printkey + "
                    "windows.envars) but both probes returned nothing. "
                    "Supply hostname= explicitly."
                ),
                "next_step": (
                    "Call opensearch_ingest(..., format='memory', "
                    "hostname='<source-host>', dry_run=True)."
                ),
            }
        hostname = derived
    else:
        hostname_source = "operator"
    # --- end B-MVP-042 ---

    source_file = str(image_path)
    results: dict = {}

    vol_cmd = _find_vol3()

    # Pre-flight: check symbol availability by running windows.info
    # This catches missing symbols early with a clear error instead of
    # failing cryptically on the first real plugin.
    try:
        test_cmd = vol_cmd.split() + [
            "-f",
            str(image_path),
            "--renderer",
            "json",
            "-q",
            "windows.info",
        ]
        test = subprocess.run(test_cmd, capture_output=True, text=True, timeout=60)
        if "Unsatisfied" in test.stderr:
            print(
                "ERROR: Volatility 3 symbols not available for this image.\n"
                "  Download symbols: vol -f <image> windows.info\n"
                "  Or set symbol path: export VOLATILITY_SYMBOLS=/path/to/symbols/",
                file=sys.stderr,
            )
            return {"windows.info": {"status": "failed", "error": "Symbols not available"}}
    except subprocess.TimeoutExpired:
        pass  # Slow but not a symbol issue — continue

    _register_memory_evidence(image_path, hostname)

    for plugin in plugin_list:
        suffix = _plugin_to_index_suffix(plugin)
        from opensearch_mcp.paths import build_index_name as _build_idx

        index_name = _build_idx(case_id, suffix, hostname)

        if on_progress:
            on_progress("plugin_start", plugin=plugin, hostname=hostname)

        try:
            records = run_vol3_plugin(image_path, plugin, timeout=timeout)
        except (RuntimeError, subprocess.TimeoutExpired) as e:
            results[plugin] = {"status": "failed", "error": str(e)}
            if audit_log:
                audit_log(
                    tool=f"ingest_vol3_{suffix}",
                    params={
                        "plugin": plugin,
                        "image": source_file,
                        "hostname": hostname,
                        "index_name": index_name,
                        "run_id": run_id,
                    },
                    result_summary=f"FAILED: {e}",
                    input_files=[str(image_path)],
                )
            if on_progress:
                on_progress("plugin_failed", plugin=plugin, error=str(e))
            continue

        if not records:
            results[plugin] = {"status": "empty", "indexed": 0}
            if on_progress:
                on_progress("plugin_done", plugin=plugin, indexed=0)
            continue

        count, bf = _index_vol3_records(
            records=records,
            client=client,
            index_name=index_name,
            plugin=plugin,
            hostname=hostname,
            source_file=source_file,
            ingest_audit_id=ingest_audit_id,
            pipeline_version=pipeline_version,
            host_dict=host_dict,
        )
        results[plugin] = {"status": "complete", "indexed": count, "bulk_failed": bf}

        # Per-plugin success audit — run_id + index_name required for
        # resolver parser_step chaining (manager.py:1057, :1075).
        # bulk_failed surfaces silent rejection counts per plugin so a
        # shard-limit issue is visible in the audit trail, not only in
        # stderr warnings.
        if audit_log:
            audit_log(
                tool=f"ingest_vol3_{suffix}",
                params={
                    "plugin": plugin,
                    "image": source_file,
                    "hostname": hostname,
                    "index_name": index_name,
                    "run_id": run_id,
                    "bulk_failed": bf,
                },
                result_summary=f"{count} indexed, {bf} bulk failed",
                input_files=[str(image_path)],
            )

        if on_progress:
            on_progress("plugin_done", plugin=plugin, indexed=count)

    # Surface which source was used to determine the hostname so the agent can
    # see it in the MCP tool response (B-MVP-042).
    results["_meta"] = {"hostname": hostname, "hostname_source": hostname_source}
    return results
