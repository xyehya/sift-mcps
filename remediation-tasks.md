# Remediation Tasks — sift-mcps Backend Fixes

**Created:** 2026-05-25 (Session 39 workflow testing)
**Updated:** 2026-05-25 (Session 40 — full current state assessment + ingest pipeline inspection)
**References:** SIFT-MCPS-PLAN.md (spec), TASKS.md (execution checklist)
**Scope:** Backend bugs found during Phase 18-pre workflow testing. UI overhaul deferred.

---

## Authoritative Workflow (read before every session)

The ONE correct workflow. All code, tool descriptions, and error messages must reinforce this exactly.

```
1. SIFT VM SETUP      install.sh → sift-gateway starts → OpenSearch starts → portal at https://<VM>:4508/portal/
2. CASE INIT          Examiner opens portal → New Case → casename slug + title → portal creates
                      /cases/{casename}-{YYYYMMDD}-{HHMM}/ with all subdirs
                      → AGENTIR_CASE_DIR propagated to gateway + all 8 subprocesses
3. EVIDENCE COPY      Examiner physically copies evidence files to /cases/{case_id}/evidence/
                      (scp, USB, SMB — out-of-band; no MCP tool involved)
4. SEAL               Examiner opens portal → Evidence tab → Seal Manifest
                      → SHA-256 hashes computed → evidence-manifest.json + ledger written
5. AGENT STARTS       Hermes connects with service token → calls case_status → gets case_id,
                      evidence_dir, platform capabilities in one response
6. EVIDENCE SURVEY    Agent calls evidence_list → sees sealed evidence files + any unregistered
                      files in evidence/ with registered:false flag
7. INGEST             Agent calls idx_ingest(path="evidence/<filename>", hostname="<host>")
                      → gateway resolves relative path against AGENTIR_CASE_DIR
                      → subprocess mounts .e01 via ewfmount → discovers artifacts → indexes to OpenSearch
8. ANALYSIS           Agent uses idx_case_summary, idx_search, idx_aggregate, idx_timeline,
                      windows-triage-mcp, forensic-rag-mcp, opencti-mcp
9. FINDINGS           Agent calls record_finding (DRAFT) → Examiner reviews in portal → APPROVED
10. REPORT            Agent calls generate_report → save_report
```

Every tool error message, docstring, and instruction string must reference this workflow — never the old "agentir case activate" or "~/.agentir/active_case" CLI workflow.

---

## Confirmed Bug Inventory

| ID | Sev | Location | Description |
|----|-----|----------|-------------|
| B1 | CRITICAL | `opensearch-mcp/server.py:2693` `_get_active_case()` | Only reads `~/.agentir/active_case`; never checks `AGENTIR_CASE_DIR` env var |
| B2 | CRITICAL | `opensearch-mcp/server.py:1344–1352` `idx_ingest` | Bypasses `_get_active_case()` entirely; reads legacy file inline |
| B3 | HIGH | `opensearch-mcp/server.py:1396–1412` `idx_ingest` | Directory with `.e01` → "No Windows artifacts found" with no container hint |
| B4 | HIGH | `case-mcp` → `agentir-core/case_ops.py:72` `case_list` | Uses `AGENTIR_CASES_DIR` (not set); default `~/cases` doesn't exist on SIFT VM |
| B5 | HIGH | `opensearch-mcp/server.py:414` `_resolve_index()` | Calls `_get_active_case()` for index default — all search/agg tools inherit B1 |
| B6 | HIGH | `opensearch-mcp/ingest_cli.py:486` `_resolve_case_id()` | Uses `AGENTIR_CASES_DIR` (not set) with default `~/cases` — wrong root on SIFT VM |
| B7 | HIGH | `opensearch-mcp/ingest_cli.py:49-53` `_write_ingest_manifest()` | Reads `active_case` file directly — B2 class; writes manifest to wrong case |
| B8 | HIGH | `opensearch-mcp/containers.py:469` `make_ingest_tmpdir()` | Hardcodes tmpdir to `~/.agentir/cases/{case_id}/tmp/` — should be under actual case dir |
| B9 | MEDIUM | `sift-gateway/server.py` | Gateway process itself does not set `AGENTIR_CASE_DIR` in its own env (only subprocesses get it) |
| B10 | MEDIUM | All opensearch tool docstrings + error messages | Reference `~/.agentir/active_case`, "agentir case activate" — wrong workflow in LLM context |
| B11 | MEDIUM | `sift_common/instructions.py:90–113` GATEWAY string | Lists `case_init`, `case_activate`, `evidence_register` as active tools — all legacy/blocked |
| B12 | MEDIUM | `sift_common/instructions.py:166–172` CASE_MCP string | First sentence: "Use case_init to create cases and case_activate to switch" — wrong |
| B13 | LOW | `case-mcp` `case_status` response | Does not return `evidence_dir`, `extractions_dir` paths explicitly; LLM must guess |
| B14 | LOW | `case-mcp` `evidence_list` | Only returns manifest-registered files; unregistered files in evidence/ are invisible to LLM |
| B15 | LOW | `opensearch-mcp` 3 undocumented tools | `idx_shard_status`, `idx_install_pipelines`, `case_host_fix` not in original spec or TASKS.md |

---

## Settled Design Decisions (non-negotiable)

**D1 — `AGENTIR_CASE_DIR` is the single runtime source of truth for the active case**
All backends read `AGENTIR_CASE_DIR`. The `~/.agentir/active_case` file is a legacy CLI artifact.
No backend reads it as a primary source. It may remain as a last-resort CLI fallback (clearly
annotated) but must never shadow a set env var. On portal case switch, write new path to it for
CLI compat.

**D2 — Case directory structure: `/cases/{case_id}/` always**
- `case_id` format: `{casename}-{YYYYMMDD}-{HHMM}` (always includes time, no collision logic needed)
- Casename: lowercase, slugified at portal (`[a-z0-9-_]` only)
- Root from `gateway.yaml → case.root` (default `/cases`); propagated as `AGENTIR_CASES_ROOT`
- Portal enforces: user provides casename + title → portal computes case_id → no free-form directory

**D3 — Subdirectory auto-resolution: tools accept relative paths**
- `evidence/` relative paths are resolved against `AGENTIR_CASE_DIR` by every tool that accepts a path
- LLM passes `path="evidence/rocba-cdrive.e01"` not `/cases/test-rocba-2026/evidence/rocba-cdrive.e01`
- `case_status` returns `evidence_dir`, `extractions_dir`, `reports_dir` explicitly so LLM has them

**D4 — All 93 MCP tools (20 opensearch + others) audited before production**
No tool ships without passing the R4 audit criteria table.

**D5 — `AGENTIR_CASES_ROOT` env var added alongside `AGENTIR_CASE_DIR`**
Value: `Path(case_dir).parent`. Set by gateway in its own env and all subprocess envs.
Lets `case_list` and `_resolve_case_id()` find all cases without guessing the root.

**D6 — `evidence_list` shows ALL files in evidence/ directory**
Registered files: full manifest entry. Unregistered files: `{path, size_bytes, registered: false}`.
The LLM sees the full picture; the evidence gate blocks analysis tools on unsealed evidence regardless.

**D7 — case_status is the agent's entry point**
It returns: case_id, path, evidence_dir, extractions_dir, reports_dir, platform_capabilities,
finding/timeline/todo counts, indexed status hint. Agent calls this first on every session start.

---

## Closed Design Questions

| Q | Answer |
|---|--------|
| case_id collision | `{casename}-{YYYYMMDD}-{HHMM}` always includes time — no collision |
| active_case on switch | Portal writes new path to `~/.agentir/active_case` on case activation (CLI compat) |
| idx_ingest path | Accept relative path; resolve against AGENTIR_CASE_DIR; LLM uses evidence/filename |
| cases root | Configurable in gateway.yaml (`case.root`), propagated as `AGENTIR_CASES_ROOT` |
| Lowercase enforcement | Enforced at portal creation; `_get_active_case()` lowercases result |
| Unregistered files | Shown in evidence_list with `registered: false`; gate blocks tools anyway |
| case_tree tool | Not needed if evidence_list shows unregistered files + case_status returns explicit paths |

---

## Ingest Pipeline — E01 Deep Inspection

### What happens when `idx_ingest(path="evidence/rocba-cdrive.e01", dry_run=False)` executes

**Step 1: server.py `idx_ingest()` wrapper**
1. `_get_active_case()` → reads `AGENTIR_CASE_DIR` (after B1 fix)
2. `detect_container(path)` → `"ewf"` (matched by `.e01` extension)
3. If `dry_run=True`: returns `{status: "preview", container: {type, file, size_mb}, case_id}` — WORKS
4. If `dry_run=False`: launches background subprocess via `agentir_plugin` → `cmd_ingest` → `cmd_scan`

**Step 2: `cmd_scan` (ingest_cli.py) — the actual ingest process**
1. `_resolve_case_id()` → reads `AGENTIR_CASES_DIR` env or `~/cases` default ← **B6 bug**
2. `detect_container()` → `"ewf"`
3. `cleanup_orphaned_mounts()` → disconnects stale `/dev/nbdX` devices
4. `make_ingest_tmpdir(case_id)` → creates temp dir under `~/.agentir/cases/{case_id}/tmp/` ← **B8 bug**
5. `mount_image(e01_path, tmpdir, ctx)`:
   - `_mount_ewf()`: `ewfmount <e01> <tmpdir/_ewf/>` ← **requires ewfmount (libewf-tools)**
   - `_mount_raw_partitions(ewf1)`: `fdisk -l <ewf1>` → parse NTFS partition offsets
   - `sudo mount -o ro,loop,offset=<N>,noexec <ewf1> <vol0>` ← **requires passwordless sudo for mount**
6. `detect_hostname_from_volume(vol0)` → reads SYSTEM hive from `vol0/Windows/System32/config/SYSTEM`
   → extracts `ComputerName` and `Domain` ← **requires Python hive parsing (python-registry or regipy)**
7. `discover(scan_root, hostname, force_hn=True)` → `scan_triage_directory(tmpdir)`
   → looks for Windows artifact structure under mounted volume
8. `_preflight_host_discovery(case_id, scan_root, hosts)` → hostname normalization
9. `ingest(hosts, client, audit, case_id, ...)` → artifact parsing loop:

**Step 3: Artifact parsing — tools called per artifact type**

| Artifact | Parser/Tool | Binary Required | Index suffix |
|----------|-------------|-----------------|--------------|
| evtx | `parse_evtx.py` (python-evtx) | none (pure Python) | `evtx` |
| amcache | AmcacheParser (Zimmerman) | `AmcacheParser` | `amcache` |
| shimcache | AppCompatCacheParser (Zimmerman) | `AppCompatCacheParser` | `shimcache` |
| registry | RECmd (Zimmerman) | `RECmd` | `registry` |
| mft | MFTECmd (Zimmerman) | `MFTECmd` | `mft` |
| usn | MFTECmd (Zimmerman) | `MFTECmd` | `usn` |
| recyclebin | RECmd or custom | `RECmd` | `recyclebin` |
| shellbags | SBECmd (Zimmerman) | `SBECmd` | `shellbags` |
| jumplists | JLECmd (Zimmerman) | `JLECmd` | `jumplists` |
| lnk | LECmd (Zimmerman) | `LECmd` | `lnk` |
| prefetch | `parse_prefetch.py` (custom) | none (pure Python) | `prefetch` |
| srum | `parse_srum.py` (custom) | none (pure Python) | `srum` |
| transcripts | `parse_transcripts.py` (custom) | none | `transcripts` |
| defender | `parse_defender.py` (custom) | none | `defender` |
| iis/httperr | `parse_w3c.py` (custom) | none | `iis`, `httperr` |
| tasks | `parse_tasks.py` (custom) | none | `tasks` |
| wer | `parse_wer.py` (custom) | none | `wer` |
| firewall | `parse_w3c.py` (custom) | none | `firewall` |
| ssh | `parse_ssh.py` (custom) | none | `ssh` |

**Step 4: Post-ingest**
- `run_hayabusa_batch()`: `hayabusa csv-timeline` on evtx dir ← **requires hayabusa binary + rules**
- `enrich_remote()`: triage enrichment via windows-triage-mcp backend

**Step 5: Cleanup**
- `mount_ctx.cleanup()`: `fusermount -u <ewf_mount>`, `sudo umount <vol0>`
- `cleanup_tmpdir(tmpdir)`: `shutil.rmtree(tmpdir)`

### Why the E01 did NOT ingest (root cause chain)

The MCP call `idx_ingest(path="/cases/test-rocba-2026/evidence/", dry_run=True)` was a DIRECTORY,
not the .e01 file directly. The directory code path calls `discover()` which calls
`scan_triage_directory()` which looks for Windows artifact subdirectory structure inside the
directory — not for container files. It found nothing → "No Windows artifacts found" (B3).

Even if B3 were fixed and the right path used:
- B2: `idx_ingest` would read wrong case_id from `~/.agentir/active_case`
- B6: `cmd_scan` subprocess would fail to find the case dir at `~/cases/test-rocba-2026` (doesn't exist)
- B8: tmpdir would be created under `~/.agentir/cases/test-rocba-2026/tmp/` (doesn't exist)

### Binary/Tool Prerequisites to verify before Phase R6

Run this on SIFT VM before integration testing:

```bash
# Mount tools
which ewfmount || echo "MISSING: libewf-tools (apt install libewf-dev)"
sudo -n mount --version 2>/dev/null || echo "MISSING: passwordless sudo for mount"
which fusermount || echo "MISSING: fuse"
which fdisk || echo "MISSING: fdisk (util-linux)"

# Zimmerman tools
which AmcacheParser && AmcacheParser --version || echo "MISSING: AmcacheParser"
which AppCompatCacheParser && AppCompatCacheParser --version || echo "MISSING: AppCompatCacheParser"
which RECmd && RECmd --version || echo "MISSING: RECmd"
which MFTECmd && MFTECmd --version || echo "MISSING: MFTECmd"
which JLECmd && JLECmd --version || echo "MISSING: JLECmd"
which LECmd && LECmd --version || echo "MISSING: LECmd"
which SBECmd && SBECmd --version || echo "MISSING: SBECmd"

# Detection
which hayabusa || echo "MISSING: hayabusa"
ls /usr/local/share/hayabusa-rules/config 2>/dev/null || echo "MISSING: hayabusa-rules"

# Python libraries (for evtx, prefetch, srum, registry parsing)
python3 -c "import evtx" || echo "MISSING: python-evtx (pip install python-evtx)"
python3 -c "import regipy" || echo "MISSING: regipy (pip install regipy)"

# OpenSearch
curl -s https://localhost:9200/_cluster/health?pretty 2>/dev/null | grep status || echo "MISSING: OpenSearch"
```

Add this as `scripts/verify-ingest-prereqs.sh` and run it as part of install.sh validation.

---

## Phase R0 — Immediate Critical Fixes (1 session)

Goal: make the basic workflow function — case resolves correctly, evidence is visible, ingest starts.

### R0-1: Fix `_get_active_case()` — env var first, file fallback

File: `packages/opensearch-mcp/src/opensearch_mcp/server.py:2693`

```python
def _get_active_case() -> str | None:
    """Return active case ID for index construction.

    Portal workflow: reads AGENTIR_CASE_DIR set by gateway in every
    stdio subprocess environment. CLI fallback: reads ~/.agentir/active_case.
    Returns None when neither source is set — callers must handle this.
    """
    import os
    from pathlib import Path

    # Primary: AGENTIR_CASE_DIR set by gateway in every stdio subprocess env
    case_dir = os.environ.get("AGENTIR_CASE_DIR", "").strip()
    if case_dir:
        return Path(case_dir).name.lower()  # lowercase required for OpenSearch indices

    # Legacy CLI fallback — not used in portal workflow
    from opensearch_mcp.paths import agentir_dir
    active_case = agentir_dir() / "active_case"
    if active_case.exists():
        raw = active_case.read_text().strip()
        if raw:
            return Path(raw).name.lower()
    return None
```

Tests:
- `test_get_active_case_env_var_wins`: env var set → returns its basename, lowercased
- `test_get_active_case_fallback_to_file`: env var absent, file present → returns file basename
- `test_get_active_case_env_var_beats_stale_file`: env var set + stale file → env var wins
- `test_get_active_case_returns_none_when_neither_set`: both absent → None

### R0-2: Fix `idx_ingest` inline case read (lines 1344–1352)

Replace the 9-line inline block with:
```python
case_id = _get_active_case()
if not case_id:
    return {
        "error": "No active case.",
        "action": "Create a case in the Examiner Portal first.",
        "portal_hint": "Open https://<SIFT_VM>:4508/portal/ → New Case → complete intake → seal evidence.",
    }
```

Also update `idx_ingest` docstring line 1306–1308 — remove the sentence:
> "Case ID is read from ~/.agentir/active_case. Not accepted as a parameter — set via 'agentir case activate'."

Replace with:
> "Case ID resolved from the active case set in the Examiner Portal. No parameter needed."

### R0-3: Fix `idx_ingest` container-in-directory detection (B3)

In `idx_ingest` in server.py, the directory path branch (where `discover()` returns no hosts):
add container scan before returning the "No Windows artifacts found" error.

```python
# --- container-in-directory detection (B3 fix) ---
if not hosts and evidence_path.is_dir():
    from opensearch_mcp.containers import detect_container
    containers_found = []
    try:
        for f in sorted(evidence_path.iterdir()):
            if f.is_file():
                ctype = detect_container(f)
                if ctype in ("ewf", "raw", "nbd", "archive"):
                    containers_found.append({
                        "path": str(f),
                        "relative_path": str(f.relative_to(evidence_path.parent.parent))
                            if evidence_path.name == "evidence" else str(f),
                        "type": ctype,
                        "size_mb": round(f.stat().st_size / 1_048_576),
                    })
    except OSError:
        pass
    if containers_found:
        return {
            "status": "containers_detected",
            "case_id": case_id,
            "message": (
                f"The directory contains {len(containers_found)} forensic container file(s). "
                "Re-run idx_ingest with the container file path directly."
            ),
            "containers": containers_found,
            "next_step": (
                f"Call idx_ingest(path=\"{containers_found[0]['relative_path']}\", "
                f"hostname=\"<hostname>\", dry_run=True) to preview ingest."
            ),
        }
```

Tests:
- `test_idx_ingest_directory_with_e01_returns_containers_detected`
- `test_idx_ingest_directory_with_multiple_containers`
- `test_idx_ingest_directory_empty_returns_error`
- `test_idx_ingest_directory_no_containers_preserves_original_error`

### R0-4: Fix `case_list` returning empty (B4)

`case_list()` → `_case_list_data()` in `agentir-core/case_ops.py` uses `AGENTIR_CASES_DIR`.
That env var is not set by gateway. Fix: also check `AGENTIR_CASES_ROOT` (new var, D5).

In `agentir-core/src/agentir_core/case_ops.py:72`:
```python
def case_list_data(cases_dir=None) -> dict:
    if cases_dir is None:
        # Try AGENTIR_CASES_ROOT first (set by gateway from case_dir parent)
        # then AGENTIR_CASES_DIR (legacy), then default ~/cases
        root = (
            os.environ.get("AGENTIR_CASES_ROOT")
            or os.environ.get("AGENTIR_CASES_DIR")
            or DEFAULT_CASES_DIR
        )
        cases_dir = Path(root)
```

Also update `case_list` response to include `active_case_dir` and `cases_root` fields.

Tests:
- `test_case_list_reads_agentir_cases_root`
- `test_case_list_falls_back_to_agentir_cases_dir`
- `test_case_list_marks_active_case_correctly`
- `test_case_list_returns_all_case_yaml_dirs`

### R0-5: Fix `case_status` response — add explicit paths (B13)

In `agentir-core/case_ops.py` `case_status_data()`, add to the returned dict:
```python
"evidence_dir": str(case_dir / "evidence"),
"extractions_dir": str(case_dir / "extractions"),
"reports_dir": str(case_dir / "reports"),
"audit_dir": str(case_dir / "audit"),
```

This gives the LLM explicit paths on every startup. No guessing.

Tests:
- `test_case_status_includes_evidence_dir`
- `test_case_status_paths_all_exist`

### R0-6: Fix `evidence_list` — show unregistered files (B14)

In `case-mcp/server.py` `evidence_list()`, after loading manifest entries, scan `evidence/` for
additional files not in the manifest:

```python
# Scan actual evidence dir for unregistered files
evidence_dir = case_dir / "evidence"
registered_paths = {f["path"] for f in active_files}
unregistered = []
if evidence_dir.is_dir():
    for f in sorted(evidence_dir.iterdir()):
        if f.is_file() and str(f) not in registered_paths:
            unregistered.append({
                "path": str(f),
                "relative_path": f"evidence/{f.name}",
                "size_bytes": f.stat().st_size,
                "registered": False,
                "note": "File not sealed. Seal via Examiner Portal → Evidence tab before indexing.",
            })

return {
    "evidence": active_files,
    "unregistered": unregistered,
    "manifest_version": manifest.get("version", 0),
    "source": "manifest_v2",
}
```

Tests:
- `test_evidence_list_shows_unregistered_files`
- `test_evidence_list_registered_flag_correct`
- `test_evidence_list_unregistered_does_not_leak_manifest_details`

### R0-7: Fix `make_ingest_tmpdir()` — use actual case dir (B8)

File: `packages/opensearch-mcp/src/opensearch_mcp/containers.py:462`

```python
def make_ingest_tmpdir(case_id: str) -> Path:
    """Create temp dir for container extraction under the actual case directory."""
    import os
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")

    # Use AGENTIR_CASE_DIR if set (portal workflow); else fall back to AGENTIR_CASES_ROOT/case_id
    case_dir_env = os.environ.get("AGENTIR_CASE_DIR", "").strip()
    if case_dir_env:
        case_dir = Path(case_dir_env)
    else:
        cases_root = Path(os.environ.get("AGENTIR_CASES_ROOT",
                          os.environ.get("AGENTIR_CASES_DIR", str(Path.home() / "cases"))))
        case_dir = cases_root / case_id

    tmp = case_dir / "tmp" / f"ingest-{ts}-{os.getpid()}"
    tmp.mkdir(parents=True, exist_ok=True)
    return tmp
```

Tests:
- `test_make_ingest_tmpdir_uses_agentir_case_dir`
- `test_make_ingest_tmpdir_falls_back_to_cases_root`

### R0-8: Fix `_write_ingest_manifest()` — use AGENTIR_CASE_DIR (B7)

File: `packages/opensearch-mcp/src/opensearch_mcp/ingest.py:27–86`

Replace the `active_case_file` read (lines 50-55) with:
```python
import os
case_dir_env = os.environ.get("AGENTIR_CASE_DIR", "").strip()
if case_dir_env:
    case_dir = Path(case_dir_env)
else:
    # Legacy CLI fallback
    active_case_file = agentir_dir() / "active_case"
    if not active_case_file.exists():
        return
    case_dir = Path(active_case_file.read_text().strip())
if not case_dir.is_dir():
    return
```

### R0-9: Fix `_resolve_case_id()` in ingest_cli.py — use AGENTIR_CASES_ROOT (B6)

File: `packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py:486`

```python
cases_root = Path(
    os.environ.get("AGENTIR_CASES_ROOT")
    or os.environ.get("AGENTIR_CASES_DIR")
    or str(Path.home() / "cases")
)
```

Same fix in `_case_dir_for()` at line 43.

---

## Phase R1 — Propagation Hardening (1 session)

### R1-1: Gateway sets `AGENTIR_CASE_DIR` and `AGENTIR_CASES_ROOT` in its own env

File: `packages/sift-gateway/src/sift_gateway/server.py`

On startup (reading `gateway.yaml → case.dir`) and on every portal case switch:
```python
import os
from pathlib import Path
os.environ["AGENTIR_CASE_DIR"] = str(case_dir)
os.environ["AGENTIR_CASES_ROOT"] = str(Path(case_dir).parent)
```

This fixes B9 — gateway's own process env was missing both vars.

### R1-2: Assert env vars in subprocess launch

In wherever stdio backends are spawned, add explicit assertion before `Popen`:
```python
env = os.environ.copy()
assert "AGENTIR_CASE_DIR" in env, "BUG: AGENTIR_CASE_DIR not in env before launching backend"
assert "AGENTIR_CASES_ROOT" in env, "BUG: AGENTIR_CASES_ROOT not in env before launching backend"
```

### R1-3: Full `active_case` sweep — find and tag every read

Run:
```bash
grep -rn "active_case\|agentir_dir.*active\|agentir case activate" \
  packages/ --include="*.py" | grep -v "test_\|# Legacy CLI fallback\|# legacy"
```

For every hit: replace primary read with `AGENTIR_CASE_DIR`, add `# Legacy CLI fallback` comment on file-based fallbacks, update error messages to portal workflow.

Files confirmed to need sweep after R0:
- `ingest_cli.py`: `_ensure_case_active()` line 504 — reads file + tries gateway call_tool
- Any remaining reads in `server.py` not covered by R0-1/R0-2

### R1-4: Portal case switch writes `active_case` for CLI compat

In gateway portal case-switch handler: after propagating `AGENTIR_CASE_DIR`, also write:
```python
active_case_file = Path.home() / ".agentir" / "active_case"
active_case_file.parent.mkdir(parents=True, exist_ok=True)
active_case_file.write_text(str(case_dir))
```

### R1-5: Tests
- `test_gateway_sets_both_env_vars_on_startup`
- `test_gateway_sets_both_env_vars_on_case_switch`
- `test_subprocess_env_contains_agentir_case_dir`
- `test_subprocess_env_contains_agentir_cases_root`
- `test_portal_case_switch_writes_active_case_file`

---

## Phase R2 — Case Directory Canonicalization (1 session)

### R2-1: Portal case create API — enforce `{casename}-{YYYYMMDD}-{HHMM}`

File: `packages/case-dashboard/src/case_dashboard/routes.py`

Changes to `POST /api/v1/case/create`:
1. Accept: `casename` (slug), `title` (display name). Reject free-form `directory` field.
2. Slugify: lowercase, replace non-`[a-z0-9-_]` with hyphen, collapse repeated hyphens, strip leading/trailing hyphens.
3. Auto-compute: `case_id = f"{slugify(casename)}-{now.strftime('%Y%m%d-%H%M')}"`
4. Auto-compute: `directory = f"{cases_root}/{case_id}"` — not user-editable.
5. Validate: `case_id` matches `^[a-z][a-z0-9-_]{2,63}$`.
6. Lowercase enforcement at creation — reject mixed-case casename with clear message.

### R2-2: Path containment guard in gateway

In case create handler: `Path(case_dir).resolve().is_relative_to(Path(cases_root).resolve())`.
Return 400 if case dir would escape cases_root. This prevents path traversal via API.

### R2-3: `case_init` and `case_activate` in case-mcp — mark as legacy

These tools are LEGACY in portal-first workflow. Update their docstrings:
```
LEGACY: This tool is provided for CLI compatibility only.
In the portal-first workflow, cases are created via the Examiner Portal.
Calling this tool will create a directory outside the portal-managed structure.
```

Do NOT remove them (CLI compat). But ensure their `next_steps` guidance says to use the portal.

### R2-4: Tests
- `test_portal_case_create_computes_case_id_with_time`
- `test_portal_case_create_lowercases_casename`
- `test_portal_case_create_rejects_free_form_directory`
- `test_portal_case_create_rejects_path_traversal`
- `test_case_id_format_validation_regex`

---

## Phase R3 — Path Auto-Resolution in Tools (1–2 sessions)

### R3-1: Add standard path resolution to AGENTS.md rules

All tools that accept a `path` argument follow this priority:
1. Absolute path under `AGENTIR_CASE_DIR` → use as-is, verify containment
2. Relative path starting with known subdir (`evidence/`, `extractions/`, `reports/`, `audit/`) → prepend `AGENTIR_CASE_DIR`
3. Bare filename → prepend `AGENTIR_CASE_DIR/evidence/` (default; tool docstring must state this)
4. Empty/None → tool-specific documented default
5. Any path outside `AGENTIR_CASE_DIR` → `{"error": "Path must be within the case directory"}`

### R3-2: `resolve_case_path()` in agentir-core

File: `packages/agentir-core/src/agentir_core/case_io.py`

```python
_CASE_SUBDIRS = frozenset(["evidence", "extractions", "reports", "audit", "tmp"])

def resolve_case_path(path: str, *, case_dir: Path | None = None,
                      default_subdir: str = "evidence") -> Path:
    """Resolve a path argument against the active case directory.

    Raises ValueError on path traversal or missing active case.
    """
    import os
    if case_dir is None:
        env = os.environ.get("AGENTIR_CASE_DIR", "").strip()
        if not env:
            raise ValueError("No active case. Use the Examiner Portal to create a case first.")
        case_dir = Path(env)

    p = Path(path)
    if p.is_absolute():
        resolved = p.resolve()
    elif p.parts and p.parts[0] in _CASE_SUBDIRS:
        resolved = (case_dir / p).resolve()
    else:
        resolved = (case_dir / default_subdir / p).resolve()

    try:
        resolved.relative_to(case_dir.resolve())
    except ValueError:
        raise ValueError(
            f"Path {path!r} resolves outside case directory. "
            "Use a relative path like 'evidence/filename.e01'."
        )
    return resolved
```

Tests: absolute, relative, subdir-relative, bare filename, traversal attack (`../../../etc`).

### R3-3: Wire `resolve_case_path()` into tools that need it

Priority order:
1. `idx_ingest` — `path` arg (highest impact, used in every investigation)
2. `idx_ingest_json`, `idx_ingest_delimited`, `idx_ingest_accesslog`, `idx_ingest_memory`
3. `run_command` in sift-mcp — `working_dir` default should be `AGENTIR_CASE_DIR`
4. `save_report` in report-mcp — output path

### R3-4: Add `_case` context to all case-scoped tool responses

For every tool that returns case-scoped data, include:
```python
"_case": {
    "id": case_id,
    "dir": str(case_dir),
    "evidence_dir": str(case_dir / "evidence"),
}
```

Gateway can inject this via response middleware rather than requiring every tool to add it.

---

## Phase R4 — Tool Registry Audit: All 93 Tools (2 sessions)

### Audit Criteria (apply to every tool)

| Check | Pass Criteria |
|-------|---------------|
| **Description** | No `active_case`, no `agentir case activate`, no `~/.agentir/`; accurate portal-first language |
| **Required args** | Only args the LLM cannot auto-resolve; path args accept relative paths |
| **Error messages** | Reference portal, not CLI; include `portal_hint` with URL when relevant |
| **Return format** | Structured dict; never bare string for errors; `case_id` field present |
| **`readOnlyHint`** | `True` for all query/list/status/verify tools; absent/False for write/exec tools |
| **Evidence gate** | Read-only tools work when UNSEALED; analysis/exec tools blocked until SEALED |
| **next_step field** | All error responses include what the LLM should do next |
| **Audit log** | Write ops logged to `AGENTIR_CASE_DIR/audit/{backend}.jsonl` |

### R4-1: Update `sift_common/instructions.py` — highest LLM impact

**GATEWAY string (line 90):** Remove `case_init`, `case_activate`, `evidence_register` from routing. Rewrite to:
```
"Case lifecycle (portal-managed): case_status, case_list, evidence_list, evidence_verify. "
"Evidence gate: SEALED state required for analysis tools; UNSEALED allows read-only tools only. "
"Path convention: idx_ingest and run_command accept relative paths under evidence/ — "
"the gateway resolves them against the active case directory. "
"Do not call case_init, case_activate, or evidence_register — these are portal-managed. "
```

**CASE_MCP string (line 166):** Rewrite:
```
"Case status and evidence tools for the Valhuntir forensic investigation platform. "
"Cases are created and activated via the Examiner Portal, not via case_init/case_activate. "
"Start every session with case_status to get case_id, evidence_dir, and platform capabilities. "
"Use evidence_list to see sealed evidence and any unregistered files in evidence/. "
"evidence_register is blocked — seal evidence via the portal Evidence tab. "
```

**OPENSEARCH string (line 143):** Add:
```
"idx_ingest accepts relative paths: path='evidence/disk.e01' resolves against the active case dir. "
"Always pass case_id explicitly to idx_search/idx_aggregate — retrieve it from case_status first. "
```

### R4-2: opensearch-mcp — 20 tools

Session 4A (query tools 1–10):

| Tool | Action needed |
|------|---------------|
| `idx_search` | Add `readOnlyHint=True`; docstring: "Pass case_id explicitly (get from case_status). Default resolves from env var." |
| `idx_count` | Add `readOnlyHint=True`; same note |
| `idx_aggregate` | Add `readOnlyHint=True`; same note |
| `idx_timeline` | Add `readOnlyHint=True`; same note |
| `idx_field_values` | Add `readOnlyHint=True`; same note |
| `idx_get_event` | Add `readOnlyHint=True` |
| `idx_status` | Add `readOnlyHint=True`; note that it shows all indices, not just active case |
| `idx_case_summary` | Add `readOnlyHint=True`; docstring: "First call in any indexed investigation. Pass case_id from case_status." |
| `idx_shard_status` | Needs spec: describe what it returns, when to call it, add `readOnlyHint=True` |
| `idx_install_pipelines` | Needs spec: admin-only? add clear description, correct annotation |

Session 4B (ingest/enrich/detection + legacy tools):

| Tool | Action needed |
|------|---------------|
| `idx_ingest` | R0-2/R0-3 done; verify all error paths have `portal_hint`, `next_step` |
| `idx_ingest_status` | Update error message; add `readOnlyHint=True` |
| `idx_ingest_json` | Path auto-resolution (R3-3); error messages |
| `idx_ingest_delimited` | Path auto-resolution (R3-3); error messages |
| `idx_ingest_accesslog` | Path auto-resolution (R3-3) |
| `idx_ingest_memory` | Error messages |
| `idx_enrich_triage` | Error messages |
| `idx_enrich_intel` | Error messages |
| `idx_list_detections` | Add `readOnlyHint=True` |
| `case_host_fix` | Needs spec: what is this? when does LLM call it? is it admin-only? |

### R4-3: case-mcp — 15 tools

| Tool | Action needed |
|------|---------------|
| `case_list` | R0-4 done; verify response includes `cases_root`, `active_case_dir` |
| `case_status` | R0-5 done; verify all path fields present |
| `evidence_list` | R0-6 done; verify unregistered + `relative_path` fields |
| `evidence_verify` | Add `readOnlyHint=True`; verify description is accurate |
| `evidence_register` | Blocked correctly; verify `portal_hint` is clear |
| `case_init` | Mark LEGACY; update docstring; keep for CLI compat |
| `case_activate` | Mark LEGACY; update docstring; keep for CLI compat |
| `audit_summary` | Add `readOnlyHint=True`; consider adding time-range filter |
| `export_bundle` | Add `readOnlyHint=True`; update description |
| `import_bundle` | Verify description, confirm CONFIRM annotation |
| `record_action` | Verify AUTO annotation |
| `log_reasoning` | Verify AUTO annotation |
| `log_external_action` | Verify AUTO annotation |
| `backup_case` | Verify CONFIRM annotation |
| `open_case_dashboard` | Verify description is useful for agent; is it even callable by agent? |

### R4-4: sift-mcp — 5 tools

- `run_command`: verify `working_dir` defaults to `AGENTIR_CASE_DIR`; verify `save_output` path
- `list_available_tools`: `readOnlyHint=True`
- `get_tool_help`: `readOnlyHint=True`
- `check_tools`: `readOnlyHint=True`
- `suggest_tools`: `readOnlyHint=True`

### R4-5: Remaining backends — 40 tools (lower risk)

forensic-mcp (9 core): verify record_finding/record_timeline_event blocks on UNSEALED; get_* all have `readOnlyHint=True`

report-mcp (6): verify `generate_report` only surfaces APPROVED findings; `readOnlyHint` correct

forensic-rag-mcp (3): `readOnlyHint=True` on all; descriptions accurate

windows-triage-mcp (13): verify no case-path dependency; `readOnlyHint=True` on all check_* tools

opencti-mcp (8): `readOnlyHint=True` on all; verify no case-path dependency

---

## Phase R5 — Legacy Code Review Methodology (1 session)

### R5-1: Automated Forbidden Pattern Gate

Create `scripts/remediation-gate.sh`:

```bash
#!/usr/bin/env bash
# remediation-gate.sh — run from repo root before every commit
set -e
FAIL=0

echo "=== B-class: legacy active_case primary reads ==="
if grep -rn "active_case\b" packages/ --include="*.py" \
   | grep -v "test_\|# Legacy CLI fallback\|# legacy\|active_case_file\|active_case_dir"; then
  echo "FAIL: untagged active_case reads"; FAIL=1
fi

echo "=== B10/B11 class: legacy workflow strings in LLM-visible text ==="
if grep -rn '"agentir case activate\|agentir case init\|~/.agentir/active_case' \
   packages/ --include="*.py" | grep -v "test_\|#"; then
  echo "FAIL: legacy CLI workflow strings in tool descriptions/errors"; FAIL=1
fi

echo "=== sys.exit in agentir-core ==="
if grep -rn "sys\.exit" packages/agentir-core/ --include="*.py"; then
  echo "FAIL: sys.exit in agentir-core (raise exceptions instead)"; FAIL=1
fi

echo "=== shell=True outside sift-mcp ==="
if grep -rn "shell=True" packages/ --include="*.py" \
   | grep -v "packages/sift-mcp\|test_"; then
  echo "FAIL: shell=True outside sift-mcp"; FAIL=1
fi

echo "=== vhir namespace ==="
if grep -rn "\bvhir\b\|\bVHIR\b" packages/ --include="*.py" | grep -v "\.vhir\b"; then
  echo "FAIL: vhir namespace leak"; FAIL=1
fi

echo "=== Tool responses: bare string errors ==="
if grep -rn 'return ".*error\|return f".*error' packages/*/src/ --include="*.py" \
   | grep -v "test_\|#"; then
  echo "WARN: bare string error returns (should be dicts)"; # FAIL=1 after R4
fi

exit $FAIL
```

### R5-2: Pre-Import Checklist for Any Code from Valhuntir

Before merging any function adapted from the original Valhuntir repo:
- [ ] Does not read `~/.agentir/active_case` as primary → replaced with `AGENTIR_CASE_DIR`
- [ ] Does not call `sys.exit()` → raises typed exception
- [ ] Does not use `shell=True` outside sift-mcp
- [ ] Does not hardcode `/var/lib/agentir`, `~/.agentir/cases/`, or `~/cases` without env var override
- [ ] Error messages reference portal workflow, not CLI commands
- [ ] Tool description is accurate for portal-first workflow
- [ ] `readOnlyHint` annotation correct per R4 criteria
- [ ] Returns structured dict; never bare string for errors
- [ ] Includes `next_step` or `portal_hint` in error responses
- [ ] Has tests: happy path + missing-case error + wrong-path error

| Backend | Adapted From | Primary Risk | Status after R4 |
|---------|-------------|--------------|-----------------|
| opensearch-mcp | Valhuntir | B1/B2/B3/B6/B7/B8/B10 | ✅ R0 fixes + R1/R4 completed (structured errors, R4 docstrings, readOnlyHint) |
| case-mcp | Valhuntir/new | B4/B12/B13/B14 | ✅ R0 fixes + R4-3 completed (hidden case_init/activate, new case_file_structure tool) |
| sift-mcp | Valhuntir | Sanitization done (Phase 6); path defaults | ✅ R4-4 completed (strict output constraints under extractions/ or tmp/) |
| forensic-mcp | Valhuntir | Phases 0–15 sweep done | ✅ R4-5 completed (active case env priority) |
| report-mcp | Valhuntir | Phase 16d done | ✅ R4-5 completed (active case env priority) |
| forensic-rag-mcp | Valhuntir | Phase 5 migration done | ✅ R4-5 verified |
| windows-triage-mcp | new | Phase 11 done; no case-path dependency expected | ✅ R4-5 verified (SQLite-backed local baseline) |
| opencti-mcp | external | No case-path dependency expected | ✅ R4-5 verified |
| agentir-core | new (Phases 2/12/16) | 225 tests; R8 gates pass | ✅ R0 additions + 225 tests passing |

### R5-4: Env Var Smoke Test (add to every backend's test suite)

```python
def test_resolves_case_from_env_not_file(tmp_path, monkeypatch):
    """Backend reads AGENTIR_CASE_DIR, never the legacy active_case file."""
    case_dir = tmp_path / "test-case-20260525-1200"
    case_dir.mkdir()
    monkeypatch.setenv("AGENTIR_CASE_DIR", str(case_dir))
    # Explicitly do NOT create ~/.agentir/active_case
    result = _get_active_case()  # or equivalent per backend
    assert result == "test-case-20260525-1200"

def test_no_active_case_returns_none(monkeypatch):
    monkeypatch.delenv("AGENTIR_CASE_DIR", raising=False)
    result = _get_active_case()
    assert result is None
```

---

## Phase R6 — Integration Validation Matrix (1 session)

Run after R0–R5. This is the Phase 18-pre gate from TASKS.md.

### Pre-conditions

Run the prereq check first:
```bash
bash scripts/verify-ingest-prereqs.sh
```
All items must pass. Missing Zimmerman tools or ewfmount = fix install.sh, not the code.

### Workflow Under Test

```
1. fresh sift-gateway restart (picks up R0–R5 changes)
2. portal case create: casename=rocba-r6test → auto case_id rocba-r6test-{YYYYMMDD}-{HHMM}
3. physical copy: cp rocba-cdrive.e01 /cases/rocba-r6test-{case_id}/evidence/
4. portal Evidence tab: Seal Manifest
5. MCP tool calls via service token (curl or Python test client)
```

### Validation Matrix

| # | Tool Call | Expected | Verifies |
|---|-----------|----------|----------|
| 1 | GET `/health` | all backends `ok` | gateway + 8 backends live |
| 2 | `case_status()` | `case_id=rocba-r6test-...`, `evidence_dir=/cases/.../evidence` | D7, B13 fix |
| 3 | `case_list()` | lists at least 1 case; `is_active=true` for current | B4 fix |
| 4 | `evidence_list()` | sealed .e01 entry + `registered:true`; no unregistered files | D6 |
| 5 | `evidence_verify()` | `status=ok`, 1 file verified | evidence chain |
| 6 | `idx_ingest(path="evidence/", dry_run=True)` | `status=containers_detected`, 1 container, `next_step` | B3 fix |
| 7 | `idx_ingest(path="evidence/rocba-cdrive.e01", dry_run=True)` | `status=preview`, correct `case_id`, no legacy error | B1+B2 fix |
| 8 | `idx_ingest(path="evidence/rocba-cdrive.e01", dry_run=True)` BEFORE seal | `blocked: true, reason: evidence_chain_unsealed` | evidence gate |
| 9 | `idx_case_summary(case_id="rocba-r6test-...")` | returns valid structure, no "agentir case activate" | B1+B5 fix |
| 10 | `idx_search(query="*", case_id="rocba-r6test-...")` | returns valid (possibly 0 docs if not ingested yet) | B5 fix |
| 11 | `evidence_register(path="...")` | `blocked: true`, `portal_hint` present | Phase 16c |
| 12 | Case switch via portal → `case_list()` | new case shown as active | B4 + R1-4 |
| 13 | Revoke service token → any tool | `403 Forbidden` | token auth |
| 14 | `generate_report(profile="status")` | includes evidence chain status | Phase 16d |
| 15 | `idx_ingest(path="evidence/rocba-cdrive.e01", dry_run=False)` | ingest starts (B6/B8 fix) | full E01 pipeline |
| 16 | `idx_ingest_status(case_id="...")` after #15 | shows progress | ingest pipeline |
| 17 | After #15 completes: `idx_case_summary(...)` | `hosts`, `artifacts`, `total_docs > 0` | full pipeline |

### Gate: Steps 1–14 must pass before marking Phase 18-pre complete.
### Gate: Steps 15–17 require binary prereqs (ewfmount, Zimmerman tools) on SIFT VM.

---

## Implementation Schedule

```
Session R0:   R0-1 through R0-9 (9 targeted fixes — opensearch-mcp + case-mcp + agentir-core)
              R5-1 (remediation-gate.sh — run at end of every session from now)
Session R1:   R1-1 through R1-5 (propagation hardening)
              R2-1 through R2-4 (case naming enforcement)
Session R2:   R3-1 through R3-4 (path auto-resolution + resolve_case_path)
Session R3:   R4-1 (instructions strings — highest impact, no code risk)
              R4-2 Session 4A (opensearch query tools 1–10)
Session R4:   R4-2 Session 4B (opensearch ingest/enrich) + R4-3 (case-mcp 15 tools)
Session R5:   R4-4 (sift-mcp) + R4-5 (remaining 40 tools)
              R5-2 (pre-import checklist) + R5-3/R5-4 (smoke tests per backend)
Session R6:   scripts/verify-ingest-prereqs.sh + R6 full integration validation
UI Overhaul:  Separate planning — portal form redesign, evidence intake workflow
```

---

## Session Start Checklist

1. Read this file top-to-bottom
2. Read `TASKS.md` current state
3. Run baseline: `uv run python -m pytest packages/{target}/ --tb=short -q`
4. After R5-1 exists: `bash scripts/remediation-gate.sh`
5. Work only the current session's phase — no scope creep
6. Add/update tests; gate must pass before finishing
7. Update TASKS.md completions and session notes
8. Update §R5-3 status column if backend status changes

---

## Quick Reference — File Locations

```
opensearch-mcp server:       packages/opensearch-mcp/src/opensearch_mcp/server.py
opensearch-mcp ingest:       packages/opensearch-mcp/src/opensearch_mcp/ingest.py
opensearch-mcp ingest_cli:   packages/opensearch-mcp/src/opensearch_mcp/ingest_cli.py
opensearch-mcp containers:   packages/opensearch-mcp/src/opensearch_mcp/containers.py
opensearch-mcp paths:        packages/opensearch-mcp/src/opensearch_mcp/paths.py
case-mcp server:             packages/case-mcp/src/case_mcp/server.py
agentir-core case_ops:       packages/agentir-core/src/agentir_core/case_ops.py
agentir-core case_io:        packages/agentir-core/src/agentir_core/case_io.py
agentir-core evidence_chain: packages/agentir-core/src/agentir_core/evidence_chain.py
sift-gateway server:         packages/sift-gateway/src/sift_gateway/server.py
instructions strings:        packages/sift-common/src/sift_common/instructions.py
portal routes:               packages/case-dashboard/src/case_dashboard/routes.py
gateway config template:     configs/gateway.yaml.template
ingest prereq script:        scripts/verify-ingest-prereqs.sh  (create in R0)
gate script:                 scripts/remediation-gate.sh  (create in R0/R5-1)

SIFT VM cases root:          /cases/  (configured in gateway.yaml → case.root)
SIFT VM active case:         AGENTIR_CASE_DIR env var in subprocess (set by gateway)
Legacy pointer (do not trust): ~/.agentir/active_case
```
