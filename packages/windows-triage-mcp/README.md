# windows-triage-mcp

SIFT-local, **offline** Windows baseline-validation MCP backend (reference /
add-on tier). It answers known-good / known-bad questions against bundled
SQLite baselines (LOLBAS, LOLDrivers, HijackLibs, process-tree expectations,
and a Windows file/service/task/autorun baseline). It is query-only and
non-authoritative: an `UNKNOWN` verdict means "not present in the local
baseline" and is neutral unless case evidence adds suspicion.

## Databases

The backend reads up to three SQLite databases from its **data directory**.
Prebuilt copies are published as compressed (`.zst`) assets on the
`AppliedIR/sift-mcp` GitHub releases under a `triage-db-*` tag.

| File                       | Required? | Size (on disk) | Verified table     |
| -------------------------- | --------- | -------------- | ------------------ |
| `known_good.db`            | yes       | ~6 GB          | `baseline_files`   |
| `context.db`               | yes       | ~3 MB          | `lolbins`, `vulnerable_drivers` |
| `known_good_registry.db`   | optional  | **~12 GB**     | `baseline_registry`|

`known_good.db` + `context.db` are the default install. `known_good_registry.db`
is the **full registry baseline** used by `wintriage_check_registry`; it is
~12 GB and is downloaded **only on explicit opt-in** (see below). Without it,
`wintriage_check_registry` returns a clear "not installed" warning and every
other tool works normally — for autorun / persistence checks use
`wintriage_check_system(type='autorun')`, which does not need this database.

### Data directory resolution (single source of truth)

The data directory is resolved by `windows_triage_mcp/config.py` in this order:

1. `$SIFT_WINDOWS_TRIAGE_DB_DIR`
2. `$WT_DATA_DIR`
3. `/var/lib/sift/windows-triage` (default)

Individual database paths can also be overridden directly:

- `$WT_KNOWN_GOOD_DB` → `known_good.db`
- `$WT_CONTEXT_DB` → `context.db`
- `$WT_REGISTRY_DB` → `known_good_registry.db`

When set, an explicit `WT_*_DB` path wins over the data-directory default. The
downloader writes to the **same** resolved directory the runtime reads from, so
a download and the running backend never diverge.

## Downloading the databases

The cross-platform downloader fetches, SHA-256-verifies (`checksums.sha256`),
decompresses, and row-count-verifies each database:

```bash
# Default install: known_good.db + context.db only
python -m windows_triage_mcp.scripts.download_databases [--dest DIR] [--tag TAG]

# Also fetch the optional ~12 GB full registry baseline
python -m windows_triage_mcp.scripts.download_databases --with-registry
```

`--with-registry` is gated on two checks before anything is downloaded:

1. a **disk-space check** — at least ~15 GB free at the destination, and
2. an explicit **operator confirmation** prompt that states the ~12 GB size.

Use `--yes` to assume yes to the confirmation for non-interactive installs
(the disk-space check still applies). With no `--dest`, the download lands in
the resolved data directory above.

For private repos, set `GITHUB_TOKEN` or authenticate the `gh` CLI.

### First-party core-addon pack

After mandatory SIFT core is installed, use the staged first-party entrypoint;
it installs the add-on into the existing runtime, validates the local baselines,
and reconciles the trusted gateway registry record automatically:

```bash
# Default baselines only; no registry baseline download
sudo /opt/sift-mcps/scripts/core-addons/setup-windows-triage.sh --install

# Explicitly opt in to the optional ~12 GiB registry baseline
sudo /opt/sift-mcps/scripts/core-addons/setup-windows-triage.sh \
  --install --with-registry
```

The pack uses the fixed service-readable default
`/var/lib/sift/windows-triage`, so the registered child has no environment
references at all—especially no control-plane or database credential reference.
It is intentionally separate from `scripts/setup-addon.sh`, which prepares
external integrations only.

For an air-gapped run, pre-stage `known_good.db` and `context.db` in that
directory and use `--offline`; the pack refuses all network access. If also
using `--with-registry` offline, pre-stage `known_good_registry.db` and provide
both its SHA-256 and a concise source descriptor:

```bash
sudo env SIFT_WINDOWS_TRIAGE_REGISTRY_SHA256='<64 hex SHA-256>' \
  SIFT_WINDOWS_TRIAGE_REGISTRY_PROVENANCE='triage-db-<release>' \
  /opt/sift-mcps/scripts/core-addons/setup-windows-triage.sh \
  --install --with-registry --offline
```

Online registry downloads fail closed unless the release includes the registry
asset's SHA-256, passes the free-space guard, and produces a local non-secret
provenance sidecar beside the database.

## Offline / air-gapped staging

For hosts without GitHub access, pre-stage the database files by hand. Place
the **decompressed** `.db` files in the resolved data directory using these
exact filenames:

```text
<data_dir>/known_good.db
<data_dir>/context.db
<data_dir>/known_good_registry.db      # optional, ~12 GB
```

where `<data_dir>` is `$SIFT_WINDOWS_TRIAGE_DB_DIR`, else `$WT_DATA_DIR`, else
`/var/lib/sift/windows-triage`. Alternatively point `$WT_REGISTRY_DB` (and/or
`$WT_KNOWN_GOOD_DB`, `$WT_CONTEXT_DB`) at an existing file in any location.

To stage from the published assets manually:

1. From a connected host, download the assets for the chosen `triage-db-*`
   release (`known_good.db.zst`, `context.db.zst`, and optionally
   `known_good_registry.db.zst`) plus `checksums.sha256`.
2. Verify: `sha256sum -c checksums.sha256`.
3. Decompress each, e.g. `zstd -d known_good_registry.db.zst`.
4. Copy the resulting `.db` files to `<data_dir>` (or the `WT_*_DB` targets)
   on the offline host, keeping the exact filenames above.

The backend opens the registry DB read-only, so the file may be owned by the
service user with read-only permissions.

## Configuration

All settings use the `WT_` environment prefix; see `windows_triage_mcp/config.py`
for the full list (`WT_LOG_LEVEL`, `WT_CACHE_SIZE`, input-length limits, etc.).
