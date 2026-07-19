# Greenfield Uninstaller

As-built contract for the streamlined SIFT VM wipe/reinstall path. Source of
implementation: `scripts/uninstall.sh` (live-proved at `c92460a`, 2026-07-12).
Original design plan: `.cursor/plans/streamlined_greenfield_uninstaller_b498a44b.plan.md`.

## Purpose

Reset a SIFT Workstation to **stock SIFT** by removing everything this project
added (gateway, portal, workers, Supabase, OpenSearch, OpenCTI, configs,
secrets, `.venv`). Never touch: Docker engine, stock SANS forensics tools
(`/opt/zimmermantools`, system Python, preinstalled apt CLIs).

## Locked decisions

| Decision | Behavior |
|----------|----------|
| Default path | Full greenfield wipe of SIFT-added stack |
| `--data` | Personalized `/cases` evidence only (extra gates). Not global RAG/OpenCTI intel |
| `--keep-caches` / `SIFT_KEEP_CACHES=1` | **OFF by default.** Thin optional spare of regenerable download caches under `/var/cache/sift` **and** Docker **images** only. Not a second install mode |
| Always removed (even with `--keep-caches`) | Named Docker **volumes**, containers, secrets/`SIFT_HOME`, `.venv`, systemd units, users, AppArmor/auditd SIFT bits |
| OpenCTI | Always tear down shared stack + volumes; images kept only under `--keep-caches` |
| Hayabusa | Best-effort preserve into `/var/cache/sift/hayabusa` when `--keep-caches` |

`--keep-caches` is for fast test environment spin-up/spin-down. Do **not** treat
it as a first-class workflow that reshapes installer structure.

## Usage

```bash
# Dry-run (default)
./scripts/uninstall.sh

# Live wipe — cases preserved
./scripts/uninstall.sh --yes --i-understand

# Live wipe — spare download caches + images (volumes still purged)
./scripts/uninstall.sh --yes --i-understand --keep-caches

# Also purge personalized evidence under /cases
./scripts/uninstall.sh --yes --i-understand --data --i-understand-evidence-loss
# (TTY also requires typing: DELETE EVIDENCE)

# Installer shim — software/greenfield only; NEVER forwards --data
./install.sh --uninstall
# Optional: SIFT_KEEP_CACHES=1 ./install.sh --uninstall
```

Reinstall after wipe:

```bash
export UV_CACHE_DIR=/var/cache/sift/uv
export SIFT_HF_HOME=/var/cache/sift/huggingface
./install.sh --with-rag --with-windows-triage
./scripts/setup-addon.sh opencti --provision
# Register opencti-mcp via Portal → Backends or installer DB seed helper
```

## Durable cache contract (install + uninstall agree)

Regenerable bulk lives under FHS `/var/cache/sift` (outside `/var/lib/sift`,
which is wiped every greenfield):

| Artifact | Path | Notes |
|----------|------|-------|
| uv wheels | `/var/cache/sift/uv` | `UV_CACHE_DIR` |
| pip | `/var/cache/sift/pip` | `PIP_CACHE_DIR` |
| HF / Qwen | `/var/cache/sift/huggingface` | default `SIFT_HF_HOME` / systemd `HF_HOME` |
| Windows-triage baselines | `/var/cache/sift/windows-triage` | pack default |
| Hayabusa (optional) | `/var/cache/sift/hayabusa/{bin,rules}` | best-effort |
| Vol symbols | `/var/cache/sift/volatility-symbols` | shared `sift` group |
| RAG seed tarball | `artifacts/qwen3-….tar.zst` in repo | never an uninstall target |

Without `--keep-caches`, wipe the whole `/var/cache/sift` tree. With the flag,
leave the named subtrees above. One-shot migrate from legacy
`$SIFT_STATE_DIR/.cache/huggingface` and `/var/lib/sift/windows-triage` on
install when present.

## Ordered teardown (as-built)

Fail-closed; no component menu.

1. **Stop** systemd: `sift-gateway`, `sift-job-worker`, `sift-mount-observer`,
   `sift-opensearch-worker@*`, and any live `sift-addon-*` transient units (add-on
   sandbox processes started via `systemd-run --collect`; not children of the
   gateway's cgroup, so they need an explicit stop — `--collect` means there is no
   unit file left to remove once stopped)
2. **Docker force purge** (`force_purge_sift_docker_state`):
   - Best-effort `compose down -v` (may no-op without env/secrets)
   - Force `docker rm -f` matching SIFT/OpenCTI/Supabase containers
     (**must** use `docker ps -a --format '{{.ID}} {{.Names}}'` — never
     `docker ps -aq --format`, which drops names and leaves volumes in use)
   - Force-remove named volumes; also `docker rm -f` by `--filter volume=`
   - **FATAL** if OpenSearch / OpenCTI / Supabase named volumes remain
3. Remove OpenCTI / OpenSearch secret+config files under `SIFT_HOME`
4. Supabase stop + CLI binary cleanup
5. Docker **image** rm unless `--keep-caches`
6. AppArmor (`sift-gateway`, `sift-custody-delete-broker`, `dfir-exec`), auditd rules, FUSE `user_allow_other`
7. Remove unit files, sudoers, helpers, users/groups
8. Runtime: always remove `.venv`; remove staged `/opt/sift-mcps` if ≠ clone;
   wipe `SIFT_HOME` (after optional hayabusa cache copy)
9. Purge `/var/lib/sift` state (never `/cases` unless `--data`)
10. Cache tree wipe unless `--keep-caches`
11. Operator `~/.sift` leftovers + `/var/backups/sift`
12. Optional `--data` evidence path (triple gate + typed confirm on TTY)

## Safety invariants

- `./install.sh --uninstall` never forwards `--data` / evidence-loss flags
  (`lib/teardown.sh` `do_uninstall`; D5 evidence boundary).
- Default live wipe does **not** delete `/cases` without `--data`.
- `--keep-caches` does **not** spare volumes or `.venv`.
- OpenCTI teardown targets shared + connectors compose only (no legacy
  dedicated OpenCTI OpenSearch).
- Contracts: `tests/test_greenfield_uninstall_contract.py`,
  `tests/test_opencti_uninstall_contract.py`,
  `tests/test_installer_no_evidence_deletion.py`.

## Fast-reset cycle (P0-INFRA)

For a fast test-environment respin (VM data is disposable — see repo `AGENTS.md`),
run the existing flags together; no separate "fast-reset" flag exists or is needed:

```bash
./scripts/uninstall.sh --yes --i-understand --keep-caches \
  --data --i-understand-evidence-loss
./install.sh --with-rag --with-windows-triage
```

`--keep-caches` spares `/var/cache/sift` (uv/pip/HF/wintriage/hayabusa) and Docker
images so reinstall doesn't re-download bandwidth-heavy artifacts; `--data` wipes
`/cases` test evidence. The user-level `~/.cache/uv` (distinct from the durable
`/var/cache/sift/uv`) is never touched by this script under any flag combination.

### Known anomalies (already covered by the existing privilege model)

- **Stray non-native (e.g. macOS UID 501) ownership on rsynced scripts, or a
  root-owned individual script** under the staged runtime tree: every removal of
  `SIFT_MCPS_INSTALL_ROOT` / `.venv` / `SIFT_HOME` goes through `sudo_if_needed`,
  so foreign or root ownership on those files does not block the wipe.
- **A permission-denied / root-owned residue subdirectory under `/cases`** (e.g. a
  stale quarantine dir): `_purge_tree()` clears `chattr -i`/`-a` first, then runs
  `sudo_if_needed rm -rf`, so root privilege — not the caller's DAC permissions —
  governs the removal.
- These are documented here rather than special-cased in the script because the
  existing sudo-escalation path already covers them; no code change was needed.

## Related code

| Path | Role |
|------|------|
| `scripts/uninstall.sh` | Canonical greenfield wiper |
| `lib/teardown.sh` | Install summary + `do_uninstall` shim |
| `lib/common.sh` / `lib/state.sh` / `lib/python.sh` | Durable cache defaults + sync |
| `lib/assets.sh` | Hayabusa prefer durable cache |
| `scripts/core-addons/setup-windows-triage.sh` | Default data dir under cache root |
| `configs/apparmor/sift-gateway.template` | Must allow `/var/cache/sift/windows-triage` for sandboxed add-on |
| `lib/config.sh` | Must normalize `unlisted_policy` to `reject` (not `contained`) |

## Live proof record

**Commit:** `c92460a` (2026-07-12) on the testing VM.

1. `uninstall --yes --i-understand --keep-caches` → verified no leftover
   `sift-mcps_opensearch-data` / OpenCTI / `supabase_db_*` volumes; caches kept.
2. `./install.sh --with-rag --with-windows-triage` → Install complete, OpenSearch healthy.
3. `./scripts/setup-addon.sh opencti --provision` + DB seed of `opencti-mcp`.
4. `/health` ok — backends: forensic-rag, opensearch, windows-triage, opencti;
   31 tools; `unlisted_policy: reject`; installer handoff present.

## Explicit non-goals

- Do not uninstall Docker, apt forensic CLIs, `/opt/zimmermantools`, or system Python.
- Do not keep Postgres/OpenSearch/OpenCTI **volumes** under `--keep-caches`.
- Do not keep `.venv`.
- Do not restore a component-pick menu as primary UX.
- Do not redesign install around `--keep-caches` as a first-class product mode.

## Change checklist (future edits)

When changing wipe/reinstall behavior:

1. Update this document and the fail-on-revert contracts in the same change.
2. Keep volume purge fail-closed; never claim “complete” if named volumes remain.
3. Keep `install.sh --uninstall` evidence-flag isolation.
4. Re-prove on the VM: wipe (`--keep-caches`) → reinstall → `/health` before
   calling the path live-proven again.
