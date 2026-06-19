# Installation Modernization Blueprint — ALT / Second Opinion (01b)

> **Status:** This is the **independent second-opinion** audit, kept separate from the canonical
> primary blueprint in `01-INSTALL-EXPLORATION.md` (authored by the recovered read-only `Explorer`).
> Author: `ExplorerW`. The reviewer should cross-check the two; where they agree, confidence is high;
> where they diverge, treat this file as the dissent to adjudicate.
> Evidence: every problem cites `file:line` from the repo at HEAD. Static/code audit only — no live fetches, no secrets.
> Operator mandate honored: **D1 — registry publishing is the PRIMARY distribution model; `--offline` is SECONDARY.**

---

## 0. Where this ALT may agree / disagree with the primary blueprint

> I was not given the primary blueprint's text (deliberately, to avoid a write-race), so this is framed
> as the load-bearing things a registry-publishing migration **must not miss** — the points most worth
> the reviewer cross-checking against the primary.

- **AGREE (almost certainly shared):** `install.sh` should become a thin entrypoint sourcing `lib/*.sh`,
  preserving the existing `BASH_SOURCE==$0` library/entrypoint duality (`install.sh:3656`) that
  `setup-addon.sh:54` already depends on. Any modularization that breaks sourcing breaks add-ons.
- **LIKELY UNIQUE / easy to miss — version skew is a hard publish blocker:** runtime packages are
  **not** version-coherent (`sift-core` and `windows-triage-mcp` = `0.1.0`; the rest = `0.6.1`; root
  `pyproject.toml:version = 0.1.0`). You cannot cut a clean `sift-mcps[full]==X.Y.Z` until this is
  reconciled. A blueprint that jumps to "publish to PyPI" without flagging this will produce an
  incoherent first release.
- **LIKELY UNIQUE — the frontend is already a published artifact in miniature:** the Vite bundle is
  committed and baked into the `case-dashboard` wheel via hatchling package-data
  (`packages/case-dashboard/src/case_dashboard/static/v2/assets/index-*.js`, served at
  `server.py:1391`). So PyPI-primary needs **no npm on the VM** and **no separate frontend publish** —
  but it also means **frontend changes are invisible unless `case-dashboard` is version-bumped**. That
  coupling must be stated or operators will ship stale UIs.
- **DISAGREE (where I'd push back if the primary is silent):** `install.sh --uninstall` should be
  **deleted and delegated** to `scripts/uninstall.sh`, not "kept and hardened." The in-script
  `do_uninstall` (`install.sh:3370`) deletes evidence behind a single typed `yes`/`-y` (`:3249`,
  `:3364`), whereas the canonical script requires typed `DELETE EVIDENCE` + triple flags. Two teardown
  paths with asymmetric destructive gates is a forensic-integrity hazard, not a convenience.
- **MUST NOT MISS — install-path security in the registry model:** moving from `uv sync` (workspace,
  `uv.lock`-pinned) to `pip install sift-mcps[full]==X.Y.Z` **loses the lockfile's transitive pinning
  unless** a hash-pinned constraints file ships with the release and the bootstrap enforces it. The
  existing binary-asset SHA discipline (`install.sh:155-187`: uv tarball, hayabusa, HF revision) is the
  bar the Python dependency set must also meet — don't regress integrity while "modernizing."

---

## 1. Executive Summary (recommended target model)

Keep `./install.sh` as the operator's verb, but invert what it *is*: today it is a 3,658-line
monolith that contains both the provisioning logic and the orchestration; tomorrow it should be a
**thin bootstrap entrypoint (~150 lines)** that sources a `lib/*.sh` module set and, in the primary
("online") mode, installs **version-pinned published distributions** rather than `uv sync`-ing a
source workspace.

Recommended end-state:

1. **Distribution:** Publish the workspace packages to **PyPI** (or a private index) as version-pinned
   wheels; the portal frontend already ships as committed bytes inside the `case-dashboard` wheel
   (`packages/case-dashboard/src/case_dashboard/static/v2/assets/index-*.js`), so it rides PyPI for
   free — no npm-on-VM, no separate frontend publish needed. A `requirements.lock`/pinned constraints
   file gives integrity + reproducibility.
2. **Bootstrap:** `install.sh` becomes a downloader+verifier of a pinned `sift-mcps[full]==X.Y.Z` into
   the system-`python3.12` venv at `/opt/sift-mcps/.venv`, then sources `lib/` to do host config,
   services, hardening, Supabase, OpenSearch. Source-tree `uv sync` becomes a `--from-source` dev path.
3. **Offline (secondary):** `--offline` consumes operator-staged wheels + the same vendored binary
   artifacts (uv, hayabusa, HF model cache) the script already SHA-pins.
4. **Tiering:** formalize three tiers — **core** (gateway/sift-core/portal/Supabase), **first-party
   add-ons** (OpenSearch, forensic-rag, forensic-knowledge), **external add-ons** (windows-triage,
   OpenCTI via `scripts/setup-addon.sh` + Portal Backends) — and map flags/extras/services to them.
5. **Modularize:** decompose into `lib/preflight.sh`, `lib/python.sh`, `lib/state.sh`, `lib/secrets.sh`,
   `lib/supabase.sh`, `lib/opensearch.sh`, `lib/tools.sh`, `lib/services.sh`, `lib/hardening.sh`,
   `lib/addons.sh`, `lib/teardown.sh`, `lib/verify.sh` — preserving the `BASH_SOURCE==$0` library/entry
   duality the codebase already relies on (`install.sh:3656`).
6. **Harden the CLI:** grouped flags, a real `--help` with examples, `--non-interactive`/`--yes`,
   `--dry-run` (today only teardown has dry-run; install has none), stable exit codes, structured
   errors with remediation hints, and a post-install `--verify` self-check.

This is achievable incrementally and low-risk-first because the riskiest seams (downloads, venv,
ownership, services, teardown) are already isolated functions — they become testable units the moment
they live in `lib/` files.

---

## 2. Current-State Audit

### 2.1 Quantifying the monolith

| File | Lines | Role |
|------|-------|------|
| `install.sh` | 3,658 | Installer + sourced function library (dual-mode via `install.sh:3656`) |
| `scripts/uninstall.sh` | 1,033 | **Canonical** teardown (dry-run default, component-scoped, triple-gated evidence) |
| `scripts/setup-addon.sh` | 693 | External add-on provisioning; **sources install.sh as a library** (`:54`) |
| `scripts/setup-supabase.sh` | 435 | Supabase CLI bring-up (SHA-pinned, demo-key guard) |
| `scripts/rotate-tls.sh` | 270 | TLS leaf renewal / CA rotation |
| `scripts/setup-agent-runtime.sh` | 180 | `agent_runtime` user + ACL sandbox |
| `scripts/setup-ingest-mount-sudoers.sh` | 125 | Narrow NOPASSWD mount allowlist |
| `scripts/inventory-sift-tools.sh` | 135 | Read-only tool inventory |
| `scripts/verify-ingest-prereqs.sh` | 90 | Read-only ingest preflight |
| `scripts/setup-run-command-systemd-scope-sudoers.sh` | 86 | RUN-3 scope helper + sudoers |
| `scripts/stage-evidence.sh` | 115 | Operator evidence copy-in |
| **Total** | **~6,820** | |

`install.sh` alone holds **~70 functions** spanning at least **14 responsibility areas**: preflight,
uv install, host prereqs, Docker, venv sync, state dirs, service-user, agent-runtime, FUSE, RAG seed,
hayabusa/Zimmerman/complementary tools, TLS, Supabase bootstrap, DB migrations, gateway/OpenSearch/FK
config, OpenCTI, systemd, hardening (immutable/auditd/AppArmor), and teardown. Function inventory by
line:

- Helpers: `log/warn/die` (`:22-24`), `sudo_if_needed` (`:26`), `svc_install_file` (`:90`),
  `verify_sha256` (`:57`), `is_offline/offline_die` (`:46/:50`).
- Reexec/staging: `stage_repo_to_install_root` (`:197`) — rsync/tar self-stage + `exec` re-run.
- Preflight: `check_os` (`:253`), `check_python` (`:265`).
- Python: `resolve_uv` (`:296`), `install_uv_if_needed` (`:302`), `sync_workspace` (`:494`),
  `_ensure_venv_integrity` (`:471`), `repair_pyewf_venv_link` (`:537`).
- State/ownership: `install_state_dirs` (`:631`), `ensure_gateway_service_user` (`:677`),
  `backup_preexisting_data_if_fresh` (`:590`).
- Tools: `install_hayabusa` (`:952`), `install_zimmerman_symlinks` (`:1057`),
  `install_complementary_tools` (`:1116`), RAG seed family (`:806-952`).
- Secrets/config: `generate_tls` (`:1241`), `write_*_env` (`:1817/:1956/:2338/:2368`),
  `write_gateway_config` (`:2154`), `apply_db_migrations` (`:2023`).
- OpenSearch: `start_opensearch` (`:2406`) … `install_opensearch_templates` (`:2631`).
- Services: `install_systemd_service` (`:2762`), `poll_gateway` (`:2831`).
- Hardening: `configure_immutable_capability` (`:2996`), `configure_auditd` (`:3015`),
  `configure_apparmor` (`:3084`), `configure_run_command_systemd_scope` (`:3123`).
- Teardown: `do_uninstall` (`:3370`) + `uninstall_*` (`:3252-3368`).
- Orchestration: `main()` (`:3399`) — flag parse + linear call sequence (`:3477-3649`).

### 2.2 Global flags & their handling (`main`, `install.sh:3410-3459`)

| Flag | Var | Notes / problems |
|------|-----|------|
| `-y/--yes` | `ASSUME_YES` | Only consumed by `_confirm_destructive` (`:3241`); does NOT make install non-interactive elsewhere (install has no other prompts, but the asymmetry is undocumented). |
| `--core-only` | `SIFT_CORE_ONLY` | Drives `--extra core` (`:506`) + skips OpenSearch/RAG/tools (`:3493`). |
| `--uninstall/--remove` | `uninstall_mode` | Routes to the **in-script** `do_uninstall` (`:3370`) — *not* the canonical `scripts/uninstall.sh`. **Divergence risk (see 2.5).** |
| `--purge-data` | `PURGE_DATA` | Wipes `/var/lib/sift` + `/cases` (`:3357`). |
| `--no-opencti` | `flag_no_opencti` | **No-op** — OpenCTI is never installed natively (`:3511`). Dead flag kept for compat. |
| `--no-rag` | `flag_no_rag` | Disables RAG (`:3500`). |
| `--external-supabase` | `SIFT_EXTERNAL_SUPABASE` | Skips Supabase auto-provision. |
| `--offline` | `SIFT_OFFLINE` | Air-gap; each download step calls `offline_die`. |
| `--enable-geoip` | `SIFT_GEOIP_ENABLED` | Opt-in live GeoIP datasource. |
| `--apparmor-enforce` | `SIFT_APPARMOR_ENFORCE` | Enforce vs complain (B-MVP-046). |
| `-h/--help` | — | Inline `printf` block (`:3423-3452`). |
| unknown | — | **Warn + ignore** (`:3455`) — no fail-fast on typos; `--prge-data` would silently no-op. |

Observations:
- Flags are **ungrouped and order-independent but un-validated** — `--core-only --offline --enable-geoip`
  produces no conflict check (e.g. core-only ignores geoip silently).
- `--apparmor-enforce` overlaps with a separate `./harden.sh` (`:3444` references it) — two posture paths.
- No `--dry-run`, `--non-interactive`, `--log-file`, or `--version` for install.

### 2.3 Riskiest sections (with `file:line`)

| # | Risk | Where | Why it bites |
|---|------|-------|--------------|
| R1 | **OS-detection mislabels the actual target** | `check_os` `:257-260` | Hard-codes `ID == ubuntu` / `22.04|24.04` and `warn`-proceeds otherwise. The SANS SIFT Workstation **is** Ubuntu-based, so this is correct for the VM — but the warning text + the 26 `apt-get` call sites (`:356-392` and elsewhere) mean the installer is **Debian/Ubuntu-only in practice**. Any non-apt host fails at `apt_install_packages` with no graceful fallback (`:359` returns 1, then `:386` `die`). The CLAUDE.md "Fedora-family" note refers to the libvirt **host** `fedora44`, NOT the VM — worth stating loudly so future maintainers don't try to dnf-ify the installer. |
| R2 | **Self-stage `chown -R` on `/opt/sift-mcps`** | `stage_repo_to_install_root` `:213` | `sudo chown -R "$owner:$group" "$dst"` runs **before** rsync; if `$dst` already contains a prior install's root-owned artifacts this re-chowns the whole tree to the operator. Combined with `--delete` rsync (`:216`) a mis-set `SIFT_MCPS_INSTALL_ROOT` could delete operator data. |
| R3 | **`uv` arch fallback re-pipes a script to `sh`** | `install_uv_if_needed` `:349` | For non-x86_64, falls back to `curl … /uv/${VER}/install.sh | sh`. Version-pinned but **not SHA-verified** (unlike the x86_64 tarball path `:329`). Asymmetric supply-chain posture. |
| R4 | **`apt-get update` failure is swallowed** | `apt_install_packages` `:363-366` | A broken third-party apt source only warns; install proceeds and may fail later at a less obvious point. |
| R5 | **venv smoke test is shallow** | `_ensure_venv_integrity` `:486` | Only `import yaml`. A venv missing `sift_gateway` passes integrity, then `sync_workspace`'s post-check (`:518`) is the real gate — duplicated, late detection. |
| R6 | **`--reinstall` retry hides errors** | `sync_workspace` `:532` | Retry pipes `2>/dev/null` and only `warn`s on failure; a genuinely broken sync can still reach `install_systemd_service` where `:2777` finally `die`s. |
| R7 | **Two teardown implementations** | `install.sh:3370` vs `scripts/uninstall.sh` | `--uninstall` uses the in-script `do_uninstall` (coarse: software-only / `--purge-data` all-or-nothing), while `scripts/uninstall.sh` is component-scoped + triple-gated. They can drift; an operator who learns one won't know the other's gates. |
| R8 | **`purge_data` clears immutable then `rm -rf` `/cases`** | `_purge_tree` `:3341-3355` + `purge_data` `:3364` | Correct by design (clears `chattr +i/+a` first) but a single typed `yes` (or `-y`) destroys sealed evidence. The canonical script requires a typed `DELETE EVIDENCE` — the in-script path is **weaker**. |
| R9 | **Long linear `main()` with no rollback** | `main` `:3477-3649` | ~40 sequential steps; a failure at step N (e.g. `apply_db_migrations` `:3557`) leaves a half-provisioned host. Only `set -Eeuo pipefail` (`:2`) + scattered `|| true`. No trap, no phase journal, no resume. |
| R10 | **OpenSearch availability silently downgrades scope** | `main` `:3588-3592` | If OpenSearch never comes healthy, `SIFT_OPENSEARCH_ENABLED=false` is set mid-run and seeding is skipped — a partial-success the operator may not notice without reading the summary. |

### 2.4 Dead code / duplication / footguns

- **Dead flag:** `--no-opencti` (`:3431`, `:3510`) is a documented no-op.
- **Duplicated TLS logic:** `generate_tls` (`install.sh:1241`) and `scripts/rotate-tls.sh` both build
  SANs + sign a leaf — should share one `lib/tls.sh` function.
- **Duplicated `_purge_tree`:** identical in `install.sh:3341` and `scripts/uninstall.sh` (~`:323`) —
  necessary today (separate processes) but a prime candidate for a shared `lib/teardown.sh`.
- **Duplicated path/var constants:** `install.sh:105-153` re-declared by `scripts/uninstall.sh` and
  consumed by `setup-addon.sh` via sourcing — a single `lib/constants.sh` removes drift.
- **Two hardening entrypoints:** `configure_apparmor` (`:3084`) + a separate `./harden.sh` referenced
  at `:3444`.

### 2.5 Teardown audit (from `scripts/uninstall.sh`, 1,033 lines)

- Dry-run **default**; live requires `--yes` (good — opposite of the in-script path).
- Component-scoped (`--components opencti,opensearch,supabase,runtime,systemd,state,cache,auditd,apparmor,tls`).
- Evidence removal is **triple-gated**: `--remove-evidence` + `--i-understand-evidence-loss` + `--yes`
  + a typed `DELETE EVIDENCE` prompt. `/cases` preserved by default.
- Footgun: residual-state sweep removes all entries under `$SIFT_STATE_DIR` — could catch operator-nested
  `--cases-root` if mis-configured (uninstall.sh ~`:781-792`).
- **Recommendation:** make `install.sh --uninstall` *delegate to* `scripts/uninstall.sh` rather than
  carry its own coarse `do_uninstall`, eliminating R7/R8.

### 2.6 Packaging current state

- **Workspace:** root `pyproject.toml` declares `[tool.uv.workspace] members=["packages/*"]`,
  `package=false`, and workspace sources for all 9 packages (`pyproject.toml:1-22`).
- **Extras chain:** `core ⊂ standard ⊂ full`; `opencti`, `windows-triage`, `chroma-import`, `dev`
  are siblings (`pyproject.toml: optional-dependencies`). Install uses `--extra full` (`:505`) or
  `--extra core` for core-only.
- **Version skew:** most packages are `0.6.1`, but `sift-core` and `windows-triage-mcp` are still
  `0.1.0` (and root is `0.1.0`). **This blocks clean PyPI publishing** — versions must be coherent.
- **Frontend:** built Vite bundle is **committed** (`packages/case-dashboard/src/case_dashboard/static/v2/assets/index-*.js|css`)
  and served by the gateway at `/portal` (`packages/sift-gateway/src/sift_gateway/server.py:1391`
  → `case_dashboard/routes.py:3854/6179/6301`). `install.sh` never runs npm — **node is build-host-only**
  (no `npm|vite|node` in install.sh). Hatchling pulls the static dir into the wheel as package data.

---

## 3. Target Architecture

### 3.1 Component tiering

| Tier | Components | Extra | Services | Dir |
|------|-----------|-------|----------|-----|
| **Core** (always) | `sift-gateway`, `sift-core`, `sift-common`, `case-dashboard` (portal), Supabase/Postgres | `core` | `sift-gateway.service`, `sift-job-worker.service` | `/opt/sift-mcps`, `/var/lib/sift`, `/cases` |
| **First-party add-ons** (default-on) | `opensearch-mcp`, `forensic-rag-mcp`, `forensic-knowledge` | `standard` (+OpenSearch), `full` (+RAG) | `sift-opensearch-worker@.service` (×N) | Docker OpenSearch; pgvector RAG; FK data dir |
| **External add-ons** (opt-in) | `windows-triage-mcp`, `opencti-mcp` | `windows-triage`, `opencti` | none native — Portal-registered backends | `scripts/setup-addon.sh` → `~/.sift/addon-register/*.json` |

Flag → tier mapping target:
- `--core-only` → core tier only (already: `:3493`).
- (default) → core + first-party.
- `--no-rag` / `--no-opensearch` (new) → drop one first-party add-on.
- External add-ons never touched by `install.sh`; only `setup-addon.sh` (keep; it already sources the lib).

### 3.2 Distribution recommendation (D1: registry-primary)

**Publish to PyPI (or private index):**
- `sift-common`, `sift-core`, `sift-gateway`, `case-dashboard`, `forensic-knowledge`,
  `opensearch-mcp`, `rag-mcp` — the runtime packages.
- Meta-distribution `sift-mcps` carrying the extras graph (already defined) so
  `pip install "sift-mcps[full]==X.Y.Z"` resolves the whole core+first-party stack.

**Keep private / source-only (initially):**
- `windows-triage-mcp`, `opencti-mcp` (license/size/maturity); operators get them via `setup-addon.sh`
  which can `uv pip install` the published external extra or a source path.

**Frontend:** no separate publish — the committed Vite bundle rides inside the `case-dashboard` wheel.
Versioning: bump frontend bundle = bump `case-dashboard` version. (Optional future: npm-publish the
frontend and have the wheel fetch a pinned tarball at build time — NOT recommended now; the
committed-bundle model already satisfies "no npm on VM" and is reproducible.)

**Integrity/pinning:** ship a generated, hash-pinned constraints file (`pip install -c sift-constraints-X.Y.Z.txt`
or a `uv.lock`-derived export). The installer verifies the resolved set against it. This replaces the
"trust the workspace `uv.lock`" model with a pinned, signed-release model.

**Release flow:** `tag vX.Y.Z` → CI builds wheels (incl. frontend bundle baked in) → `twine`/`uv publish`
→ generate + attach constraints file + the binary-asset SHA ledger (uv, hayabusa, HF revision) already
maintained at `install.sh:155-187`.

**Migration path (source-`uv` → published):** keep `sync_workspace` behind a new `--from-source` flag
for developers; the default `install.sh` path becomes "create venv with system python3.12 →
`uv pip install --python /opt/sift-mcps/.venv 'sift-mcps[full]==X.Y.Z' -c constraints.txt`". The venv
location, ownership, and entrypoint checks (`:2777`) are unchanged, so services/hardening/teardown are
untouched.

**`--offline` (secondary):** operator stages a wheelhouse dir + the vendored binaries; the bootstrap
uses `uv pip install --no-index --find-links <wheelhouse>` and the existing `offline_die` staging
messages (`:50`). Same code path, different source.

### 3.3 Dir / service layout (unchanged, formalized)

```
/opt/sift-mcps/            # staged runtime tree (rsync/tar self-stage, install.sh:197); .venv here
/var/lib/sift/.sift/       # SIFT_HOME: gateway.yaml, tls/, backups/, *.env (sift-service-owned 0700)
/var/lib/sift/{passwords,tokens,verification,snapshots,enrichment}/
/var/cache/sift/volatility-symbols/   # 2775 group=sift shared cache (install.sh:135)
/cases/                    # evidence; immutable-flagged; preserved by canonical teardown
/etc/systemd/system/sift-*.service     # system services
/etc/apparmor.d/sift-gateway, /etc/audit/rules.d/99-sift-evidence.rules, /etc/sudoers.d/sift-*
```

---

## 4. Proposed CLI & Help Spec

### 4.1 Flag table (grouped)

| Group | Flag | Replaces / new | Meaning |
|-------|------|----------------|---------|
| Mode | `--from-source` | new (default flips to published) | Dev path: `uv sync` the workspace instead of installing published wheels. |
| Mode | `--offline` | keep | Air-gapped; staged wheelhouse + vendored binaries. |
| Tier | `--core-only` | keep | Core tier only. |
| Tier | `--no-rag` | keep | Drop forensic-rag first-party add-on. |
| Tier | `--no-opensearch` | new (split from core-only) | Drop OpenSearch first-party add-on. |
| Tier | ~~`--no-opencti`~~ | **remove** (dead) | OpenCTI is external; never installed here. |
| Supabase | `--external-supabase` | keep | Use externally-supplied control plane. |
| Optional | `--enable-geoip` | keep | Live ip2geo datasource. |
| Hardening | `--apparmor-enforce` | keep | Enforce mode (else complain). |
| UX | `--non-interactive` | new | Never prompt; fail (not hang) if input needed. |
| UX | `-y/--yes` | keep | Assume yes to destructive prompts. |
| UX | `--dry-run` | **new for install** | Print the plan + per-phase skip/do decisions; change nothing. |
| UX | `--verify` | new | Run only the post-install health self-check. |
| UX | `--log-file PATH` | new | Tee structured log (redacted) to PATH. |
| UX | `--version` | new | Print installer + target package version. |
| Teardown | `--uninstall` | keep, but **delegate to scripts/uninstall.sh** | Remove software; preserve data. |
| Teardown | `--purge-data` | keep, but adopt canonical triple-gate | Also wipe state/evidence. |
| Help | `-h/--help` | keep, grouped | |

Validation: unknown flags **fail fast** (replace warn+ignore at `:3455`); conflicting flags
(`--core-only --enable-geoip`, `--offline --from-source` without staged wheels) error with a hint.

### 4.2 Literal `--help` mockup

```
sift-mcps installer — provisions a forensic MCP runtime on SIFT Workstation

USAGE
  ./install.sh [OPTIONS]            install/upgrade (idempotent, re-run safe)
  ./install.sh --uninstall [...]    remove software (data preserved by default)
  ./install.sh --verify             health self-check only

INSTALL MODE
  --from-source         Build from this checkout (uv sync) instead of installing
                        published, version-pinned wheels (developer path).
  --offline             Air-gapped: install only operator-staged wheels + vendored
                        binaries (uv, hayabusa, HF model cache, Supabase CLI).

COMPONENT TIERS
  --core-only           Gateway + portal + in-process core tools only.
  --no-opensearch       Skip the OpenSearch first-party add-on.
  --no-rag              Skip the forensic-rag first-party add-on.
                        (External add-ons — windows-triage, OpenCTI — are NEVER
                         installed here; use scripts/setup-addon.sh + Portal.)

CONTROL PLANE
  --external-supabase   Use an external Supabase/Postgres (requires SUPABASE_URL,
                        SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY,
                        SIFT_CONTROL_PLANE_DSN in env).

OPTIONS
  --enable-geoip        Enable OpenSearch ip2geo (off by default; live fetch).
  --apparmor-enforce    Load AppArmor profiles in enforce mode (default: complain).

UX
  --dry-run             Show the plan + per-phase skip/do decisions; change nothing.
  --non-interactive     Never prompt; fail instead of hanging.
  -y, --yes             Assume yes to destructive prompts.
  --log-file PATH       Tee a redacted structured log to PATH.
  --version             Print installer and target package version.
  -h, --help            This help.

TEARDOWN
  --uninstall           Stop/remove services, venv, config/TLS/secrets, hardening,
                        hayabusa symlink, docker stacks. PRESERVES /var/lib/sift,
                        /cases, docker volumes. (Delegates to scripts/uninstall.sh.)
  --purge-data          With --uninstall: ALSO wipe state + /cases (EVIDENCE).
                        Irreversible — requires typing "DELETE EVIDENCE" unless -y.

EXAMPLES
  ./install.sh                              # full online install (core + first-party)
  ./install.sh --core-only                  # minimal gateway + portal
  ./install.sh --no-rag --enable-geoip      # OpenSearch w/ GeoIP, no RAG
  ./install.sh --offline                    # staged-artifact install
  ./install.sh --from-source                # developer build from this checkout
  ./install.sh --uninstall                  # remove software, keep evidence
  ./install.sh --verify                     # post-install health check

Run from a clone; the installer self-stages into /opt/sift-mcps and re-execs.
Every step is idempotent. System python3.12 only; no managed-Python downloads.
```

### 4.3 Interactive / silent / dry-run semantics

- **Interactive (default):** prompts only on destructive teardown (already the only prompt today).
- **`--non-interactive`:** sets an internal flag so any `read` path `die`s with a clear message instead
  of blocking; CI/automation use this. (Today only `_confirm_destructive` reads — `:3248`.)
- **`--dry-run`:** every phase function gains an early `if dry_run; then log "WOULD: …"; return 0; fi`
  guard, fed by the idempotency probes in §6 so it prints *skip* vs *do* per phase.

---

## 5. Modularization Plan (file-by-file)

Preserve the `BASH_SOURCE[0] == $0` library/entrypoint duality (`install.sh:3656`) — `setup-addon.sh`
already depends on sourcing (`setup-addon.sh:54`). New layout under `lib/` (sourced by both
`install.sh` and the scripts):

| Module | Owns (moved from install.sh) | Independently testable units |
|--------|------------------------------|------------------------------|
| `lib/constants.sh` | All path/var defaults `:105-187` | (data only) |
| `lib/log.sh` | `log/warn/die`, redaction, `--log-file` tee `:22-24` | `redact()` |
| `lib/preflight.sh` | `check_os` `:253`, `check_python` `:265`, `install_host_prereqs` `:370`, Docker check `:406` | `check_python` (temp PATH), `apt_install_packages` (fake apt) |
| `lib/python.sh` | `resolve_uv` `:296`, `install_uv_if_needed` `:302`, **new** `install_published()`, `sync_workspace` `:494` (→ `--from-source`), `_ensure_venv_integrity` `:471`, `repair_pyewf_venv_link` `:537` | `verify_sha256` `:57`, `_ensure_venv_integrity` |
| `lib/state.sh` | `install_state_dirs` `:631`, `ensure_gateway_service_user` `:677`, `backup_preexisting_data_if_fresh` `:590`, `svc_install_file` `:90` | `backup_preexisting_data_if_fresh` (temp dirs) |
| `lib/secrets.sh` | `generate_tls` `:1241`, `write_*_env` `:1817/:1956/:2338/:2368`, `_render_file` `:1762` | `_tls_san_value` `:1198`, `_render_file` |
| `lib/supabase.sh` | `preflight_supabase` `:1864`, `write_supabase_env`, `bootstrap_supabase_operator` `:1454`, `apply_db_migrations` `:2023` | DSN resolvers `:1909/:1920/:1938` |
| `lib/opensearch.sh` | `start_opensearch` `:2406` … `install_opensearch_templates` `:2631` | `_opensearch_api` `:2393` |
| `lib/tools.sh` | hayabusa `:952`, Zimmerman `:1057`, complementary `:1116`, RAG seed `:806-952`, `fix_volatility_permissions` `:1162` | `install_zimmerman_symlinks` (fake bins) |
| `lib/services.sh` | `install_systemd_service` `:2762`, `poll_gateway` `:2831`, `write_handoff` `:2880` | unit-render via `_render_file` |
| `lib/hardening.sh` | `configure_immutable_capability` `:2996`, `configure_auditd` `:3015`, `configure_apparmor` `:3084`, `configure_run_command_systemd_scope` `:3123`, FUSE/ingest/agent-runtime wiring `:743-806` | profile-load helpers |
| `lib/addons.sh` | `seed_addon_backends` `:1409`, `_seed_one_addon_backend` `:1335` | seed-row builder |
| `lib/teardown.sh` | thin wrapper that **execs `scripts/uninstall.sh`** (replaces `do_uninstall` `:3370`); keep `_purge_tree` here as the single copy | `_purge_tree` (temp dirs + chattr-absent) |
| `lib/verify.sh` | post-install self-check (new): `/health`, seeded backends, services active, venv imports | each probe |

Thin `install.sh` (target ~150 lines): shebang + `set -Eeuo pipefail` + trap → source `lib/*.sh` →
parse+validate flags → `stage_repo_to_install_root` → ordered phase calls (the §3 sequence) →
`print_summary`. The `BASH_SOURCE==$0` guard stays so sourcing still yields a function library.

---

## 6. Sequencing / Routing / Fail-Safe / Idempotency

### 6.1 Correct phase order (mirrors `main` `:3477-3649`, with dependency notes)

1. Preflight: OS, python3.12, `awk/curl`, host prereqs, Docker-for-Supabase. **(fail-fast gate)**
2. Self-stage to `/opt/sift-mcps` + re-exec (`:3475`). *(must precede everything that uses `$REPO_DIR`)*
3. Tier resolution (core/first-party flags) `:3493-3519`.
4. Supabase preflight `:3524` → **before** any `write_*_env`/migrations (they read its exports).
5. Python: uv → venv → install (published or `--from-source`) `:3527-3535`.
6. Service user + state dirs + agent-runtime + FUSE `:3536-3547`. *(user must exist before chown)*
7. TLS + examiner + env files `:3548-3551`.
8. DB migrations `:3557` → **before** `bootstrap_supabase_operator` + `seed_addon_backends` (`:3553` comment).
9. Gateway config + FK assets `:3564-3566`.
10. First-party: RAG seed, hayabusa, OpenSearch bring-up + cluster/templates `:3573-3599`.
11. Seed add-on backends **before** systemd start `:3614` (OSX1: avoids "no tools until restart" race).
12. Validate evidence root `:3617` → install + start services `:3619`.
13. Hardening (immutable/auditd/apparmor/run_command scope) `:3625-3628`.
14. `poll_gateway` `:3629` → Supabase operator bootstrap `:3639` → handoff + summary.

### 6.2 Parallelizable vs serial

- **Serial (hard deps):** preflight→stage→python→state/user→TLS/env→migrations→config→services→hardening.
- **Parallelizable (independent, network-bound):** hayabusa download, Zimmerman/complementary tool
  installs, RAG index/model fetch, HF model warm — all under §10 tools, none feed each other. Today
  they run sequentially `:3577-3599`; a `lib/tools.sh` could background them and `wait`.
- **Skip-if-satisfied** (cheap re-run): each is already idempotent (e.g. hayabusa checks the pinned
  binary; venv integrity `:471`); formalize a per-phase `_is_done` probe so `--dry-run` and fast
  re-runs short-circuit.

### 6.3 Fail-safe upgrades (gaps + proposals)

Current: `set -Eeuo pipefail` (`:2`), scattered `|| true`, two soft-failure spots (`sync` retry `:532`,
OpenSearch downgrade `:3588`). No trap, no rollback, no resume.

Propose:
- **`trap` on ERR** → emit phase name + remediation hint + stable exit code; on the riskiest phases
  (DB migrations, service install) capture a "what to do to resume" line.
- **Stable exit codes:** `0` ok; `10` preflight; `20` python/install; `30` supabase/migrations;
  `40` services; `50` hardening; `60` verify. (Today everything is `die`→`1`.)
- **Transactional-ish rollback** for the two genuinely risky phases: snapshot `gateway.yaml` + the
  unit files before `_render_file` overwrites, restore on ERR (the data is already backed up for fresh
  installs via `backup_preexisting_data_if_fresh` `:590`).
- **Phase journal** at `$SIFT_STATE_DIR/.install-journal` recording last-completed phase → enables a
  future `--resume`.

### 6.4 Idempotency & verification

- Per-phase "already done" probes already exist informally (venv `:471`, "Updating vs Writing" service
  file `:2780`, hayabusa pin). Formalize as `phase_<name>_is_done` returning 0/1.
- **Upgrade vs fresh** is detected today only by `backup_preexisting_data_if_fresh` (`$SIFT_HOME`
  presence `:592`). Surface it explicitly in the summary and in `--dry-run` ("UPGRADE: live cases
  preserved" vs "FRESH: orphaned data → preinstall backup").
- **Post-install self-check (`--verify`, new `lib/verify.sh`):** `/health` via the CA, `systemctl
  is-active` for gateway/worker/opensearch-workers, seeded backends present in `app.mcp_backends`,
  venv imports of `sift_gateway`/`mcp`. Reuses `poll_gateway` (`:2831`).

---

## 7. Skeleton / Pseudocode

### 7.1 New thin `install.sh` (entrypoint)

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

SIFT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/lib" && pwd)"
# Order matters: constants + log first, the rest are independent.
source "$SIFT_LIB_DIR/constants.sh"
source "$SIFT_LIB_DIR/log.sh"
for m in preflight python state secrets supabase opensearch tools services hardening addons teardown verify; do
  source "$SIFT_LIB_DIR/$m.sh"
done

on_error() {           # structured fail-safe (§6.3)
  local code=$? phase="${CURRENT_PHASE:-unknown}"
  warn "FAILED in phase '$phase' (exit $code). Remediation: $(remediation_for "$phase")"
  exit "$code"
}
trap on_error ERR

phase() { CURRENT_PHASE="$1"; shift; "$@"; }   # names the phase for the trap + journal

main() {
  parse_and_validate_flags "$@"        # fail-fast on unknown/conflicting (replaces :3455)
  [[ "$DO_HELP"      == 1 ]] && { print_help; exit 0; }
  [[ "$DO_VERSION"   == 1 ]] && { print_version; exit 0; }
  [[ "$UNINSTALL"    == 1 ]] && { exec "$REPO_DIR/scripts/uninstall.sh" "${UNINSTALL_ARGS[@]}"; }
  [[ "$DO_VERIFY"    == 1 ]] && { run_self_check; exit $?; }

  phase preflight    run_preflight
  phase stage        stage_repo_to_install_root "$@"   # may re-exec
  phase tiers        resolve_tiers
  phase supabase-pre preflight_supabase
  phase python       install_runtime          # published wheels OR --from-source uv sync
  phase state        provision_state_and_users
  phase secrets      provision_secrets_and_env
  phase migrations   apply_db_migrations
  phase config       write_runtime_config
  phase firstparty   provision_first_party_addons   # RAG, OpenSearch, tools (may parallelize §6.2)
  phase seed         seed_addon_backends
  phase services     install_and_start_services
  phase hardening    apply_hardening
  phase verify       poll_gateway initial && bootstrap_supabase_operator
  print_summary
}
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && main "$@"
```

### 7.2 Representative module — `lib/python.sh` (published-primary, source-secondary)

```bash
# lib/python.sh — Python runtime provisioning. Honors D1 (published primary).
# Hard invariants (verify in code): system python3.12, no managed python, no downloads.

install_runtime() {
  install_uv_if_needed                 # unchanged: pinned + SHA-verified tarball (was install.sh:302)
  export UV_PYTHON="$SYSTEM_PYTHON" UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never
  if [[ "${SIFT_FROM_SOURCE:-0}" == "1" ]]; then
    sync_workspace                     # developer path (was install.sh:494)
  else
    install_published                  # NEW default
  fi
  verify_runtime_imports               # was the post-sync loop (install.sh:518) — now shared
}

install_published() {
  local extra="full"; [[ "${SIFT_CORE_ONLY:-0}" == 1 ]] && extra="core"
  local spec="sift-mcps[$extra]==${SIFT_PKG_VERSION:?pin required}"
  local constraints="$REPO_DIR/dist/constraints-${SIFT_PKG_VERSION}.txt"   # shipped, hash-pinned
  [[ -d "$VENV_DIR" ]] || "$UV_BIN" venv --python "$SYSTEM_PYTHON" "$VENV_DIR"
  if is_offline; then
    "$UV_BIN" pip install --python "$VENV_PYTHON" --no-index \
      --find-links "${SIFT_WHEELHOUSE:?stage a wheelhouse for --offline}" "$spec"
  else
    "$UV_BIN" pip install --python "$VENV_PYTHON" \
      ${constraints:+-c "$constraints"} "$spec"     # pinned + integrity-checked
  fi
}

verify_runtime_imports() {            # idempotency + fail-safe (§6.4)
  local ok=1
  for pkg in yaml mcp sift_core sift_gateway; do
    "$VENV_PYTHON" -c "import $pkg" 2>/dev/null || { warn "import '$pkg' failed"; ok=0; }
  done
  [[ "$ok" == 1 ]] || die "runtime import verification failed"   # was a soft warn (install.sh:524)
}
```

---

## 8. Risk Register & Ordered Migration (low-risk-first)

| Step | Action | Touches | Risk | Reversible? |
|------|--------|---------|------|-------------|
| M0 | **Tests first (AXIS_I I1):** extract `verify_sha256`, `_ensure_venv_integrity`, `_purge_tree`, `_render_file` into `lib/` files and unit-test with temp dirs/fakes — install.sh keeps sourcing them. | `install.sh:57/471/3341/1762` → `lib/` | Very low | Yes |
| M1 | Add `bash -n` + shellcheck CI over install.sh + scripts + lib. | CI | None | Yes |
| M2 | Fix dead/footgun flags: remove `--no-opencti`, fail-fast unknown flags, add `--non-interactive`/`--dry-run`/`--version`/`--verify` skeleton. | `main:3410-3459` | Low | Yes |
| M3 | Make `install.sh --uninstall` **delegate** to `scripts/uninstall.sh`; delete `do_uninstall`/`purge_data` (R7/R8). | `install.sh:3252-3393` | Med (behavior change) | Yes (re-add) |
| M4 | Move all functions into `lib/*.sh` per §5; `install.sh` becomes the thin entrypoint. No logic change. | whole file | Med (mechanical) | Yes |
| M5 | Add ERR trap + stable exit codes + phase journal. | `lib/log.sh`, entrypoint | Low | Yes |
| M6 | Add `--verify` self-check (`lib/verify.sh`). | new | Low | Yes |
| M7 | **Version coherence:** bump `sift-core`/`windows-triage-mcp`/root to the `0.6.x` line. | `pyproject.toml` ×3 | Low | Yes |
| M8 | CI: build wheels (frontend baked) + generate hash-pinned constraints + asset SHA ledger on tag. | CI, `dist/` | Med | Yes |
| M9 | Add `install_published()` + `--from-source`; flip default to published once M7/M8 land. Keep `sync_workspace` as `--from-source`. | `lib/python.sh` | **High** (core flow) | Yes (flag flip) |
| M10 | Parallelize §6.2 tool downloads behind `wait`. | `lib/tools.sh` | Low | Yes |
| M11 | Consolidate duplicated TLS into shared `lib/tls.sh` (install + rotate-tls). | `install.sh:1241`, `rotate-tls.sh` | Low | Yes |

Land M0–M6 with zero distribution change (pure hardening + modularization, all reversible), then
M7–M9 to deliver the registry-primary model, then M10–M11 cleanup.

---

## 9. Open Questions / Decisions Needed From the Lead

1. **PyPI vs private index.** D1 says "registry-primary," but does the operator want these on **public
   PyPI** (forensic tooling, name-squatting, disclosure surface) or a **private/self-hosted index**
   (devpi/Artifactory)? This changes the bootstrap auth, the `-c constraints` source of truth, and
   whether package names must be globally unique. The frontend bundle ships inside `case-dashboard`
   either way (no separate npm decision needed).

2. **Where does the published-vs-source default live, and what's the version pin source of truth?**
   Today the version pin would be `$SIFT_PKG_VERSION`, but the repo has **version skew** (`sift-core`
   and `windows-triage-mcp` are `0.1.0`; everything else `0.6.1`; root `0.1.0`). Before publishing,
   does the lead want a single coherent version line for all runtime packages (recommended), and
   should the installer derive its pin from a checked-in `VERSION`/git tag or accept it as an env var?

3. **Should `install.sh --uninstall` be removed entirely in favor of `scripts/uninstall.sh`?** The
   in-script `do_uninstall` (`:3370`) has *weaker* evidence-deletion gating than the canonical script
   (single `yes` / `-y` vs typed `DELETE EVIDENCE` + triple flags). I recommend M3 (delegate) — but if
   any automation calls `./install.sh --purge-data` today, delegating changes its prompt contract.
   Does the lead know of callers (CI, `reset-vm-test.sh` is already gone) that depend on the current
   coarse behavior?

---

### Appendix — cross-references
- Download/asset inventory + SHA ledger: `docs/new-docs/install-nextgen/03-DOWNLOAD-ASSET-INVENTORY.md`
  (Track B); installer pins at `install.sh:155-187`; provenance ledger referenced at `install.sh:160`.
- Installer verification track: `docs/new-docs/AXIS_I_BUILD_PLAN.md` (I1 static harness, I2 smoke,
  I3 replacement decision — this blueprint is the I3 input, M0 maps to I1).
- Operator decision D1: `docs/new-docs/install-nextgen/00-ORCHESTRATION-LOG.md`.
