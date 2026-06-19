

---
Installation Modernization Blueprint — Protocol SIFT Gateway (v2, registry-primary)

---
1. Executive Summary

Target model: thin bootstrap installer + registry-published packages, with sourced-library Bash modularization as the parallel structural modernization.

The installer (./install.sh) shrinks to a ~150-line bootstrap entrypoint that:
1. Sources a lib/ directory of independently-testable Bash modules.
2. Installs the Python workspace from PyPI (published, version-pinned wheels) using the system /usr/bin/python3.12 and uv, rather than building from a gitclone.
3. Installs the portal frontend from a GitHub Release artifact (pre-built npm dist tarball) into the case-dashboard static directory.
4. Provisions system services, TLS, secrets, users, and OS hardening exactly as today.

Offline/air-gap is supported as a secondary mode: operators pre-stage the published wheel files and the frontend tarball, and --offline routes to those staged artifacts instead.

The nine workspace packages are published to PyPI under a coordinated versioning scheme. The portal frontend is published as a versioned tarball on GitHubReleases (or a private npm registry). The scripts/uninstall.sh becomes the single canonical teardown; the duplicate inline uninstall in install.sh is removed.

---
2. Current-State Audit

2.1 Monolith Statistics

┌─────────────────────────────────────┬─────────────────────────────────────────────────────────────────────┐
│               Metric                │                                Value                                │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Total lines                         │ 3,658                                                               │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Declared functions                  │ 95                                                                  │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Inlined Python heredocs             │ ~18 <<'PY' blocks                                                   │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Distinct phases                     │ 14 (Phase 0 through 14 + main + inline uninstall)                   │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Named download pins                 │ 5 (uv D1, hayabusa D2, BGE model D3, RAG index D4, Supabase CLI D5) │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Flags parsed by main()              │ 10 flags                                                            │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
│ Exported environment variable knobs │ ~28                                                                 │
└─────────────────────────────────────┴─────────────────────────────────────────────────────────────────────┘

2.2 Phase Inventory

┌─────────────────────┬───────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│        Phase        │   Line    │                                                  Responsibilities                                                  │
│                     │   range   │                                                                                                                    │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 0 — pre-flight      │ 249–461   │ check_os, check_python, install_host_prereqs, ensure_docker_ready_for_supabase                                     │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 1 — uv install      │ 292–354   │ install_uv_if_needed (pinned D1, SHA-256 gate, arch branch)                                                        │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2 — venv integrity  │ 463–574   │ _ensure_venv_integrity, sync_workspace, repair_pyewf_venv_link                                                     │
│ + sync              │           │                                                                                                                    │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3 — state           │ 576–783   │ backup_preexisting_data_if_fresh, install_state_dirs, ensure_gateway_service_user, configure_agent_runtime,        │
│ directories         │           │ join_shared_symbol_group, configure_ingest_mount_sudoers                                                           │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 4 — assets          │ 785–1172  │ configure_fuse, prepare_enrichment_assets, load_rag_pgvector, install_hayabusa, install_zimmerman_symlinks,        │
│                     │           │ install_complementary_tools, fix_volatility_permissions (no-op)                                                    │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 5 — TLS             │ 1174–1278 │ generate_tls, _tls_san_value, _tls_write_leaf_ext, _tls_sign_leaf                                                  │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 6 — examiner        │ 1280–1447 │ write_default_examiner, _seed_one_addon_backend, seed_addon_backends, bootstrap_supabase_operator                  │
│ account             │           │                                                                                                                    │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 7 — gateway +       │           │ preflight_supabase, write_supabase_env, write_control_plane_env, write_gateway_config, _migrate_gateway_config,    │
│ OpenSearch config   │ 1758–2389 │ _render_file, write_fk_env, write_opensearch_config, write_opensearch_env, validate_evidence_root,                 │
│                     │           │ apply_db_migrations                                                                                                │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 8 — OpenSearch      │ 2390–2662 │ start_opensearch, configure_opensearch_cluster, configure_geoip_pipeline, configure_opensearch_detections,         │
│ Docker              │           │ install_opensearch_templates                                                                                       │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 9 — OpenCTI (dead   │ 2664–2756 │ prepare_opencti_secrets, install_opencti, install_opencti_feeds (all gated SIFT_OPENCTI_ENABLED=false; unreachable │
│ path)               │           │  from main())                                                                                                      │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 10 — systemd        │ 2758–2825 │ install_systemd_service                                                                                            │
│ service             │           │                                                                                                                    │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 11 — validation     │ 2827–2874 │ poll_gateway                                                                                                       │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 12 — handoff        │ 2876–2990 │ write_handoff                                                                                                      │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 13 — OS hardening   │ 2992–3131 │ configure_immutable_capability, configure_auditd, configure_apparmor, configure_run_command_systemd_scope          │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ 14 — summary        │ 3133–3219 │ print_summary                                                                                                      │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Uninstall (inline)  │ 3221–3393 │ do_uninstall, uninstall_systemd, uninstall_docker_stacks, uninstall_system_hardening, uninstall_runtime,           │
│                     │           │ purge_data, _purge_tree                                                                                            │
├─────────────────────┼───────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ main()              │ 3399–3658 │ Flag parsing, phase sequencing, feature-flag wiring                                                                │
└─────────────────────┴───────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

2.3 Current Packaging: Source-Install via uv sync

The installer currently stages the git repo to /opt/sift-mcps (stage_repo_to_install_root, line 197), then runs uv sync --extra full --project "$REPO_DIR"--python "$SYSTEM_PYTHON" (line 508). This builds a venv from the workspace sources in place. All nine workspace packages are local, co-versioned, and never published anywhere. Consequences:

- The installed runtime IS the git tree at /opt/sift-mcps. Source code changes on the VM directly affect the running service (useful for development;problematic for a stable production install).
- setup-addon.sh sources install.sh as a function library (setup-addon.sh:54) — it must run from the staged tree or the console-script paths break.
- There is no concept of a "release": the operator installs from whatever git commit they cloned.
- Re-installs are git pull && ./install.sh, which re-runs uv sync against the updated source.

2.4 Problems, Dead Code, and Footguns

P1 — Dual uninstall implementations (HIGH).
install.sh:3221–3393 contains a full inline teardown (do_uninstall, 7 functions, ~170 lines). scripts/uninstall.sh is a separate, more capable teardown with per-component selection, dry-run default, interactive menu, and evidence blast-radius gate. The two are asymmetric: the inline path does not handleOpenSearch workers or AppArmor component-level teardown; scripts/uninstall.sh does. _purge_tree is defined in both. Risk: --uninstall produces incomplete teardown.

P2 — Phase 9 OpenCTI install code is dead weight (LOW).
prepare_opencti_secrets, install_opencti, install_opencti_feeds (lines 2664–2756) are unreachable: main() unconditionally sets SIFT_OPENCTI_ENABLED="false" at line 3516. These ~100 lines pollute the global namespace with OPENCTI_TOKEN, OPENCTI_ENCRYPTION_KEY, OPENCTI_HEALTH_ACCESS_KEY.

P3 — setup-addon.sh sources entire install.sh (MEDIUM).
setup-addon.sh:54: source "$REPO_ROOT/install.sh". Any structural change to install.sh (including the move to a thin entrypoint) must keep the source-guard pattern or break the add-on helper. In the registry-install model this dependency is also wrong: setup-addon.sh would be sourcing an installer whoseREPO_DIR may no longer point to actual package sources.

P4 — stage_repo_to_install_root re-execs installer before any library is sourced (HIGH).
Line 246: exec "$dst/install.sh" "$@". This re-exec happens before lib/ can be sourced, and after re-exec REPO_DIR changes to /opt/sift-mcps. In theregistry-install model this function's purpose changes entirely (the source tree is no longer the runtime; the runtime is the venv).

P5 — ~18 Python heredocs embedded in Bash (MEDIUM).
Migration runner, Supabase bootstrap, config renderer, seed registrar — all are unexported, untestable Python strings passed via env-variable callingconvention.

P6 — fix_volatility_permissions is an explicit no-op (LOW).
Line 1162 returns 0 immediately. Still called from main() at line 3599.

P7 — check_os warns on non-Ubuntu but is stale (MEDIUM).
Line 253 warns if ID != "ubuntu". The SIFT VM is Ubuntu, but the comment says "Fedora-family." The check is correct; the comment is stale.

P8 — No --dry-run for install (MEDIUM).
scripts/uninstall.sh has dry-run by default. install.sh has none.

P9 — Unit files re-rendered on every re-run (LOW).
install_systemd_service at line 2780 always calls _render_file and then daemon-reload + restart, even when nothing changed.

P10 — Frontend is pre-built and committed (MEDIUM, design smell).
packages/case-dashboard/frontend/ is a Vite+React app; built output is in packages/case-dashboard/src/case_dashboard/static/. No npm build step in theinstaller. Static assets may drift from source between developer builds.

---
3. Target Architecture

3.1 Three-Tier Component Model

Tier A — Core (always installed, published to PyPI as first-class packages)

┌─────────────────────┬─────────────────────────────────┬───────────────────────────────┐
│      Component      │          PyPI package           │            Service            │
├─────────────────────┼─────────────────────────────────┼───────────────────────────────┤
│ Gateway             │ sift-gateway                    │ sift-gateway.service          │
├─────────────────────┼─────────────────────────────────┼───────────────────────────────┤
│ Core forensic tools │ sift-core                       │ in-process                    │
├─────────────────────┼─────────────────────────────────┼───────────────────────────────┤
│ Portal              │ case-dashboard                  │ in-process, served by gateway │
├─────────────────────┼─────────────────────────────────┼───────────────────────────────┤
│ Common libs + FK    │ sift-common, forensic-knowledge │ in-process                    │
├─────────────────────┼─────────────────────────────────┼───────────────────────────────┤
│ Job worker          │ sift-gateway (console script)   │ sift-job-worker.service       │
└─────────────────────┴─────────────────────────────────┴───────────────────────────────┘

Tier B — Core-addons / First-party (published to PyPI, installed by default, individually toggleable)

┌────────────────────────┬────────────────┬──────────────────────────────────┬─────────┐
│       Component        │  PyPI package  │             Service              │ Default │
├────────────────────────┼────────────────┼──────────────────────────────────┼─────────┤
│ OpenSearch MCP         │ opensearch-mcp │ sift-opensearch-worker@N.service │ ON      │
├────────────────────────┼────────────────┼──────────────────────────────────┼─────────┤
│ Forensic RAG knowledge │ rag-mcp        │ stdio subprocess                 │ ON      │
└────────────────────────┴────────────────┴──────────────────────────────────┴─────────┘

These ship with the default --extra full uv install. They are NOT external add-ons; they are seeded into app.mcp_backends automatically by the installer.

Tier C — True External Add-ons (published to PyPI as optional extras; never installed by install.sh)

┌────────────────────┬────────────────────┬────────────────────────────────────────────┐
│     Component      │    PyPI package    │                Registration                │
├────────────────────┼────────────────────┼────────────────────────────────────────────┤
│ OpenCTI            │ opencti-mcp        │ scripts/setup-addon.sh → Portal → Backends │
├────────────────────┼────────────────────┼────────────────────────────────────────────┤
│ Windows Triage     │ windows-triage-mcp │ scripts/setup-addon.sh → Portal → Backends │
├────────────────────┼────────────────────┼────────────────────────────────────────────┤
│ Community backends │ user-provided      │ Portal → Backends                          │
└────────────────────┴────────────────────┴────────────────────────────────────────────┘

install.sh has zero code paths for Tier C. Phase 9 dead code is removed.

3.2 Packaging and Distribution Strategy (registry-primary)

Recommended Primary Model: PyPI-published wheels + thin bootstrap installer

Which packages to publish and how:

All nine workspace packages should be published to PyPI (or a private registry if the operator prefers). Publication rationale: the VM has network access;pulling pinned, signed wheels from PyPI is more reproducible than pulling from a git branch, easier to audit by hash, and enables a standard upgrade flow (uv pip install --upgrade sift-gateway==1.2.3).

┌────────────────────┬─────────────────────────┬────────────────┬───────────────────────────────────────────────────────────┐
│      Package       │  PyPI name (proposed)   │    Publish     │                         Rationale                         │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ sift-gateway       │ sift-gateway            │ Yes            │ Core; public forensic tool                                │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ sift-core          │ sift-core               │ Yes            │ Core; public forensic tool                                │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ case-dashboard     │ sift-case-dashboard     │ Yes            │ Portal; included in sift-gateway[portal] extra            │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ sift-common        │ sift-common             │ Yes            │ Shared lib depended on by all                             │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ forensic-knowledge │ sift-forensic-knowledge │ Yes            │ Data package; bundles reference KB JSONL                  │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ opensearch-mcp     │ sift-opensearch-mcp     │ Yes            │ Tier B core-addon                                         │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ rag-mcp            │ sift-rag-mcp            │ Yes            │ Tier B core-addon                                         │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ opencti-mcp        │ sift-opencti-mcp        │ Yes (optional) │ Tier C; install via setup-addon.sh --extra opencti        │
├────────────────────┼─────────────────────────┼────────────────┼───────────────────────────────────────────────────────────┤
│ windows-triage-mcp │ sift-windows-triage-mcp │ Yes (optional) │ Tier C; install via setup-addon.sh --extra windows-triage │
└────────────────────┴─────────────────────────┴────────────────┴───────────────────────────────────────────────────────────┘

Extras → published distributions mapping:

The root pyproject.toml extras define install profiles. In the published model, a meta-package sift-mcps (or sift-gateway[full]) pulls all Tier A + Tier Bpackages:

# Published meta-package / extra on sift-gateway
[project.optional-dependencies]
core     = ["sift-core", "sift-case-dashboard", "sift-common", "sift-forensic-knowledge"]
standard = ["sift-gateway[core]", "sift-opensearch-mcp"]
full     = ["sift-gateway[standard]", "sift-rag-mcp"]
# Tier C extras (not in default install):
opencti        = ["sift-opencti-mcp"]
windows-triage = ["sift-windows-triage-mcp"]

The bootstrap installer runs:
uv pip install --python "$SYSTEM_PYTHON" \
  "sift-gateway[full]==1.2.3" \
  --constraint /opt/sift-mcps/constraints.txt   # pinned transitive deps

Versioning and release flow:

All nine packages share a single version (monorepo style, analogous to how pip, setuptools, and related tools release). A single VERSION file at repo root drives all pyproject.toml versions via hatch-vcs or a simple sed step. The release flow:

1. Tag: git tag v1.2.3
2. CI (GitHub Actions): python -m build on each package → dist/*.whl + *.tar.gz
3. CI: twine upload --repository pypi dist/* (or uv publish)
4. CI: build portal frontend → upload sift-portal-v1.2.3.tar.gz to GitHub Release
5. CI: update install.sh SIFT_VERSION pin and SIFT_WHEEL_SHA256 constraints file

The bootstrap installer pins the version via SIFT_VERSION and validates wheel hashes via a constraints.txt / requirements.txt with --hash=sha256:...entries (PEP 751 / pip-compile --generate-hashes pattern, compatible with uv).

Integrity and pinning of published deps:

constraints.txt in the repo root is generated at release time:
uv pip compile pyproject.toml --extra full --generate-hashes \
  --python-version 3.12 -o constraints.txt
The bootstrap installer uses:
uv pip install --python "$SYSTEM_PYTHON" \
  "sift-gateway[full]==$SIFT_VERSION" \
  --constraint "$REPO_DIR/constraints.txt" \
  --require-hashes
This is the equivalent of the current SHA-256 pinning for uv/hayabusa/Supabase CLI, but applied to the Python dependency graph.

Portal frontend distribution:

The Vite+React frontend (packages/case-dashboard/frontend/) is built in CI (npm ci && npm run build) and the dist/ output is:
1. Copied into packages/case-dashboard/src/case_dashboard/static/ before the wheel is built (so the static assets are bundled inside thesift-case-dashboard wheel — the current pattern, now automated in CI).
2. Also uploaded as a standalone tarball sift-portal-v1.2.3.tar.gz to the GitHub Release for operators who need to update the portal without reinstallingthe full Python package.

The bootstrap installer does NOT run npm. The pre-built static assets ride inside the sift-case-dashboard wheel. A Makefile target (make portal) runs the npm build for developers.

Migration from source-uv to published-package install:

┌────────────────────┬──────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────┐
│        Step        │               Current                │                                         Target                                          │
├────────────────────┼──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ Operator action    │ git clone && ./install.sh            │ curl -fsSL https://…/install.sh | sh -s -- --version 1.2.3 OR git clone && ./install.sh │
│                    │                                      │  --version 1.2.3                                                                        │
├────────────────────┼──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ Python package     │ uv sync --project $REPO_DIR (local   │ uv pip install sift-gateway[full]==1.2.3 --constraint constraints.txt --require-hashes  │
│ source             │ source)                              │                                                                                         │
├────────────────────┼──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ Runtime tree       │ /opt/sift-mcps/ = git clone          │ /opt/sift-mcps/ = thin scaffold (configs, migrations, scripts only; no package source)  │
├────────────────────┼──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ Venv               │ built from workspace source          │ built from published wheels                                                             │
├────────────────────┼──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ Upgrade            │ git pull && ./install.sh             │ ./install.sh --version 1.2.4 (bootstrap re-runs pip install with new pin)               │
├────────────────────┼──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
│ Rollback           │ git checkout v1.2.2 && ./install.sh  │ ./install.sh --version 1.2.2                                                            │
└────────────────────┴──────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────┘

Migration risk: the workspace has internal cross-references via [tool.uv.sources] (workspace members). When publishing to PyPI, these become versioned PyPI deps. The release CI must publish all packages atomically (or in dependency order: sift-common → sift-core → sift-gateway) to avoid a window where sift-gateway==1.2.3 is published but sift-core==1.2.3 is not yet available.

Offline / air-gap (secondary mode):

In offline mode (--offline / SIFT_OFFLINE=1), the bootstrap installer skips PyPI and instead installs from a pre-staged wheel directory:
uv pip install --python "$SYSTEM_PYTHON" \
  --no-index --find-links "$SIFT_OFFLINE_WHEEL_DIR" \
  "sift-gateway[full]==$SIFT_VERSION" \
  --constraint "$REPO_DIR/constraints.txt" \
  --require-hashes
The scripts/bundle-offline.sh tool creates the offline bundle:
# On an internet-connected machine:
uv pip download "sift-gateway[full]==$SIFT_VERSION" \
  --constraint constraints.txt \
  --require-hashes \
  -d /tmp/sift-offline-wheels/
# Also stage: uv binary, Supabase CLI tarball, hayabusa zip, BGE model weights
tar czf sift-offline-bundle-$SIFT_VERSION.tar.gz /tmp/sift-offline-wheels/ sift-portal-$SIFT_VERSION.tar.gz
This tarball is the forensic air-gap artifact. The installer detects it via SIFT_OFFLINE_WHEEL_DIR or --offline-bundle PATH.

3.3 Directory/Service Layout (target)

/opt/sift-mcps/              ← runtime scaffold (NOT a git clone)
  .venv/                     ← uv-managed venv (wheels from PyPI)
  supabase/                  ← migrations (copied from release tarball or thin scaffold)
  configs/                   ← systemd units, AppArmor, gateway template
  lib/                       ← NEW: sourced installer library modules
  constraints.txt            ← pinned transitive deps with hashes
  install.sh                 ← thin bootstrap entrypoint (~150 lines)
  scripts/
    uninstall.sh             ← canonical teardown
    setup-addon.sh           ← updated (sources lib/ directly, not install.sh)
    setup-supabase.sh        ← unchanged
    bundle-offline.sh        ← NEW: creates offline wheel bundle

/var/lib/sift/               ← SIFT_STATE_DIR (service-owned)
  .sift/                     ← SIFT_HOME (secrets, TLS, config)
  passwords/, tokens/, etc.  ← state subdirs

/var/cache/sift/
  volatility-symbols/        ← shared symbol cache (2775, group sift)

/cases/                      ← evidence root

/etc/systemd/system/
  sift-gateway.service
  sift-job-worker.service
  sift-opensearch-worker@.service

The key difference from current: /opt/sift-mcps/ is no longer a live git checkout. It is a minimal scaffold containing configs, migrations, and the venv populated from published wheels. Package source code lives only in the wheels inside the venv, not on disk under /opt/sift-mcps/packages/.

Implication for setup-addon.sh: the SIFT_MCPS_ROOT path is still /opt/sift-mcps; the venv is still at $SIFT_MCPS_ROOT/.venv. Console scripts(opensearch-mcp, rag-mcp) are still at $SIFT_MCPS_ROOT/.venv/bin/. The add-on helper's core logic is unchanged; only its internal source call changes (see §5).

---
4. Proposed CLI and Help Spec

4.1 Flag Table (target)

Install scope:

┌─────────────────────┬───────────────────────────────┬────────────────────────────────────────────────────────────────────────────────────┐
│        Flag         │           Env equiv           │                                    Description                                     │
├─────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ (no flags)          │ —                             │ Full install: core + core-addons (OpenSearch + RAG), version from SIFT_VERSION     │
├─────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ --version VER       │ SIFT_VERSION=VER              │ Install specific published version (default: latest stable pin in constraints.txt) │
├─────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ --core-only         │ SIFT_CORE_ONLY=1              │ Core only: gateway + portal + in-process tools. No OpenSearch, RAG, Docker.        │
├─────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ --no-opensearch     │ SIFT_OPENSEARCH_ENABLED=false │ Disable OpenSearch (keep RAG)                                                      │
├─────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ --no-rag            │ SIFT_RAG_ENABLED=false        │ Disable forensic-rag-mcp backend                                                   │
├─────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ --external-supabase │ SIFT_EXTERNAL_SUPABASE=1      │ Use pre-exported Supabase creds                                                    │
└─────────────────────┴───────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────┘

Network / registry:

┌───────────────────────┬────────────────────────────┬──────────────────────────────────────────────────────────────────────┐
│         Flag          │         Env equiv          │                             Description                              │
├───────────────────────┼────────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ --offline             │ SIFT_OFFLINE=1             │ No network. Install from --offline-bundle or SIFT_OFFLINE_WHEEL_DIR. │
├───────────────────────┼────────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ --offline-bundle PATH │ SIFT_OFFLINE_BUNDLE=PATH   │ Path to the pre-staged offline bundle tarball                        │
├───────────────────────┼────────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ --offline-wheels DIR  │ SIFT_OFFLINE_WHEEL_DIR=DIR │ Path to pre-staged wheel directory                                   │
├───────────────────────┼────────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ --index-url URL       │ SIFT_PYPI_INDEX=URL        │ Override PyPI index (private registry / air-gap mirror)              │
├───────────────────────┼────────────────────────────┼──────────────────────────────────────────────────────────────────────┤
│ --enable-geoip        │ SIFT_GEOIP_ENABLED=1       │ Enable OpenSearch ip2geo (off by default)                            │
└───────────────────────┴────────────────────────────┴──────────────────────────────────────────────────────────────────────┘

Security / hardening:

┌────────────────────┬─────────────────────────┬────────────────────────────────────────┐
│        Flag        │        Env equiv        │              Description               │
├────────────────────┼─────────────────────────┼────────────────────────────────────────┤
│ --apparmor-enforce │ SIFT_APPARMOR_ENFORCE=1 │ Load AppArmor profiles in ENFORCE mode │
└────────────────────┴─────────────────────────┴────────────────────────────────────────┘

Tuning:

┌─────────────────────┬─────────────────────────────┬────────────────────────────────────────────────────────┐
│        Flag         │          Env equiv          │                      Description                       │
├─────────────────────┼─────────────────────────────┼────────────────────────────────────────────────────────┤
│ --workers N         │ SIFT_OPENSEARCH_WORKERS=N   │ OpenSearch ingest/enrich worker instances (default: 2) │
├─────────────────────┼─────────────────────────────┼────────────────────────────────────────────────────────┤
│ --install-root PATH │ SIFT_MCPS_INSTALL_ROOT=PATH │ Override staging root (default: /opt/sift-mcps)        │
└─────────────────────┴─────────────────────────────┴────────────────────────────────────────────────────────┘

Dry-run / safety:

┌───────────┬───────────────────────────────────────────────────────────────────┐
│   Flag    │                            Description                            │
├───────────┼───────────────────────────────────────────────────────────────────┤
│ --dry-run │ Print what WOULD be done; no privileged or destructive operations │
├───────────┼───────────────────────────────────────────────────────────────────┤
│ -y, --yes │ Non-interactive: assume yes on prompts                            │
└───────────┴───────────────────────────────────────────────────────────────────┘

Teardown:

┌──────────────┬──────────────────────────────────────────────────────────────────────────────┐
│     Flag     │                                 Description                                  │
├──────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ --uninstall  │ Thin shim: delegates to scripts/uninstall.sh --all --yes --i-understand      │
├──────────────┼──────────────────────────────────────────────────────────────────────────────┤
│ --purge-data │ With --uninstall, also passes --remove-evidence --i-understand-evidence-loss │
└──────────────┴──────────────────────────────────────────────────────────────────────────────┘

Info:

┌────────────────┬───────────────────────────────────────────┐
│      Flag      │                Description                │
├────────────────┼───────────────────────────────────────────┤
│ -h, --help     │ Grouped help with examples                │
├────────────────┼───────────────────────────────────────────┤
│ --version-info │ Print installed package versions and exit │
└────────────────┴───────────────────────────────────────────┘

4.2 Literal --help Mockup

Usage: ./install.sh [OPTIONS]

Bootstrap and provision a Protocol SIFT Gateway stack on SIFT Workstation (Ubuntu 22.04/24.04).
Installs published, version-pinned wheels from PyPI using system Python (/usr/bin/python3.12).
Re-run safe: every step detects already-complete work.

INSTALL SCOPE
  (no flags)             Full install: gateway + portal + OpenSearch + RAG knowledge
  --version VER          Install specific published version (e.g. --version 1.2.3)
  --core-only            Core only: gateway + portal. No OpenSearch, RAG, Docker.
  --no-opensearch        Skip OpenSearch backend (keep RAG).
  --no-rag               Skip forensic-rag-mcp backend.

SUPABASE / CONTROL PLANE
  --external-supabase    Use pre-exported Supabase creds (no auto-provision).
                         Requires: SUPABASE_URL, SUPABASE_ANON_KEY,
                                   SUPABASE_SERVICE_ROLE_KEY, SIFT_CONTROL_PLANE_DSN.

NETWORK / REGISTRY
  --offline              No network downloads. Install from staged wheels.
                         Use --offline-bundle or --offline-wheels to point at them.
                         For bundling: scripts/bundle-offline.sh --version VER
  --offline-bundle PATH  Path to a pre-staged offline bundle tarball.
  --offline-wheels DIR   Path to a directory of pre-staged .whl files.
  --index-url URL        Override the PyPI index (private registry / air-gap mirror).
                         Equivalent to uv pip install --index-url URL.
  --enable-geoip         Enable OpenSearch ip2geo datasource (fetches live; off by default).

SECURITY / HARDENING
  --apparmor-enforce     Load AppArmor profiles in ENFORCE mode (default: complain).
                         Can also be done post-install via ./harden.sh.

WORKERS / TUNING
  --workers N            Number of OpenSearch ingest/enrich worker instances (default: 2).
  --install-root PATH    Override staging root (default: /opt/sift-mcps).

DRY-RUN / SAFETY
  --dry-run              Show what would be done; no privileged or destructive operations.
  -y, --yes              Assume yes to all confirmation prompts (non-interactive).

TEARDOWN
  --uninstall            Remove installed stack (delegates to scripts/uninstall.sh).
                         Preserves /cases (evidence) and /var/lib/sift (state) by default.
  --purge-data           With --uninstall, ALSO wipe /var/lib/sift and /cases. IRREVERSIBLE.

ADD-ON BACKENDS
  Not installed by this script. Prepare with:  scripts/setup-addon.sh
  Then register:  Portal → Backends → Add backend → Validate → Register

KEY ENVIRONMENT VARIABLES
  SIFT_VERSION=1.2.3            Pin the package version to install
  SIFT_OFFLINE=1                Same as --offline
  SIFT_CORE_ONLY=1              Same as --core-only
  SIFT_OPENSEARCH_ENABLED=false Disable OpenSearch
  SIFT_RAG_ENABLED=false        Disable RAG
  SIFT_OPENSEARCH_WORKERS=N     Worker count
  SIFT_PYPI_INDEX=URL           Override PyPI index URL
  SIFT_OFFLINE_WHEEL_DIR=PATH   Pre-staged wheel directory
  SIFT_UV_VERSION=0.11.21       Pin uv bootstrap version
  SIFT_HAYABUSA_TAG=v3.9.0      Pin hayabusa release
  SIFT_MCPS_INSTALL_ROOT=PATH   Override staging root

EXAMPLES
  ./install.sh                            # Full install, latest stable
  ./install.sh --version 1.2.3           # Specific published version
  ./install.sh --core-only               # Gateway + portal only
  ./install.sh --offline --offline-bundle /tmp/sift-bundle.tar.gz
  ./install.sh --apparmor-enforce        # Full install + AppArmor enforce
  ./install.sh --dry-run                 # Preview what would happen
  ./install.sh --uninstall               # Remove installed stack
  SIFT_VERSION=1.2.3 ./install.sh --offline-wheels /tmp/wheels/

For teardown options:  scripts/uninstall.sh --help
For add-on setup:      scripts/setup-addon.sh --help
For AppArmor harden:   ./harden.sh --help
For offline bundling:  scripts/bundle-offline.sh --help

---
5. Modularization Plan

5.1 New File Layout

install.sh            ← thin bootstrap entrypoint (~150 lines)
lib/
  common.sh           ← log/warn/die, sudo_if_needed, user_name, group_name, require_cmd,
                         random_hex, verify_sha256, offline_die/is_offline, svc_read/svc_test_f/
                         svc_install_file, _same_path, run_dry (DRY_RUN guard wrapper)
  paths.sh            ← SIFT_* path/const vars and download-pin vars
  preflight.sh        ← check_os, check_python, preflight_check (disk space + deps),
                         install_host_prereqs, ensure_docker_ready_for_supabase
  python.sh           ← install_uv_if_needed, install_packages_from_registry,
                         install_packages_offline, _ensure_venv_integrity, repair_pyewf_venv_link
  users.sh            ← ensure_gateway_service_user, configure_agent_runtime,
                         join_shared_symbol_group, configure_ingest_mount_sudoers
  state.sh            ← install_state_dirs, backup_preexisting_data_if_fresh,
                         validate_evidence_root
  tls.sh              ← generate_tls, _tls_san_value, _tls_write_leaf_ext, _tls_sign_leaf
  config.sh           ← _render_file, write_gateway_config, _migrate_gateway_config,
                         write_supabase_env, write_control_plane_env, write_fk_env,
                         write_opensearch_config, write_opensearch_env,
                         preflight_supabase, _env_file_value, _resolved_control_plane_dsn,
                         _resolved_token_pepper, _resolved_session_secret
  migrations.sh       ← apply_db_migrations (delegates to scripts/run_migrations.py)
  supabase.sh         ← bootstrap_supabase_operator (delegates to scripts/bootstrap_operator.py)
  assets.sh           ← configure_fuse, prepare_enrichment_assets, install_hayabusa,
                         install_hayabusa_system_links, report_hayabusa_status,
                         install_zimmerman_symlinks, install_complementary_tools
  rag.sh              ← load_rag_pgvector, seed_rag_pgvector_direct, download_rag_index
  opensearch.sh       ← start_opensearch, configure_opensearch_cluster, configure_geoip_pipeline,
                         install_opensearch_templates
  addons.sh           ← seed_addon_backends, _seed_one_addon_backend, write_default_examiner
  services.sh         ← install_systemd_service, configure_run_command_systemd_scope,
                         configure_immutable_capability, configure_auditd,
                         configure_apparmor, poll_gateway
  handoff.sh          ← write_handoff, print_summary
  teardown.sh         ← do_uninstall (shim to scripts/uninstall.sh), _confirm_destructive

scripts/
  run_migrations.py               ← extracted from apply_db_migrations heredoc
  bootstrap_operator.py           ← extracted from bootstrap_supabase_operator heredoc
  seed_backend.py                 ← extracted from _seed_one_addon_backend heredoc
  configure_opensearch_detections.py  ← extracted from configure_opensearch_detections heredoc
  render_template.py              ← extracted from _render_file heredoc
  bundle-offline.sh               ← NEW: creates offline wheel bundle
  uninstall.sh                    ← existing, enhanced
  setup-addon.sh                  ← updated: sources lib/ directly, not install.sh
  setup-supabase.sh               ← unchanged

5.2 Key Change: lib/python.sh — Registry vs Offline Install

This is the heart of the packaging modernization. The current sync_workspace (line 494) becomes two paths:

# lib/python.sh

install_packages_from_registry() {
  # Primary path: install published wheels from PyPI (or --index-url override).
  local version="${SIFT_VERSION:-}"
  local index_url="${SIFT_PYPI_INDEX:-}"
  local pkg_spec="sift-gateway[full]"
  [[ -n "$version" ]] && pkg_spec="${pkg_spec}==${version}"
  [[ "${SIFT_CORE_ONLY:-0}" == "1" ]] && pkg_spec="${pkg_spec%%\[*}[core]${version:+==$version}"

  log "Installing $pkg_spec from registry (system Python: $SYSTEM_PYTHON)."
  local index_args=()
  [[ -n "$index_url" ]] && index_args=(--index-url "$index_url")

  UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
    "$UV_BIN" pip install \
      --python "$SYSTEM_PYTHON" \
      --no-managed-python \
      --no-python-downloads \
      "${index_args[@]}" \
      --constraint "$REPO_DIR/constraints.txt" \
      --require-hashes \
      "$pkg_spec"
}

install_packages_offline() {
  # Secondary path: install from pre-staged wheels (no network).
  local wheel_dir="${SIFT_OFFLINE_WHEEL_DIR:-}"
  if [[ -z "$wheel_dir" && -n "${SIFT_OFFLINE_BUNDLE:-}" ]]; then
    wheel_dir="$(mktemp -d)"
    trap "rm -rf '$wheel_dir'" RETURN
    tar -xzf "$SIFT_OFFLINE_BUNDLE" -C "$wheel_dir" --strip-components=1
  fi
  [[ -n "$wheel_dir" ]] || offline_die "Python packages" \
    "pre-stage wheels with: scripts/bundle-offline.sh --version $SIFT_VERSION"
  log "Installing from offline wheels: $wheel_dir"
  UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
    "$UV_BIN" pip install \
      --python "$SYSTEM_PYTHON" \
      --no-managed-python \
      --no-python-downloads \
      --no-index \
      --find-links "$wheel_dir" \
      --constraint "$REPO_DIR/constraints.txt" \
      --require-hashes \
      "sift-gateway[full]${SIFT_VERSION:+==$SIFT_VERSION}"
}

install_workspace() {
  if is_offline; then
    install_packages_offline
  else
    install_packages_from_registry
  fi
  repair_pyewf_venv_link
}

5.3 lib/teardown.sh — Unified Teardown Shim

The 170-line inline uninstall in install.sh is replaced by a 10-line shim:

# lib/teardown.sh
do_uninstall() {
  local uninstall_script="$REPO_DIR/scripts/uninstall.sh"
  [[ -x "$uninstall_script" ]] || die "Uninstall script not found: $uninstall_script"
  local args=(--all)
  [[ "${ASSUME_YES:-0}" == "1" ]] && args+=(--yes --i-understand)
  [[ "${PURGE_DATA:-0}" == "1" ]] && args+=(--remove-evidence --i-understand-evidence-loss)
  log "Delegating to $uninstall_script ${args[*]}"
  exec "$uninstall_script" "${args[@]}"
}

5.4 setup-addon.sh — Decouple from install.sh

Current line 54: source "$REPO_ROOT/install.sh". Replace with targeted sources:

# scripts/setup-addon.sh (updated preamble)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
SIFT_MCPS_INSTALL_ROOT="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"

# Source only the lib modules we need; not the entire installer.
source "$SIFT_MCPS_INSTALL_ROOT/lib/common.sh"
source "$SIFT_MCPS_INSTALL_ROOT/lib/paths.sh"
source "$SIFT_MCPS_INSTALL_ROOT/lib/python.sh"   # resolve_uv
source "$SIFT_MCPS_INSTALL_ROOT/lib/opensearch.sh"  # write_opensearch_config, start_opensearch etc.

This breaks the tight coupling. setup-addon.sh no longer needs to guard against main() self-execution.

5.5 What Becomes Independently Testable (BATS)

┌────────────────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│           Module           │                                                   BATS testable units                                                    │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ lib/common.sh              │ verify_sha256, is_offline, offline_die, run_dry wrapper                                                                  │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ lib/preflight.sh           │ check_python (mocked SYSTEM_PYTHON), install_host_prereqs (mocked apt-get)                                               │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ lib/python.sh              │ _ensure_venv_integrity (temp venv), install_packages_from_registry (mocked uv), install_packages_offline (temp wheel     │
│                            │ dir)                                                                                                                     │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ lib/tls.sh                 │ generate_tls (temp SIFT_HOME), _tls_san_value (pure output check)                                                        │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ lib/config.sh              │ _env_file_value (temp env file), _resolved_control_plane_dsn                                                             │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ lib/state.sh               │ backup_preexisting_data_if_fresh (temp dirs), install_state_dirs (fake SIFT_STATE_DIR)                                   │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ lib/teardown.sh            │ do_uninstall (mock scripts/uninstall.sh), _confirm_destructive (mocked stdin)                                            │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ scripts/run_migrations.py  │ pytest with mock psycopg / temp Postgres                                                                                 │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ scripts/seed_backend.py    │ pytest with mock McpBackendRegistry                                                                                      │
├────────────────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ scripts/render_template.py │ pytest with sample template + env                                                                                        │
└────────────────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

---
6. Sequencing, Routing, Fail-Safe, and Idempotency Design

6.1 Correct Phase Ordering (with dependencies)

1.  parse_flags + source lib/                    [blocks on source failure]
2.  preflight_check                              [HARD FAIL: Python, openssl, awk, disk ≥5GB]
3.  install_host_prereqs                         [soft fail: warn non-critical, hard fail: acl missing]
4.  ensure_docker_ready_for_supabase             [HARD FAIL if Supabase mode + no Docker]
5.  preflight_supabase                           [HARD FAIL if no creds after auto-provision]
6.  install_uv_if_needed                         [HARD FAIL; offline: staged path hint]
7.  install_workspace                            [HARD FAIL; routes to registry or offline]
8.  repair_pyewf_venv_link                       [soft fail: warn]
9.  ensure_gateway_service_user                  [HARD FAIL; idempotent]
10. backup_preexisting_data_if_fresh             [soft fail: warn; idempotent guard]
11. install_state_dirs                           [HARD FAIL; idempotent]
12. configure_agent_runtime                      [HARD FAIL; delegates to setup-agent-runtime.sh]
13. join_shared_symbol_group                     [soft fail: warn]
14. configure_ingest_mount_sudoers               [HARD FAIL; delegates to setup-ingest-mount-sudoers.sh]
15. configure_fuse                               [soft fail: warn]
16. generate_tls                                 [HARD FAIL; idempotent (preserves CA)]
17. write_default_examiner                       [HARD FAIL; idempotent]
18. write_supabase_env                           [HARD FAIL; idempotent]
19. write_control_plane_env                      [HARD FAIL; idempotent]
20. apply_db_migrations                          [HARD FAIL; idempotent via ledger skip]
21. write_gateway_config                         [HARD FAIL; idempotent]
22. prepare_enrichment_assets                    [soft fail: warn]
23. write_fk_env                                 [HARD FAIL; idempotent]
    ↳ CORE-ONLY exits here ↴
24. load_rag_pgvector                            [soft fail: warn; gated on SIFT_RAG_ENABLED]
25. install_hayabusa                             [soft fail: warn; SHA-256 gate; offline: staged path]
26. write_opensearch_config + env               [HARD FAIL; idempotent]
27. start_opensearch                             [soft fail: sets OPENSEARCH_UP=0; gates 28-31]
28. configure_opensearch_cluster                 [soft fail; gated on OPENSEARCH_UP]
29. configure_geoip_pipeline                     [soft fail; gated on OPENSEARCH_UP]
30. install_opensearch_templates                 [soft fail; gated on OPENSEARCH_UP]
31. configure_opensearch_detections              [soft fail; gated on OPENSEARCH_UP]
32. install_hayabusa_system_links                [soft fail]
33. report_hayabusa_status                       [informational]
34. install_zimmerman_symlinks                   [soft fail: warn]
35. install_complementary_tools                  [soft fail: warn; best-effort apt]
36. seed_addon_backends                          [soft fail: warn; gated on backend health]
37. validate_evidence_root                       [HARD FAIL]
38. install_systemd_service                      [HARD FAIL; skip if unit file unchanged]
39. configure_run_command_systemd_scope          [HARD FAIL]
40. configure_immutable_capability               [soft fail: warn]
41. configure_auditd                             [soft fail: warn]
42. configure_apparmor                           [soft fail: warn]
43. poll_gateway                                 [soft fail: warn on degraded]
44. bootstrap_supabase_operator                  [soft fail: warn]
45. write_handoff                                [HARD FAIL]
46. print_summary                                [informational]

Nothing runs in parallel: all phases carry shared state (OPENSEARCH_UP, SUPABASE_URL, SIFT_CONTROL_PLANE_DSN, venv path). Serial execution is correct.

6.2 Idempotency Gaps and Fixes

┌───────────────┬─────────────────────────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────┐
│     Phase     │           Skip condition            │                                          Gap and fix                                           │
├───────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Package       │ venv exists + sift-gateway          │ NEW: version check: "$VENV_PYTHON" -c "import sift_gateway; assert sift_gateway.__version__ == │
│ install       │ importable at correct version       │  '$SIFT_VERSION'" → skip if passes                                                             │
├───────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Unit file     │ currently: no skip                  │ FIX: SHA-256 compare rendered output against installed file; skip daemon-reload+restart if     │
│ render        │                                     │ identical                                                                                      │
├───────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Hayabusa      │ binary exists                       │ GAP: rules not refreshed on version pin bump; FIX: check hayabusa --version against pin,       │
│ rules         │                                     │ re-install if mismatch                                                                         │
├───────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
│ DB migrations │ version in Supabase ledger          │ Correct; ledger absent = all re-apply (safe)                                                   │
├───────────────┼─────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────┤
│ State dir     │ directory exists                    │ GAP: mode drift not re-asserted; FIX: chmod + chown idempotently on re-run (install -d is a    │
│ modes         │                                     │ no-op for existing dirs, but ownership/mode corrections are cheap)                             │
└───────────────┴─────────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────┘

6.3 Error Handling Audit and Target

Current: set -Eeuo pipefail at line 2. mktemp temps cleaned per-function but no trap — interrupt leaves temp dirs and potentially half-written svc-owned files.

Target:
- Each function creating a mktemp dir adds trap "rm -rf '$tmpd'" RETURN.
- Top-level trap 'cleanup_on_exit $?' EXIT in main() that records which phase failed and writes a partial-state marker.
- Structured exit codes:
  - Exit 0: success.
  - Exit 1: preflight/environment failure.
  - Exit 2: package install failure.
  - Exit 3: config or secret write failure.
  - Exit 4: service install/start failure.
  - Exit 10: network download failure (online mode only).
- Preflight fast-fail gate (before any write) checking: Python executable, openssl, awk, disk ≥5 GB, not running as sift-service.

---
7. Skeleton: Thin Bootstrap Entrypoint and Registry Install Module

7.1 Thin install.sh Entrypoint

#!/usr/bin/env bash
set -Eeuo pipefail
# Protocol SIFT Gateway — thin bootstrap entrypoint.
# Sources lib/*.sh for all business logic; parses flags; calls main().
# See ./install.sh --help for usage.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source library modules in dependency order.
# shellcheck source=/dev/null
for _lib in common paths preflight python users state tls config \
            migrations supabase assets rag opensearch addons services handoff teardown; do
  source "$REPO_DIR/lib/${_lib}.sh"
done

parse_flags() {
  SIFT_CORE_ONLY="${SIFT_CORE_ONLY:-0}"
  SIFT_EXTERNAL_SUPABASE="${SIFT_EXTERNAL_SUPABASE:-0}"
  SIFT_APPARMOR_ENFORCE="${SIFT_APPARMOR_ENFORCE:-0}"
  ASSUME_YES=0; DRY_RUN=0; UNINSTALL_MODE=0; PURGE_DATA=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version)         shift; SIFT_VERSION="${1:-}"; shift ;;
      --core-only)       SIFT_CORE_ONLY=1; shift ;;
      --no-opensearch)   SIFT_OPENSEARCH_ENABLED=false; shift ;;
      --no-rag)          SIFT_RAG_ENABLED=false; shift ;;
      --external-supabase) SIFT_EXTERNAL_SUPABASE=1; shift ;;
      --offline)         SIFT_OFFLINE=1; shift ;;
      --offline-bundle)  shift; SIFT_OFFLINE_BUNDLE="${1:-}"; shift ;;
      --offline-wheels)  shift; SIFT_OFFLINE_WHEEL_DIR="${1:-}"; shift ;;
      --index-url)       shift; SIFT_PYPI_INDEX="${1:-}"; shift ;;
      --enable-geoip)    SIFT_GEOIP_ENABLED=1; shift ;;
      --apparmor-enforce) SIFT_APPARMOR_ENFORCE=1; shift ;;
      --workers)         shift; SIFT_OPENSEARCH_WORKERS="${1:-2}"; shift ;;
      --install-root)    shift; SIFT_MCPS_INSTALL_ROOT="${1:-}"; shift ;;
      --dry-run)         DRY_RUN=1; shift ;;
      -y|--yes)          ASSUME_YES=1; shift ;;
      --uninstall|--remove) UNINSTALL_MODE=1; shift ;;
      --purge-data)      PURGE_DATA=1; shift ;;
      --no-opencti)      shift ;;  # compatibility no-op
      -h|--help)         print_help; exit 0 ;;
      --version-info)    print_version_info; exit 0 ;;
      *)                 warn "Unknown option '$1' — ignored. Run ./install.sh -h for help."; shift ;;
    esac
  done
  export SIFT_CORE_ONLY SIFT_EXTERNAL_SUPABASE SIFT_APPARMOR_ENFORCE ASSUME_YES DRY_RUN
  export SIFT_OFFLINE SIFT_OFFLINE_BUNDLE SIFT_OFFLINE_WHEEL_DIR SIFT_PYPI_INDEX
  export SIFT_OPENSEARCH_ENABLED SIFT_RAG_ENABLED SIFT_GEOIP_ENABLED
  export SIFT_OPENSEARCH_WORKERS SIFT_MCPS_INSTALL_ROOT SIFT_VERSION
}

main() {
  parse_flags "$@"

  [[ "$UNINSTALL_MODE" -eq 1 ]] && { do_uninstall; exit 0; }
  is_offline && log "OFFLINE MODE: no network downloads; staged artifacts required."

  preflight_check           # fast-fail: python, openssl, awk, disk space

  install_host_prereqs
  ensure_docker_ready_for_supabase
  preflight_supabase
  install_uv_if_needed
  install_workspace         # registry or offline path

  ensure_gateway_service_user
  backup_preexisting_data_if_fresh
  install_state_dirs
  configure_agent_runtime
  join_shared_symbol_group
  configure_ingest_mount_sudoers

  configure_fuse
  generate_tls
  write_default_examiner
  write_supabase_env
  write_control_plane_env
  apply_db_migrations
  write_gateway_config
  prepare_enrichment_assets
  write_fk_env

  if [[ "${SIFT_CORE_ONLY:-0}" != "1" ]]; then
    load_rag_pgvector
    install_hayabusa
    write_opensearch_config
    write_opensearch_env
    start_opensearch
    if [[ "${OPENSEARCH_UP:-0}" -eq 1 ]]; then
      configure_opensearch_cluster
      configure_geoip_pipeline
      install_opensearch_templates
      configure_opensearch_detections
    fi
    install_hayabusa_system_links
    report_hayabusa_status
    install_zimmerman_symlinks
    install_complementary_tools
    seed_addon_backends
  fi

  validate_evidence_root
  install_systemd_service
  configure_run_command_systemd_scope
  configure_immutable_capability
  configure_auditd
  configure_apparmor
  poll_gateway "initial"
  bootstrap_supabase_operator
  write_handoff
  print_summary
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi

7.2 Representative Module: lib/python.sh (registry + offline routing)

#!/usr/bin/env bash
# lib/python.sh — Python/uv install and venv management.
# Deps: lib/common.sh (log/warn/die/require_cmd/offline_die/is_offline/verify_sha256)
#       lib/paths.sh  (SYSTEM_PYTHON, VENV_DIR, VENV_PYTHON, SIFT_UV_VERSION,
#                      SIFT_UV_TARBALL_SHA256, SIFT_VERSION, SIFT_MCPS_INSTALL_ROOT)
# BATS-testable: install_packages_from_registry with UV_BIN mocked; _ensure_venv_integrity
# with temp venv; install_packages_offline with temp wheel dir.

UV_BIN=""

resolve_uv() {
  command -v uv >/dev/null 2>&1 && { command -v uv; return; }
  [[ -x "$HOME/.local/bin/uv" ]] && { echo "$HOME/.local/bin/uv"; return; }
  echo ""
}

install_uv_if_needed() {
  local uv_bin
  uv_bin="$(resolve_uv)"
  if [[ -n "$uv_bin" ]]; then
    log "uv found: $uv_bin"; UV_BIN="$uv_bin"; return
  fi
  is_offline && offline_die "uv ${SIFT_UV_VERSION}" \
    "pre-install uv (e.g. place ~/.local/bin/uv) before re-running ./install.sh"
  require_cmd curl
  log "Installing uv ${SIFT_UV_VERSION} (pinned, SHA-256 verified)."
  local tmpd arch tarball
  tmpd="$(mktemp -d)"; trap "rm -rf '$tmpd'" RETURN
  arch="$(uname -m 2>/dev/null || echo unknown)"
  if [[ "$arch" == "x86_64" || "$arch" == "amd64" ]]; then
    tarball="$tmpd/uv.tar.gz"
    curl -fsSL -o "$tarball" \
      "https://github.com/astral-sh/uv/releases/download/${SIFT_UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz"
    verify_sha256 "$tarball" "$SIFT_UV_TARBALL_SHA256" \
      || die "uv tarball SHA-256 mismatch — supply-chain guard. Bump SIFT_UV_TARBALL_SHA256 if pin was intentionally updated."
    mkdir -p "$HOME/.local/bin"
    tar -xzf "$tarball" -C "$tmpd"
    local uv_bin_path
    uv_bin_path="$(find "$tmpd" -type f -name uv | head -1)"
    [[ -n "$uv_bin_path" ]] && install -m 755 "$uv_bin_path" "$HOME/.local/bin/uv"
  else
    log "  Arch $arch: using version-pinned uv install script."
    curl -LsSf "https://astral.sh/uv/${SIFT_UV_VERSION}/install.sh" | sh
  fi
  UV_BIN="$(resolve_uv)"
  [[ -n "$UV_BIN" ]] || die "uv install completed but uv binary not found."
}

_ensure_venv_integrity() {
  [[ -x "$VENV_PYTHON" ]] || { log "No venv at $VENV_DIR — will create."; return 1; }
  local sys_ver venv_ver
  sys_ver="$("$SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
  venv_ver="$("$VENV_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo none)"
  if [[ "$venv_ver" != "$sys_ver" ]]; then
    warn "Venv Python ($venv_ver) ≠ system Python ($sys_ver) — rebuilding."; rm -rf "$VENV_DIR"; return 1
  fi
  if ! "$VENV_PYTHON" -c 'import yaml' 2>/dev/null; then
    warn "Venv import smoke failed — will reinstall."; return 1
  fi
  # Version check: skip reinstall if already at target version.
  if [[ -n "${SIFT_VERSION:-}" ]]; then
    local installed_ver
    installed_ver="$("$VENV_PYTHON" -c 'import sift_gateway; print(sift_gateway.__version__)' 2>/dev/null || echo none)"
    if [[ "$installed_ver" == "$SIFT_VERSION" ]]; then
      log "Venv integrity OK: sift-gateway==$installed_ver"; return 0
    fi
    log "Venv has sift-gateway==$installed_ver; target is $SIFT_VERSION — reinstalling."
    return 1
  fi
  log "Venv integrity OK."; return 0
}

install_packages_from_registry() {
  local pkg_spec
  pkg_spec="$(_build_pkg_spec)"
  local index_args=()
  [[ -n "${SIFT_PYPI_INDEX:-}" ]] && index_args=(--index-url "$SIFT_PYPI_INDEX")
  log "Installing $pkg_spec from registry."
  UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
    "$UV_BIN" pip install \
      --python "$SYSTEM_PYTHON" \
      --no-managed-python --no-python-downloads \
      "${index_args[@]}" \
      --constraint "$REPO_DIR/constraints.txt" \
      --require-hashes \
      "$pkg_spec" \
    || die "Package install failed. Check network connectivity and PyPI index."
}

install_packages_offline() {
  local wheel_dir="${SIFT_OFFLINE_WHEEL_DIR:-}"
  if [[ -z "$wheel_dir" && -n "${SIFT_OFFLINE_BUNDLE:-}" ]]; then
    wheel_dir="$(mktemp -d)"; trap "rm -rf '$wheel_dir'" RETURN
    log "Extracting offline bundle: $SIFT_OFFLINE_BUNDLE"
    tar -xzf "$SIFT_OFFLINE_BUNDLE" -C "$wheel_dir" --strip-components=1
  fi
  [[ -n "$wheel_dir" ]] || offline_die "Python packages" \
    "pre-stage with: scripts/bundle-offline.sh --version ${SIFT_VERSION:-latest}"
  log "Installing from offline wheels: $wheel_dir"
  UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
    "$UV_BIN" pip install \
      --python "$SYSTEM_PYTHON" \
      --no-managed-python --no-python-downloads \
      --no-index --find-links "$wheel_dir" \
      --constraint "$REPO_DIR/constraints.txt" \
      --require-hashes \
      "$(_build_pkg_spec)" \
    || die "Offline package install failed. Verify wheel directory: $wheel_dir"
}

_build_pkg_spec() {
  local extra="full"
  [[ "${SIFT_CORE_ONLY:-0}" == "1" ]] && extra="core"
  local version_pin=""
  [[ -n "${SIFT_VERSION:-}" ]] && version_pin="==$SIFT_VERSION"
  echo "sift-gateway[${extra}]${version_pin}"
}

install_workspace() {
  _ensure_venv_integrity && return 0  # already at target version
  if is_offline; then
    install_packages_offline
  else
    install_packages_from_registry
  fi
  repair_pyewf_venv_link
  log "Workspace install complete."
}

repair_pyewf_venv_link() {
  # (unchanged from current install.sh:537)
  [[ -x "$VENV_PYTHON" ]] || return 0
  "$VENV_PYTHON" -c 'import pyewf' >/dev/null 2>&1 && { log "pyewf import OK."; return 0; }
  local origin; origin="$("$SYSTEM_PYTHON" -c 'import importlib.util; s=importlib.util.find_spec("pyewf"); print(s.origin if s and s.origin else "")' 2>/dev/null || true)"
  [[ -z "$origin" || ! -e "$origin" ]] && { warn "pyewf not in system Python — skipping relink."; return 0; }
  local site_dir; site_dir="$("$VENV_PYTHON" -c 'import site; print(site.getsitepackages()[0])' 2>/dev/null || true)"
  [[ -z "$site_dir" ]] && { warn "Cannot locate venv site-packages for pyewf."; return 0; }
  ln -sfn "$origin" "$site_dir/$(basename "$origin")"
  "$VENV_PYTHON" -c 'import pyewf' >/dev/null 2>&1 && log "Linked system pyewf into venv." || warn "pyewf relink did not work."
}

---
8. Risk Register and Migration Steps

8.1 Migration Steps (ordered, low-risk-first)

#: M1
Step: Delete fix_volatility_permissions no-op
Risk: None
Files touched: install.sh:1162; remove call at line 3599
Notes: Zero functional impact
────────────────────────────────────────
#: M2
Step: Delete Phase 9 OpenCTI dead install functions
Risk: None
Files touched: install.sh:2664–2756
Notes: scripts/uninstall.sh:teardown_opencti stays (still useful for external deployments)
────────────────────────────────────────
#: M3
Step: Add trap "rm -rf '$tmpd'" RETURN to every mktemp function
Risk: Low
Files touched: ~8 functions
Notes: Safety; no behavior change
────────────────────────────────────────
#: M4
Step: Expand --help to grouped format
Risk: None
Files touched: install.sh:3422–3453
Notes: Documentation only
────────────────────────────────────────
#: M5
Step: Add --no-opensearch and --dry-run flags and run_dry wrapper
Risk: Low
Files touched: install.sh:main()
Notes: New flags; run_dry wraps existing calls
────────────────────────────────────────
#: M6
Step: Fix idempotency in install_systemd_service: skip if unit file unchanged
Risk: Low
Files touched: install.sh:2780
Notes: SHA-256 compare; skip daemon-reload+restart if byte-identical
────────────────────────────────────────
#: M7
Step: Unify --uninstall to shim → scripts/uninstall.sh
Risk: Low
Files touched: install.sh:3221–3393 (remove 7 inline functions + add 10-line shim)
Notes: Removes ~170 lines
────────────────────────────────────────
#: M8
Step: Create lib/ directory; extract lib/common.sh and lib/paths.sh
Risk: Low
Files touched: New files + install.sh header section
Notes: All constants; no logic change
────────────────────────────────────────
#: M9
Step: Extract lib/preflight.sh
Risk: Low
Files touched: install.sh:249–461
Notes: Source in main()
────────────────────────────────────────
#: M10
Step: Extract lib/tls.sh + add trap
Risk: Low
Files touched: install.sh:1174–1278
Notes: BATS test: generate_tls with temp SIFT_HOME
────────────────────────────────────────
#: M11
Step: Extract lib/config.sh
Risk: Low-Med
Files touched: install.sh:1758–2389 (config write + preflight_supabase)
Notes: Complex; verify with _env_file_value unit tests
────────────────────────────────────────
#: M12
Step: Extract remaining lib modules: users.sh, state.sh, assets.sh, rag.sh, opensearch.sh, addons.sh, services.sh, handoff.sh, teardown.sh
Risk: Medium
Files touched: All corresponding install.sh sections
Notes: One at a time; bash -n install.sh after each
────────────────────────────────────────
#: M13
Step: Extract inline Python heredocs to scripts/*.py
Risk: Medium
Files touched: scripts/run_migrations.py, bootstrap_operator.py, seed_backend.py, configure_opensearch_detections.py, render_template.py
Notes: Each extracted script needs pytest coverage before removal of heredoc
────────────────────────────────────────
#: M14
Step: Update setup-addon.sh to source lib/ directly instead of install.sh
Risk: Medium
Files touched: scripts/setup-addon.sh:54
Notes: Test all 5 add-on paths after change; do atomically with M12 completion
────────────────────────────────────────
#: M15
Step: Publish packages to PyPI (major milestone)
Risk: High
Files touched: All packages/*/pyproject.toml, new CI workflow publish.yml, new constraints.txt
Notes: Requires: (a) coordinated versioning, (b) CI build pipeline, (c) portal frontend bundled in sift-case-dashboard wheel before publish, (d)
  constraints.txt generated with --require-hashes, (e) atomic publish order: sift-common → sift-core → sift-gateway et al.
────────────────────────────────────────
#: M16
Step: Create lib/python.sh with registry/offline routing and replace sync_workspace
Risk: High
Files touched: lib/python.sh, install.sh:main()
Notes: Depends on M15 (packages must be on PyPI); validate with full install smoke on clean VM
────────────────────────────────────────
#: M17
Step: Create scripts/bundle-offline.sh
Risk: Low
Files touched: New file
Notes: After M15; tests that bundle + --offline-bundle path produces identical runtime
────────────────────────────────────────
#: M18
Step: Add BATS test harness for lib/*.sh
Risk: Medium
Files touched: New: tests/install/
Notes: Start with common.sh, tls.sh, config.sh; wire into CI
────────────────────────────────────────
#: M19
Step: Add CI portal-build step: npm ci && npm run build → committed to static/ + uploaded as release artifact
Risk: Low
Files touched: .github/workflows/publish.yml, Makefile
Notes: Automates what is currently done manually; no installer change

8.2 Risk Register

Risk: PyPI publish timing gap: sift-gateway==1.2.3 published before sift-core==1.2.3
Likelihood: Medium
Impact: HIGH
Mitigation: Publish atomically in CI: build all wheels first, then twine upload all in a single job step. Or: publish in reverse-dependency order with retry
  on dependency not-yet-available.
────────────────────────────────────────
Risk: Workspace internal deps become versioned PyPI deps: sift-core = { workspace = true } → sift-core==1.2.3
Likelihood: Low
Impact: HIGH
Mitigation: constraints.txt --require-hashes ensures the exact build is installed. Strict version pins on all inter-package deps. Use
  packaging.version.Version comparison in the CI gate to block publish if any workspace dep is not yet on PyPI.
────────────────────────────────────────
Risk: stage_repo_to_install_root re-exec: in source-install mode this works; in registry mode the runtime is the venv, not the git tree
Likelihood: Medium
Impact: HIGH
Mitigation: After M15, stage_repo_to_install_root is replaced by a much simpler "ensure scaffold dir exists" step that copies configs/, supabase/,scripts/,
  and constraints.txt to /opt/sift-mcps/ without the rsync+re-exec pattern. No self-re-exec needed. This is the single biggest semantic change in the
  migration.
────────────────────────────────────────
Risk: setup-addon.sh breaks when install.sh structure changes
Likelihood: Medium
Impact: MEDIUM
Mitigation: M14 must happen atomically with M12. Keep a compatibility shim in install.sh that sources lib/common.sh + lib/paths.sh (the minimal set
  setup-addon.sh actually uses) until M14 is complete.
────────────────────────────────────────
Risk: constraints.txt hash-lock breaks on routine dep bumps
Likelihood: High
Impact: LOW
Mitigation: Regenerate constraints.txt in CI on every release. Provide a make constraints developer target: uv pip compile pyproject.toml --extra full
  --generate-hashes -o constraints.txt.
────────────────────────────────────────
Risk: PyPI name conflicts: sift-gateway, sift-core may be taken
Likelihood: Medium
Impact: MEDIUM
Mitigation: Pre-check with pip index versions sift-gateway before starting M15. If taken, use a namespace like protocol-sift-gateway, protocol-sift-core,
  etc. Adjust all inter-package deps accordingly.
────────────────────────────────────────
Risk: BGE model / HuggingFace weights in offline bundle: model is ~430 MB; bundle grows large
Likelihood: Low
Impact: LOW
Mitigation: Bundle script pre-stages weights only when --include-model flag is passed. Default offline bundle is wheels only; model is seeded separatelyvia
  rag-mcp-seed-pgvector --embedding-mode model after install.
────────────────────────────────────────
Risk: repair_pyewf_venv_link breaks after switch from workspace-source to published wheel
Likelihood: Low
Impact: LOW
Mitigation: pyewf is a system library linked into the venv. The link target is the system Python's pyewf.so, not a workspace package. The logic is identical
  in both install modes.

---
9. Open Questions / Decisions Needed from the Lead

Q1 — PyPI namespace and organization.
sift-gateway, sift-core etc. may be taken on PyPI. Does the project use a scoped namespace like protocol-sift-gateway, sift-mcps-gateway, or register under a PyPI organization (sift-mcps)? This decision blocks M15 and affects all inter-package dependency declarations.

Q2 — Public vs private PyPI registry.
Is PyPI (public) the right registry, or should a private registry (GitHub Packages, AWS CodeArtifact, Gemfury) be used? For a forensic tool with an operator/deployment model, a private registry may be preferred. The bootstrap installer's --index-url flag already supports this.

Q3 — Versioning strategy: shared monorepo version vs independent.
The recommendation is shared-version (all 9 packages at the same version, released together). The alternative is independent versioning (each package releases on its own cadence). Independent versioning is more flexible but requires the constraints.txt to track inter-package version compatibilitycarefully. Decision needed before M15.

Q4 — stage_repo_to_install_root replacement semantics.
In the registry-install model, /opt/sift-mcps/ no longer holds a git tree — it holds a minimal scaffold (configs, migrations, scripts, constraints). Whatis the correct install action when the operator runs ./install.sh from a fresh clone? Options: (a) copy the scaffold from the clone and install wheels into the venv there (simplest); (b) the bootstrap is a standalone single-file script downloaded via curl that creates the scaffold and installs from PyPI (nogit clone needed for the operator). Option (b) is the cleanest end-state but requires the most migration work. Decision needed before M16.

Q5 — Portal frontend: wheel-bundled or standalone artifact?
The recommendation bundles the pre-built frontend inside the sift-case-dashboard wheel (current pattern, automated in CI). The alternative is a standalonesift-portal-v1.2.3.tar.gz that the bootstrap installer fetches separately from the wheel install. The standalone approach allows portal updates without a full Python reinstall. Decision affects CI workflow and install_workspace logic.

Q6 — Linear issue for M15 (PyPI publish) vs current I-track.
M15 is a significant milestone. Should it be a new Linear issue (e.g. XYE-PKG-1: Publish SIFT workspace packages to PyPI) with M16 as a child (XYE-PKG-2: Switch bootstrap to registry install)? Or should it be tracked under the existing Axis I issues (I3)?

Q7 — Dead Phase 9 OpenCTI removal (M2) scope.
scripts/uninstall.sh:teardown_opencti should be kept (useful for operators who deployed OpenCTI externally). Only the install-side functions in install.sh are removed. Confirm this is the right boundary.

Q8 — check_os Ubuntu vs SIFT target.
check_os warns on non-Ubuntu. The CLAUDE.md calls the SIFT VM "Fedora-family" which appears to be stale — the current VM is Ubuntu. Should the warning be removed (Ubuntu is the only supported target), updated to list exact supported versions, or kept as-is?

Understood — but looking at the task, the Explorer agent already completed its deliverable (the blueprint text) without needing to write any files. Thelead will persist it to disk. No file writes were needed from this agent.

The blueprint has been returned as the final message above. To summarize what was delivered:

What the Explorer produced:

1. Executive summary — registry-published wheels as the primary model, thin lib/-modularized bootstrap entrypoint, sourced Bash library architecture.
2. Full current-state audit — phase inventory (14 phases, lines 249–3658), 95 functions catalogued, all 10 flags + 28 env knobs documented, 10 specificproblems cited with line numbers (dead Phase 9 code at lines 2664–2756, dual uninstall at 3221–3393, fix_volatility_permissions no-op at line 1162, etc.).
3. Three-tier component model — Tier A (core, always installed), Tier B (core-addons: OpenSearch + RAG, on by default), Tier C (true external add-ons:OpenCTI, windows-triage, never touched by install.sh).
4. Registry-primary packaging strategy — all 9 workspace packages published to PyPI with coordinated versioning, constraints.txt --require-hashes forsupply-chain integrity, portal frontend bundled in the sift-case-dashboard wheel via CI npm build, offline/air-gap as a secondary --offline-bundle path, full migration path from source-uv to published-wheel install.
5. CLI and help spec — 20-flag table with env equivalents, literal --help mockup, --dry-run design.
6. Modularization plan — 17 lib/*.sh modules mapped to specific install.sh line ranges, 5 Python heredocs extracted to scripts/*.py, setup-addon.shdecoupled from install.sh source dependency.
7. Sequencing/fail-safe/idempotency — 46-step ordered phase list, idempotency gap table with fixes, structured exit codes, trap pattern for temp dirs.
8. Skeleton code — thin install.sh entrypoint (~150 lines) and lib/python.sh with full registry/offline routing.
9. 19 ordered migration steps (M1–M19, low-risk-first) + 8-item risk register with mitigations.
10. 8 open questions for the lead covering PyPI namespace, public vs private registry, versioning strategy, stage_repo_to_install_root replacement semantics, frontend distribution model, Linear issue tracking, and two stale-comment cleanup items.
v2 complete and handed back to the lead for the Auditor re-review.

Summary of v2 revision

I addressed all 9 items in the Auditor's punch-list and bumped the document to DRAFT v2 with a full changelog (§7).

The three majors:

- M1 — Added the entire missing forensic-rag online-source subsystem (the single largest unpinned fetch surface): row #25a (~17 git clone --depth 1 HEAD feeds + GitHub API — SigmaHQ, atomic/stratus red-team, the full MITRE set, elastic/splunk rules, LOLBAS/GTFOBins/HijackLibs/LOLDrivers, KAPE, Velociraptor, chainsaw, hayabusa-rules) and #25b (D3FEND + CISA-KEV JSON). Verified it's triggered by rag-mcp refresh with skip_online=False by default but never run by install.sh. This changed the headline trust conclusion — the riskiest surface is the public, version-unpinned upstreams, not the private release channel.
- M2 — Enumerated all three workflows; added #26 for ci.yml (checkout@v6, setup-python@v6, setup-uv@v8.2.0); confirmed live-vm.yml is a fetch-free manual checklist.
- M3 — Resolved G1: confirmed via git ls-files that the portal is served from a committed Vite bundle under static/v2/, staged by rsync; npm is build-host-only. Kept the residual provenance gap (m9/G1-residual).

Minors m4–m9 all applied (prefix-filtered latest semantics, triage tag-pin asymmetry, broadened auth-helper scope, unpinned alternate BGE models → G11, corepack/setup-python fetches, portal-bundle provenance line).

★ Insight ─────────────────────────────────────
The most consequential correction was M1: the package's direct install path looks download-free, but sources.py is a second, parallel fetch subsystem inthe same package gated by a different entry point (refresh, not install.sh). This is a recurring audit trap — a component can have multiple independent network paths reached by different triggers, so "the installer doesn't download it" is not the same as "the component doesn't download it." The defense the code does have (host-allowlist + HTTPS-only + IP-literal/octal block + size cap) is SSRF protection, which is orthogonal to supply-chain pinning — worth separating those two axes in any inventory.
─────────────────────────────────────────────────

Final state: 28 asset rows (was 24), gaps G1–G11 (G1 resolved, G10/G11 added). No correctness changes to the original rows, no secrets, no live fetches, every new row anchored to file:line. Structured to feed XYE-48.

