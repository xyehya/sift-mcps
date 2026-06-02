# Phase 6 GATE — live e2e QA log

> Structured ledger for the MVP-completion run (full add-on install + ROCBA e2e on the
> live VM, 192.168.122.81). Append as you go; triage at the end of each stage; fix every
> **blocker/major** before advancing and re-run the affected stage.

## Framing (do not drift)

The **SIFT Protocol Gateway (SPG)** *is* the product: core + gateway + portal + the agent's
in-process MCP server. It is complete on its own (`install.sh --core-only`). OpenCTI,
OpenSearch, windows-triage, and forensic-rag are **external, independent, optional** add-on
backends — *reference implementations* of the SIFT MCP Backend Contract. An operator runs
any subset (including none) or brings their own conformant backend. There is exactly **one**
integration door for all of them: point the portal at a `sift-backend.json` manifest →
validate against the spec → register → hot-reload. The core never special-cases a backend.

## Run metadata

| | |
|---|---|
| VM | 192.168.122.81 (sansforensics / forensics) |
| Branch / commit | revamp/spg-v1 @ _(fill at close)_ |
| Evidence set | ROCBA (23 GB `.e01` + 19 GB RAM) |
| Service token | _(record `sift_svc_*`, redacted, at close)_ |
| Case path | _(fill)_ |

## Severity scale

`blocker` = stops the gate · `major` = wrong behavior, must fix before MVP · `minor` =
works but rough · `cosmetic` = wording/UX nit.

---

## Table 1 — Tool inventory & definition review

One row per advertised tool. "Description verdict" = is the tool's description/schema clear
and correct *for an autonomous DFIR agent* (OK / vague / misleading). "Call test" = result
of invoking it once on a sealed case via Claude Code.

| Tool | Backend / namespace | Description verdict | inputSchema sanity | Call test | Notes |
|------|---------------------|---------------------|--------------------|-----------|-------|
| _(core tools — fill from `tools/list` at Stage 2)_ | sift-core | | | | |
| _(add-on tools — fill per backend at Stage 3/4)_ | | | | | |

---

## Table 2 — Defect ledger

| ID | Area | Severity | Repro | Expected vs actual | Root-cause hypothesis | Remediation status | Retest |
|----|------|----------|-------|--------------------|-----------------------|--------------------|--------|
| D-001 | install / core | major (off-message; runtime-inert) | `install.sh --core-only` → inspect `~/.sift/gateway.yaml` | Expected: a standalone-core config names **no** add-on backends. Actual: `backends:` block enumerated all four reference add-ons with `enabled: false`. | `configs/gateway.yaml.template` hardcoded the four reference backends, each `enabled: ${SIFT_*_ENABLED}`; core-only set the flags false but the entries still rendered. Contradicts "SPG core is self-contained; add-ons external/optional/bring-your-own" and is redundant with the portal register flow that writes entries on registration. | **FIXED (all paths)** — template now ships `backends: {}` (with a comment forbidding pre-seeding); `_migrate_gateway_config` no longer auto-enables rag/wintriage/opensearch/opencti (only normalizes args for portal-written entries); install summary directs operators to register add-ons via Portal → Backends / `setup-addon.sh`. Template renders to `backends: {}`, valid YAML. | Pending live re-gen on VM (`rm ~/.sift/gateway.yaml && ./install.sh --core-only`) |
| D-001-note | install / core | minor | inspect `enrichment:` block | `enrichment.forensic_rag` / `opensearch_context` carried add-on names in core config. | Vestigial flags — **nothing reads them**; grounding/enrichment is already declaration-driven via `set_reference_backend_provider`. | **FIXED** — removed both keys from the template; `enrichment` now holds only core `enabled`/`forensic_knowledge`/`root` with a comment that add-on enrichment is derived from registered-backend manifests. | Pending live re-gen |
| D-002 | core / agent-tool | major | call `case_status` (and the findings considerations path) | `platform_capabilities` advertised add-ons via `importlib.util.find_spec("<pkg>")` — "is the package installed," NOT "is a backend registered + advertising." Full install → all four advertised even when none registered; an external/HTTP/third-party backend would never be detected. Violated R-no-hardcoded-names / declaration-driven model. | `_build_platform_capabilities()` (agent_tools.py) + duplicate find_spec block in `case_manager.py` Layer-4. Predates the manifest-driven `capability_guide`/`environment_summary` (6.4c). | **FIXED (declaration-driven, field kept)** — gateway exposes `get_available_backend_capabilities()` (registered+available backends + advertised `provides`), injected into sift_core via `set_backend_capability_provider`. New `case_manager.build_platform_capabilities()` builds the field name-agnostically (capability `provides` union + per-backend `{name,namespace,provides}` + generated guidance); `case_status` and the case-manager path both use it; both find_spec blocks removed. No provider/gateway ⇒ core-only (correct). Tests: `test_platform_capabilities.py` (4). sift-core 305 / gateway 134 green. | Pending live verify in Stage 2/4 |
| D-002-note | core / methodology | minor | grep `forensic-mcp/server.py:534` | `forensic-mcp` still has a `find_spec` capability block. | It is the Phase-7 methodology backend — not served in-process and not on the live agent surface (backends are `{}`; forensic-mcp not started). | OPEN (Phase-7-scoped) — fix when methodology → /skills lands | — |

Area ∈ { install · core · add-on · portal · agent-tool · security }.

---

## Pre-run notes (Stage 0, local — recorded before touching the VM)

- **Scripts:** added source-guard to `install.sh` (reusable as a function library); hardened
  `scripts/reset-vm-test.sh` to restart via `systemctl --user` (was stale `nohup uv run`);
  added `scripts/setup-addon.sh` (optional add-on provisioning + env echo + generic
  register-payload emitter; registers nothing, edits no config).
- **OpenSearch `requires` string** (`https://localhost:9200`) vs runtime `http://127.0.0.1:9200`:
  **verified benign** — `Gateway.evaluate_requirement` (server.py:247) does a plain TCP
  connect to host:port (explicit `:9200`), so scheme and `localhost`↔`127.0.0.1` don't
  matter. No change made.
- **Offline manifest probe:** `probe_backends.py --manifest-dir packages --skip-mcp` →
  all 4 backends conform.
- **setup-addon.sh payload smoke:** emits valid `{name, config{type,command,args,
  manifest_path,enabled}}` with explicit `manifest_path` — the same shape an external backend
  submits.

## Stage checklist (tick as completed live)

- [ ] **Stage 1** — `install.sh --uninstall --purge-data -y` → `install.sh --core-only`; healthy, 19 core tools, 0 add-on tools.
- [ ] **Stage 2** — portal first-run; F-A blocks pre-seal; tool-definition review (Table 1); `phase2_gate_test.py` 14/14.
- [ ] **Stage 3** — `setup-addon.sh` per backend → portal validate→register→hot-reload; `tools/list` namespaced; `environment_summary` health; `requires[]` gating; live `probe_backends.py`; non-conformant manifest → 422, no write.
- [ ] **Stage 4** — Claude Code MCP wired to `https://192.168.122.81:4508/mcp/`; call each tool once (Table 1).
- [ ] **Stage 5** — ROCBA: create case → copy evidence → seal → full agent loop → examiner commit → signed report.
- [ ] **Stage 6** — invariants: F-A corrupt-evidence; R-B jail; executor deny-floor/traversal/output-cap; R-core-survives (disable add-on); R-roles (portal rejects agent token).
- [ ] **Stage 7** — all blocker/major fixed + retested; gate ticked in `revamp-tasks.md`; Session Log appended.
