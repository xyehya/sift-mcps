# Axis I - Installer Verification / Replacement Path

> Covers: install.sh, uninstall.sh, scripts/setup-addon.sh, scripts/stage-evidence.sh, docs/drafts/operator/**, .github/workflows/live-vm.yml
> Class: living-plan
> Last validated: dd4c656 (2026-06-18)

**Status**: plan-ready for OT2.
**Source assessment gap**: the installer is sophisticated but large shell code
with limited automated proof. Recent issues (`XYE-37`, `XYE-41`, `XYE-42`,
`XYE-43`, `XYE-44`) show this surface deserves its own verification track.

## I1 - Installer Static And Helper Test Harness

**Goal**: add repeatable checks for the riskiest shell helpers without rewriting
the installer first.

**Scope fence**
- `bash -n` plus shell test harness or focused helper extraction.
- Start with helpers that affect downloads, venv sync, service files, teardown,
  and ownership boundaries.

**Acceptance**
- CI or local validation can exercise helper behavior with temp dirs/fakes.
- Tests pin no-managed-Python and no-download expectations.

## I2 - Greenfield Install / Uninstall Smoke Harness

**Goal**: make the live-VM install proof repeatable and less ad hoc.

**Hard constraints**
- No destructive VM operation without operator gate.
- Sanitized proof only; no secrets, DSNs, JWTs, private keys, or full sensitive
  evidence paths in Linear.

**Acceptance**
- Smoke checklist covers fresh install, `/health`, seeded backends, add-on setup,
  restart-to-apply, uninstall `--all`, and reinstall.
- Output format is compact enough for Linear proof comments.

## I3 - Installer Replacement / Wrapper Decision

**Goal**: decide whether to keep hardening Bash, wrap it with tested Python, or
move staged provisioning to Ansible.

**Acceptance**
- Options compare migration risk, operator workflow, VM constraints, testability,
  and rollback.
- Operator decision is recorded before any replacement branch.

## I4 - Service And Add-On Lifecycle Regression Suite

**Goal**: pin the lifecycle semantics clarified by `XYE-44`.

**Acceptance**
- Tests/docs cover default install seeding only opensearch + RAG, setup-addon
  payload generation, Portal Register, restart-to-apply, proxy-mounted
  on-demand status, and no misleading Start/Stop controls for proxy mounts.
