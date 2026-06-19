# Install Modernization Blueprint — Review & Remediation (consolidated)

**Track A review deliverable · Reviewer: code-reviewer (Reviewer + Reviewer2 passes) · Date: 2026-06-19**

Consolidates the two Reviewer2 session outputs (`reviewer2-part1.md` findings/recommendations
+ `reviewer2-solutions.md` patch specs) into one document. Reviews
[`01-INSTALL-EXPLORATION.md`](01-INSTALL-EXPLORATION.md) (primary blueprint) against
[`01b-INSTALL-EXPLORATION-ALT.md`](01b-INSTALL-EXPLORATION-ALT.md) (second opinion) and the
signed-off [`FINAL-ASSET-INVENTORY.md`](FINAL-ASSET-INVENTORY.md). Every claim ground-truthed
against `install.sh`, `scripts/uninstall.sh`, `scripts/setup-addon.sh`, and all 9
`packages/*/pyproject.toml`.

## Verdict

**REVISION REQUIRED — 3 blocker · 4 major · 2 minor** (+ 1 cross-blueprint divergence finding
+ 1 bonus committed-lock finding).

| # | Blocker | One-line |
|---|---------|----------|
| 1 | Non-existent package+extra | `sift-gateway[full]` resolves to nothing; `core/standard/full` extras live only on root `sift-mcps` which is `package=false`. |
| 2 | Version skew | `sift-core`/`windows-triage-mcp`/root = 0.1.0, six others = 0.6.1 → no coherent `[full]==X.Y.Z`. |
| 3 | Evidence-deletion gate regression | `install.sh --purge-data -y` wipes `/cases` behind one gate vs the canonical script's four; **and the blueprint's own shim re-introduces the bypass** by auto-forwarding the evidence-unlock flags. |

Net adjudication: **01 is the better document; 01b is more correct on the three gating items
(version coherence, package naming/mechanism, evidence-gate hazard).** Actionable blueprint =
01's structure + skeletons, corrected by 01b's precondition fixes.

## The 5 operator decisions (must be made before the registry cutover)

1. **Meta-package mechanism** — flip root `sift-mcps` to a buildable meta-distribution (**recommended, Option A**) vs move `core/standard/full` extras onto `sift-gateway` (Option B).
2. **Version line + mechanism** — adopt **0.6.2** (bump the three 0.1.0 packages up) via **hatch-vcs + git tag** as single source of truth (recommended) vs a checked-in `VERSION` + sed stopgap.
3. **Uninstall contract** — ratify "**install.sh can never delete evidence**": delegate to `scripts/uninstall.sh` and do **not** forward `--remove-evidence`/`--i-understand-evidence-loss` (recommended). Accept the `--purge-data -y` contract change after grepping for callers.
4. **Public PyPI vs private index** — *no default; gates the dist-naming.* Public ⇒ rename dists to `sift-` prefix (collision/squat risk); private ⇒ keep current names (`rag-mcp`, `case-dashboard`, …).
5. **G10 carve-out** — confirm the ~22 unpinned RAG/triage `git clone HEAD` feeds are explicitly **out of scope** for the install track and tracked as a separate Linear fork issue.

---

## Part A — Findings & Recommended Solutions

Proposed Solutions — Install Modernization Blueprint Revision

Scope: concrete fixes for the 3 blockers, 4 majors, 2 minors, plus the divergence finding. Each is grounded in source I verified. I have no write access, so these are specs for whoever implements — copy as needed.

---
Blocker #1 — Non-existent package + extra (sift-gateway[full])

Problem (verified): core/standard/full extras exist only on root sift-mcps (pyproject.toml:31-46), which is package = false (pyproject.toml:5) and therefore not buildable. sift-gateway has only a dev extra (packages/sift-gateway/pyproject.toml:32-33). The blueprint's install command uv pip install "sift-gateway[full]==X" resolves to nothing on PyPI.

Recommended solution — Option A: make sift-mcps a buildable meta-distribution. This is the smallest diff and keeps the extras graph exactly where it already lives.

In root pyproject.toml:
[tool.uv]
package = true            # was false — flip so the meta-package builds

[tool.hatch.build.targets.wheel]
bypass-selection = true   # meta-package: no code, just dependency extras
Then convert each workspace-source dep into a normal versioned PyPI dep at publish time. Keep extras as-is; the published install command becomes:
uv pip install "sift-mcps[full]==X.Y.Z" -c constraints.txt --require-hashes

Why A over B (move extras onto sift-gateway): Option B forces sift-gateway — a runtime code package — to also be the dependency-aggregation hub, whichcouples "the gateway app" to "the install profile." It also breaks the mental model where sift-gateway is one Tier-A component among several. Blueprint 01 chose B; I'd push back. Option A matches what 01b proposes and matches the existing structure (extras already on root), so it's less churn and lesssemantic distortion.

Required corollary: [tool.hatch.build.targets.wheel] packages = [] (root pyproject.toml:70-71) already declares an empty package list — that's compatible with a no-code meta-wheel, but it must be paired with bypass-selection = true or hatchling errors on "no files selected." Implementer musttest python -m build on the root actually produces a wheel.

Decision needed from operator: ratify A (meta-package) vs B (extras on gateway). My recommendation: A.

---
Blocker #2 — Version skew

Problem (verified): sift-core=0.1.0, windows-triage-mcp=0.1.0, root=0.1.0; six others=0.6.1. New aggravating fact: versions are also hand-duplicated in__init__.py __version__ strings (sift-core, sift-gateway, opensearch-mcp, rag-mcp, windows-triage-mcp all carry one). So every package has two version sources that can drift.

Recommended solution — single source of truth via hatch-vcs (git tag), eliminating both pyproject literals and __init__.__version__ literals:

Per package pyproject.toml:
[build-system]
requires = ["hatchling", "hatch-vcs"]

[project]
dynamic = ["version"]      # remove the literal version = "0.x.x"

[tool.hatch.version]
source = "vcs"

[tool.hatch.build.hooks.vcs]
version-file = "src/<pkg>/_version.py"   # generated, gitignored
Then change each __init__.py to read the generated file instead of hardcoding:
from ._version import __version__   # was: __version__ = "0.x.x"
Tag v0.6.2 → every package builds at 0.6.2 from one source. No more drift, no more skew.

If the operator wants a lighter touch first: a checked-in VERSION file + a make set-version sed step that rewrites all nine pyproject literals AND the__init__ strings. Less elegant, but no build-system change. I'd only recommend this as a stopgap because it leaves two literals per package live.

Decision needed: pick the line (recommend 0.6.2, since six packages already sit at 0.6.1 — bumping three up beats demoting six down) and pick the mechanism (recommend hatch-vcs/git-tag). This directly fixes the blueprint's M7.

---
Blocker #3 — Evidence-deletion gate regression (the strongest one)

Problem (verified): Inline purge_data (install.sh:3357-3368) → _confirm_destructive (:3239-3250) wipes /cases after a single typed "yes", and -y/ASSUME_YES skips even that. Canonical scripts/uninstall.sh requires four gates incl. typed DELETE EVIDENCE (:35-37, 292-316).

The trap in the blueprint's own fix: 01 §5.3's shim does
[[ "$PURGE_DATA" == 1 ]] && args+=(--remove-evidence --i-understand-evidence-loss)
[[ "$ASSUME_YES" == 1 ]] && args+=(--yes --i-understand)
So ./install.sh --uninstall --purge-data -y auto-supplies three of the four evidence gates and the canonical script's typed DELETE EVIDENCE prompt is the only thing left — but that prompt reads from stdin, and under -y automation stdin is typically closed/non-interactive, so read returns empty and the script aborts (good) — UNLESS someone pipes "DELETE EVIDENCE" in. Net: the shim is safer than the inline path, but it still lets --purge-data translate to "evidence-deletion unlocked" in one operator gesture.

Recommended solution — delete-and-delegate, but DO NOT auto-translate --purge-data into the evidence-unlock flags:
do_uninstall() {
  local uninstall_script="$REPO_DIR/scripts/uninstall.sh"
  [[ -x "$uninstall_script" ]] || die "Uninstall script not found: $uninstall_script"
  local args=(--all)
  [[ "${ASSUME_YES:-0}" == "1" ]] && args+=(--yes --i-understand)
  if [[ "${PURGE_DATA:-0}" == "1" ]]; then
    # State (/var/lib/sift) is fine to pass through. EVIDENCE is NOT.
    # We deliberately do NOT pass --remove-evidence/--i-understand-evidence-loss.
    # Evidence deletion must be an explicit, separate operator action against
    # scripts/uninstall.sh so the typed "DELETE EVIDENCE" gate is unavoidable.
    warn "--purge-data wipes state but PRESERVES /cases."
    warn "To delete evidence, run scripts/uninstall.sh --remove-evidence --i-understand-evidence-loss --yes (requires typed DELETE EVIDENCE)."
  fi
  log "Delegating to $uninstall_script ${args[*]}"
  exec "$uninstall_script" "${args[@]}"
}
This is the forensic-integrity-correct posture: install.sh can never delete evidence, by construction. Evidence destruction requires going through the one canonical script that has the typed prompt. That removes the entire class of "one-flag-wipes-the-case" risk and is the strictest reading of theCLAUDE.md rule that evidence seal/unseal is a sensitive re-auth action.

Caveat to confirm before merge (blueprint already flags this): verify no automation calls ./install.sh --purge-data expecting it to clear /cases. reset-vm-test.sh is already removed (per CLAUDE.md). Grep CI/scripts for --purge-data callers; if none, this contract change is free.

Decision needed: ratify "install.sh never deletes evidence — delegate to uninstall.sh, do NOT forward evidence-unlock flags." Recommend yes.

---
Major #1 — G8: unhashed non-x86_64 uv fallback

Problem (verified): install.sh:349 does curl -LsSf https://astral.sh/uv/${VER}/install.sh | sh for non-x86_64, while the x86_64 path (:329-340) SHA-256-verifies the tarball and dies on mismatch. Asymmetric supply-chain posture on the exact bootstrap that installs everything else.

Recommended solution: pin the arch-specific tarball + SHA for aarch64 the same way x86_64 is pinned, rather than piping a script to sh. uv publishesper-arch tarballs (uv-aarch64-unknown-linux-gnu.tar.gz) with checksums. Add an arch→(url,sha) map:
case "$arch" in
  x86_64)  uv_sha="$SIFT_UV_TARBALL_SHA256_X86_64"; uv_triple="x86_64-unknown-linux-gnu" ;;
  aarch64) uv_sha="$SIFT_UV_TARBALL_SHA256_AARCH64"; uv_triple="aarch64-unknown-linux-gnu" ;;
  *) die "Unsupported arch '$arch' — pin a uv tarball+SHA or pre-stage uv (offline)." ;;
esac
# download + verify_sha256 the same way the x86_64 path already does
Net effect: every uv install path is SHA-gated; the curl | sh line is deleted. Note the SIFT VM is x86_64 so this is latent today, but it's a realintegrity gap and cheap to close. This is a blueprint addendum the current 01 doesn't address.

---
Major #2 — G10: unpinned RAG/triage online feeds (~22 git clone HEAD + live JSON)

Problem (verified): inventory G10 + sources.py:639-642 — ~22 public upstreams pulled at git clone --depth 1 HEAD with host-allowlist only, plus liveMITRE D3FEND / CISA KEV JSON. Registry publishing does nothing for this because it's a runtime refresh subsystem, not an install-time wheel.

Recommended solution — out of scope for the install blueprint; file as a separate fork issue, but make the blueprint say so explicitly. The fix belongs in sources.py/refresh.py, not install.sh:
- Pin each git feed to a commit SHA (or a periodically-bumped manifest of {repo: commit}), not HEAD.
- Snapshot the live MITRE/CISA JSON into the release artifact and treat live fetch as an explicit opt-in refresh, so a default install is reproducible.

The blueprint's job here is honesty: add a sentence to §3.2 that "registry publishing pins the code; the RAG knowledge corpus remainsHEAD-at-refresh-time until G10 is addressed separately (fork issue XYE-XX)." Don't let the modernization imply reproducibility it doesn't deliver. This matches the RAG-knowledge-only architecture rule in CLAUDE.md.

Decision needed: confirm G10 is explicitly carved OUT of the install track and tracked as its own Linear issue.

---
Major #3 — --require-hashes + package = false constraints generation

Problem: you cannot uv pip compile --generate-hashes a hash-pinned constraints file from a package = false workspace and have those hashes match what's on PyPI — local wheels aren't the published wheels.

Recommended solution — two-phase release, compile from the published index:
1. Phase 1 (publish): build + twine/uv publish all packages atomically in dep order (sift-common → sift-core → sift-gateway → meta). No constraints file yet.
2. Phase 2 (pin): once the index has the wheels, uv pip compile pyproject.toml --extra full --generate-hashes --python-version 3.12 -o constraints.txt resolving against the published index, commit the constraints file, and ship it in the release scaffold.

The installer then uses -c constraints.txt --require-hashes and gets hashes that actually match PyPI. The blueprint's release-flow section (01 §3.2 step 5) must be reordered to make "generate constraints" a post-publish step, not a pre-publish one. This is a sequencing correction, not new infrastructure.

---
Major #4 — setup-addon.sh couples to install.sh via full source

Problem (verified): setup-addon.sh:54 does source "$REPO_ROOT/install.sh", relying on the BASH_SOURCE==$0 guard (install.sh:3656). In the registry model, /opt/sift-mcps is a thin scaffold and install.sh is a ~150-line bootstrap — sourcing it no longer yields the provisioning functions the add-onhelper needs.

Recommended solution — source the specific lib/*.sh modules, as both blueprints propose (01 §5.4):
source "$SIFT_MCPS_INSTALL_ROOT/lib/common.sh"
source "$SIFT_MCPS_INSTALL_ROOT/lib/paths.sh"
source "$SIFT_MCPS_INSTALL_ROOT/lib/python.sh"      # resolve_uv
source "$SIFT_MCPS_INSTALL_ROOT/lib/opensearch.sh"  # if it uses OS config helpers
Implementation gate: this is strictly downstream of the M4 modularization (functions must actually live in lib/ first). Sequence it after M4, and add asmoke test that setup-addon.sh --help runs without sourcing install.sh. Until M4 lands, leave the source install.sh line intact — don't half-migrate.

---
Minor #1 — _ensure_venv_integrity / idempotency version check

Problem: blueprint §6.2 proposes import sift_gateway; assert sift_gateway.__version__ == '$SIFT_VERSION' as the package-install skip probe. But__version__ is a hand-maintained literal in __init__.py (confirmed: sift-gateway, sift-core, etc. all carry one) — it can drift from the installed wheel's real version.

Recommended solution: use installed-distribution metadata, not the module attribute:
from importlib.metadata import version
assert version("sift-gateway") == "$SIFT_VERSION"
This reads the actually-installed wheel's metadata and is immune to a stale __version__ literal. (And if you adopt the hatch-vcs fix in Blocker #2, __version__ becomes generated and this concern partly evaporates — but importlib.metadata.version is still the correct probe.)

---
Minor #2 — Loose line-anchors in blueprint 01

Problem: 01 cites several file:line ranges that are approximate. Low impact, but a forensic-tooling doc should be precise.

Recommended solution: re-anchor 01's citations against current HEAD before ratification (01b is already tightly anchored — use it as the reference). Mechanical pass; no code change.

---
New finding the prior reviewer missed — PyPI dist-name divergence between 01 and 01b

Problem: 01 renames distributions (sift-rag-mcp, sift-case-dashboard, sift-forensic-knowledge, …); 01b keeps current names (rag-mcp, case-dashboard, …). The current dist names are rag-mcp, case-dashboard, forensic-knowledge, opensearch-mcp (verified in each [project] name).

Recommended solution — decide once, apply in three places: Whatever the operator picks, it must be consistent across (a) each package's [project] name,(b) the meta-package's extras list, and (c) the generated constraints file and setup-addon.sh install specs.

My recommendation: rename to the sift- prefix (01's approach) if publishing to public PyPI — rag-mcp, case-dashboard, opensearch-mcp are generic names highly likely to be squatted or collide. If publishing to a private index (01b's open question #1), keep current names — collision risk is moot andrenaming is needless churn. So this decision is downstream of the public-vs-private-index decision, which the operator hasn't made yet. Flag both as a linked pair.

---
Suggested migration ordering (reconciling 01b's M0–M11 with the above)

1. M0–M2 (extract testable funcs to lib/, add bash -n/shellcheck CI, fix dead flags) — zero distribution risk, do first.
2. Blocker #3 fix (delegate uninstall, no evidence-flag forwarding) — independent, high safety value, land early.
3. Blocker #2 fix (version coherence via hatch-vcs + tag 0.6.2) — prerequisite for any publish.
4. Decide public-vs-private index → settles the dist-name divergence.
5. Blocker #1 fix (meta-package buildable) + Major #3 (two-phase publish + post-publish constraints).
6. M4 modularization → then Major #4 (setup-addon.sh decouple).
7. Major #1 (uv arch SHA pin) — anytime, independent.
8. Major #2/G10 — separate fork issue, explicitly carved out.

---

## Part B — Implementation-Ready Patch Specs (copy-ready)

Implementation-Ready Patch Specs — All Solutions

Conventions: each patch gives the file, the exact current state I verified, the target, and a verification command. Diffs are illustrative (line numbers drift as you apply earlier patches); apply in the migration order at the end.

---
PATCH SET 1 — Blocker #2: Version coherence (do this first; everything publishable depends on it)

1a. Adopt hatch-vcs across all nine packages

The repo already has the correct pattern in one place — opensearch-mcp/src/opensearch_mcp/__init__.py:5 does __version__ = version("opensearch-mcp"). The fix makes the other packages match, and moves the version number itself to git tags.

Each packages/*/pyproject.toml — replace the static version block:
 [build-system]
-requires = ["hatchling"]
+requires = ["hatchling", "hatch-vcs"]
 build-backend = "hatchling.build"

 [project]
 name = "sift-core"
-version = "0.1.0"
+dynamic = ["version"]
 ...

+[tool.hatch.version]
+source = "vcs"
+raw-options = { root = "../.." }   # tags live at repo root, package is two levels down
+
+[tool.hatch.build.hooks.vcs]
+version-file = "src/sift_core/_version.py"
raw-options.root = "../.." is required because each package builds from packages/<name>/, but the git tags are at the repo root two levels up. Repeatper package with the right version-file path (src/sift_gateway/_version.py, src/rag_mcp/_version.py, etc.).

Root pyproject.toml — same treatment, root = ".":
 [build-system]
-requires = ["hatchling"]
+requires = ["hatchling", "hatch-vcs"]

 [project]
 name = "sift-mcps"
-version = "0.1.0"
+dynamic = ["version"]

+[tool.hatch.version]
+source = "vcs"

1b. Convert the four hardcoded __init__.py literals to metadata reads

Verified current state: sift-core:3, sift-gateway:1, windows-triage:7, rag-mcp:35 hardcode literals; opensearch-mcp:5 already does it right.

packages/sift-core/src/sift_core/__init__.py:
 """sift-core: shared case I/O, identity, approval auth, and HMAC verification."""
-
-__version__ = "0.1.0"
+from importlib.metadata import version
+
+__version__ = version("sift-core")
Apply the identical edit (with the right distribution name string) to sift-gateway (version("sift-gateway")), windows-triage-mcp (version("windows-triage-mcp")), and rag-mcp (version("rag-mcp")). After this, zero version literals remain in the tree — the git tag is the onlysource.

▎ Note: importlib.metadata.version reads installed-dist metadata, so it works only when the package is installed (editable or wheel) — which is always true in this venv-based runtime. opensearch-mcp has run this way already, so it's proven.

1c. gitignore the generated _version.py files

.gitignore (after line 6 *.egg-info/):
 *.egg-info/
+# hatch-vcs generated version files (build artifacts, not source)
+packages/*/src/*/_version.py

1d. Cut the version tag

git tag v0.6.2 && git push origin v0.6.2     # bumps the three 0.1.0 packages up to 0.6.2

Verification

# every package reports the same version, sourced from the tag
for d in packages/*; do
  uv run --directory "$d" python -c "import importlib.metadata as m; print('$d', m.version(open('$d/pyproject.toml').read().split('name = \"')[1].split('\"')[0]))" 2>/dev/null
done
# no literals remain
grep -rn '__version__ = "' packages/*/src   # expect: no matches

---
PATCH SET 2 — Blocker #3: install.sh can never delete evidence

2a. Replace the inline teardown block

install.sh — delete install.sh:3239-3393 (_confirm_destructive, uninstall_systemd, uninstall_docker_stacks, uninstall_system_hardening,uninstall_runtime, _purge_tree, purge_data, do_uninstall) and replace do_uninstall with the delegating shim. Component tokens verified against scripts/uninstall.sh:119.

# install.sh — teardown now delegates to the single canonical script.
# install.sh has NO code path that deletes evidence, by construction.
do_uninstall() {
  local uninstall_script="$REPO_DIR/scripts/uninstall.sh"
  [[ -x "$uninstall_script" ]] || die "Canonical uninstaller missing: $uninstall_script"

  local args=(--all)
  [[ "${ASSUME_YES:-0}" == "1" ]] && args+=(--yes --i-understand)

  if [[ "${PURGE_DATA:-0}" == "1" ]]; then
    # Clear state/runtime/control-plane but NEVER /cases. We deliberately do
    # not forward --remove-evidence / --i-understand-evidence-loss: evidence
    # deletion must be a separate explicit run of scripts/uninstall.sh so the
    # typed "DELETE EVIDENCE" gate (uninstall.sh:308) is unavoidable.
    args=(--components systemd,runtime,supabase,state,cache,auditd,apparmor,tls)
    [[ "${ASSUME_YES:-0}" == "1" ]] && args+=(--yes --i-understand)
    warn "--purge-data clears state (/var/lib/sift) but PRESERVES /cases (evidence)."
    warn "To delete evidence, run as a separate explicit step:"
    warn "  scripts/uninstall.sh --remove-evidence --i-understand-evidence-loss --yes"
  fi

  log "Delegating to $uninstall_script ${args[*]}"
  exec "$uninstall_script" "${args[@]}"
}

2b. Pre-merge guard — confirm no caller depends on the old /cases-wipe

grep -rn -- '--purge-data' scripts/ .github/ docs/ install.sh
# reset-vm-test.sh is already removed (CLAUDE.md). Expect only doc/help references.
If a caller expects /cases removal, it must be migrated to call scripts/uninstall.sh --remove-evidence ... directly. Document the contract change in the install changelog.

Verification

bash -n install.sh
# dry-run delegation prints the canonical script invocation, never an rm of /cases
PURGE_DATA=1 ASSUME_YES=1 DRY_RUN=1 bash -c 'source install.sh; do_uninstall' 2>&1 | grep -i 'PRESERVES /cases'

---
PATCH SET 3 — Blocker #1 + Major #3: buildable meta-package + two-phase release

3a. Make root sift-mcps buildable

Root pyproject.toml:
 [tool.uv]
-package = false
+package = true

 [tool.hatch.build.targets.wheel]
-packages = []
+bypass-selection = true        # dependency-only meta-wheel; ships no Python modules

3b. Pin extras at build time (keep dev resolution via [tool.uv.sources])

Keep [tool.uv.sources] (lines 7-16) for local uv sync. The release step strips it and pins extras. Target extras (templated ${V} substituted by CI tothe tag version):
[project.optional-dependencies]
core     = ["sift-core==${V}", "case-dashboard==${V}", "forensic-knowledge==${V}", "sift-common==${V}", "sift-gateway==${V}"]
standard = ["sift-mcps[core]==${V}", "opensearch-mcp==${V}"]
full     = ["sift-mcps[standard]==${V}", "rag-mcp==${V}"]
opencti        = ["opencti-mcp==${V}"]
windows-triage = ["windows-triage-mcp==${V}"]

▎ Names kept as current (rag-mcp, case-dashboard, …) pending the public-vs-private index decision (Patch Set 5). If public PyPI is chosen, this table and every [project] name flip to the sift- prefix in one pass.

3c. Release CI workflow (new .github/workflows/release.yml)

Models the existing ci.yml (uv + setup). Two-phase: publish members → publish meta → compile constraints from the published index.

name: Release
on:
  push:
    tags: ['v*']
permissions:
  contents: write        # attach constraints + bundle to the GitHub Release
  id-token: write        # PyPI trusted publishing (OIDC), no stored token
jobs:
  build-publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with: { fetch-depth: 0 }        # hatch-vcs needs full history + tags
      - uses: astral-sh/setup-uv@v8.2.0
      - name: Resolve version from tag
        run: echo "V=${GITHUB_REF_NAME#v}" >> "$GITHUB_ENV"
      - name: Pin meta extras to $V
        run: sed -i "s/\${V}/${V}/g" pyproject.toml
      - name: Build all packages (members + meta)
        run: |
          for d in packages/sift-common packages/sift-core \
                   packages/sift-gateway packages/opensearch-mcp \
                   packages/forensic-rag-mcp packages/case-dashboard \
                   packages/forensic-knowledge packages/windows-triage-mcp \
                   packages/opencti-mcp .; do
            uv build --wheel --sdist -o dist/ "$d"
          done
      - name: Publish members first, meta last (dependency order)
        run: |
          uv publish dist/sift_common-*  dist/sift_core-*
          uv publish dist/sift_gateway-* dist/opensearch_mcp-* dist/rag_mcp-* \
                     dist/case_dashboard-* dist/forensic_knowledge-* \
                     dist/windows_triage_mcp-* dist/opencti_mcp-*
          uv publish dist/sift_mcps-*           # meta resolves only after members exist
  pin-constraints:
    needs: build-publish
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: astral-sh/setup-uv@v8.2.0
      - name: Compile hash-pinned constraints from the PUBLISHED index
        run: |
          V="${GITHUB_REF_NAME#v}"
          uv pip compile pyproject.toml --extra full --generate-hashes \
            --python-version 3.12 -o "constraints-${V}.txt"
      - name: Attach to release
        run: gh release upload "${GITHUB_REF_NAME}" "constraints-${{ github.ref_name }}.txt"
        env: { GH_TOKEN: ${{ github.token }} }
The constraints compile is a separate job gated on build-publish — that enforces the post-publish ordering (Major #3). The installer ships and consumesconstraints-X.Y.Z.txt, never a locally-compiled one.

Verification

python -m build --wheel .                          # meta wheel builds
unzip -p dist/sift_mcps-*.whl '*/METADATA' | grep Requires-Dist   # pinned ==X.Y.Z, no workspace markers
# dry resolve against a throwaway local index (pypiserver) before the real publish

---
PATCH SET 4 — Major #1: symmetric uv SHA + Major #4: setup-addon decouple

4a. Per-arch SHA-pinned uv (delete the curl | sh fallback)

install.sh:325-351 — replace the x86_64-only branch + script fallback with an arch map:
local triple sha_expected
case "$arch" in
  x86_64|amd64)  triple="x86_64-unknown-linux-gnu";  sha_expected="${SIFT_UV_TARBALL_SHA256_X86_64:-$SIFT_UV_TARBALL_SHA256}" ;;
  aarch64|arm64) triple="aarch64-unknown-linux-gnu"; sha_expected="${SIFT_UV_TARBALL_SHA256_AARCH64:-}" ;;
  *) rm -rf "$tmpd"; die "Unsupported arch '$arch'. Pre-stage uv on PATH (offline) or add a pinned tarball+SHA for this arch." ;;
esac
[[ -n "$sha_expected" ]] || { rm -rf "$tmpd"; die "No pinned uv SHA-256 for arch '$arch' (set SIFT_UV_TARBALL_SHA256_$( echo "$arch" | tr a-z A-Z ))."; }
tarball="$tmpd/uv-${triple}.tar.gz"
curl -fsSL -o "$tarball" \
  "https://github.com/astral-sh/uv/releases/download/${SIFT_UV_VERSION}/uv-${triple}.tar.gz" \
  || { rm -rf "$tmpd"; die "uv tarball download failed for ${triple}."; }
verify_sha256 "$tarball" "$sha_expected" \
  || { rm -rf "$tmpd"; die "uv ${SIFT_UV_VERSION} ${triple} failed SHA-256 verification (supply-chain guard)."; }
mkdir -p "$HOME/.local/bin"
tar -xzf "$tarball" -C "$tmpd"
uv_extracted="$(find "$tmpd" -type f -name uv | head -1)"
[[ -n "$uv_extracted" ]] && install -m 755 "$uv_extracted" "$HOME/.local/bin/uv"
rm -rf "$tmpd"
Keep SIFT_UV_TARBALL_SHA256 as a back-compat alias for the x86_64 hash (the :- fallback above). Add SIFT_UV_TARBALL_SHA256_AARCH64 to the asset SHAledger near install.sh:155-187. Every path is now hash-gated; unsupported arch fails closed.

4b. setup-addon.sh sources lib/, not install.sh — AFTER modularization (M4)

scripts/setup-addon.sh:54 (post-M4 only):
-source "$REPO_ROOT/install.sh"
+SIFT_MCPS_INSTALL_ROOT="${SIFT_MCPS_INSTALL_ROOT:-/opt/sift-mcps}"
+LIB="$SIFT_MCPS_INSTALL_ROOT/lib"
+source "$LIB/common.sh"      # log/warn/die, sudo_if_needed, verify_sha256
+source "$LIB/paths.sh"       # SIFT_* path vars, REPO_DIR
+source "$LIB/python.sh"      # resolve_uv
+source "$LIB/opensearch.sh"  # OS config helpers, if used
Gate: invalid until functions live in lib/. Until M4 lands, leave the source install.sh line intact. Smoke test after:
bash -n scripts/setup-addon.sh
scripts/setup-addon.sh --help     # must not source install.sh, must not start an install

---
PATCH SET 5 — Decision-gated items (no code until operator rules)

5a. Dist-name divergence (gated on public-vs-private index)

- Public PyPI → rename [project] name to sift-rag-mcp, sift-case-dashboard, sift-forensic-knowledge, sift-opensearch-mcp, sift-windows-triage-mcp,sift-opencti-mcp; update the meta extras (Patch 3b), [tool.uv.sources] keys, the importlib.metadata.version("...") strings in each __init__.py, and setup-addon.sh install specs. Module import names (rag_mcp, case_dashboard) do not change — only distribution names.
- Private index → keep current names; only configure --index-url/auth in the bootstrap.

5b. Major #2 / G10 — carve out as a separate Linear fork issue

Not an install-track change. Add to blueprint 01 §3.2 the honesty sentence: "Registry publishing pins package code only; the RAG knowledge corpus stays HEAD-at-refresh-time until G10 (XYE-XX). A default install is not byte-reproducible at the knowledge layer until then." The fix belongs insources.py/refresh.py (pin git feeds to commit SHAs via a checked-in manifest; snapshot MITRE/CISA JSON into the release; make live fetch opt-in).

5c. Minor #1 — idempotency probe (folds into the registry-install path)

In the new install_published skip-probe, use distribution metadata:
from importlib.metadata import version; assert version("sift-mcps") == "$SIFT_VERSION"
Keep the existing import probe (install.sh:518) as the integrity gate beneath it.

5d. Minor #2 — re-anchor blueprint 01's file:line citations against HEAD (mechanical; adopt 01b's anchors).

---
Bonus finding surfaced while ground-truthing — committed-lock gap

.gitignore:8 ignores uv.lock, yet ci.yml:47 runs uv sync --locked. A --locked sync requires a committed uv.lock; with it gitignored, CI either relies on the cache or this is silently not enforcing a lock. This undercuts the ALT's "trust the workspace lockfile" premise — there is no committed lockfile to trust. Recommendation: either commit uv.lock (remove .gitignore:8) so --locked is meaningful and the constraints story has a dev-side anchor, or drop--locked from CI. This is adjacent to the install track but directly relevant to the integrity/pinning narrative — worth a quick Linear note.

---
Apply order (dependency-correct, reversible-first)

┌─────┬────────────────────────────────────────────────────────────────────────┬──────────┬───────────────────────────┐
│  #  │                               Patch set                                │   Risk   │           Gate            │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 1   │ PS1 version coherence (hatch-vcs + tag v0.6.2)                         │ low      │ —                         │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 2   │ PS2 uninstall delegation                                               │ low      │ grep --purge-data callers │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 3   │ PS4a per-arch uv SHA                                                   │ low      │ add aarch64 SHA to ledger │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 4   │ (M0–M2 from ALT) extract funcs to lib/, shellcheck CI, fail-fast flags │ low      │ —                         │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 5   │ decide public-vs-private index                                         │ decision │ operator                  │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 6   │ PS3 meta-package + release CI + two-phase constraints                  │ med      │ PS1, #5                   │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 7   │ (M4) modularize → PS4b setup-addon decouple                            │ med      │ M4                        │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 8   │ PS5a dist rename (if public)                                           │ low      │ #5                        │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 9   │ PS5b/G10 RAG-feed pinning                                              │ —        │ separate fork issue       │
├─────┼────────────────────────────────────────────────────────────────────────┼──────────┼───────────────────────────┤
│ 10  │ commit-lock gap (bonus)                                                │ low      │ quick decision            │
└─────┴────────────────────────────────────────────────────────────────────────┴──────────┴───────────────────────────┘

PS1–PS4a + M0–M2 ship with zero distribution change (pure hardening, all reversible). Then the index decision unblocks the registry-primary cutover(PS3, PS4b, PS5a).