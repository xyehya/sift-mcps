# B-MVP-052 — Shared `deprecated_aliases` add-on feature vs. gateway strict manifest enforcement

Status: DECIDED — **Option (c) adopted and IMPLEMENTED** (2026-06-16, branch
`fix/b052-remove-deprecated-aliases`). The `deprecated_aliases` mechanism was removed
from the shared add-on contract (both `register_all` alias loops, the
`deprecated_alias_of` branch in both `_function_tool`s, and the `ToolDef` field in all
three packages' `contracts.py`). Add-on authoring guidance now documents the safe
rename path (new manifest tool name + `manifest_sha256` bump + re-register) and a
gateway regression test pins the served ⊆ manifest invariant
(`packages/sift-gateway/tests/test_f1_opensearch_backend_registry.py::test_started_backend_serving_undeclared_tool_is_rejected`).
The analysis below is preserved as-written (append-only history).
Source: backlog B-MVP-052, root-caused 2026-06-15 via the `opensearch_host_fix` incident.
Scope-fence: this doc only. The orchestrator folds the outcome into `REGISTER.md`,
`Session-Notes.md`, and (if implemented) the code/CONVENTIONS.

---

## 1. Problem statement

The shared add-on contract lets a `ToolDef` declare extra MCP tool names that the
add-on **serves** but the gateway never **declares**, producing a hard 500 on the
next portal-driven backend Start/Restart.

**The mechanism (identical in both add-ons):**

- `ToolDef.deprecated_aliases: list[str] = []` — declared in the shared contract,
  duplicated verbatim in both packages:
  - `packages/opensearch-mcp/src/opensearch_mcp/contracts.py:49`
  - `packages/opencti-mcp/src/opencti_mcp/contracts.py:49`
- `register_all` adds one FastMCP tool per canonical name **and one per alias**, so
  every alias becomes a real served tool on the backend's `tools/list`:
  - opensearch: `packages/opensearch-mcp/src/opensearch_mcp/registry.py:2394-2397`
  - opencti: `packages/opencti-mcp/src/opencti_mcp/registry.py:899-904`
- The alias tool gets `meta = {... "deprecated": True, "canonical_name": <orig>}`:
  - opensearch: `packages/opensearch-mcp/src/opensearch_mcp/registry.py:2432-2438`
  - opencti: `packages/opencti-mcp/src/opencti_mcp/registry.py:929-935`

**Why served ⊄ declared raises.** The gateway `_build_tool_map` enforces, for a
**started** backend, that every name in the live `tools/list` is declared in the
manifest `tools[]` block:

- `packages/sift-gateway/src/sift_gateway/server.py:498-520` — for `backend.started`,
  it builds `declared_names = {t["name"] for t in manifest["tools"]}`
  (`server.py:502-503`) and, for each live tool, raises
  `ValueError(f"Tool '{tool.name}' from backend '{name}' is not declared in the
  manifest 'tools' block")` (`server.py:517-519`). The `except` re-raises any
  `ValueError` (`server.py:529-530`), so this is fatal — it surfaces as HTTP 500 on
  the portal Start/Restart action. A `deprecated_alias` is **never** auto-added to
  the manifest, so any served alias trips this guard.

**The lenient-at-boot vs. strict-on-start asymmetry.** The same function takes a
different path when the backend is **not** started:

- `server.py:532-550` — for a not-started backend it builds the tool map **from the
  manifest `tools[]`** (synthesizing placeholder `Tool` objects), never asking the
  backend what it actually serves. Aliases are absent from `tools[]`, so there is
  nothing to mismatch and **no error at boot**.
- Gateway boot seeds backends and builds the map from manifests (the not-started
  path), so a deployment can come up clean. The 500 only appears later when the
  operator clicks "Start"/"Restart" in the portal and the gateway compares the
  backend's *real* served tools against the manifest.

This asymmetry is the footgun: the alias passes every static and boot-time check and
only detonates on the first live Start of the backend — exactly what bit
`opensearch_host_fix` on wintriage's Start. (Note: `validate_manifest_contract` is
also static and manifest-only — `docs/add-ons/spec.md:249-251` — so it cannot catch
a served-but-undeclared alias either.)

**Current live state.** The opensearch alias was removed by the operator ("drop the
alias"): `packages/opensearch-mcp/src/opensearch_mcp/registry.py:2138-2145` sets
`deprecated_aliases=[]` with a comment pointing back to this design item. The
**feature** remains in both contracts and both `register_all` loops, so the next
author who populates `deprecated_aliases` re-creates the 500.

---

## 2. Options

### (a) Author MUST declare each deprecated alias in the manifest `tools[]`

Make the feature gateway-legal by requiring the alias to appear as its own manifest
tool entry (with `hidden_from_agent: true` and a `canonical_name`-style note), so it
is both served and declared.

- **Correctness:** Fully resolves the 500 — served ⊆ declared holds. The alias also
  flows through the normal manifest meta path (`server.py:474-496`), so it inherits
  `read_only`, `required_scopes`, `case_scoped`, etc. — important, because a served
  alias with no manifest entry currently has **no authority/scope contract** indexed.
- **Security:** Strongest. No invariant is relaxed; the alias is a fully-governed
  tool. Hidden-from-agent filtering (`server.py:485`) keeps it out of the agent's
  `tools/list` surface while still callable, matching the existing pattern.
- **Blast radius:** Small and local to each add-on. Requires authoring discipline +
  a contract test that fails if `deprecated_aliases` ⊄ manifest `tools[]`.
- **Who changes:** Add-on authors (manifest + a guard test); add-on authoring docs
  must state the rule. Gateway unchanged.
- **Weakness:** Duplicates the alias declaration in two places (Python `ToolDef`
  *and* the JSON manifest); easy to forget one half → re-introduces the asymmetry
  unless a test couples them. The coupling test is the load-bearing part.

### (b) Gateway exempts a served tool whose `meta.canonical_name` ∈ declared tools

Relax `_build_tool_map` (`server.py:511-520`): before raising, check the live tool's
`meta` for `deprecated: true` + `canonical_name`, and allow it through if the
canonical name is in `declared_names`.

- **Correctness:** Resolves the 500 without author action. But it makes the gateway
  trust backend-supplied `meta` to bypass its own surface guard.
- **Security: RELAXES a security invariant — requires `/security-review`.**
  Served ⊆ manifest is the gateway's promise that every exposed tool is one the
  operator registered and pinned by `manifest_sha256`
  (`docs/add-ons/spec.md:327-328`). Today a compromised/buggy backend cannot expand
  its own attack surface past the manifest. Option (b) lets the backend self-declare
  an *undeclared* tool legal merely by tagging it `canonical_name=<a-declared-tool>`
  — **surface shadowing**: the alias has no manifest entry, so it acquires **no**
  `required_scopes`, `read_only`, or `case_scoped` contract
  (`server.py:474-496` only indexes manifest `tools[]`). `AddonAuthorityMiddleware`
  scope enforcement and `is_case_scoped_tool` case-injection
  (`server.py:811-829`) both key off `_tool_manifest_meta`, so an exempted alias
  could run **without** the scope/case guards that bind its canonical twin. That is a
  privilege-escalation / case-isolation hole, not just a naming convenience.
- **Blast radius:** One gateway change, but it weakens the policy boundary for
  *all* add-ons forever, and the `manifest_sha256` pin no longer bounds the served
  surface.
- **Who changes:** Gateway + security review + new tests proving the alias still
  inherits the canonical tool's scopes/case-scoping (which itself requires
  *more* gateway code to copy the canonical meta onto the alias).

### (c) Remove `deprecated_aliases` from the shared contract entirely

Delete the field from both `contracts.py`, the two `register_all` alias loops, and
the alias branch of `_function_tool`.

- **Correctness:** Eliminates the footgun at the root; served ⊆ manifest is
  trivially preserved. Renames are still possible — they just go through the normal
  flow (new manifest tool name + `manifest_sha256` bump + cutover), which is the
  existing, audited mechanism (`docs/regenerate/backend-contract.md:324-328`).
- **Security:** Strongest — removes an entire class of "served-but-ungoverned" tool.
- **Blast radius:** Tiny **today**. opensearch already serves zero aliases
  (`registry.py:2145`, `deprecated_aliases=[]`). opencti serves **zero** aliases
  too — none of its 8 `ToolDef`s pass `deprecated_aliases`, so all default to `[]`
  (verified: `rg "deprecated_aliases\s*=" packages/opencti-mcp/...` returns nothing;
  the only opencti hit is the `register_all` loop at `registry.py:901`). opencti's
  `cti_get_health` is a "deprecated tool-form alias for the `cti://health`
  *resource*" (`registry.py:731-734`) — a fully-declared real tool, **not** a
  `deprecated_aliases` entry, so it is unaffected by removal.
- **Who changes:** Both add-on packages (small deletions); CONVENTIONS / authoring
  docs drop the feature. Tests that assert the field exists (if any) get removed.
- **Weakness:** Loses the "serve old + new name for one cutover cycle" convenience.
  But that convenience is exactly the unsafe path, and the safe rename path already
  exists.

---

## 3. Recommendation

**Adopt Option (c): remove `deprecated_aliases` from the shared contract.**

Justification against repo principles:

- **The gateway is the single policy boundary, and served ⊆ manifest is a security
  invariant** (`server.py:511-520`; `docs/add-ons/spec.md:249-251,327-328`). Option
  (b) is the only one that breaks that invariant, and it does so for *all* add-ons to
  buy a renaming convenience — a bad trade. Option (a) keeps the invariant but leaves
  a dual-declaration trap that re-arms on the next forgotten manifest entry. Option
  (c) makes the invariant *structurally* unbreakable by deleting the only code path
  that produced served-but-undeclared tools.
- **No silent decisions / no latent footgun.** The feature is defined-but-unused in
  both add-ons today, so removal costs nothing live and removes a guaranteed
  future 500. Keeping a defined-but-dangerous feature is exactly the "latent footgun"
  the backlog flagged.
- **Renames already have a safe, audited home.** Add a new manifest tool name, bump
  `manifest_sha256`, re-register via portal, retire the old name next cycle
  (`docs/regenerate/backend-contract.md:324-328`). No contract surface needed for it.

**Exactly what would change IF implemented (do not implement here):**

- `packages/opensearch-mcp/src/opensearch_mcp/contracts.py:49` — delete the
  `deprecated_aliases` field.
- `packages/opencti-mcp/src/opencti_mcp/contracts.py:49` — delete the field.
- `packages/opensearch-mcp/src/opensearch_mcp/registry.py:2394-2397` — drop the alias
  `for` loop in `register_all`; and `2138-2145` — drop the now-dead
  `deprecated_aliases=[]` arg + comment.
- `packages/opensearch-mcp/src/opensearch_mcp/registry.py:2425-2438` — drop the
  `deprecated_alias_of` parameter and its description/meta branch in `_function_tool`.
- `packages/opencti-mcp/src/opencti_mcp/registry.py:899-904` — drop the alias loop;
  `921-935` — drop the `deprecated_alias_of` parameter/branch.
- Authoring docs (`docs/add-ons/author-guide.md`, `docs/add-ons/spec.md`) and
  CONVENTIONS — remove any mention of `deprecated_aliases`; document the safe rename
  path instead.

If the operator wants to keep a one-cycle alias capability despite the above, the
**fallback is Option (a)** (manifest-declared + a coupling test), never Option (b).

---

## 4. Migration / impact

- **opensearch:** Already serves no alias (`registry.py:2145`). Removal is a clean
  deletion; no behavioral change live.
- **opencti:** Serves no `deprecated_aliases` alias (all 8 `ToolDef`s use the default
  `[]`). `cti_get_health` is a declared real tool, untouched. No behavioral change.
- **Add-on authoring standard:** Replace "serve old+new for a cutover cycle via
  `deprecated_aliases`" with "rename = new manifest tool entry + `manifest_sha256`
  bump + re-register; retire old name next cycle." State the invariant explicitly:
  *every served tool MUST be declared in manifest `tools[]`* — and note that this is
  enforced strict-on-start (`server.py:517-519`), not only at registration.
- **CONVENTIONS:** No `[V]`-gated structure changes (this is code/contract, not the
  parsed docs). Add a one-line authoring rule if CONVENTIONS grows an add-on section;
  otherwise the change is captured in `docs/add-ons/*`.
- **Tests:** Remove any test asserting `deprecated_aliases` exists or that aliases are
  served. Optionally add a regression test to `test_phase6.py` /
  `test_f1_opensearch_backend_registry.py` asserting that a started backend's served
  tools are a subset of its manifest `tools[]` — this pins the invariant regardless
  of which option lands and would have caught the original incident.

---

## 5. Open questions / forks for the operator

1. **F: Confirm Option (c) over (a).** Is the one-cutover-cycle dual-serving
   convenience worth keeping at all? Recommendation says no (the safe rename path
   covers it). If yes → Option (a) with a mandatory coupling test; Option (b) is
   rejected on security grounds.
2. **F: Add the subset-invariant regression test now?** Independently of (a)/(b)/(c),
   should we add a started-backend "served ⊆ manifest" test so this class of bug
   fails in CI rather than on a live portal Start?
3. **F: Authoring-doc home.** Should the rename guidance live in
   `docs/add-ons/author-guide.md`, `docs/add-ons/spec.md`, or both, and does
   CONVENTIONS need an add-on subsection at all? (No `[V]` structure is affected
   either way.)
