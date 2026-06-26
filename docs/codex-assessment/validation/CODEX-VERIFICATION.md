# CODEX Verification - Independent Cross-Model Security Review

Date: 2026-06-26

Verifier: Codex, independent adversarial cross-model verifier. I treated the authored branches as untrusted until code, tests, and bypass paths were checked.

Branches verified:

| Branch | Worktree | Commit |
| --- | --- | --- |
| `sec/auth-registration-hardening` | `/home/yk/AI/SIFTHACK/wt/sec-auth-reg` | `093b129` |
| `sec/opensearch-case-isolation` | `/home/yk/AI/SIFTHACK/wt/sec-opensearch` | `6cea166` |
| `sec/secdef-hardening-test` | `/home/yk/AI/SIFTHACK/wt/sec-db-test` | `7c0abfd` |

Base commit for all diffs: `911072b`.

## Summary Table

| Branch | Issues | Verdict | Tests reproduced | Most serious finding |
| --- | --- | --- | --- | --- |
| `sec/auth-registration-hardening` @ `093b129` | SEC-1, SEC-4 | **FAIL** | Yes: `56 passed` | SEC-4 command allowlist allows whole directories, including the gateway venv `bin` and `$SIFT_MCPS_ROOT`; that can admit generic interpreter launchers such as `python`, restoring arbitrary stdio backend execution by absolute path. |
| `sec/opensearch-case-isolation` @ `6cea166` | SEC-2, SEC-12 | **PASS-WITH-FIXES** | Yes: `41 passed` | Gateway agent path is case-bound, but the backend still falls back to legacy no-active-case behavior where `case-*` is accepted. This is not a gateway-agent bypass, but it is a residual direct-backend/standalone exposure unless explicitly accepted. |
| `sec/secdef-hardening-test` @ `7c0abfd` | SEC-13 residual | **PASS** | Yes: `2 skipped` because no control-plane DSN was set | No concrete defect found. The SQL uses PostgreSQL privilege semantics that include default PUBLIC EXECUTE on `proacl IS NULL`. |

## Branch 1: `sec/auth-registration-hardening` @ `093b129`

### 1. Does it implement the decided fix?

Partially. SEC-1 is implemented cleanly, and the SEC-4 environment leak fix is implemented. The SEC-4 command allowlist is not strong enough to close the recurrence class.

SEC-1 evidence:

- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/auth.py:313-356` defines `require_control_plane_operator`. It denies non-user operator classes by `principal_type`, including agent/service, denies `role in {"agent", "service", "readonly"}`, and is deny-by-default for unexpected principal types.
- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/auth.py:171-237` makes the anonymous single-user allowance unreachable once auth is configured: unauthenticated `/api/v1` requests get 401, invalid bearer tokens get 403, and Supabase validation failures fail closed unless fallback is explicitly configured.
- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/auth.py:378-449` implements step-up reauth. It is a no-op only when Supabase is disabled; with Supabase enabled it denies missing callback, missing credentials, wrong password, identity mismatch, and reverify exceptions.
- The mutation handlers call the gate at the top before doing the mutation:
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:489-493` service start.
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:534-538` service stop.
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:563-567` service restart.
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:624-649` create join code, including step-up.
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:967-975` backend reload.
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:1135-1168` backend validate/register, including step-up for register.
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:1171-1180` backend unregister.
  - `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:1234-1245` backend set enabled.
- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/rest.py:1292-1310` lists the live REST routes; I did not find another `/api/v1` control-plane mutation route in `rest_routes()` missing the handler gate.
- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py:276-306` adds a registry-layer defense-in-depth gate for mutable registry operations. The HTTP paths pass the actor through at register/set_enabled/unregister (`:568`, `:658-660`, `:693-695`). `actor=None` remains allowed for trusted in-process/system callers, including the existing public join-code flow, which is outside the SEC-1 operator-control-plane route set.

SEC-4 environment evidence:

- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py:39-71` defines an allowlisted environment surface, not a denylist.
- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py:74-105` copies only known-safe base names, `LC_*`, SIFT case context variables, and explicitly configured backend env.
- `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py:165-173` uses the minimal builder at spawn time instead of copying `os.environ`. This prevents ambient `*_DSN`, Supabase service keys, and other backend tokens from reaching the child unless an operator explicitly configures them in backend env.

### 2. Bypass / fail-open hunt

SEC-1: I tried to find a route where an unstamped request reaches `require_control_plane_operator` and is treated as anonymous operator. I did not find one for configured auth. The middleware rejects missing/invalid auth before handlers on `/api/v1`, and the public-path exemptions do not include the protected mutation routes except the intentionally public setup/join path.

SEC-4 command allowlist: I did find a bypass class. `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py:400-429` builds allowed directories from configured directories, the gateway venv `bin` directory, `sys.prefix/bin`, and `$SIFT_MCPS_ROOT`. `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py:445-484` then authorizes any absolute command whose real path is inside any allowed directory.

That is a directory allowlist, not a command allowlist. In the expected gateway deployment posture, the venv `bin` directory contains generic launchers such as `python`/`python3` and often tooling launchers. A registered stdio backend can set `command` to that absolute interpreter path and put arbitrary code in `args` (for example `-c ...`) while satisfying the current allowlist check. `$SIFT_MCPS_ROOT` as a broad allowed directory has the same shape problem if executable files are present under the repo tree.

The tests reject bare `python`, `/usr/bin/python3`, `/bin/sh`, and `/tmp/evil`, but they positively accept a venv console-script path and do not assert that generic interpreters inside an allowed directory are rejected (`/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/tests/test_sec4_stdio_env_and_command_allowlist.py:106-117`).

### 3. Invariant preservation

The operator gate preserves the gateway as the thin policy boundary and keeps agent/service/readonly principals out of control-plane mutations. The minimal stdio environment preserves DB-authority separation by preventing ambient database and service-role secrets from leaking to add-on children.

The command allowlist defect does not reintroduce automatic DB secret inheritance, but it leaves an operator-authorized registration path capable of starting arbitrary interpreter-backed code. That is weaker than the decided "command allowlist for registered stdio backends" requirement and should not be merged as-is.

### 4. Test quality

The SEC-1 structural test is real, not a hand-picked theater list. `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/tests/test_rest_control_plane_authz.py:88-98` derives mutation routes from `rest_routes()`, and `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/tests/test_rest_control_plane_authz.py:101-110` prevents the route set from silently becoming empty with spot checks and a minimum count. `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/tests/test_rest_control_plane_authz.py:113-131` asserts agent/readonly denial and examiner acceptance across that live set.

The SEC-4 env tests are meaningful for secret non-inheritance (`/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/tests/test_sec4_stdio_env_and_command_allowlist.py:45-100`), but the command allowlist tests miss the interpreter-inside-allowed-directory bypass class.

### 5. Test reproduction result

Command run from `/home/yk/AI/SIFTHACK/wt/sec-auth-reg`:

```bash
PYTHONDONTWRITEBYTECODE=1 uv run --extra full --extra dev pytest packages/sift-gateway/tests/test_rest_control_plane_authz.py packages/sift-gateway/tests/test_sec4_stdio_env_and_command_allowlist.py -q -p no:cacheprovider
```

Result: `56 passed in 1.75s`.

Note: `uv` created a local ignored `.venv` in the worktree while running the requested test command. I did not edit source, config, commits, branches, or git state.

### 6. Concrete defect and suggested fix

Defect: `/home/yk/AI/SIFTHACK/wt/sec-auth-reg/packages/sift-gateway/src/sift_gateway/mcp_backends_registry.py:400-429` and `:445-484` authorize directories rather than an exact command catalog. This can allow arbitrary interpreter launchers inside the gateway venv or repo tree.

Suggested fix, not applied:

- Replace directory containment with exact allowed executable paths derived from installed add-on console-script entry points or signed backend manifests.
- Explicitly reject generic interpreters/package managers/shells even if they live under an allowed directory: `python`, `python3`, `pip`, `uv`, `bash`, `sh`, `node`, etc.
- Consider validating owner/mode/no-world-writable and symlink targets for allowed executables.
- Add a regression test that an absolute path to the gateway venv `python` is denied, while the intended exact add-on console script is allowed.

Merge recommendation: **NO-GO** until the command allowlist is narrowed to exact approved executables.

## Branch 2: `sec/opensearch-case-isolation` @ `6cea166`

### 1. Does it implement the decided fix?

Mostly yes for the gateway-agent path.

Backend evidence:

- `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:144-198` defines `_validate_index`. With an active case, every non-empty comma segment must start with `case-{key}-`. The trailing dash blocks prefix confusion such as active `case-a` matching `case-a2-*`.
- The query handlers validate the index before executing:
  - `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:950-954` search.
  - `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:1082-1086` count.
  - `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:1152-1156` aggregate.
  - `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:1237-1239` get_event.
  - `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:1301-1305` timeline.
  - `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:1394-1398` field_values.

Gateway boundary evidence:

- `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/sift-gateway/src/sift_gateway/server.py:480-567` reads backend manifest metadata including `case_bound_argument_names`.
- `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/sift-gateway/src/sift_gateway/server.py:946-980` computes case-bound argument names and the active-case index prefix.
- `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/sift-gateway/src/sift_gateway/server.py:1165-1214` enforces every supplied `index` comma segment against the active-case prefix and raises on mismatch. This covers `opensearch_get_event`, whose backend handler has no case-dir injection.
- The boundary is reached after active-case resolution for case-scoped tools. If the active-case service is configured, the code requires an active case before index validation. If no active-case service exists, the gateway cannot bind the index; that is a legacy/no-DB residual, not a bypass of the configured gateway-agent path.
- `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/sift-backend.json:73-79`, `:108-114`, `:147-153`, and `:179-182` mark `index` as a case-bound argument for search/count/aggregate/get_event. The same manifest pattern applies to the other case-bound query tools.

SEC-12 evidence:

- The in-process `SIFT_ENRICHMENT_SCOPE` gate is removed from the backend path. `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:3392-3405` documents that gateway authorization is authoritative.
- The gateway manifest still requires `enrichment:intel` for `opensearch_enrich_intel` at `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/sift-backend.json:512-516`.
- `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/tests/test_k4_host_identity_authority.py:296-324` proves the old inert env gate no longer fail-closes the legitimate backend path.
- `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/sift-gateway/tests/test_ad2_addon_conformance.py:819-852` proves the gateway `AddonAuthorityMiddleware` still denies enrichment without `enrichment:intel`.

### 2. Bypass / fail-open hunt

With an active case, I tried the obvious escapes: `case-*`, exact other-case indices, mixed comma segments, prefix confusion (`case-a-12345-*` against `case-a-1234`), and empty comma segments. The active-case tests cover the material cases at `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/tests/test_security.py:267-331`, including the flipped wildcard denial at `:281-286`. I did not find a cross-case escape when active case is present.

The remaining gap is the no-active-case path. `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:187-198` falls back to the old `case-` prefix policy when no active prefix exists, and `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/tests/test_security.py:215-265` intentionally preserves `case-*` acceptance without an active case. That is not an agent-path bypass through the configured gateway, but it means the backend itself does not always "bind the free-form index to the DB-active case"; it binds only when an active case context exists.

Empty segments are skipped under active case. I did not find this to escape case scope, but `case-a-1234-evtx-*,` is accepted by the validator shape. Rejecting empty segments would be cleaner.

### 3. Invariant preservation

The gateway remains the authoritative policy boundary for agent-reachable paths, and the backend now has matching defense-in-depth when active case context is injected. The gateway worker still surfaces backend errors through the result path instead of silently querying another case. The SEC-12 removal preserves the intended gateway `AddonAuthorityMiddleware` authority model rather than keeping an inert in-process env gate.

### 4. Test quality

The OpenSearch tests are meaningful and would catch a revert of the active-case index binding. `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/tests/test_security.py:267-331` exercises wildcard denial, other-case denial, exact active-case acceptance, intra-case narrowing, comma mixing, and prefix confusion. `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/tests/test_security.py:426-463` asserts that denial is surfaced in the public result payload.

Gateway tests are also meaningful: `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/sift-gateway/tests/test_ad2_addon_conformance.py:775-810` checks cross-case gateway rejection and same-case acceptance, while `:819-852` checks enrichment scope denial at the gateway.

### 5. Test reproduction result

Command run from `/home/yk/AI/SIFTHACK/wt/sec-opensearch`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=packages/opensearch-mcp/src:packages/opensearch-mcp/tests:packages/sift-gateway/src:packages/sift-common/src:packages/sift-core/src:packages/case-dashboard/src /home/yk/AI/SIFTHACK/sift-mcps/.venv/bin/pytest packages/opensearch-mcp/tests/test_security.py -q -p no:cacheprovider
```

Result: `41 passed in 0.45s`.

### 6. Concrete defect and suggested fix

Residual defect: `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/src/opensearch_mcp/server.py:187-198` still permits broad `case-*` when no active case context exists. This is explicitly tested as passing in `/home/yk/AI/SIFTHACK/wt/sec-opensearch/packages/opensearch-mcp/tests/test_security.py:231-239`.

Suggested fix, not applied:

- If the decided spec is strict for the backend itself, make `_validate_index` fail closed for case-bound query tools when no active case exists, unless a deliberate operator-only standalone mode is set.
- Alternatively, document and explicitly accept the no-active-case backend mode as non-agent standalone behavior, and keep the gateway manifest binding as the merge gate.
- Tighten comma parsing to reject empty segments instead of skipping them.

Merge recommendation: **GO for the configured gateway-agent isolation path only if the no-active-case backend fallback is explicitly accepted as a standalone residual. Otherwise NO-GO until `_validate_index` fails closed without active case context.**

## Branch 3: `sec/secdef-hardening-test` @ `7c0abfd`

### 1. Does it implement the decided fix?

Yes. `/home/yk/AI/SIFTHACK/wt/sec-db-test/packages/sift-gateway/tests/test_secdef_no_public_execute.py:46-60` queries all `app` schema `SECURITY DEFINER` functions and uses `has_function_privilege('public', p.oid, 'EXECUTE')`. PostgreSQL privilege checks include implicit/default privileges, so this catches the important recurrence class: a future SECURITY DEFINER function with `proacl IS NULL` and default PUBLIC EXECUTE.

The file also includes a service-role over-revoke guard at `/home/yk/AI/SIFTHACK/wt/sec-db-test/packages/sift-gateway/tests/test_secdef_no_public_execute.py:112-148`.

### 2. Bypass / fail-open hunt

The main concern was whether the test only caught explicit PUBLIC grants and missed `proacl IS NULL`. It does not: `has_function_privilege` computes effective privileges, including defaults. A freshly created `app` SECURITY DEFINER function with default execute would be reported as public-executable and fail the test.

### 3. Invariant preservation

This branch is test-only. It does not change production code, schema, gateway behavior, DB-authority, MCP surfacing, evidence gates, or sandbox posture.

### 4. Test quality

The DSN gating is clean. `/home/yk/AI/SIFTHACK/wt/sec-db-test/packages/sift-gateway/tests/test_secdef_no_public_execute.py:63-75` skips when no control-plane DSN is configured. `/home/yk/AI/SIFTHACK/wt/sec-db-test/packages/sift-gateway/tests/test_secdef_no_public_execute.py:78-109` skips rather than green-passing if the DB has zero app SECURITY DEFINER functions. The skip is visible in pytest output.

One limitation: without a live DSN, I reproduced the skip path rather than the live DB assertion path. The SQL itself is the right primitive for the recurrence class.

### 5. Test reproduction result

Command run from `/home/yk/AI/SIFTHACK/wt/sec-db-test`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=packages/sift-gateway/src:packages/sift-common/src:packages/sift-core/src:packages/case-dashboard/src:packages/opensearch-mcp/src /home/yk/AI/SIFTHACK/sift-mcps/.venv/bin/pytest packages/sift-gateway/tests/test_secdef_no_public_execute.py -rs -p no:cacheprovider
```

Result: `2 skipped in 0.03s`.

Skip reason: `SIFT_CONTROL_PLANE_DSN` was not set.

### 6. Concrete defect and suggested fix

No concrete defect found.

Suggested future improvement, not required for this branch: add an isolated integration fixture or documented live-DB CI lane that creates a temporary `app` SECURITY DEFINER function with default privileges and proves the test fails before cleanup. That would demonstrate fail-on-recurrence without relying solely on PostgreSQL semantics.

Merge recommendation: **GO**.

## Final Merge Recommendations

| Branch | Recommendation |
| --- | --- |
| `sec/auth-registration-hardening` @ `093b129` | **NO-GO**. SEC-1 and stdio env minimization are solid, but the stdio command allowlist is bypassable because it authorizes whole directories containing generic launchers. |
| `sec/opensearch-case-isolation` @ `6cea166` | **Conditional GO / PASS-WITH-FIXES**. The configured gateway-agent path is protected. Decide explicitly whether the no-active-case backend `case-*` fallback is acceptable standalone behavior; otherwise tighten to fail closed. |
| `sec/secdef-hardening-test` @ `7c0abfd` | **GO**. Test uses the right PostgreSQL privilege primitive and skips honestly without DSN or target functions. |

Cross-branch concern: the strongest remaining merge blocker is the SEC-4 command allowlist. The OpenSearch residual is a boundary-definition decision; the auth branch defect is a concrete bypass of the claimed command allowlist.

One-paragraph stdout summary: Codex verification found the auth/register branch is **NO-GO** despite good SEC-1 coverage because its stdio "command allowlist" authorizes broad directories such as the gateway venv `bin` and `$SIFT_MCPS_ROOT`, which can admit generic interpreter launchers; the OpenSearch branch is **PASS-WITH-FIXES / conditional GO** because active-case gateway-agent isolation is enforced but the backend still allows `case-*` when no active case context exists; the SECURITY DEFINER branch is **GO**, with tests skipped honestly without a DSN and SQL that catches default PUBLIC EXECUTE via `has_function_privilege`.
