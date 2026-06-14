# B-MVP-023 — Legacy v1 `/dashboard` Removal: Impact Trace

Status: PLANNING (not yet executed). Source: code-explorer trace, 2026-06-15.
Owner batch: BATCH-CL2 (wave step 5). Decision (2026-06-14): REMOVE.

Scope: delete the dead v1 operator portal — the `legacy_portal_session_enabled`
flag, the `sift_session` cookie/Bearer legacy auth branch, and the v1 `/dashboard`
mount (`create_dashboard_app` + `serve_index`). The real operator app is v2 at
`/portal`. **Auth-plane change → requires `/security-review` on the executing diff.**

> CRITICAL: `_dashboard_api_routes()` (case-dashboard `routes.py`) is the shared REST
> backbone called by BOTH `create_dashboard_app` (v1) and `create_dashboard_v2_app`
> (v2). It MUST be kept. Any grep that flags it as "v1-only" is wrong.

---

## 1. Reference inventory

### packages/sift-gateway/src/sift_gateway/server.py
| File:Line | Reference | Class | Reason |
|---|---|---|---|
| server.py:37 | `_PortalHTTPSGuard`: `startswith(("/portal", "/dashboard"))` | REMOVE `/dashboard` half | Dead path once mount gone; `/portal` stays |
| server.py:60 | `SecureHeadersMiddleware`: `startswith("/dashboard")` CSP branch | REMOVE `/dashboard` half | No HTML under `/dashboard` after removal |
| server.py:1299 | `from case_dashboard.routes import (create_dashboard_app,` | REMOVE import only | `create_dashboard_v2_app` on same line stays |
| server.py:1333 | `legacy_portal_session_enabled=auth_config.legacy_portal_session_enabled` | REMOVE | Kwarg to v2 factory; gone with the flag |
| server.py:1351 | `routes.append(Mount("/dashboard", app=create_dashboard_app()))` | REMOVE | The entire v1 mount |

### packages/sift-gateway/src/sift_gateway/auth.py
| File:Line | Reference | Class | Reason |
|---|---|---|---|
| auth.py:28–29 | `"/dashboard"`, `"/dashboard/"` in `_PUBLIC_PATHS` | REMOVE | No v1 HTML public; `/portal` stays |
| auth.py:156–157 | `path.startswith(("/portal/", "/dashboard/"))` static bypass | REMOVE `/dashboard/` half | `/portal/` v2 asset bypass stays |

### packages/sift-gateway/src/sift_gateway/supabase_auth.py
| File:Line | Reference | Class | Reason |
|---|---|---|---|
| supabase_auth.py:207 | `legacy_portal_session_enabled: bool = True` field | REMOVE | The flag itself |
| supabase_auth.py:219 | `"legacy_portal_session=%r, "` in `__repr__` | REMOVE | Refers to deleted field |
| supabase_auth.py:230 | `self.legacy_portal_session_enabled,` in `__repr__` args | REMOVE | Refers to deleted field |
| supabase_auth.py:297 | `legacy_portal_session_enabled=_as_bool(legacy.get("portal_session_enabled"), True)` | REMOVE | Config parse for deleted flag |

### packages/case-dashboard/src/case_dashboard/routes.py
| File:Line | Reference | Class | Reason |
|---|---|---|---|
| routes.py:109–112 | `_LEGACY_PORTAL_SESSION_ENABLED` module var + comment | REMOVE | Never read by any handler; zero behavioral effect |
| routes.py:3636 | `post_auth_logout` docstring re legacy cookie | REMOVE (update doc) | No longer accurate |
| routes.py:3653–3658 | Legacy sift_session JTI revocation block | REMOVE | Supabase logout (3642–3651) stays |
| routes.py:3661–3669 | `COOKIE_NAME` response-clear in `post_auth_logout` | KEEP (recommended) | Proactively clears stale browser cookie during transition |
| routes.py:3697–3722 | `get_auth_me` legacy fallback (`_load_pw_entry`, old shape) | REMOVE | Live Supabase branch (3689–3695) stays |
| routes.py:3725–3732 | `async def serve_index` | REMOVE | v1-only HTML index; v2 uses `serve_v2_index` (3763) |
| routes.py:6052–6056 | `def create_dashboard_app()` | REMOVE | v1 sub-app; no PortalSessionMiddleware; calls serve_index |
| routes.py:6104 | `legacy_portal_session_enabled` param of `create_dashboard_v2_app` | REMOVE | Once gone, middleware always built as `False` |
| routes.py:6154–6159 | Docstring para explaining the flag | REMOVE | Refers to deleted param |
| routes.py:6167,6185 | `global _LEGACY_PORTAL_SESSION_ENABLED` + assignment | REMOVE | Module var + setter gone |
| routes.py:6199 | `legacy_portal_session_enabled=...` pass-through to PortalSessionMiddleware | REMOVE | Kwarg gone |
| routes.py:5650–5732 | `def _dashboard_api_routes()` + handlers | **KEEP** | Shared v1+v2; REST backbone of `/portal` |

### packages/case-dashboard/src/case_dashboard/auth.py
| File:Line | Reference | Class | Reason |
|---|---|---|---|
| auth.py:11 | Module docstring mentions flag | REMOVE (update) | Doc only |
| auth.py:117 | `legacy_portal_session_enabled: bool = True` ctor param | REMOVE | Middleware permanently operates as False |
| auth.py:124 | `self._legacy_enabled = ...` | REMOVE | Instance var unnecessary |
| auth.py:231–281 | Entire `if self._legacy_enabled:` block (cookie check + Bearer fallback) | REMOVE | Entirety of legacy auth in dispatch |
| auth.py:31–33 | Imports `COOKIE_NAME/PATH/SAME_SITE`, `verify_jwt`, `generate_jwt` | REMOVE (after block) | Only used in deleted block |

### packages/case-dashboard/src/case_dashboard/session_jwt.py
| File:Line | Reference | Class | Reason |
|---|---|---|---|
| session_jwt.py:17 | `COOKIE_NAME = "sift_session"` | REMOVE | Nothing reads it post-removal |
| session_jwt.py:18–19 | `COOKIE_PATH`, `COOKIE_SAME_SITE` | REMOVE | Only paired with COOKIE_NAME |
| session_jwt.py:64 | `def generate_jwt(...)` | KEEP (recommend) | Still imported by 3 tests; pure crypto helper. Delete only if those tests rewritten |
| session_jwt.py:95 | `def revoke_jti(...)` | REMOVE after routes 3653–3658 gone | No remaining callers |

### Other
| File:Line | Reference | Class | Reason |
|---|---|---|---|
| case_dashboard/static/index.html:740,858 | `fetch('/dashboard'+path)` v1 SPA | REMOVE (whole file) | Served only by serve_index; v2 in static/v2/ |
| configs/gateway.yaml.template:141 | `portal_session_enabled: false` | REMOVE (post step 3) | Key ignored once field deleted |
| sift-gateway/tests/test_secure_headers.py:36,75–81 | `/dashboard/index.html` route + CSP asserts | REMOVE | Dead CSP path; `/portal` CSP test stays |

---

## 2. How v2 `/portal` mounts

`Gateway.create_app()` (server.py 1296–1353) imports both factories in one `try`.
- **v2 (live):** `create_dashboard_v2_app(...)` (line 1321) with full DI payload →
  `Starlette` + `PortalSessionMiddleware`, mounted `Mount("/portal", ...)` (1350).
  Redirects `/` and `/portal` → `/portal/` (1345–1349).
- **v1 (legacy):** `create_dashboard_app()` (1351), no args → bare `Starlette`, only
  `SecurityHeadersMiddleware`, no Supabase wiring. Mounted `Mount("/dashboard", ...)`.

Both call `_dashboard_api_routes()` (shared). They diverge only in middleware stack
and HTML route: v1 = `serve_index` (static/index.html); v2 = `serve_v2_index` /
`serve_v2_assets` / `serve_v2_static` (static/v2/). **`create_dashboard_app` and
`serve_index` are v1-only**; deleting them does not affect v2.

---

## 3. Auth-plane impact

`PortalSessionMiddleware.dispatch` (auth.py 225–287) waterfall:
1. Supabase session-envelope cookie (`sift_portal_session`) — always active.
2. Legacy `sift_session` JWT cookie — only when `_legacy_enabled`.
3. Legacy Bearer-token examiner fallback — only when `_legacy_enabled`.
4. Unauthenticated → 401.

After removal: collapses to step 1 (Supabase) or step 4 (401). Steps 2 & 3 deleted.

Security-relevant changes:
- Stale `sift_session` cookies → 401 (intentional).
- Examiner Bearer-token fallback on `/portal/` stops working. Template default
  (`portal_session_enabled: false`) already disabled it; deployments on the old code
  default (`True`) will notice.
- `revoke_jti` no longer called from logout; Supabase invalidation is the live path.
- `get_auth_me` stops returning the legacy `{examiner, role, expires_at, must_reset}`
  shape; Supabase path already returns `_principal_profile`. Affects only un-migrated
  `sift_session` clients (≈zero in prod).

---

## 4. Test migration plan

All case-dashboard tests below currently pass `legacy_portal_session_enabled=False` —
remove the kwarg (default behavior post-removal); no deletion unless noted.

- **test_session_middleware.py** — KEEP; remove kwarg (line 66).
- **test_pr03_supabase_portal_auth.py** — KEEP; **DELETE** `TestLegacyFlag.test_legacy_cookie_accepted_when_flag_enabled` (478–489, tests deleted behavior); rename `test_legacy_cookie_rejected_when_flag_disabled` (471–476) → `test_unauthenticated_returns_401`; drop `COOKIE_NAME`/`generate_jwt` imports (27–29).
- **test_case_create.py** — KEEP; remove kwarg (68,125,437).
- **test_todo_endpoints.py** — KEEP; remove kwarg (53,158,266,317).
- **test_reports_endpoints.py** — KEEP; remove kwarg (34,52).
- **test_k6_audit_view_db.py** — KEEP; remove kwarg (63).
- **test_get_endpoints_auth.py** — KEEP; remove kwarg (35).
- **test_case_metadata_endpoint.py** — KEEP; remove kwarg (36,54).
- **test_a1_bootstrap.py** — KEEP; remove kwarg (148,166,189); line 256 uses `=True` + `supabase_auth=None` to test the 503 forced-reset path — keep the test, drop only the kwarg.
- **test_session_jwt.py** — KEEP (pure crypto util test); if `COOKIE_NAME` deleted, drop the assert at line 28.
- **test_phase13_rbac.py** — KEEP/refactor; uses `generate_jwt` only to build a role payload. If `generate_jwt` retained → unchanged; if deleted → use `SimpleNamespace(state=SimpleNamespace(role=...))`.

---

## 5. Recommended removal sequence
1. Delete v1 static asset `case_dashboard/static/index.html` (only served by `serve_index`; v2 bundle in `static/v2/` unaffected).
2. Remove `create_dashboard_app`, `serve_index`, `/dashboard` mount + the server.py guard/CSP halves + auth.py public-path/static-bypass halves + test_secure_headers scaffolding.
3. Delete the `legacy_portal_session_enabled` flag end-to-end (supabase_auth field+parse, server.py kwarg, routes.py param/var/passthrough, auth.py param/branch, gateway.yaml.template key) + remove the kwarg from all parametrized tests; delete the one legacy-accept test.
4. Clean `sift_session` cookie refs (routes logout JTI block + `get_auth_me` fallback; session_jwt `COOKIE_*`; auth.py imports) — keeping `generate_jwt`/`verify_jwt` as internal utils unless tests are rewritten.

Proof at each step: targeted `pytest` on the touched test files, then full
`packages/case-dashboard/tests/` + `packages/sift-gateway/tests/`, then
`validate_docs.py` + `validate_migration_docs.py`.

---

## 6. Risks / sharp edges
1. **`_dashboard_api_routes()` is shared — do NOT delete** (used by both factories).
2. `post_auth_logout` clears both cookies; keep the `COOKIE_NAME` response-clear to proactively clean stale browsers (cookie expires ≤8h anyway).
3. `generate_jwt`/`verify_jwt` used by tests beyond legacy path — keep as internal utils.
4. Module-level `_LEGACY_PORTAL_SESSION_ENABLED` is never read — deletion is zero-impact.
5. `test_legacy_cookie_rejected_when_flag_disabled` becomes trivially true → re-express as generic "unauthenticated → 401".
6–7. Comment-only `sift_session` refs in `_supabase_reauth_harness.py:5` and `test_e1_portal_db_authority.py:250` — tidy, no behavior.
8. Remove `/dashboard` from `_PUBLIC_PATHS` in the same commit as the mount.
9. gateway.yaml.template key removal is non-breaking; note in run log that existing installs' `portal_session_enabled: false` is silently ignored post-removal.
