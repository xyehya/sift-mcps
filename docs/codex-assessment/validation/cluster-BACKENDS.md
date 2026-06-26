# Validation — Cluster BACKENDS

> Validator agent: sec-backends (Opus 4.8, xhigh). Read-only. Validates the restored
> Codex assessment against **current HEAD** (`93f8999`), not the stale scan base `b995491`
> (183 commits old). codeguard-security:codeguard secure-coding lens applied to every
> finding + fix. No source code was modified — this file is the only output.
>
> **Drift note (applies to all four):** all four cited files are **byte-identical** to the
> scan base (`git diff b995491..HEAD -- <file>` empty for each). The cited line numbers are
> therefore still accurate. But I re-traced the surrounding controls (auth deps, egress
> validators, env materialization) that live in *other* files, since a fix could have landed
> there. It did not — the gaps are intact.

## Summary table

| Candidate | Codex verdict | **Current status** | Current severity | Confidence | Already-fixed-by | Fix effort |
|---|---|---|---|---|---|---|
| DSS-CAN-003 | valid (high, conf 0.65) | NEEDS-OPERATOR-DECISION (intended authority, doc-confirmed) + PARTIALLY-VALID hardening | Low (DiD) | high | — | S (shares env fix w/020) |
| DSS-CAN-004 | valid (high, conf 0.9) | STILL-VALID | High | high | — | M (shared egress policy) |
| DSS-CAN-019 | partial (med, conf 0.65) | PARTIALLY-VALID (registration-time host check exists; runtime-connect + code-binding gaps remain) | Medium | med | partial: `_validate_remote_fetch_url` at manifest-fetch | M (shares fix w/004) |
| DSS-CAN-020 | valid (high, conf 0.9) | STILL-VALID | High | high | — | S (minimal base env) |

**One-line cross-cluster shape:** 004+019 share **one** runtime-egress policy fix; 003+020 share **one** minimized-env fix. Both pairs are real and independently shippable.

---

## DSS-CAN-003 — Examiner backend management can register & start arbitrary stdio backend commands

**Codex claim (verbatim intent):** A non-readonly examiner can register stdio backend metadata
(command, args, cwd, env refs) and later start/restart it; the gateway then launches that process
under the gateway account. Codex narrowed confidence to 0.65 citing "possible intended examiner authority."

**Current code located at:** `packages/case-dashboard/src/case_dashboard/backends_routes.py:171-203`
(`register_backend_route`) — codex cited `171-203` on `b995491` (unchanged).

**Drift since scan:** `git log --oneline b995491..HEAD -- backends_routes.py` → **no commits**; file unchanged.

**CURRENT STATUS:** NEEDS-OPERATOR-DECISION (the authority is intended-by-design) with a PARTIALLY-VALID
defense-in-depth hardening that is real and shippable.

**Evidence (current source):**
```python
# backends_routes.py:171-203 — portal register route, controls ALREADY present:
async def register_backend_route(request: Request) -> JSONResponse:
    examiner = getattr(request.state, "examiner", None)
    if not examiner: return 401
    role_err = _require_examiner_role(request)          # role must == "examiner"  (line 175)
    if role_err: return role_err
    origin_err = _verify_origin(request)                # same-origin CSRF guard   (line 178)
    if origin_err: return origin_err
    ...
    from case_dashboard.routes import _supabase_reverify
    challenge_err = await _supabase_reverify(request, body)   # fail-closed re-auth (line 196)
    if challenge_err: return challenge_err
    response, status_code = await register_backend_logic(gateway, body, actor=actor)
```
The portal path is **already gated** by examiner-role + same-origin + Supabase re-auth. The genuine
residuals are two design choices, not missing controls:

1. **Role-tier collapse.** `_require_examiner_role` checks the *binary* portal role (`role == "examiner"`),
   and `case_dashboard/auth.py:52` maps **every** non-readonly `system_role` (`operator`/`lead`/`owner`/`admin`)
   to `"examiner"`. So any non-readonly user can register, where the more privileged token-lifecycle routes
   reserve themselves for `system_role in ("owner","admin")` (`routes.py:4423`). Backend registration is the
   only control-plane mutation that does *not* use that higher tier.
2. **No command allowlist.** `create_backend` (`backends/__init__.py:391-403`) accepts any `command` string
   (only `shutil.which` *warns*, never rejects). Combined with **DSS-CAN-020** (full-env inheritance), a
   registered stdio backend = arbitrary code execution as the gateway account *with the gateway's DB DSNs in env*.

**Intended-authority check (the question the orchestrator asked):** `docs/new-docs/ADDON_ECOSYSTEM_AND_VERIFICATION.md`
is explicit that backend registration is an **operator capability** and the threat model is *not* malicious code:
- "the gateway **trusts the manifest's self-description**" (§intro)
- "backends are **rare, operator-installed**, and mostly reference/query plane (live: 3)"
- "The actual likely failure is **drift / stale-registration** and declared-but-not-installed capability, **not malicious code**."

So examiner/operator-level backend registration **is intended product authority**, behind re-auth + origin.
This downgrades DSS-003 from "privilege gap" to "defense-in-depth hardening." Codex's own 0.65 confidence
anticipated exactly this.

**Reachability trace:** Portal `POST /api/backends` → `register_backend_route` (examiner+origin+reauth, above) →
`register_backend_logic` → `registry.register(...)` (DB row in `app.mcp_backends`). The DB manifest snapshot is
runtime authority; the stdio backend launches on the next gateway start via `StdioMCPBackend.start()`.
**Stronger reachability lives in the AUTH cluster:** the *raw* gateway route `POST /api/v1/backends`
(`rest.py:1241` → `register_backend` at `1108`) has **no** route-local examiner/origin/re-auth in the handler —
that is DSS-CAN-002's concern. DSS-003 as cited (the portal route) is the *gated* path.

**Exploit preconditions:** Authenticated non-readonly portal principal + valid Supabase re-auth + same-origin
request. i.e. a trusted operator. Not reachable by agent/service tokens or readonly users on the portal route.

**Blast radius if treated as a gap:** Arbitrary process launch as the gateway account; with DSS-020, that
process reads `SIFT_CONTROL_PLANE_DSN` / `SIFT_AUDIT_WRITER_DSN` and any backend tokens in env.

**Project-invariant check:** Touches **gateway-as-policy-boundary** (the gateway launches the process) and
**DB-authority** (registration writes `app.mcp_backends`; runtime authority is that snapshot, per the
gateway-manifest-registration-drift invariant). The minimized-env hardening directly serves the
**"add-on subprocess has no DB creds by design"** invariant (see DSS-020).

**FIX APPROACH (secure-by-design, preserves invariants):**
- **Root cause (the part worth fixing now):** the blast radius of a registered backend, not the registration
  right itself. Fix the blast radius via the shared minimized-env change in **DSS-CAN-020** — that is the
  high-value, low-controversy change and needs no policy decision.
- **Optional authority hardening (operator decision):** gate `register/unregister/enable/start/stop` on
  `system_role in ("owner","admin")` instead of the collapsed binary `examiner`, to match the token-lifecycle
  tier (`routes.py:4423`). Land it in `_require_examiner_role`'s callers (or a new `_require_backend_admin`
  helper in `backends_routes.py`) — NOT by monkey-patching the gateway.
- **Optional allowlist:** restrict stdio `command` to an installed-add-on catalog (the doc's "Path A" already
  has `MVP_FORENSIC_ALLOWLIST`; an analogous backend catalog would extend that model). This is a larger design
  item — defer to the Axis-H register-time verifier (XYE-25) already referenced in `backends/__init__.py:206`.
- **Why it preserves identity:** keeps the gateway the policy boundary; keeps the DB manifest as runtime
  authority; does not weaken the operator workflow the product intends.
- **Test strategy:** unit test on `_require_backend_admin` (owner/admin pass, plain examiner 403) if the
  authority gate is adopted; the env hardening's fail-on-revert test is specified under DSS-020. No MCP-surface
  test applies (this is control-plane, not tool output). Live deploy-and-prove only if the env change is taken
  (covered by DSS-020's live step).
- **Alternatives rejected:** removing examiner registration entirely — rejected, it is the intended operator
  workflow per the contract doc; signature verification of add-on code — out of scope, tracked as XYE-25.

**Cross-cluster dependency:** Shares the minimized-env fix with **DSS-CAN-020** (same file, `stdio_backend.py`).
Authority-tier question ties to **AUTH cluster** (DSS-CAN-002 raw-route gating; DSS-CAN-014 owner/admin token tier).

**Open question for operator:** Should backend register/start be reserved for `system_role in ("owner","admin")`,
or is the current "any non-readonly operator + re-auth" the intended bar? (The contract doc implies the latter
is acceptable; this is your call.)

---

## DSS-CAN-004 — HTTP MCP backend runtime egress validation reaches private / rebound destinations

**Codex claim (verbatim intent):** Remote *manifest* fetches have a private-address validator, but
DB-registered `HttpMCPBackend` **runtime URLs** are materialized + connected with only syntax checks →
persistent gateway-originated SSRF / DNS-rebinding, possibly attaching bearer creds.

**Current code located at:** `packages/sift-gateway/src/sift_gateway/backends/__init__.py:279-318`
(manifest-fetch validator) + the unguarded runtime path in `create_backend` (`__init__.py:405-421`),
`mcp_backends_registry.resolve_runtime_config` (`mcp_backends_registry.py:328-348`), and
`HttpMCPBackend.start` (`http_backend.py:79-152`). Codex cited `279-318` on `b995491` (unchanged).

**Drift since scan:** `git log --oneline b995491..HEAD -- backends/__init__.py` → **no commits**; unchanged.

**CURRENT STATUS:** STILL-VALID (High).

**Evidence (current source):**
```python
# __init__.py:25-47 — the egress validator EXISTS but is called ONLY on manifest fetches:
def _validate_remote_fetch_url(url, *, label):   # resolves host, rejects private/loopback/link-local/...
    ...
# ...applied at __init__.py:285 (explicit manifest_path URL) and :310 (default <url>/manifest fetch) ONLY.

# __init__.py:405-421 — runtime URL gets ONLY syntax checks at materialization:
elif backend_type == "http":
    url = config.get("url")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"): raise ...
    if not parsed.hostname: raise ...
    return HttpMCPBackend(name, config, manifest=manifest)   # no _validate_remote_fetch_url(url)

# http_backend.py:79-123 — connect attaches bearer BEFORE any destination check, no egress validation:
url = self.config.get("url")
bearer_token = self.config.get("bearer_token")
if bearer_token:
    headers["Authorization"] = f"Bearer {bearer_token}"        # creds attached pre-connect
transport = await ...streamablehttp_client(url, headers=headers, ...)   # connects to runtime url, no IP check
```
`normalize_connection_config` (`mcp_backends_registry.py:271-325`) and `resolve_runtime_config` (`:328-348`)
also perform **no** egress validation — only whitespace-trim + env-ref name validation. So no layer between
"persist" and "connect" classifies the destination IP.

**Two concrete reachable variants (both bypass the manifest-fetch check):**
1. **Separate-manifest bypass (no DNS rebinding needed).** Register an http backend with
   `manifest_path = https://attacker-public.example/m.json` (a valid public manifest) **and**
   `url = http://169.254.169.254/...` (or any internal address). `_load_manifest_for_rest` (`rest.py:144-166`)
   validates/fetches the *manifest_path*, never the runtime `url`; `create_backend` only syntax-checks `url`.
   At runtime the gateway connects to the internal `url` and **sends the bearer token** there.
2. **DNS rebinding (TOCTOU).** Even when the default `<url>/manifest` fetch validates the host at registration
   (`__init__.py:310`), the resolution is one-time. `HttpMCPBackend.start` re-resolves at connect, and
   `call_tool` reconnects via `start()` again (`http_backend.py:216,240,264`) — each re-resolve is unchecked.
   An attacker controlling DNS for the registered hostname rebinds it to an internal IP after registration.

**Exploit preconditions:** backend-registration influence (operator per DSS-003 / raw route per DSS-002 /
join flow per DSS-019) + an attacker-controlled hostname or DNS. A gateway restart applies the registered
backend (D34 / D22A restart-to-apply).

**Blast radius if valid:** Persistent gateway-originated SSRF to internal services (cloud metadata
`169.254.169.254`, internal admin planes, OpenSearch, the control-plane DB host) and **credential exfiltration**
— the configured bearer token is transmitted to whatever address `url` currently resolves to.

**Project-invariant check:** Touches **gateway-as-policy-boundary** (the gateway is the egress origin) and
**DB-authority** (the runtime `url` comes from the `app.mcp_backends` snapshot). Fix must run on the
DB-authority materialization path + the connect path, not a one-off at the REST handler.

**FIX APPROACH (secure-by-design — ONE shared egress policy, see cross-cluster):**
- **Root cause:** `_validate_remote_fetch_url` is scoped to manifest fetches; the runtime connect has no
  equivalent and re-resolution defeats any one-time check.
- **Proposed change (exact layers):** promote `_validate_remote_fetch_url` to a shared
  `validate_egress_destination(host, port)` helper and call it (a) at materialization in
  `create_backend`/`resolve_runtime_config` for `type=="http"`, and (b) **immediately before every connect** in
  `HttpMCPBackend.start` — resolve the host, classify each returned IP, **pin the validated IP for the actual
  socket** (resolve-then-connect-to-pinned-IP with SNI/Host preserved) to close the rebinding window, and
  **attach the bearer/Authorization header only after** the destination is validated. Apply the same on the
  `call_tool` reconnect path (it routes through `start()`, so one fix covers it).
- **Why it preserves identity:** keeps the gateway the single policy boundary for outbound add-on traffic;
  reuses the existing validator semantics (consistent allow/deny); does not change the DB-authority model.
- **Test strategy:** unit tests — (i) http backend whose `url` resolves to a private/loopback/link-local/
  metadata IP is refused at `start()` *before* any header is sent; (ii) `manifest_path` public + `url` private
  is refused; (iii) a rebinding stub (host resolves public at register, private at connect) is refused at
  connect. These are **fail-on-revert** (deleting the connect-time check re-opens them). Not an MCP-surface
  test. **Live deploy-and-prove (behavioral):** on the VM, register an http backend pointing `url` at
  `http://169.254.169.254/` and at an internal IP, restart the gateway, confirm the connect is refused and no
  Authorization header leaves the host (journal/tcpdump).
- **Alternatives rejected:** validate only at registration — rejected, defeated by rebinding + restart gap;
  block all non-loopback http — rejected, wintools/remote add-ons are a legitimate deployment (the validator's
  allow-public/deny-private classification is the right granularity).

**Cross-cluster dependency:** **Shares ONE fix with DSS-CAN-019** — the join flow persists an http backend and
relies on the same runtime-connect validation. Design the shared egress policy once; both consume it.
Ties to **AUTH cluster** DSS-CAN-002 (the raw register route is the unauthenticated-control-plane reach).

**Open question for operator:** Confirm the allow-public / deny-private classification is correct for your
deployment (any legitimate backend on an RFC-1918 address would need an explicit allowlist entry).

---

## DSS-CAN-019 — Public Wintools join persists attacker-selected HTTP backend URL after join-code exchange

**Codex claim (verbatim intent):** The public setup join route treats a one-time join code as the credential;
for `machine_type=wintools` it accepts a caller-supplied HTTP URL + token, stores the token in process env,
builds an HTTP backend config, and calls `register_backend_logic`. Join-code + manifest validation narrow the
direct SSRF claim.

**Current code located at:** `packages/sift-gateway/src/sift_gateway/rest.py:651-793` (`join_gateway`);
codex cited `651-680` on `b995491` (unchanged).

**Drift since scan:** `git log --oneline b995491..HEAD -- rest.py` → **no commits**; file unchanged.

**CURRENT STATUS:** PARTIALLY-VALID (Medium). Registration-time host validation is present; the runtime-connect
gap (= DSS-004) and the join-code-not-host-bound gap remain.

**Evidence (current source):**
```python
# rest.py:651-655 — join is UNAUTHENTICATED; the join code is the only credential:
async def join_gateway(request: Request) -> JSONResponse:
    """... Unauthenticated — the join code is the auth mechanism."""
# rest.py:668-681 — caller supplies code + machine_type + wintools_url/token/cert; code consumed (no host binding):
matched_hash = await validate_and_consume_join_code(code)   # binds to nothing about the caller/host
# rest.py:699-750 — wintools branch: syntax-check url, store token in process env, build http config, register:
parsed = urlparse(wintools_url)            # scheme + hostname syntax only (lines 700-710)
os.environ[token_env] = str(wintools_token)            # token written into gateway process env (line 735)
backend_config = {"type": "http", "url": wintools_url, "bearer_token_env": token_env, "enabled": True}
register_response, register_status = await register_backend_logic(
    gateway, {"name": "wintools-mcp", "config": backend_config}, actor=None)   # line 746-750
```
**Mitigation that narrows it:** the built `backend_config` has **no** `manifest_path`, so
`register_backend_logic` → `_load_manifest_for_rest` → `load_and_validate_manifest` takes the default
`<wintools_url>/manifest` path, which **does** call `_validate_remote_fetch_url` (`__init__.py:310`). Therefore
at *registration* the `wintools_url` host must resolve to a **public** address **and** serve a schema-valid
`sift-backend.json` (a missing/invalid manifest is a hard reject, `__init__.py:320-326`). Pure
register-time SSRF to an arbitrary internal IP is blocked. This is why I rate it PARTIALLY-VALID, not STILL-VALID.

**Residual gaps (real):**
1. **No host-identity binding on the join code** (`validate_and_consume_join_code(code)` matches a hash only) —
   anyone with the one-time code, from any source IP (subject to `check_join_rate_limit`), can drive the join.
2. **Runtime-connect SSRF/rebinding (= DSS-004):** the validated registration host is re-resolved at the
   post-restart runtime connect with no check → rebinding window; the bearer token (now in `os.environ`) is sent
   to the rebound destination.
3. **Token in process env (= DSS-020 amplifier):** `SIFT_BACKEND_WINTOOLS_MCP_TOKEN` is written to
   `os.environ` (line 735), so every **stdio** backend subprocess inherits it (full-env inheritance, DSS-020).

**Reachability trace:** `POST /api/v1/setup/join` (unauthenticated, rate-limited) → valid one-time code →
wintools branch → `register_backend_logic(actor=None)` → DB row → backend connects on next restart.

**Exploit preconditions:** Possession of a valid, unexpired one-time join code (operator-generated via
`create_join_code`, 2h default TTL) + an attacker-controlled public hostname serving a valid manifest +
(for the SSRF payoff) DNS control over that hostname + a gateway restart.

**Blast radius if valid:** Same as DSS-004 (internal SSRF + bearer exfil) but reachable via the *unauthenticated*
join surface once a code leaks; plus the wintools token landing in the shared process env.

**Project-invariant check:** Touches **portal-managed lifecycle** (join is the wintools onboarding flow),
**gateway-as-policy-boundary**, and **DB-authority** (registers into `app.mcp_backends`). Fix must not break the
legitimate wintools onboarding (a real remote Windows host registering its MCP).

**FIX APPROACH (secure-by-design):**
- **Root cause (shared):** runtime egress is unvalidated on connect — identical to DSS-004. **Adopt the same
  shared egress policy**; that closes the SSRF/rebinding half of DSS-019 for free.
- **Join-specific hardening:** bind the join code to an expected host identity — e.g. record the intended
  wintools host/cert fingerprint at `create_join_code` time and verify the presented `wintools_url`/cert against
  it in `join_gateway`; reject mismatches fail-closed. Keep the rate-limit + one-time consumption.
- **Token handling:** prefer writing the wintools token to the password store referenced by `*_env` indirection
  consistently rather than leaving it broadly in `os.environ` — naturally resolved once DSS-020's minimal-env
  fix stops stdio subprocesses from inheriting it.
- **Why it preserves identity:** keeps join unauthenticated-by-code (the intended onboarding UX) while removing
  the SSRF payoff and binding the code to its intended target.
- **Test strategy:** unit — join with `wintools_url` whose host resolves private is refused at runtime connect
  (shares DSS-004's test harness); join with a `wintools_url` not matching the code's bound host is rejected.
  **Live deploy-and-prove:** mint a join code, attempt a join pointing at an internal IP, confirm refusal.
- **Alternatives rejected:** authenticating the join route — rejected, it is intentionally code-authenticated
  for headless wintools onboarding; blocking wintools http entirely — rejected, it is a supported topology.

**Cross-cluster dependency:** **Shares the runtime-egress fix with DSS-CAN-004** (design once). Token-in-env
amplification resolved by **DSS-CAN-020**. Join-route auth posture ties to **AUTH cluster** (control-plane near
`rest.py`, DSS-CAN-002).

**Open question for operator:** Should join codes be bound to a specific expected wintools host/cert at creation
time, or is the one-time-code-from-any-host model acceptable given the rate limiter + manifest requirement?

---

## DSS-CAN-020 — Registered stdio MCP backends inherit the full Gateway environment incl. service secrets

**Codex claim (verbatim intent):** DB-registered stdio backends start with `env = dict(os.environ)` then overlay
configured env refs — so any registered/compromised stdio backend can read unrelated gateway secrets (DSNs,
Supabase keys, tokens).

**Current code located at:** `packages/sift-gateway/src/sift_gateway/backends/stdio_backend.py:85-114`
(`StdioMCPBackend.start`). Codex cited `85-114` on `b995491` (unchanged).

**Drift since scan:** `git log --oneline b995491..HEAD -- stdio_backend.py` → **no commits**; file unchanged.

**CURRENT STATUS:** STILL-VALID (High).

**Evidence (current source):**
```python
# stdio_backend.py:85-114
command = self.config.get("command", "python")
args = self.config.get("args", [])
configured_env = self.config.get("env") or {}
env = dict(os.environ)              # <-- FULL gateway environment inherited  (line 88)
env.update(configured_env)          # configured refs only OVERLAY, never restrict (line 89)
env = {k: v for k, v in env.items() if v}
...
server_params = StdioServerParameters(command=command, args=args, env=env)   # child gets it all
```
The gateway process env demonstrably holds secrets the child must not see — confirmed by grep over the gateway
source:
- `SIFT_CONTROL_PLANE_DSN` and `SIFT_AUDIT_WRITER_DSN` (control-plane + audit DB DSNs) are read from
  `os.environ` by the gateway.
- `SIFT_BACKEND_WINTOOLS_MCP_TOKEN` is *written into* `os.environ` by the join flow (`rest.py:735`), so a stdio
  add-on inherits another backend's bearer token.
- `resolve_runtime_config` (`mcp_backends_registry.py:342-347`) builds `config["env"]` from the *explicitly
  approved* `env_refs` — but that approved subset is still merely overlaid on top of the full `dict(os.environ)`,
  so the approval list provides **no** isolation.

**Reachability trace:** Any registered stdio backend (DB `app.mcp_backends` row → `StdioMCPBackend` →
`start()`) — i.e. every add-on subprocess — receives the DSNs. Reachable by the registration paths in DSS-003
(operator), DSS-002 (raw route), and by a supply-chain-compromised but legitimately-installed add-on.

**Exploit preconditions:** A stdio backend exists/registered (the normal case — live deployment runs
`forensic-rag-mcp`, `windows-triage`, etc.) **and** that subprocess executes attacker-influenced or buggy code.
No additional privilege needed; the leak is unconditional at start.

**Blast radius if valid:** A stdio add-on can read `SIFT_CONTROL_PLANE_DSN`/`SIFT_AUDIT_WRITER_DSN` and connect
**directly to the control-plane DB**, bypassing the gateway entirely — plus harvest any backend tokens in env.

**Project-invariant check — DIRECT VIOLATION:** This breaks the recalled invariant **"the agent backend has NO
DB creds by design (DB-reading logic belongs in the gateway, not the add-on subprocess)."** Full-env inheritance
hands the add-on subprocess the gateway's DB DSNs, so the "no DB creds" boundary is only true by accident of
which vars happen to be set — not enforced. Also undermines **least-priv** and the **gateway-as-policy-boundary**
(an add-on can reach the DB without going through the gateway).

**FIX APPROACH (secure-by-design — shared minimized-env with DSS-003):**
- **Root cause:** `env = dict(os.environ)` is an allow-all default; it should be a deny-all base with an explicit
  allowlist.
- **Proposed change (exact layer):** in `StdioMCPBackend.start`, build `env` from a **minimal base allowlist**
  (`PATH`, `HOME`, `LANG`/`LC_*`, `TMPDIR`, plus the gateway-supplied case context the backend contract requires:
  `SIFT_CASE_DIR`, `SIFT_CASES_ROOT`, and any documented `SIFT_*` runtime vars the add-on contract declares),
  then overlay **only** `configured_env`/resolved `env_refs`. Never copy the whole process environment.
  Define the base allowlist as a module constant so it is auditable.
- **Why it preserves identity:** restores the "add-on has no DB creds" invariant by construction; the gateway
  remains the only DB-credentialed process; add-ons still receive exactly the case context the Backend Contract
  promises (so no functional regression for compliant add-ons).
- **Test strategy:** **fail-on-revert unit test** — set `os.environ["SIFT_CONTROL_PLANE_DSN"]="sentinel"` (and a
  fake token), construct a `StdioMCPBackend` with a known `command`/`env_refs`, capture the `StdioServerParameters`
  env (monkeypatch `stdio_client` or assert on the constructed `server_params.env`), and assert the sentinel DSN
  is **absent** while the approved refs + case context are present. Reverting to `dict(os.environ)` fails this
  test. This is a unit/process test (not MCP-surface). **Live deploy-and-prove (behavioral):** register a stdio
  backend whose command dumps its environment to the case `agent/` dir, restart the gateway, confirm the DSNs and
  other-backend tokens are absent from the child env.
- **Alternatives rejected:** scrubbing a denylist of known-secret vars — rejected, fails open for any new secret
  var (exactly the bug class); relying on `env_refs` approval alone — rejected, it overlays, it does not isolate.

**Cross-cluster dependency:** **Shares this fix with DSS-CAN-003** (the minimized-env half of 003's hardening is
*this* change). Resolves the token-in-env amplifier noted in **DSS-CAN-019**.

**Open question for operator:** Confirm the minimal base-env allowlist set — specifically which `SIFT_*` runtime
vars (beyond `SIFT_CASE_DIR`/`SIFT_CASES_ROOT`) the installed stdio add-ons legitimately require, so the
allowlist does not break a compliant backend.

---

## Cross-cluster summary (for the orchestrator)

- **004 + 019 = ONE shared fix:** a single `validate_egress_destination` policy applied at materialization
  (`create_backend`/`resolve_runtime_config`) **and** immediately before every connect/reconnect
  (`HttpMCPBackend.start`), with resolve-then-pin to kill rebinding and creds attached only post-validation.
  019 adds a join-code→host-identity binding on top.
- **003 + 020 = ONE shared fix:** minimal base env in `StdioMCPBackend.start` (the high-value change). 003's
  remaining authority-tier question (owner/admin gate + command catalog) is an **operator decision**, not a code
  defect — the contract doc establishes examiner/operator backend registration as intended.
- **Ties to AUTH cluster:** DSS-CAN-002 (raw `/api/v1/backends` + `/api/v1/setup/join` control-plane routes lack
  route-local operator/origin/re-auth — the stronger reachability behind 003/004/019); DSS-CAN-014 (owner/admin
  token tier — precedent for 003's authority question).
- **Surfacing-layer note:** none of these four are MCP *tool-output* findings, so the registry `*Out` /
  `result_public` surfacing layers do not apply; fail-on-revert coverage here is unit/process tests + live
  deploy-and-prove, as specified per candidate.
