# Supabase Default Key Remediation (Self-Hosted / CLI Stack)

**Status:** Research — decision-grade. Operator-actionable.
**Date:** 2026-06-15
**Sourcing rule:** Official Supabase sources only (`supabase.com/docs`, `supabase.com/blog`,
`github.com/supabase`). Any non-official claim is marked **UNVERIFIED** and is not relied on.

**Headline recommendation:** **Rotate-in-place using the official self-hosted scripts** —
specifically `utils/generate-keys.sh` + `utils/add-new-auth-keys.sh`, then `docker compose down && up -d`.
A full hand-rolled self-managed compose is **not** required and is only the fallback if our pinned
stack predates 2026-03-16 (the release that shipped these scripts) and cannot be bumped.

---

## 1. The Problem (precise)

The Supabase self-hosted / CLI demo stack ships a complete set of **publicly known default
credentials** in `.env.example`. The docs are explicit that these are placeholders and must never
be used in a running install:

> "While we provided example placeholder passwords and keys in the `.env.example` file, you should
> **never** start your self-hosted Supabase using these defaults."
> — [Self-Hosting with Docker | Supabase Docs](https://supabase.com/docs/guides/self-hosting/docker)

The auth-relevant defaults are:

- **Default JWT secret:** `super-secret-jwt-token-with-at-least-32-characters-long`
  ([Discussion #19560](https://github.com/orgs/supabase/discussions/19560);
  value also referenced across the self-hosting docs).
- **Default `anon` key** and **default `service_role` key** — both are **HS256 JWTs signed by that
  shared JWT secret**, carrying `"iss":"supabase-demo"` and the role claim (`anon` /
  `service_role`) in the payload. The docs describe them as: ANON_KEY = "Legacy version of
  publishable keys" (low privilege), SERVICE_ROLE_KEY = "Legacy version of secret keys" (elevated
  privilege), both "JWT (long lived)".
  ([Understanding API keys | Supabase Docs](https://supabase.com/docs/guides/api/api-keys);
  [self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx))

**Why this is a critical auth hole:** because the `anon` and `service_role` keys are deterministic
JWTs signed with the *published* default secret, anyone who knows the default secret (it is in the
public repo) can locally **mint a valid `service_role` JWT** — full-database, RLS-bypassing
privilege — and present it to any reachable Supabase API endpoint. The keys themselves are also
published, so no minting is even needed. Shipping a real install on these values is equivalent to
shipping with a published root credential.

**How the keys are derived (verification chain):** `generate-keys.sh` "reads `JWT_SECRET` from
`.env` and includes it as a symmetric key inside both `JWT_KEYS` and `JWT_JWKS`." GoTrue and
PostgREST then sign/verify with that secret. So the secret is the single root: change it and the
old `anon`/`service_role` JWTs no longer verify; keep it and they remain valid forever (long-lived,
effectively non-expiring in the demo payload).
([docker.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/docker.mdx);
[self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx))

---

## 2. Official In-Place Rotation Mechanism(s)

There are **two** official self-hosted paths. The stack we run determines which applies.

### 2.A — Modern path (RECOMMENDED): official key-generation scripts

As of the **2026-03-16** docker release, the self-hosted stack ships first-class scripts. The
docs prescribe this exact sequence for a secure install / re-key:

```sh
sh utils/generate-keys.sh        # generates secure POSTGRES_PASSWORD, JWT_SECRET, dashboard creds, etc.
sh utils/add-new-auth-keys.sh    # adds new sb_ API keys + asymmetric (EC P-256) key pair; folds JWT_SECRET into JWT_KEYS/JWT_JWKS
# review .env, then:
docker compose down && docker compose up -d
```

Sources:
[docker.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/docker.mdx),
[self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx),
[CHANGELOG](https://github.com/supabase/supabase/blob/master/docker/CHANGELOG.md).

`generate-keys.sh` writes the generated secrets/passwords to `.env`. `add-new-auth-keys.sh
--update-env` "generates new configuration environment variables and writes them to `.env`," and
re-running it "generates a new EC P-256 key pair, new JWKS, new asymmetric JWTs, and new `sb_` API
keys." It reads the (now non-default) `JWT_SECRET` and includes it as a symmetric key in `JWT_KEYS`
/ `JWT_JWKS`, so legacy `anon`/`service_role` HS256 verification is rebound to the **new** secret in
the same step. (Note: a later release, PR #45941, removed the OpenSSL/Node.js dependency from these
scripts — [CHANGELOG](https://github.com/supabase/supabase/blob/master/docker/CHANGELOG.md).)

**Env vars / config that must change together (docs-confirmed wiring):**

| Variable | Service | Source |
|---|---|---|
| `JWT_SECRET` | root symmetric secret (GoTrue + PostgREST) | docker.mdx |
| `ANON_KEY`, `SERVICE_ROLE_KEY` | legacy HS256 JWTs, must be re-minted when `JWT_SECRET` changes | api-keys, #19560 |
| `JWT_KEYS` → `GOTRUE_JWT_KEYS: ${JWT_KEYS:-[]}` | Auth/GoTrue | self-hosted-auth-keys.mdx |
| `JWT_JWKS` → `PGRST_JWT_SECRET: ${JWT_JWKS:-${JWT_SECRET}}` | PostgREST (`rest`) | self-hosted-auth-keys.mdx |
| `JWT_JWKS` → `API_JWT_JWKS: ${JWT_JWKS:-{"keys":[]}}` | Realtime | self-hosted-auth-keys.mdx |
| `JWT_JWKS` → `JWT_JWKS: ${JWT_JWKS:-{"keys":[]}}` | Storage | self-hosted-auth-keys.mdx |
| `SUPABASE_PUBLISHABLE_KEY` / `SUPABASE_SECRET_KEY` (`sb_...`) | new API keys (Kong + clients) | self-hosted-auth-keys.mdx |

The docs note the new asymmetric configuration "operates entirely at the API gateway and service
configuration layer" and "requires no database changes," and that it is "fully backward
compatible" (both legacy and new key systems work simultaneously).
([self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx))

**Files the changelog says the auth-keys feature touches** (relevant if our stack is partly
customized): `.env`, `.env.example`, `docker-compose.yml`, `utils/add-new-auth-keys.sh`,
`utils/rotate-new-api-keys.sh`, `volumes/api/kong-entrypoint.sh`, `volumes/api/kong.yml`.
**Podman caveat:** Podman does not support nested interpolation (`${A:-${B}}`); those defaults
must be substituted manually.
([self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx))

**Services that must restart:** all auth-path services together — Auth (GoTrue), PostgREST (`rest`),
Realtime, Storage, Kong (API gateway). The docs give a single command: `docker compose down &&
docker compose up -d`.
([self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx))

### 2.B — Legacy manual path (only if no scripts in our stack)

Older self-hosted stacks (pre-2026-03-16) had no `add-new-auth-keys.sh`. The historically
documented flow, echoed in [Discussion #19560](https://github.com/orgs/supabase/discussions/19560),
is:

1. Generate a new `JWT_SECRET`, then mint matching `ANON_KEY` and `SERVICE_ROLE_KEY` from it (the
   docs' "Generate API keys" flow / JWT generator).
2. Bind the new secret in Postgres:
   `ALTER DATABASE postgres SET "app.settings.jwt_secret" TO "<new_secret>";`
3. `docker compose down`
4. Update `.env` with the new `JWT_SECRET` / `ANON_KEY` / `SERVICE_ROLE_KEY`
5. `docker compose up -d`

> **Sourcing caveat (important):** In Discussion #19560, **no Supabase staff member responded** — the
> working `ALTER DATABASE ...` step and the "just editing `.env` is not enough" finding come from a
> **community** contributor (`icarus-sullivan`). The *referenced* doc text ("Use the JWT secret to
> generate new anon and service API keys… restart all services") is official, but the SQL step
> itself is **UNVERIFIED against official docs**. Treat path 2.B as the fallback-of-last-resort and
> validate the `ALTER DATABASE` step empirically before trusting it.

---

## 3. Newer API-Key Model (publishable / secret + asymmetric signing)

**What it is:**
- **Publishable keys** `sb_publishable_<random>_<checksum>` — "Safe to expose online: web page,
  mobile or desktop app, GitHub actions, CLIs, source code." Low privilege.
- **Secret keys** `sb_secret_<random>_<checksum>` — "Only use in backend components… servers,
  already secured APIs (admin panels), Edge Functions, microservices." Elevated privilege.
- **Asymmetric JWT signing keys** — EC **P-256 / ES256** key pair; tokens verified via a JWKS
  (public key) rather than a shared symmetric secret.
  ([api-keys](https://supabase.com/docs/guides/api/api-keys),
  [self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx),
  [Introducing JWT Signing Keys](https://supabase.com/blog/jwt-signing-keys))

**Available for self-hosted? YES** — shipped to the docker stack on **2026-03-16**:

> "Added scripts and templates to support the new API key format (`sb_` API keys) and the new
> asymmetric authentication. Check the how-to guide for detailed instructions — PR #43554"
> — [docker/CHANGELOG.md](https://github.com/supabase/supabase/blob/master/docker/CHANGELOG.md)

**Does it offer a cleaner rotation story? YES — materially.** Two distinct rotation surfaces:

- **Rotate just the API keys** (compromised `sb_` keys): `sh utils/rotate-new-api-keys.sh
  --update-env` → restart. The docs state this "does not invalidate existing user sessions," because
  "user session JWTs are verified using the asymmetric key pair" (you can regenerate `sb_publishable`
  / `sb_secret` "without touching the asymmetric key pair").
- **Rotate the signing key pair** (re-run `add-new-auth-keys.sh`): generates a fresh EC P-256 pair +
  JWKS; this *does* invalidate ES256 sessions (users re-authenticate), but is decoupled from the
  client-facing API keys.

This separation — client key vs signing key, public-key verification — is the cleaner story versus
the legacy single-shared-secret model where the secret signs *and* authorizes everything and any
change blast-radiuses every consumer at once.
([self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx),
[api-keys](https://supabase.com/docs/guides/api/api-keys))

**Legacy deprecation timeline (official):** legacy `anon`/`service_role` keys "will be deprecated by
the end of 2026, and you should now use the publishable (`sb_publishable_xxx`) and secret
(`sb_secret_xxx`) keys instead." ([api-keys](https://supabase.com/docs/guides/api/api-keys))

> **Caveat on one search-surfaced sentence:** a WebSearch snippet asserted "For self-hosted
> instances, it is no longer possible to rotate the legacy anon, service and JWT secrets." That exact
> claim was **not** confirmed when fetching the underlying official pages, which instead show
> `JWT_SECRET` is still honored and still folded into `JWT_KEYS`/`JWT_JWKS`. Treat "legacy rotation
> impossible self-hosted" as **UNVERIFIED**; the verified position is that legacy rotation still
> works but is **superseded** by the new model and slated for end-2026 deprecation. Plan to land on
> the new model, not the legacy secret.

---

## 4. RLS / Blast-Radius Implications of Rotation

- **RLS is unaffected by key identity.** Row-Level Security policies key off the JWT **role/claims**
  (`anon`, `authenticated`, `service_role`), not off the specific key string. Re-minting `anon` /
  `service_role` with a new secret preserves role semantics; policies do not need editing. (Derived
  from the role-claim model in [api-keys](https://supabase.com/docs/guides/api/api-keys) and
  [JWTs](https://supabase.com/docs/guides/auth/jwts) — no policy-rewrite step appears in any
  official rotation doc.)
- **Changing `JWT_SECRET` invalidates every token signed by the old secret.** All previously issued
  legacy JWTs (including any `service_role` tokens we or agents minted, and existing **user
  sessions** signed symmetrically) stop verifying. Every consumer holding a legacy key must be handed
  the new value.
- **Asymmetric model narrows the blast radius:** rotating `sb_` API keys leaves sessions intact;
  only regenerating the EC key pair forces re-auth ("Existing user session tokens signed with the old
  EC key will fail verification. Users will need to sign in again").
  ([self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx))
- **Backward-compat window:** during migration both legacy and new systems verify simultaneously, so
  consumers can be cut over incrementally rather than in a single flag-day.
  ([self-hosted-auth-keys.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx))

**Operator note for SIFT:** every place that currently embeds a Supabase key — the Gateway, portal,
sift-core, MCP backends, any installer-staged `.env`/token file — must be re-pointed in the same
change, or those services will 401 after restart. Inventory consumers before the `down`.

---

## 5. Recommendation

### Rotate-in-place — do NOT stand up a hand-rolled compose.

The install already uses the official docker stack; that stack ships the official, supported,
no-extra-infra remediation. A self-managed compose adds maintenance surface and abandons upstream
security updates for zero benefit here.

**Concrete recommended steps (modern path, 2.A):**

1. **Confirm the stack is current** (post-2026-03-16): check that `utils/add-new-auth-keys.sh`,
   `utils/rotate-new-api-keys.sh`, and `JWT_KEYS`/`JWT_JWKS` wiring exist in our docker tree and
   `docker/CHANGELOG.md`. (Bump the pinned stack if missing — see trigger below.)
2. **Inventory consumers** of the current `anon`/`service_role`/`JWT_SECRET` across Gateway, portal,
   sift-core, MCP backends, installer-staged token files. (SIFT-specific; not in Supabase docs.)
3. **Generate fresh roots:** `sh utils/generate-keys.sh` (new `JWT_SECRET`, `POSTGRES_PASSWORD`,
   dashboard creds, `SECRET_KEY_BASE`, `VAULT_ENC_KEY`, etc.).
4. **Mint new auth keys:** `sh utils/add-new-auth-keys.sh --update-env` (new `sb_` keys + EC P-256
   pair; rebinds legacy `anon`/`service_role` to the new secret via `JWT_KEYS`/`JWT_JWKS`).
5. **Review `.env`**, then restart the whole auth path:
   `docker compose down && docker compose up -d`.
6. **Re-point every consumer** to the new keys; prefer the new `sb_secret_...` for backend/agent
   credentials over the legacy `service_role` JWT, ahead of the end-2026 legacy deprecation.
7. **Also rotate non-auth defaults flagged by the docs** while down: `POSTGRES_PASSWORD`,
   `DASHBOARD_USERNAME`/`DASHBOARD_PASSWORD`, `SECRET_KEY_BASE` (64+), `VAULT_ENC_KEY` (exactly 32),
   `PG_META_CRYPTO_KEY`, `LOGFLARE_*_ACCESS_TOKEN`, `S3_PROTOCOL_ACCESS_KEY_*`, `MINIO_ROOT_PASSWORD`,
   plus URL settings (`SITE_URL`, `API_EXTERNAL_URL`, `SUPABASE_PUBLIC_URL`).
   ([docker.mdx](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/docker.mdx))
8. **Verify:** confirm the default `super-secret-jwt-token...` secret and the demo `supabase-demo`
   JWTs no longer verify; smoke a portal-issued credential against `/mcp`.

**Ongoing:** for routine key rotation thereafter, use `utils/rotate-new-api-keys.sh` (no session
loss); reserve `add-new-auth-keys.sh` re-run (forces re-auth) for actual signing-key compromise.

### Fallback trigger → full self-managed compose

Only fall back to a hand-rolled compose if **all** of the following hold:
- our pinned stack predates 2026-03-16 (no `add-new-auth-keys.sh` / `JWT_KEYS` wiring), **and**
- we cannot bump the pinned docker stack to a version that includes them, **and**
- the legacy manual path (2.B) cannot be validated (the **UNVERIFIED** `ALTER DATABASE
  app.settings.jwt_secret` step fails to take effect in our deployment).

In practice the first-choice fallback is **bump the stack**, not hand-roll compose. Hand-rolling is
last resort.

---

## Open Questions for Operator

1. **What version is our pinned Supabase docker stack?** Determines path 2.A vs 2.B. If pre-2026-03-16,
   confirm we can bump it (preferred) rather than hand-roll.
2. **Consumer inventory:** which SIFT components hold `service_role` today, and can they move to the
   new `sb_secret_...` key now, or must we keep legacy `service_role` alive through the end-2026
   deprecation window?
3. **Installer behavior:** does our installer currently *write* the demo defaults into staged `.env` /
   token files? If so, the real fix is to make the installer call `generate-keys.sh` +
   `add-new-auth-keys.sh` at provision time so a default-key install is impossible, not just remediated.

---

## Sources (official only)

- [Self-Hosting with Docker | Supabase Docs](https://supabase.com/docs/guides/self-hosting/docker) ·
  [docker.mdx source](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/docker.mdx)
- [New API Keys and Asymmetric Authentication | Supabase Docs](https://supabase.com/docs/guides/self-hosting/self-hosted-auth-keys) ·
  [self-hosted-auth-keys.mdx source](https://github.com/supabase/supabase/blob/master/apps/docs/content/guides/self-hosting/self-hosted-auth-keys.mdx)
- [Understanding API keys | Supabase Docs](https://supabase.com/docs/guides/api/api-keys)
- [JWT Signing Keys | Supabase Docs](https://supabase.com/docs/guides/auth/signing-keys)
- [JSON Web Token (JWT) | Supabase Docs](https://supabase.com/docs/guides/auth/jwts)
- [Introducing JWT Signing Keys | Supabase Blog](https://supabase.com/blog/jwt-signing-keys)
- [docker/CHANGELOG.md](https://github.com/supabase/supabase/blob/master/docker/CHANGELOG.md) (PRs #43554, #45941)
- [Discussion #19560 — Can't change JWT secret on self-hosted](https://github.com/orgs/supabase/discussions/19560) — **community, no staff reply; ALTER DATABASE step UNVERIFIED**

---

## Addendum — CLI local-stack (`supabase start`) rotation

**Status:** Research — decision-grade. Verified against the **Supabase CLI source at the exact
pinned tag `v2.105.0`** (stronger than docs prose for this question; the public docs site
returned 404 for the live config page during this pass, so the struct/source is the authority).
**Date:** 2026-06-15.
**Scope:** This addendum is about the **CLI-provisioned local stack** (`supabase start`), which is
what `scripts/setup-supabase.sh` runs — NOT the docker-compose self-hosted stack covered above.

### Ground truth — why a fresh install comes up on demo keys

The CLI generates the local `anon`/`service_role` keys at `supabase start` time **in Go code**, not
from a fixed table. The relevant logic is in `apps/cli-go/pkg/config/apikeys.go` at `v2.105.0`:

```go
const (
    defaultJwtSecret      = "super-secret-jwt-token-with-at-least-32-characters-long"
    defaultJwtExpiry      = 1983812996
    defaultPublishableKey = "sb_publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH"
    defaultSecretKey      = "sb_secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"
)

func (a *auth) generateAPIKeys() error {
    if len(a.JwtSecret.Value) == 0 {
        a.JwtSecret.Value = defaultJwtSecret          // <-- falls back to the PUBLIC demo secret
    } else if len(a.JwtSecret.Value) < 16 {
        return errors.Errorf("Invalid config for auth.jwt_secret. Must be at least 16 characters")
    }
    if len(a.AnonKey.Value) == 0 {
        signed, _ := a.generateJWT("anon")            // HS256 over JwtSecret, iss "supabase-demo"
        a.AnonKey.Value = signed
    }
    if len(a.ServiceRoleKey.Value) == 0 {
        signed, _ := a.generateJWT("service_role")
        a.ServiceRoleKey.Value = signed
    }
    if len(a.PublishableKey.Value) == 0 { a.PublishableKey.Value = defaultPublishableKey }
    if len(a.SecretKey.Value) == 0      { a.SecretKey.Value = defaultSecretKey }
    return nil
}
```

So: our `config.toml` sets `jwt_expiry` only and leaves `auth.jwt_secret` empty ⇒ the CLI takes the
`defaultJwtSecret` branch ⇒ it HS256-signs `anon`/`service_role` over the **published** demo secret
with `iss:"supabase-demo"` ⇒ `supabase status -o env` emits the well-known public demo keys. (The
`sb_publishable_…`/`sb_secret_…` opaque keys are likewise hardcoded constants when unset.)
([apps/cli-go/pkg/config/apikeys.go @ v2.105.0](https://github.com/supabase/cli/blob/v2.105.0/apps/cli-go/pkg/config/apikeys.go))

### Q1 — Can the CLI local stack take a CUSTOM JWT secret so `status` emits OUR keys? **YES — config-time.**

The `[auth]` config struct (`apps/cli-go/pkg/config/auth.go @ v2.105.0`) exposes these TOML keys,
each typed `Secret` so they accept literal values **or** `env(VAR)` interpolation / `.env` injection
(the struct comment is literally `// Custom secrets can be injected from .env file`):

| `config.toml` key (under `[auth]`) | Go field | Type | Effect when set |
|---|---|---|---|
| `jwt_secret` | `JwtSecret` | `Secret` | Root HS256 secret; min **16 chars** or `supabase start` errors. When set, `anon`/`service_role` are signed by THIS (unique per install) instead of the demo secret. |
| `anon_key` | `AnonKey` | `Secret` | Override the emitted anon key outright (else minted from `jwt_secret`). |
| `service_role_key` | `ServiceRoleKey` | `Secret` | Override the emitted service_role key (else minted from `jwt_secret`). |
| `publishable_key` | `PublishableKey` | `Secret` | Override `sb_publishable_…` (else hardcoded demo constant). |
| `secret_key` | `SecretKey` | `Secret` | Override `sb_secret_…` (else hardcoded demo constant). |
| `signing_keys_path` | `SigningKeysPath` | `string` | Path to a JWK file; if present (with a loaded key), keys are minted **asymmetrically** (ES256/RS256) instead of HS256 — see Q3. |

Source: `auth.go @ v2.105.0`, struct fields with `toml:"jwt_secret"`, `toml:"anon_key"`,
`toml:"service_role_key"`, `toml:"publishable_key"`, `toml:"secret_key"`, `toml:"signing_keys_path"`.
([apps/cli-go/pkg/config/auth.go @ v2.105.0](https://github.com/supabase/cli/blob/v2.105.0/apps/cli-go/pkg/config/auth.go))

**Version landed:** `auth.jwt_secret` / `anon_key` / `service_role_key` as `[auth]` config keys are
present and load-bearing in the generation path at our pin **v2.105.0** (confirmed in source). They
predate it (the "inject from .env" comment and `generateAPIKeys` fallback have been in the CLI's
config-as-code model since the v2 line; `gen signing-key` + `signing_keys_path` + the ES256 default
arrived earlier in the v2.71.x range per cli issue #4726). The exact first-introduction tag was not
pinned down in this pass and is **UNVERIFIED**, but is moot — they exist at v2.105.0, which is what we run.

So the answer is concretely: set **`auth.jwt_secret`** (literal or `env(SUPABASE_JWT_SECRET)`) in
`supabase/config.toml`, run `supabase start`, and `supabase status -o env` will emit `ANON_KEY` /
`SERVICE_ROLE_KEY` HS256-signed by OUR secret — unique per install. No demo keys.

### Q2 — If it did NOT support it (it does)

Not applicable: config-time custom secret IS supported at v2.105.0 (Q1). Post-start re-minting and
re-keying GoTrue/PostgREST/Kong containers by hand is therefore **unnecessary** and not recommended
for the CLI stack — the CLI owns those containers and wires them from `config.toml` at start. Doing
it by hand would be fought by the next `supabase start`/`stop`. (Recorded only to close the question.)

### Q3 — Asymmetric signing keys / `sb_publishable_*` / `sb_secret_*` on the LOCAL stack at v2.105.0

**Available: YES.**
- `signing_keys_path = "./signing_key.json"` under `[auth]` makes the local stack mint tokens with an
  **asymmetric** key (ES256 P-256 or RS256). Generate the key with `supabase gen signing-key
  --algorithm ES256` (also supports `RS256`; `--append` to add to an existing file) and save it as a
  **single raw JSON object** (not an array) at that path. When `signing_keys_path` is set and a key is
  loaded, `generateJWT` calls `GenerateAsymmetricJWT` (ES256/RS256) with a 10-year expiry instead of
  the HS256 path. ([apikeys.go @ v2.105.0](https://github.com/supabase/cli/blob/v2.105.0/apps/cli-go/pkg/config/apikeys.go);
  [gen signing-key CLI ref](https://supabase.com/docs/reference/cli/supabase-gen-signing-key))
- The opaque `sb_publishable_…` / `sb_secret_…` keys are overridable via `auth.publishable_key` /
  `auth.secret_key`; **unset, they fall back to hardcoded demo constants** (see code above), so they
  must be set explicitly if you care about them locally.
- **Cleaner provision story?** For our goal (fresh install never on demo keys), asymmetric is **not
  simpler** — it adds a generated key file to manage and the `gen signing-key` step. The single
  `jwt_secret` HS256 override is the leaner config-time fix. Asymmetric is the better long-term posture
  (public-key verification, decoupled rotation) but is optional for this remediation. Note the default
  algorithm flipped to ES256 in the v2.71.x line (cli issue #4726); HS256 minting only happens when
  `signing_keys_path` is empty — which is our current state, hence HS256 demo keys today.

### Q4 — Bottom line: single recommended mechanism for `scripts/setup-supabase.sh`

**Config-time, one key. Write a unique `auth.jwt_secret` before `supabase start`.** Concrete bash:

1. Generate a unique secret per install (≥16 chars; 32+ recommended), e.g.
   `JWT_SECRET="$(openssl rand -hex 32)"` (or `head -c 32 /dev/urandom | base64`).
2. Make `config.toml` read it from env rather than hardcoding — add under `[auth]`:
   ```toml
   [auth]
   jwt_secret = "env(SUPABASE_AUTH_JWT_SECRET)"
   ```
   and export `SUPABASE_AUTH_JWT_SECRET="$JWT_SECRET"` (or place it in the project-root `.env` the CLI
   reads) **before** calling `supabase start`. (Literal-in-toml also works but persists the secret in
   a tracked file — prefer `env()`.)
3. `supabase start` (already pinned v2.105.0). The CLI mints `anon`/`service_role` HS256-signed by our
   secret automatically — no container re-keying, no post-start re-mint.
4. Read keys as today: `supabase status -o env` ⇒ `ANON_KEY` / `SERVICE_ROLE_KEY` are now ours.
5. If `supabase start` was already run once with the old/empty secret, the change takes effect after
   **`supabase stop && supabase start`** (config is read at start; a restart reloads it). `db reset` is
   NOT required for key generation (it concerns DB state, not key minting).
6. Optional hardening: also set `auth.publishable_key` / `auth.secret_key` (else they stay demo
   constants), and/or move to `signing_keys_path` asymmetric keys later.

**UNVERIFIED / needs VM confirmation:**
- That a fresh `supabase start` with `auth.jwt_secret` set propagates the new secret to **all** local
  containers our agents hit (GoTrue, PostgREST/Kong) in one shot — the source says the CLI owns that
  wiring, but we have not empirically run `supabase status -o env` + a `service_role` smoke against the
  local `/rest`/`/auth` with a custom secret on the VM. Confirm by diffing the emitted `ANON_KEY`
  against the known demo string and authenticating once.
- The exact earliest CLI tag that introduced `auth.jwt_secret` as a config key (moot — present at our
  pinned v2.105.0).
- The live config-doc page (`/docs/guides/local-development/cli/config`) 404'd during this pass; the
  config keys above are sourced from CLI **source at the v2.105.0 tag**, which is authoritative for our
  pin. If a doc-prose citation is later needed, that page (rendered) is the home for these keys.

### Addendum sources (official only)
- [supabase/cli `apps/cli-go/pkg/config/apikeys.go` @ v2.105.0](https://github.com/supabase/cli/blob/v2.105.0/apps/cli-go/pkg/config/apikeys.go) — key generation + demo constants
- [supabase/cli `apps/cli-go/pkg/config/auth.go` @ v2.105.0](https://github.com/supabase/cli/blob/v2.105.0/apps/cli-go/pkg/config/auth.go) — `[auth]` struct (`jwt_secret`, `anon_key`, `service_role_key`, `publishable_key`, `secret_key`, `signing_keys_path`)
- [Managing config and secrets | Supabase Docs](https://supabase.com/docs/guides/local-development/managing-config) — `env(VAR)` interpolation + `.env` at project root
- [supabase gen signing-key | CLI Reference](https://supabase.com/docs/reference/cli/supabase-gen-signing-key) — `--algorithm ES256|RS256`, `--append`
- [supabase/cli issue #4726](https://github.com/supabase/cli/issues/4726) — default flipped HS256→ES256 in v2.71.1; `jwt_algorithm` request
