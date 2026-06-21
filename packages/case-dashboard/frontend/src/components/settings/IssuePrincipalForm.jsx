// ─────────────────────────────────────────────────────────────────────────
// IssuePrincipalForm — issue an agent/service JWT session (legacy parity §4).
// kind (agent/service) · display name (required) · tool scopes · operator
// password (required, re-verified server-side against Supabase). Reskinned to
// graphite/orange tokens. autoComplete="current-password" so the OS can autofill
// the operator's password; no token material is rendered here.
// ─────────────────────────────────────────────────────────────────────────

const FIELD =
  'w-full rounded-lg border border-border-soft bg-bg-raised px-3 py-2 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring'
const LABEL = 'mono mb-1 block text-[10px] text-muted-foreground'

export function IssuePrincipalForm({ form, onField, onSubmit }) {
  return (
    <div className="flex h-fit flex-col rounded-lg border border-border-faint bg-card p-4 lg:col-span-1">
      <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-[.1em] text-muted-foreground">
        Issue JWT Session
      </p>
      <form onSubmit={onSubmit} className="space-y-4">
        <div>
          <label htmlFor="principal-kind" className={LABEL}>
            KIND
          </label>
          <select id="principal-kind" value={form.kind} onChange={(e) => onField('kind', e.target.value)} className={FIELD}>
            <option value="agent">agent</option>
            <option value="service">service</option>
          </select>
        </div>
        <div>
          <label htmlFor="principal-name" className={LABEL}>
            DISPLAY NAME *
          </label>
          <input
            id="principal-name"
            type="text"
            placeholder="e.g. Hermes investigation agent"
            value={form.name}
            onChange={(e) => onField('name', e.target.value)}
            required
            className={FIELD}
          />
        </div>
        <div>
          <label htmlFor="principal-scopes" className={LABEL}>
            TOOL SCOPES (comma-separated)
          </label>
          <input
            id="principal-scopes"
            type="text"
            placeholder="mcp:* or tool:foo, namespace:bar"
            value={form.scopes}
            onChange={(e) => onField('scopes', e.target.value)}
            className={`${FIELD} mono`}
          />
        </div>
        <div>
          <label htmlFor="principal-password" className={LABEL}>
            OPERATOR PASSWORD *
          </label>
          <input
            id="principal-password"
            type="password"
            placeholder="Re-auth: confirm your password"
            value={form.password}
            onChange={(e) => onField('password', e.target.value)}
            required
            autoComplete="current-password"
            className={FIELD}
          />
          <p className="mt-1 text-[10px] text-text-ghost">
            Issuing a credential is a sensitive action — re-verified against Supabase.
          </p>
        </div>
        <button
          type="submit"
          className="mono w-full rounded-lg border border-primary bg-primary/10 py-2 text-xs font-semibold text-primary transition-opacity hover:opacity-85 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          Issue session
        </button>
      </form>
    </div>
  )
}
