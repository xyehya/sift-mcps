import {
  formatDateTime,
  formatTtl,
  principalStatus,
  tokenTypeLabel,
  statusChipClass,
  isRevoked,
} from './settings-utils'

// ─────────────────────────────────────────────────────────────────────────
// PrincipalsTable — the active agent/service JWT principals table (legacy
// parity §6/§7): token type · name · derived status chip · live TTL remaining ·
// scopes · revoke action. Revoke is disabled for already-revoked principals and
// while a revoke is in flight. Reskinned to token classes; revoke uses the
// crimson (irreversible) tone.
// ─────────────────────────────────────────────────────────────────────────

const TH = 'mono whitespace-nowrap px-3 py-2.5 text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground'

export function PrincipalsTable({ principals, loading, revoking, nowMs, onRevoke }) {
  const canRevoke = typeof onRevoke === 'function'
  const colSpan = canRevoke ? 6 : 5
  return (
    <div
      className={`flex flex-col rounded-lg border border-border-faint bg-card p-4 ${
        canRevoke ? 'lg:col-span-2' : 'lg:col-span-3'
      }`}
    >
      <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-[.1em] text-muted-foreground">
        Active Principals
      </p>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-left text-xs">
          <thead>
            <tr className="border-b border-border-soft bg-secondary/40">
              <th className={TH}>Token Type</th>
              <th className={TH}>Name</th>
              <th className={TH}>Status</th>
              <th className={TH}>TTL Remaining</th>
              <th className={TH}>Scopes</th>
              {canRevoke && <th className={`${TH} text-right`}>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={colSpan} className="mono animate-pulse py-8 text-center text-muted-foreground">
                  Loading principals…
                </td>
              </tr>
            ) : principals.length === 0 ? (
              <tr>
                <td colSpan={colSpan} className="mono py-8 text-center text-muted-foreground">
                  No agent/service principals.
                </td>
              </tr>
            ) : (
              principals.map((p) => {
                const status = principalStatus(p, nowMs)
                const revokeKey = `${p.principal_type}-${p.principal_id}`
                const revoked = isRevoked(p)
                const revokeDisabled = revoked || revoking === revokeKey
                return (
                  <tr key={revokeKey} className="border-b border-border-faint align-top transition-colors hover:bg-secondary/50">
                    <td className="px-3 py-3">
                      <div className="mono text-[13px] text-foreground">{tokenTypeLabel(p)}</div>
                      <div className="mono text-[10px] text-muted-foreground">{p.principal_type}</div>
                    </td>
                    <td className="px-3 py-3">
                      <div className="mono text-[13px] font-semibold text-foreground">{p.display_name || p.principal_id}</div>
                      <div className="mono text-[10px] text-muted-foreground">{p.principal_id}</div>
                    </td>
                    <td className="px-3 py-3">
                      <span
                        className={`mono inline-flex w-fit items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em] ${statusChipClass(status)}`}
                      >
                        {status}
                      </span>
                    </td>
                    <td className="mono px-3 py-3 text-[11px] tabular-nums text-muted-foreground">
                      <div>{formatTtl(p.last_issued_expires_at, nowMs)}</div>
                      <div className="text-[10px] text-text-ghost">{formatDateTime(p.last_issued_expires_at)}</div>
                    </td>
                    <td className="mono max-w-[220px] px-3 py-3 text-[10px] text-muted-foreground">
                      {(p.tool_scopes || []).length > 0 ? (p.tool_scopes || []).join(', ') : 'none'}
                    </td>
                    {canRevoke && (
                      <td className="px-3 py-3 text-right">
                        <button
                          type="button"
                          onClick={() => onRevoke(p.principal_type, p.principal_id)}
                          disabled={revokeDisabled}
                          className={`mono rounded-md border px-2.5 py-1 text-[10px] font-semibold transition-opacity hover:opacity-85 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-40 ${
                            revokeDisabled
                              ? 'border-border-soft bg-bg-raised text-muted-foreground'
                              : 'border-crimson/30 bg-crimson/10 text-destructive'
                          }`}
                        >
                          {revoked ? 'Revoked' : revoking === revokeKey ? 'Revoking…' : 'Revoke'}
                        </button>
                      </td>
                    )}
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
