import { AlertOctagon } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { violationPath } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// CustodyViolations — chain-of-custody violation panel (legacy IA parity §4).
// Renders only when there are missing or modified files. Missing → Retire.
// Modified (hash mismatch) → Re-seal (reacquire) / Retire, with the custody
// copy preserved: the prior sealed hash is superseded, not deleted; both record
// an append-only, re-authenticated custody event.
// ─────────────────────────────────────────────────────────────────────────

export function CustodyViolations({ chainStatus, onRetire, onReacquire }) {
  const missing = chainStatus?.missing ?? []
  const modified = chainStatus?.modified ?? []
  if (!missing.length && !modified.length) return null

  return (
    <div className="rounded-lg border border-destructive/50 bg-destructive/5 p-4 text-destructive" role="alert">
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-bold">
        <AlertOctagon className="size-3.5" aria-hidden /> Chain of Custody Violation
      </h4>

      {missing.length > 0 && (
        <div className="mb-3 text-xs">
          <strong className="mb-1 block">Missing Files:</strong>
          <ul className="list-disc space-y-1 pl-5">
            {missing.map((f) => {
              const path = violationPath(f)
              return (
                <li key={path} className="mono">
                  <div className="flex items-center justify-between">
                    <span className="break-all">{path}</span>
                    <Button
                      type="button"
                      variant="outline"
                      size="xs"
                      onClick={() => onRetire(path)}
                      className="mono ml-4 shrink-0 text-[10px] text-destructive border-destructive/40 hover:bg-destructive/10"
                    >
                      Retire File
                    </Button>
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      )}

      {modified.length > 0 && (
        <div className="text-xs">
          <strong className="mb-1 block">Modified Files (Hash Mismatch):</strong>
          <p className="mb-2 text-[11px] opacity-80">
            The sealed bytes changed on disk. If this is a legitimate re-acquisition (e.g. a corrupted
            image was re-imaged), <strong>Re-seal</strong> to supersede the old hash with the new one.
            If the file no longer belongs in the case, <strong>Retire</strong> it. Both record an
            append-only, re-authenticated custody event — the prior sealed hash is never deleted.
          </p>
          <ul className="list-disc space-y-1 pl-5">
            {modified.map((f) => {
              const path = violationPath(f)
              return (
                <li key={path} className="mono">
                  <div className="flex items-center justify-between gap-2">
                    <span className="break-all">{path}</span>
                    <div className="flex shrink-0 gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="xs"
                        onClick={() => onReacquire(path)}
                        className="mono text-[10px] text-status-approved border-status-approved/40 hover:bg-status-approved/10"
                      >
                        Re-seal
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="xs"
                        onClick={() => onRetire(path)}
                        className="mono text-[10px] text-destructive border-destructive/40 hover:bg-destructive/10"
                      >
                        Retire
                      </Button>
                    </div>
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </div>
  )
}
