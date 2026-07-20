import { AlertOctagon } from 'lucide-react'

import { violationPath } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// CustodyViolations — chain-of-custody violation panel. Renders only when
// there are missing or modified files. D4: both findings resolve via ONE
// honest verb — Retire (Replace/Reacquire and exact Restore are permanently
// out of scope). Selection feeds the shared batch Resolve flow in
// EvidenceTab; no per-finding password prompt here.
// ─────────────────────────────────────────────────────────────────────────

function ViolationRow({ path, selected, onToggle }) {
  return (
    <li className="mono">
      <label className="flex cursor-pointer items-center justify-between gap-2">
        <span className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={selected}
            onChange={() => onToggle(path)}
            className="size-3.5 accent-destructive"
            aria-label={`Select ${path} to retire`}
          />
          <span className="break-all">{path}</span>
        </span>
        <span className="mono shrink-0 text-[10px] font-semibold uppercase tracking-wider text-destructive">
          Retire
        </span>
      </label>
    </li>
  )
}

export function CustodyViolations({ chainStatus, selectedTargets, onToggleTarget }) {
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
                <ViolationRow
                  key={path}
                  path={path}
                  selected={selectedTargets.has(path)}
                  onToggle={onToggleTarget}
                />
              )
            })}
          </ul>
        </div>
      )}

      {modified.length > 0 && (
        <div className="text-xs">
          <strong className="mb-1 block">Modified Files (Hash Mismatch):</strong>
          <p className="mb-2 text-[11px] opacity-80">
            The sealed bytes changed on disk. <strong>Retire</strong> the object — the prior sealed
            hash is never deleted, only excluded from the active manifest. A legitimate re-acquisition
            of the current bytes is a new Evidence Object at the next Seal, not a Resolve action.
          </p>
          <ul className="list-disc space-y-1 pl-5">
            {modified.map((f) => {
              const path = violationPath(f)
              return (
                <ViolationRow
                  key={path}
                  path={path}
                  selected={selectedTargets.has(path)}
                  onToggle={onToggleTarget}
                />
              )
            })}
          </ul>
        </div>
      )}
    </div>
  )
}
