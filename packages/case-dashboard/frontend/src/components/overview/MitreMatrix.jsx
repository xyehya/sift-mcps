import { useState } from 'react'

import { cn } from '@/lib/utils'
import { mitreByTactic, tacticMeta, techniqueMeta } from '@/components/overview/overview-metrics'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'

// ─────────────────────────────────────────────────────────────────────────
// MITRE ATT&CK panel — RUN-4c #32. Techniques referenced across findings, GROUPED
// under their ATT&CK tactic (kill-chain order) with a coloured tactic header so it
// reads "Lateral Movement › T1021.001", not a flat pill list. Chips are colour-
// coded by tactic (token classes; colour is supplementary to the always-present
// tactic label + mono T-code → colour-not-only) and CLICKABLE: each opens a Sheet
// with the technique detail + the findings that cite it. No external navigation
// (CSP stays 'self') — the panel is informational. Empty state guides the examiner.
// ─────────────────────────────────────────────────────────────────────────

export function MitreMatrix({ findings }) {
  const [selected, setSelected] = useState(null)
  const groups = mitreByTactic(findings)

  if (groups.length === 0) {
    return <p className="text-sm text-muted-foreground">No MITRE ATT&CK techniques mapped in findings yet.</p>
  }

  const sel = selected ? techniqueMeta(selected) : null
  const selMeta = sel ? tacticMeta(sel.tactic) : null
  const selFindings = selected ? (findings ?? []).filter((f) => (f.mitre_ids ?? []).includes(selected)) : []

  return (
    <div className="flex flex-col gap-3" aria-label="MITRE ATT&CK techniques grouped by tactic">
      {groups.map((g) => (
        <div key={g.tactic} className="flex flex-col gap-1.5">
          <div className="flex items-center gap-1.5">
            <span aria-hidden className={cn('size-1.5 rounded-full', g.meta.dot)} />
            <span className={cn('mono text-xs font-semibold uppercase tracking-[0.12em]', g.meta.text)}>{g.meta.label}</span>
            <span className="tnum text-xs text-muted-foreground">· {g.techniques.length}</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {g.techniques.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setSelected(t.id)}
                aria-label={`${g.meta.label}: ${t.id}${t.name ? ` — ${t.name}` : ''}. View technique detail.`}
                className={cn(
                  /* text-xs (12px) — meets WCAG 4.5:1 small-text requirement (was text-[11px]) */
                  'mono inline-flex items-center rounded-full border px-2 py-0.5 text-xs transition-colors hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  g.meta.ring,
                  g.meta.tint,
                  g.meta.text,
                )}
              >
                {t.id}
              </button>
            ))}
          </div>
        </div>
      ))}

      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent side="right" className="w-full sm:max-w-md">
          {sel && (
            <>
              <SheetHeader>
                <div className="flex items-center gap-2">
                  <span aria-hidden className={cn('size-2 rounded-full', selMeta.dot)} />
                  <span className={cn('mono text-[10px] font-semibold uppercase tracking-[0.14em]', selMeta.text)}>{selMeta.label}</span>
                </div>
                <SheetTitle className="mono text-lg">{sel.id}</SheetTitle>
                <SheetDescription>{sel.name ?? 'Technique referenced by findings in this case.'}</SheetDescription>
              </SheetHeader>

              <div className="flex flex-col gap-4 px-4 pb-4">
                <p className="rounded-lg border border-border bg-secondary/40 p-3 text-xs leading-relaxed text-muted-foreground">
                  ATT&CK reference shown for context only — informational, with no external navigation (the portal CSP stays
                  <span className="mono"> 'self'</span>).
                </p>

                <div className="flex flex-col gap-2">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    Cited by {selFindings.length} finding{selFindings.length === 1 ? '' : 's'}
                  </p>
                  <ul className="flex flex-col gap-2">
                    {selFindings.map((f) => (
                      <li key={f.id} className="flex items-start gap-2 text-xs">
                        <span className="mono shrink-0 text-muted-foreground">{f.id}</span>
                        <span className="text-foreground">{f.title ?? '—'}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  )
}
